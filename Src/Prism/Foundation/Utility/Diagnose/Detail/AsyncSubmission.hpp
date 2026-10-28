/** @file AsyncSubmission.hpp
 * @brief 唯一记录队列的非阻塞准入与控制 barrier。
 */
#pragma once
#include <Prism/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/BackendWorker.hpp>
#include <Prism/Foundation/Utility/Diagnose/Submission/Request.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/Record.hpp>
#include <Prism/Foundation/Utility/Text/Redaction.hpp>
#include <chrono>
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <mutex>
#include <optional>

namespace Prism::Diagnose::Detail
{
    class EmergencyWriter final
    {
    public:
        /**
         * @brief 设置应急输出目标。
         * @param Destination 写入目标；默认使用标准错误流，传入 nullptr 会使后续写入失败。
         */
        explicit EmergencyWriter(std::FILE* Destination = stderr) noexcept : Destination_(Destination)
        {
        }

        /**
         * @brief 对一条记录执行脱敏、限长并同步写入目标文件流。
         * @param Record 已拥有消息和上下文的记录。
         * @return 完整写入并 flush 成功时返回 true；目标为空、并发占用写入门闩、写入失败或发生异常时返回 false。
         * @details 每次输出最多 MaxFallbackBytes 字节，包含末尾换行；本方法不等待其他应急写入完成。
         */
        auto Write(const SubmissionRecord& Record) -> bool
        {
            if (Destination_ == nullptr || Gate_.test_and_set(std::memory_order_acquire))
            {
                return false;
            }
            struct GateRelease final
            {
                std::atomic_flag& Gate;
                ~GateRelease()
                {
                    Gate.clear(std::memory_order_release);
                }
            } Release{Gate_};

            auto Payload = Text::RedactSensitiveText(BuildPayload(Record));
            auto [Bounded, Unused] = TruncateUtf8(Payload, MaxFallbackBytes - 1U);
            (void)Unused;
            Bounded.push_back('\n');
            return std::fwrite(Bounded.data(), 1U, Bounded.size(), Destination_) == Bounded.size() &&
                std::fflush(Destination_) == 0;
        }

        static constexpr std::size_t MaxFallbackBytes = 2048U; ///< 单条应急输出的最大字节数，包含换行。

    private:
        std::atomic_flag Gate_ = ATOMIC_FLAG_INIT; ///< 防止多个调用同时写入同一 FILE。
        std::FILE* Destination_{nullptr}; ///< 非拥有输出指针，生命周期由构造方保证。
    };

    /** @brief 门闩持有期间独占 producer；释放与归还不分配。 */
    class SubmissionGate final
    {
    public:
        explicit SubmissionGate(std::atomic_flag& Gate) noexcept : Gate_(Gate),
            Acquired_(!Gate.test_and_set(std::memory_order_acquire)) {}
        ~SubmissionGate()
        {
            if (Acquired_) { Gate_.clear(std::memory_order_release); Gate_.notify_all(); }
        }
        [[nodiscard]] auto Acquired() const noexcept -> bool { return Acquired_; }
    private:
        std::atomic_flag& Gate_;
        bool Acquired_;
    };
    class AsyncSubmission final
    {
    public:
        [[nodiscard]] static auto ShouldWrite(const LogLevel Configured, const LogLevel Requested) noexcept -> bool
        {
            return IsLevelEnabled(Configured, Requested);
        }
        /**
         * @brief 先取得实际队列槽，再同步捕获全部输入，最后一次发布。
         * @details 只复制固定 storage；容量/竞争返回 Dropped，快照溢出返回 Failed。
         *          Accepted 不表示已渲染或落盘；取消只能由 owner 停止接入，不清掉已接受记录。
         */
        [[nodiscard]] static auto Submit(AsyncBackendState& State, const SubmissionRequest& Request) noexcept
            -> SubmissionReceipt
        {
            if (!State.Accepting_.load(std::memory_order_acquire) || !Request.Epoch ||
                Request.Epoch->Value().Closed.load(std::memory_order_acquire))
            {
                return {SubmissionStatus::Stopped, 0U};
            }
            SubmissionGate Gate(State.EnqueueGate_);
            if (!Gate.Acquired()) { return QueueFailure(State, Request); }
            if (!State.Accepting_.load(std::memory_order_acquire)) { return {SubmissionStatus::Stopped, 0U}; }
            const auto Write = State.Write_.load(std::memory_order_relaxed);
            if (Write - State.Read_.load(std::memory_order_acquire) >= State.Settings_.Logging.QueueCapacity)
            {
                return QueueFailure(State, Request);
            }
            const auto Sequence = State.NextSequence_.load(std::memory_order_relaxed);
            if (Write == UINT64_MAX || Sequence == UINT64_MAX)
            {
                State.CaptureFailures_.fetch_add(1U, std::memory_order_relaxed);
                return {SubmissionStatus::Failed, 0U, {Prism::Fault::Code::ResourceUnavailable}};
            }
            auto& Record = State.Queue_[Write % State.Settings_.Logging.QueueCapacity];
            Record.Message.Reset();
            Record.Epoch.reset();
            const auto Captured = CaptureMessageValue(
                Record.Message, Request, Request.Epoch->Value().Settings.Logging.Formatting);
            if (Captured.Failed())
            {
                Record.Message.Reset();
                State.CaptureFailures_.fetch_add(1U, std::memory_order_relaxed);
                return {SubmissionStatus::Failed, 0U, Captured};
            }
            if (!Request.Context || !Record.Context.Capture(*Request.Context))
            {
                Record.Message.Reset();
                State.CaptureFailures_.fetch_add(1U, std::memory_order_relaxed);
                return {SubmissionStatus::Failed, 0U, {Prism::Fault::Code::ResourceUnavailable}};
            }
            Record.Epoch = Request.Epoch;
            Record.Level = Request.Level;
            Record.Kind = Request.Kind;
            Record.Command = QueueCommand::Message;
            Record.Sequence = Sequence;
            Record.TimestampMilliseconds = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
            State.NextSequence_.store(Sequence + 1U, std::memory_order_relaxed);
            Publish(State, Write);
            return {SubmissionStatus::Accepted, Sequence};
        }
        /** @brief 非阻塞提交 flush；容量不足时跳过，最终关闭仍执行真实 flush。 */
        static auto Flush(AsyncBackendState& State) noexcept -> void
        {
            (void)TryControl(State, QueueCommand::Flush, 0U);
        }
        /** @brief 禁止新消息；已入队记录继续保活到消费完成。 */
        static auto Stop(AsyncBackendState& State) noexcept -> void
        {
            State.Accepting_.store(false, std::memory_order_release);
        }
        /**
         * @brief 控制线程以同一绝对截止时间完成非阻塞入队与 barrier 等待。
         * @note 只能在非协程控制线程调用；没有 block overflow policy 或临时 logger/promise。
         */
        [[nodiscard]] static auto DrainOnControlThread(AsyncBackendState& State,
            const std::chrono::steady_clock::time_point Deadline) -> SubmissionReceipt
        {
            SubmissionGate Barrier(State.BarrierGate_);
            if (!Barrier.Acquired()) { return {SubmissionStatus::Dropped, 0U, {Prism::Fault::Code::ResourceUnavailable}}; }
            const auto Id = State.NextBarrier_.load(std::memory_order_relaxed);
            if (Id == UINT64_MAX) { return {SubmissionStatus::Failed, 0U}; }
            State.NextBarrier_.store(Id + 1U, std::memory_order_relaxed);
            for (;;)
            {
                if (std::chrono::steady_clock::now() >= Deadline) { return {SubmissionStatus::TimedOut, 0U, {Prism::Fault::Code::Timeout}}; }
                if (TryControl(State, QueueCommand::Barrier, Id)) { break; }
                if (State.WorkerFailed_.load(std::memory_order_acquire))
                {
                    return {SubmissionStatus::Failed, 0U, {Prism::Fault::Code::IoError}};
                }
                std::unique_lock Lock(State.ControlMutex_);
                const auto Retry = (std::min)(Deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds{1});
                State.ControlChanged_.wait_until(Lock, Retry);
            }
            std::unique_lock Lock(State.ControlMutex_);
            const auto Ready = State.ControlChanged_.wait_until(Lock, Deadline, [&State, Id]
            {
                return State.CompletedBarrier_.load(std::memory_order_acquire) >= Id ||
                    State.WorkerFailed_.load(std::memory_order_acquire);
            });
            if (!Ready) { return {SubmissionStatus::TimedOut, 0U, {Prism::Fault::Code::Timeout}}; }
            if (State.WorkerFailed_.load(std::memory_order_acquire))
            {
                return {SubmissionStatus::Failed, 0U, {Prism::Fault::Code::IoError}};
            }
            if (State.CompletedBarrierTicks_.load(std::memory_order_acquire) > Deadline.time_since_epoch().count())
            {
                return {SubmissionStatus::TimedOut, 0U, {Prism::Fault::Code::Timeout}};
            }
            const auto Status = State.BarrierStatus_.load(std::memory_order_acquire);
            if (Status != SubmissionStatus::Flushed)
            {
                return {SubmissionStatus::Failed, 0U, {Prism::Fault::Code::IoError}};
            }
            return {SubmissionStatus::Flushed,
                State.BarrierWrittenSequence_.load(std::memory_order_acquire)};
        }
    private:
        [[nodiscard]] static auto CaptureMessageValue(DeferredMessage& Message,
            const SubmissionRequest& Request, const FormattingLimits& Limits) noexcept -> Prism::Fault::Failure
        {
            if (Request.Capture) { return Request.Capture(Message, Request.Input, Limits); }
            return Message.CaptureText(Request.Message, Limits);
        }
        static auto Publish(AsyncBackendState& State, const std::uint64_t Write) noexcept -> void
        {
            State.Write_.store(Write + 1U, std::memory_order_release);
            State.ObserveQueueHighWatermark(State.QueueSize());
            BackendWorker::Wake(State);
        }
        [[nodiscard]] static auto TryControl(AsyncBackendState& State, const QueueCommand Command,
            const std::uint64_t Id) noexcept -> bool
        {
            SubmissionGate Gate(State.EnqueueGate_);
            if (!Gate.Acquired() || State.WorkerFailed_.load(std::memory_order_acquire) ||
                State.Stopping_.load(std::memory_order_acquire)) { return false; }
            const auto Write = State.Write_.load(std::memory_order_relaxed);
            if (Write == UINT64_MAX || Write - State.Read_.load(std::memory_order_acquire) >=
                State.Settings_.Logging.QueueCapacity) { return false; }
            auto& Record = State.Queue_[Write % State.Settings_.Logging.QueueCapacity];
            Record.Command = Command;
            Record.BarrierId = Id;
            Record.Epoch.reset();
            Record.Message.Reset();
            Publish(State, Write);
            return true;
        }
        [[nodiscard]] static auto QueueFailure(AsyncBackendState& State,
            const SubmissionRequest& Request) noexcept -> SubmissionReceipt
        {
            State.Dropped_[static_cast<std::size_t>(Request.Level)].fetch_add(1U, std::memory_order_relaxed);
            if (Request.Kind == SubmissionKind::Audit) { State.TerminalFailures_.fetch_add(1U, std::memory_order_relaxed); }
            return {SubmissionStatus::Dropped, 0U, {Prism::Fault::Code::ResourceUnavailable}};
        }
    };
}

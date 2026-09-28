/**
 * @file AsyncSubmission.hpp
 * @brief Preview Diagnose 对 spdlog async_logger 的轻量提交策略。
 * @details 本文件不创建线程、互斥量或自有队列；队列和 worker 完全由 spdlog thread pool 管理。
 */
#pragma once

#include <array>
#include <atomic>
#include <charconv>
#include <cstdio>
#include <ctime>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp>
#include <Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp>
#include <Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp>
#include <Preview/Statistics/Redaction.hpp>

namespace Preview::Diagnose::Detail
{

    /**
     * @brief 将拥有型记录转换为交给 spdlog 的消息正文。
     * @param Record 已捕获消息和上下文的记录。
     * @return Structured 模式返回单行 JSON 正文；人类模式返回身份前缀、扩展字段和消息正文。
     * @details 人类模式的等级由正文写为大驼峰标签；时间由 sink pattern 添加，不输出操作系统线程号。
     */
    [[nodiscard]] inline auto BuildPayload(const SubmissionRecord &Record) -> std::string
    {
        if (Record.Context.Mode == RenderMode::Structured)
        {
            auto Payload = ContextDecoder::RenderStructured(Record);
            if (!Payload.empty() && Payload.back() == '\n')
            {
                Payload.pop_back();
            }
            return Payload;
        }
        auto Payload = ContextDecoder::RenderHuman(Record.Context, Record.Message);
        Payload.insert(0U, "[" + std::string(Preview::Diagnose::LogLevelName(Record.Level)) + "] ");
        return Payload;
    }
    /**
     * @brief 在控制线程上将记录同步写入有界应急输出。
     * @details 默认目标为 stderr；写入前对消息脱敏和限长。常规 facade 提交不调用此类。
     * @warning Write 会同步执行 fwrite 和 fflush，禁止从协程或 I/O worker 调用。
     */
    class EmergencyWriter final
    {
    public:
        /**
         * @brief 设置应急输出目标。
         * @param Destination 写入目标；默认使用标准错误流，传入 nullptr 会使后续写入失败。
         */
        explicit EmergencyWriter(std::FILE *Destination = stderr) noexcept : Destination_(Destination)
        {
        }

        /**
         * @brief 对一条记录执行脱敏、限长并同步写入目标文件流。
         * @param Record 已拥有消息和上下文的记录。
         * @return 完整写入并 flush 成功时返回 true；目标为空、并发占用写入门闩、写入失败或发生异常时返回 false。
         * @details 每次输出最多 MaxFallbackBytes 字节，包含末尾换行；本方法不等待其他应急写入完成。
         */
        auto Write(const SubmissionRecord &Record) noexcept -> bool
        {
            if (Destination_ == nullptr || Gate_.test_and_set(std::memory_order_acquire))
            {
                return false;
            }
            struct GateRelease final
            {
                std::atomic_flag &Gate;
                ~GateRelease()
                {
                    Gate.clear(std::memory_order_release);
                }
            } Release{Gate_};

            try
            {
                auto Payload = Preview::Statistics::RedactSensitiveText(BuildPayload(Record));
                auto [Bounded, Unused] = TruncateUtf8(Payload, MaxFallbackBytes - 1U);
                (void)Unused;
                Bounded.push_back('\n');
                return std::fwrite(Bounded.data(), 1U, Bounded.size(), Destination_) == Bounded.size() &&
                       std::fflush(Destination_) == 0;
            }
            catch (...)
            {
                return false;
            }
        }

        static constexpr std::size_t MaxFallbackBytes = 2048U; ///< 单条应急输出的最大字节数，包含换行。

    private:
        std::atomic_flag Gate_ = ATOMIC_FLAG_INIT; ///< 防止多个调用同时写入同一 FILE。
        std::FILE *Destination_{nullptr};          ///< 非拥有输出指针，生命周期由构造方保证。
    };
    /**
     * @brief 将拥有型记录非阻塞地提交到 spdlog 异步队列。
     * @details 不创建线程、等待队列空间或执行同步 sink 写入。队列采用 discard_new；队列满时记录丢弃并立即返回。
     */
    class AsyncSubmission final
    {
    public:
        /**
         * @brief 判断日志级别是否通过配置阈值。
         * @param Configured 当前配置的级别。
         * @param Requested 本条记录请求的级别。
         * @return IsLevelEnabled 允许该级别时返回 true。
         */
        [[nodiscard]] static auto ShouldWrite(const LogLevel Configured, const LogLevel Requested) noexcept
            -> bool
        {
            return IsLevelEnabled(Configured, Requested);
        }

        /**
         * @brief 分配序号并将一条记录交给 spdlog 异步队列。
         * @param State 当前 backend 状态、spdlog pool、logger 和提交指标。
         * @param Record 已捕获的拥有型记录；本函数会写入提交序号和提交类型。
         * @param Kind 普通记录或终态 Audit 记录。
         * @return Accepted 表示 spdlog 接受异步请求；队列满时返回 Dropped；backend 不可用时返回 Failed。
         * @details 所有级别均使用同一非阻塞队列策略。Accepted 不代表 sink 已完成写入或 flush；Audit 也不提供持久化保证。
         */
        [[nodiscard]] static auto Submit(AsyncBackendState &State, SubmissionRecord Record,
                                         const SubmissionKind Kind = SubmissionKind::Ordinary) noexcept
            -> SubmissionReceipt
        {
            const auto Sequence = State.NextSequence_.fetch_add(1U, std::memory_order_relaxed);
            if (!ShouldWrite(State.Settings_.Logging.Level, Record.Level) && Kind != SubmissionKind::Audit &&
                Record.Level != LogLevel::Critical)
            {
                return {SubmissionStatus::Filtered, Sequence};
            }
            Record.Sequence = Sequence;
            Record.Kind = Kind;

            if (State.Logger_ == nullptr)
            {
                return {SubmissionStatus::Failed, Sequence};
            }

            if (State.EnqueueGate_.test_and_set(std::memory_order_acquire))
            {
                const auto Pool = State.Pool_.load(std::memory_order_acquire);
                if (Pool)
                {
                    State.ObserveQueueHighWatermark(Pool->queue_size());
                }
                return QueueFailure(State, Record, Kind, Sequence);
            }
            struct GateRelease final
            {
                std::atomic_flag &Gate;
                ~GateRelease()
                {
                    Gate.clear(std::memory_order_release);
                }
            } Release{State.EnqueueGate_};

            try
            {
                // 独占 pool 和入队门闩使本次调用能准确归因 discard counter 的变化。
                auto Payload = BuildPayload(Record);
                const auto Pool = State.Pool_.load(std::memory_order_acquire);
                std::uint64_t DiscardBefore = 0U;
                if (Pool)
                {
                    DiscardBefore = Pool->discard_counter();
                }
                State.Logger_->log(ToSpdlogLevel(Record.Level),
                                   spdlog::string_view_t(Payload.data(), Payload.size()));
                if (Pool && Pool->discard_counter() != DiscardBefore)
                {
                    State.ObserveQueueHighWatermark(Pool->queue_size());
                    return QueueFailure(State, Record, Kind, Sequence);
                }
                std::size_t QueueSize = 0U;
                if (Pool)
                {
                    QueueSize = Pool->queue_size();
                }
                State.ObserveQueueHighWatermark(QueueSize);
                return {SubmissionStatus::Accepted, Sequence};
            }
            catch (...)
            {
                State.CaptureFailures_.fetch_add(1U, std::memory_order_relaxed);
                return {SubmissionStatus::Failed, Sequence};
            }
        }

        /**
         * @brief 非阻塞地向 spdlog 队列提交 sink flush 请求。
         * @param State 当前 backend 状态。
         * @details 若入队门闩正被日志提交使用，则跳过本次 flush；后续定时请求可再次尝试。
         */
        static auto Flush(AsyncBackendState &State) noexcept -> void
        {
            if (State.Logger_ == nullptr || State.EnqueueGate_.test_and_set(std::memory_order_acquire))
            {
                return;
            }
            struct GateRelease final
            {
                std::atomic_flag &Gate;
                ~GateRelease()
                {
                    Gate.clear(std::memory_order_release);
                }
            } Release{State.EnqueueGate_};
            State.Logger_->flush();
        }

        /**
         * @brief 禁止 backend 接收新的提交。
         * @param State 要停止接收的 backend 状态。
         * @note 此操作不排空队列、不关闭 logger，也不等待进行中的提交。
         */
        static auto Stop(AsyncBackendState &State) noexcept -> void
        {
            State.Accepting_.store(false, std::memory_order_release);
        }

    private:
        /**
         * @brief 将 Diagnose 级别映射到 spdlog 的级别。
         * @param Level Diagnose 日志级别。
         * @return 对应的 spdlog 级别；Access 使用 info sink level，并由消息正文保留独立标签。
         */
        [[nodiscard]] static constexpr auto ToSpdlogLevel(const LogLevel Level) noexcept
            -> spdlog::level::level_enum
        {
            switch (Level)
            {
            case LogLevel::Trace: return spdlog::level::trace;
            case LogLevel::Debug: return spdlog::level::debug;
            case LogLevel::Info:
            case LogLevel::Access: return spdlog::level::info;
            case LogLevel::Warn: return spdlog::level::warn;
            case LogLevel::Error: return spdlog::level::err;
            case LogLevel::Critical: return spdlog::level::critical;
            case LogLevel::Off: return spdlog::level::off;
            }
            return spdlog::level::off;
        }

        /**
         * @brief 记录非阻塞提交未能接收本条记录的结果。
         * @param State backend 提交指标所属状态。
         * @param Record 未成功进入异步队列的记录。
         * @param Kind 普通记录或审计记录。
         * @param Sequence 此次提交已分配的序号。
         * @return 返回 Dropped；入队门闩忙或队列满均立即丢弃；Audit 同时增加终态记录未入队计数。
         */
        [[nodiscard]] static auto QueueFailure(AsyncBackendState &State, const SubmissionRecord &Record,
                                               const SubmissionKind Kind,
                                               const std::uint64_t Sequence) noexcept -> SubmissionReceipt
        {
            State.Dropped_[static_cast<std::size_t>(Record.Level)].fetch_add(1U, std::memory_order_relaxed);
            if (Kind == SubmissionKind::Audit)
            {
                State.TerminalFailures_.fetch_add(1U, std::memory_order_relaxed);
            }
            return {SubmissionStatus::Dropped, Sequence};
        }
    };

} // namespace Preview::Diagnose::Detail

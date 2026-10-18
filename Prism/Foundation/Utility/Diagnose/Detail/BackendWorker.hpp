/** @file BackendWorker.hpp
 * @brief 单 worker 按 accepted epoch 格式化、轮转、写入和完成 flush。
 */
#pragma once

#include <Prism/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/RenderRecord.hpp>
#include <Prism/Foundation/Utility/Text/Redaction.hpp>

namespace Prism::Diagnose::Detail
{
    /** @brief thread owner 的唯一执行入口；普通 sink I/O 失败只记录观察结果。 */
    class BackendWorker final
    {
    public:
        static auto Start(AsyncBackendState& State) -> void
        {
            State.Worker_ = std::thread([&State] { Entry(State); });
        }

        static auto Wake(AsyncBackendState& State) noexcept -> void
        {
            State.Wake_->Notify();
        }

        static auto Entry(AsyncBackendState& State) noexcept -> void
        {
            try
            {
                Run(State);
            }
            catch (...)
            {
                while (State.EnqueueGate_.test_and_set(std::memory_order_acquire))
                {
                    State.EnqueueGate_.wait(true, std::memory_order_acquire);
                }
                State.Accepting_.store(false, std::memory_order_release);
                State.WorkerFailed_.store(true, std::memory_order_release);
                const auto Written = State.Write_.load(std::memory_order_acquire);
                const auto Read = State.Read_.exchange(Written, std::memory_order_acq_rel);
                State.RenderFailures_.fetch_add(Written - Read, std::memory_order_relaxed);
                for (auto Index = Read; Index < Written; ++Index)
                {
                    auto& Record = State.Queue_[Index % State.Settings_.Logging.QueueCapacity];
                    Record.Message.Reset();
                    Record.Epoch.reset();
                }
                State.EnqueueGate_.clear(std::memory_order_release);
                State.EnqueueGate_.notify_all();
                State.ControlChanged_.notify_all();
                const auto Flushed = State.FlushOutputs();
                if (!Flushed)
                {
                    State.SinkFailure_.store(true, std::memory_order_release);
                    State.SinkFailures_.fetch_add(1U, std::memory_order_relaxed);
                }
                State.FinalFlushSucceeded_.store(Flushed, std::memory_order_release);
            }
        }

    private:
        static auto Run(AsyncBackendState& State) -> void
        {
            for (;;)
            {
                auto Read = State.Read_.load(std::memory_order_relaxed);
                while (Read < State.Write_.load(std::memory_order_acquire))
                {
                    auto& Snapshot = State.Queue_[Read % State.Settings_.Logging.QueueCapacity];
                    Consume(State, Snapshot);
                    Snapshot.Message.Reset();
                    Snapshot.Epoch.reset();
                    ++Read;
                    State.Read_.store(Read, std::memory_order_release);
                    {
                        std::lock_guard Lock(State.ControlMutex_);
                        State.ControlChanged_.notify_all();
                    }
                    State.CleanupRetiredResources();
                }
                const auto Wake = State.Wake_->Value.load(std::memory_order_acquire);
                if (State.Stopping_.load(std::memory_order_acquire) && State.QueueSize() == 0U)
                {
                    break;
                }
                State.CleanupRetiredResources();
                if (State.QueueSize() == 0U)
                {
                    State.Wake_->Value.wait(Wake, std::memory_order_acquire);
                }
            }
            const auto Flushed = State.FlushOutputs();
            if (!Flushed)
            {
                State.SinkFailure_.store(true, std::memory_order_release);
                State.SinkFailures_.fetch_add(1U, std::memory_order_relaxed);
            }
            State.FinalFlushSucceeded_.store(Flushed, std::memory_order_release);
        }

        static auto Consume(AsyncBackendState& State, const SubmissionSnapshot& Snapshot) -> void
        {
            if (Snapshot.Command != QueueCommand::Message)
            {
                const auto Flushed = State.FlushOutputs();
                if (!Flushed)
                {
                    State.SinkFailure_.store(true, std::memory_order_release);
                    State.SinkFailures_.fetch_add(1U, std::memory_order_relaxed);
                }
                if (Snapshot.Command == QueueCommand::Barrier)
                {
                    std::lock_guard Lock(State.ControlMutex_);
                    State.BarrierStatus_.store(
                        Flushed ? SubmissionStatus::Flushed : SubmissionStatus::Failed,
                        std::memory_order_relaxed);
                    State.BarrierWrittenSequence_.store(
                        State.LastWrittenSequence_.load(std::memory_order_acquire),
                        std::memory_order_relaxed);
                    State.CompletedBarrierTicks_.store(
                        std::chrono::steady_clock::now().time_since_epoch().count(),
                        std::memory_order_relaxed);
                    State.CompletedBarrier_.store(Snapshot.BarrierId, std::memory_order_release);
                    State.ControlChanged_.notify_all();
                }
                return;
            }
            if (!Snapshot.Epoch)
            {
                State.RenderFailures_.fetch_add(1U, std::memory_order_relaxed);
                State.LastProcessedSequence_.store(Snapshot.Sequence, std::memory_order_release);
                return;
            }
            const auto& Epoch = Snapshot.Epoch->Value();
            const auto Sinks = Epoch.Sinks.load(std::memory_order_acquire);
            if (!Sinks)
            {
                State.RenderFailures_.fetch_add(1U, std::memory_order_relaxed);
                State.LastProcessedSequence_.store(Snapshot.Sequence, std::memory_order_release);
                return;
            }
            SubmissionRecord Record;
            Record.Level = Snapshot.Level;
            Record.Kind = Snapshot.Kind;
            Record.Sequence = Snapshot.Sequence;
            Record.TimestampMilliseconds = Snapshot.TimestampMilliseconds;
            std::array<char, DeferredMessage::RenderBytes> SafeMessage{};
            const auto Message = Snapshot.Message.Render();
            const auto Safe = StoreFieldText(Message.Text, SafeMessage, true);
            Record.Message.assign(SafeMessage.data(), Safe.first);
            Record.MessageTruncated = Message.Truncated || Safe.second;
            Record.Context = Snapshot.Context.Decode(
                Epoch.Settings.Mode, Epoch.Settings.TraceSelection);
            const auto Payload = BuildPayload(Record);
            State.ConsoleOutputSeen_ = State.ConsoleOutputSeen_ || Sinks->ConsoleEnabled();
            const PathWritePolicy Policy{
                Epoch.Settings.Mode,
                Epoch.Settings.Logging.RotateBytes,
                Epoch.Settings.Logging.RotateFiles};
            if (Sinks->Write(Record.Level, Payload, Policy))
            {
                State.Written_.fetch_add(1U, std::memory_order_relaxed);
                State.LastWrittenSequence_.store(Record.Sequence, std::memory_order_release);
            }
            else
            {
                State.SinkFailure_.store(true, std::memory_order_release);
                State.SinkFailures_.fetch_add(1U, std::memory_order_relaxed);
            }
            State.LastProcessedSequence_.store(Record.Sequence, std::memory_order_release);
        }
    };
}

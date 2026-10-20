/** @file AsyncBackendState.hpp
 * @brief 唯一有界记录队列、generation epoch 与物理 sink owner 的 process owner。
 */
#pragma once

#include <Prism/Foundation/Utility/Diagnose/Detail/ContextSnapshot.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/DeferredMessage.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/PathSinkOwner.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/RenderEpoch.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/SinkSet.hpp>
#include <Prism/Foundation/Utility/Text/TraceSelection.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace Prism::Diagnose::Detail
{
    /** @brief 不阻塞协程 prepare 的 epoch registry gate；worker 可 wait 原子通知。 */
    class EpochGate final
    {
    public:
        [[nodiscard]] auto TryLock() noexcept -> bool
        {
            return !Flag_.test_and_set(std::memory_order_acquire);
        }
        auto lock() noexcept -> void
        {
            while (Flag_.test_and_set(std::memory_order_acquire))
            {
                Flag_.wait(true, std::memory_order_acquire);
            }
        }
        auto unlock() noexcept -> void
        {
            Flag_.clear(std::memory_order_release);
            Flag_.notify_one();
        }
    private:
        std::atomic_flag Flag_ = ATOMIC_FLAG_INIT;
    };

    /** @brief Prepare 使用的非阻塞 gate scope；竞争时调用方返回 typed ResourceUnavailable。 */
    class EpochGateGuard final
    {
    public:
        explicit EpochGateGuard(EpochGate& Gate) noexcept
            : Gate_(Gate), Acquired_(Gate_.TryLock())
        {
        }
        ~EpochGateGuard()
        {
            if (Acquired_)
            {
                Gate_.unlock();
            }
        }
        [[nodiscard]] auto Acquired() const noexcept -> bool
        {
            return Acquired_;
        }
    private:
        EpochGate& Gate_;
        bool Acquired_{false};
    };
    enum class QueueCommand : std::uint8_t { Message, Flush, Barrier };

    /** @brief 记录槽直接 pin 所属 epoch，控制槽不绑定 record epoch。 */
    struct SubmissionSnapshot final
    {
        LogLevel Level{LogLevel::Info};
        SubmissionKind Kind{SubmissionKind::Ordinary};
        QueueCommand Command{QueueCommand::Message};
        std::uint64_t Sequence{0U};
        std::uint64_t TimestampMilliseconds{0U};
        std::uint64_t BarrierId{0U};
        DeferredMessage Message{};
        ContextSnapshot Context{};
        Prism::Diagnose::RenderEpochPin Epoch{};
    };

    /** @brief worker 退休 epoch 时保留关闭回执与其唯一物理路径 key。 */
    struct EpochRegistration final
    {
        std::weak_ptr<RenderEpoch> Epoch;
        std::shared_ptr<RenderEpochCloseState> CloseState;
        std::filesystem::path Path;
    };

    /**
     * @brief 冷构造一份有界槽与唯一后台线程；活动输出 epoch 可热替换。
     * @details producer 只复制到固定槽，不创建第二条队列；worker 按槽固定的 epoch 输出。
     */
    class AsyncBackendState final
    {
    public:
        static constexpr std::size_t LevelCount = static_cast<std::size_t>(LogLevel::Off) + 1U;
        static constexpr std::size_t MaxRetainedEpochs = 8U;
        static constexpr std::size_t MaxPathOwners = 8U;

        AsyncBackendState(const std::uint64_t OwnerId, BackendSettings Settings)
            : OwnerId_(OwnerId), Settings_(std::move(Settings)),
              Queue_(std::make_unique<SubmissionSnapshot[]>(Settings_.Logging.QueueCapacity)),
              Wake_(std::make_shared<BackendWakeSignal>())
        {
            Epochs_.reserve(MaxRetainedEpochs);
        }

        AsyncBackendState(const AsyncBackendState&) = delete;
        auto operator=(const AsyncBackendState&) -> AsyncBackendState& = delete;

        [[nodiscard]] auto QueueSize() const noexcept -> std::size_t
        {
            const auto Read = Read_.load(std::memory_order_acquire);
            const auto Write = Write_.load(std::memory_order_acquire);
            return static_cast<std::size_t>(Write - Read);
        }

        [[nodiscard]] auto QueueHighWatermark() const noexcept -> std::size_t
        {
            return QueueHighWatermark_.load(std::memory_order_relaxed);
        }

        auto ObserveQueueHighWatermark(const std::size_t Value) noexcept -> void
        {
            auto Previous = QueueHighWatermark_.load(std::memory_order_relaxed);
            while (Value > Previous && !QueueHighWatermark_.compare_exchange_weak(
                Previous, Value, std::memory_order_relaxed))
            {
            }
        }

        auto ResetQueueHighWatermark() noexcept -> void
        {
            QueueHighWatermark_.store(QueueSize(), std::memory_order_relaxed);
        }

        [[nodiscard]] auto Dropped(const LogLevel Level) const noexcept -> std::uint64_t
        {
            if (static_cast<std::size_t>(Level) >= LevelCount)
            {
                return 0U;
            }
            return Dropped_[static_cast<std::size_t>(Level)].load(std::memory_order_relaxed);
        }

        [[nodiscard]] auto TerminalFailures() const noexcept -> std::uint64_t
        {
            return TerminalFailures_.load(std::memory_order_relaxed);
        }

    private:
        friend class BackendLifecycleOwner;
        friend class BackendBridge;
        friend class AsyncSubmission;
        friend class BackendWorker;
        friend struct BackendLifecycleTestAccess;

        [[nodiscard]] auto FlushOutputs() noexcept -> bool
        {
            std::lock_guard Lock(EpochGate_);
            bool Succeeded = !SinkFailure_.load(std::memory_order_acquire);
            bool FlushConsole = ConsoleOutputSeen_;
            for (const auto &Entry : Epochs_)
            {
                if (const auto Epoch = Entry.Epoch.lock())
                {
                    const auto Sinks = Epoch->Sinks.load(std::memory_order_acquire);
                    FlushConsole = FlushConsole || (Sinks && Sinks->ConsoleEnabled());
                }
            }
            for (const auto &[Path, Owner] : PathOwners_)
            {
                (void)Path;
                Succeeded = Owner->Flush() && Succeeded;
            }
            if (FlushConsole)
            {
                Succeeded = SinkSet::FlushConsole() && Succeeded;
            }
            if (!Succeeded)
            {
                SinkFailure_.store(true, std::memory_order_release);
            }
            return Succeeded;
        }

        auto CleanupRetiredResources() noexcept -> void
        {
            std::lock_guard Lock(EpochGate_);
            auto Entry = Epochs_.begin();
            while (Entry != Epochs_.end())
            {
                if (!Entry->Epoch.expired())
                {
                    ++Entry;
                    continue;
                }
                bool Failed = false;
                const auto Owner = PathOwners_.find(Entry->Path);
                if (Owner != PathOwners_.end() && Owner->second.use_count() == 1)
                {
                    Failed = !Owner->second->Close();
                    if (Failed)
                    {
                        SinkFailure_.store(true, std::memory_order_release);
                        SinkFailures_.fetch_add(1U, std::memory_order_relaxed);
                    }
                    PathOwners_.erase(Owner);
                }
                Entry->CloseState->Failed.store(Failed, std::memory_order_release);
                Entry->CloseState->Closed.store(true, std::memory_order_release);
                Entry = Epochs_.erase(Entry);
            }
            auto Path = PathOwners_.begin();
            while (Path != PathOwners_.end())
            {
                if (Path->second.use_count() != 1)
                {
                    ++Path;
                    continue;
                }
                if (!Path->second->Close())
                {
                    SinkFailures_.fetch_add(1U, std::memory_order_relaxed);
                }
                Path = PathOwners_.erase(Path);
            }
        }

        [[nodiscard]] auto CloseOutputs() noexcept -> bool
        {
            std::lock_guard Lock(EpochGate_);
            Accepting_.store(false, std::memory_order_release);
            ActiveEpoch_.store(Prism::Diagnose::RenderEpochPin{}, std::memory_order_release);
            bool Succeeded = !SinkFailure_.load(std::memory_order_acquire);
            if (ConsoleOutputSeen_)
            {
                const auto ConsoleFlushed = SinkSet::FlushConsole();
                if (!ConsoleFlushed)
                {
                    SinkFailure_.store(true, std::memory_order_release);
                }
                Succeeded = ConsoleFlushed && Succeeded;
            }
            for (auto &Entry : Epochs_)
            {
                bool EpochSucceeded = !SinkFailure_.load(std::memory_order_acquire);
                const auto Owner = PathOwners_.find(Entry.Path);
                if (const auto Epoch = Entry.Epoch.lock())
                {
                    const auto Sinks = Epoch->Sinks.exchange({}, std::memory_order_acq_rel);
                    if (Sinks)
                    {
                        EpochSucceeded = Sinks->Close() && EpochSucceeded;
                    }
                    Epoch->Closed.store(true, std::memory_order_release);
                }
                if (Owner != PathOwners_.end())
                {
                    EpochSucceeded = Owner->second->Close() && EpochSucceeded;
                }
                Succeeded = EpochSucceeded && Succeeded;
                Entry.CloseState->Failed.store(!EpochSucceeded, std::memory_order_release);
                Entry.CloseState->Closed.store(true, std::memory_order_release);
            }
            for (auto &[Path, Owner] : PathOwners_)
            {
                (void)Path;
                Succeeded = Owner->Close() && Succeeded;
            }
            PathOwners_.clear();
            Epochs_.clear();
            if (!Succeeded)
            {
                SinkFailure_.store(true, std::memory_order_release);
            }
            FinalCloseSucceeded_.store(Succeeded, std::memory_order_release);
            return Succeeded;
        }

        const std::uint64_t OwnerId_;
        const BackendSettings Settings_;
        const std::unique_ptr<SubmissionSnapshot[]> Queue_;
        const std::shared_ptr<BackendWakeSignal> Wake_;
        std::atomic<Prism::Diagnose::RenderEpochPin> ActiveEpoch_{};
        EpochGate EpochGate_;
        std::vector<EpochRegistration> Epochs_;
        std::map<std::filesystem::path, std::shared_ptr<PathSinkOwner>> PathOwners_;
        std::uint64_t NextEpochId_{1U};
        bool ConsoleOutputSeen_{false};
        std::thread Worker_{};
        std::atomic<std::uint64_t> Read_{0U};
        std::atomic<std::uint64_t> Write_{0U};
        std::atomic<std::uint64_t> NextSequence_{1U};
        std::atomic<std::size_t> QueueHighWatermark_{0U};
        std::atomic_flag EnqueueGate_ = ATOMIC_FLAG_INIT;
        std::atomic<bool> Accepting_{true};
        std::atomic<bool> Stopping_{false};
        std::atomic<bool> WorkerFailed_{false};
        std::array<std::atomic<std::uint64_t>, LevelCount> Dropped_{};
        std::atomic<std::uint64_t> TerminalFailures_{0U};
        std::atomic<std::uint64_t> CaptureFailures_{0U};
        std::atomic<std::uint64_t> RenderFailures_{0U};
        std::atomic<std::uint64_t> SinkFailures_{0U};
        std::atomic<bool> SinkFailure_{false};
        std::atomic<std::uint64_t> Written_{0U};
        std::atomic<std::uint64_t> LastProcessedSequence_{0U};
        std::atomic<std::uint64_t> LastWrittenSequence_{0U};
        std::atomic<std::uint64_t> BarrierWrittenSequence_{0U};
        std::atomic_flag BarrierGate_ = ATOMIC_FLAG_INIT;
        std::atomic<std::uint64_t> NextBarrier_{1U};
        std::atomic<std::uint64_t> CompletedBarrier_{0U};
        std::atomic<std::chrono::steady_clock::rep> CompletedBarrierTicks_{0};
        std::atomic<SubmissionStatus> BarrierStatus_{SubmissionStatus::Failed};
        std::atomic<bool> FinalCloseSucceeded_{false};
        std::atomic<bool> FinalFlushSucceeded_{false};
        std::condition_variable ControlChanged_{};
        std::mutex ControlMutex_{};
    };
}

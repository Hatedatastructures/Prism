/**
 * @file TaskState.hpp
 * @brief Preview 协程的值身份、一次性完成状态和取消状态
 * @details TaskState 不拥有 registry 裸指针。完成通知通过 shared/weak state
 *          传递；registry 销毁后，迟到通知最多改变自身状态，不能回访 owner。
 */

#pragma once

#include <atomic>
#include <exception>
#include <functional>
#include <memory>
#include <utility>

#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Lifecycle/CancellationDomain.hpp>

namespace Preview::Lifecycle
{

    /**
     * @struct TaskIdentity
     * @brief 一个 Preview 任务的稳定值身份
     * @note 使用 Foundation 的强类型 ID，避免任务、会话、流、worker 和 generation
     *       在生命周期边界发生隐式混用。
     */
    struct TaskIdentity final
    {
        Preview::TaskId TaskId{};
        Preview::SessionId SessionId{};
        Preview::StreamId StreamId{};
        Preview::WorkerId WorkerId{};
        Preview::GenerationId Generation{};
    };

    using TaskCancelFn = std::function<void()>;

    struct TaskRequest final
    {
        TaskIdentity Identity{};
        TaskCancelFn Cancel;
        /// SessionControl 提交的操作在同一 command 序列中先进入 started 状态。
        bool StartOnSubmit{false};
    };

    enum class TaskOutcome
    {
        Pending,
        Succeeded,
        Cancelled,
        Failed,
        Quarantined,
    };

    struct TaskResult final
    {
        TaskOutcome Outcome{TaskOutcome::Pending};
        std::exception_ptr Failure;
    };

    class TaskState final : public std::enable_shared_from_this<TaskState>
    {
    private:
        enum class Phase
        {
            Pending,
            Started,
            CancelPending,
            CancelRequested,
            Completing,
            Completed,
            Quarantined,
        };

        [[nodiscard]] auto CancellationPreventsStart() const noexcept -> bool
        {
            return Domain_->IsCancelled() ||
                   (!StartOnSubmit_ && Domain_->IsCancellationRequested());
        }

    public:
        using CancelFn = TaskCancelFn;
        using CompletionSink = std::function<void(const std::shared_ptr<TaskState> &)>;

        struct Options final
        {
            TaskIdentity Identity{};
            std::shared_ptr<CancellationDomain> Domain;
            std::shared_ptr<Preview::Resource::ExecutorReclaimer> Reclaimer;
            CancelFn Cancel;
            /// 已进入 SessionControl 提交边界的操作。
            bool StartOnSubmit{false};
        };

        TaskState(Options OptionsValue, CompletionSink CompletionValue)
            : Identity_(OptionsValue.Identity),
              Domain_(std::move(OptionsValue.Domain)),
              Reclaimer_(std::move(OptionsValue.Reclaimer)),
              Cancel_(std::move(OptionsValue.Cancel)),
              StartOnSubmit_(OptionsValue.StartOnSubmit),
              Completion_(std::move(CompletionValue))
        {
        }

        TaskState(const TaskState &) = delete;
        auto operator=(const TaskState &) -> TaskState & = delete;
        TaskState(TaskState &&) = delete;
        auto operator=(TaskState &&) -> TaskState & = delete;

        [[nodiscard]] auto Identity() const noexcept -> TaskIdentity
        {
            return Identity_;
        }

        [[nodiscard]] auto StartOnSubmit() const noexcept -> bool
        {
            return StartOnSubmit_;
        }

        [[nodiscard]] auto TryStart() noexcept -> bool
        {
            for (;;)
            {
                auto Expected = Phase_.load(std::memory_order_acquire);
                if (Expected == Phase::CancelPending)
                {
                    (void)Complete();
                    return false;
                }
                if (Expected != Phase::Pending)
                {
                    return false;
                }
                if (CancellationPreventsStart())
                {
                    (void)RequestCancel();
                    return false;
                }

                if (!Phase_.compare_exchange_weak(
                        Expected, Phase::Started, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    continue;
                }
                Started_.store(true, std::memory_order_release);
                if (CancellationPreventsStart())
                {
                    (void)RequestCancel();
                    return false;
                }
                return true;
            }
        }

        /**
         * @brief 请求取消并在目标 executor 上最多调用一次 cancel hook
         */
        [[nodiscard]] auto RequestCancel() noexcept -> bool
        {
            for (;;)
            {
                auto Expected = Phase_.load(std::memory_order_acquire);
                if (Expected == Phase::Completed || Expected == Phase::Quarantined ||
                    Expected == Phase::Completing || Expected == Phase::CancelPending ||
                    Expected == Phase::CancelRequested)
                {
                    return false;
                }

                const auto RequestedPhase =
                    Expected == Phase::Pending ? Phase::CancelPending : Phase::CancelRequested;
                if (!Phase_.compare_exchange_weak(
                        Expected, RequestedPhase, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    continue;
                }
                CancelRequested_.store(true, std::memory_order_release);
                break;
            }

            (void)Domain_->Cancel();
            if (Domain_->IsDispatchBlocked())
            {
                CancelDispatchFailed_.store(true, std::memory_order_release);
            }
            const auto Self = weak_from_this().lock();
            if (Self)
            {
                if (!Reclaimer_->Post([Self] { Self->InvokeCancel(); }))
                {
                    CancelDispatchFailed_.store(true, std::memory_order_release);
                }
            }
            return true;
        }

        /**
         * @brief 完成任务；所有调用方共享同一个 CAS 入口
         * @param Failure 业务异常；为空表示正常或取消完成
         * @return 本次调用取得完成权返回 true
         */
        [[nodiscard]] auto Complete(std::exception_ptr Failure = {}) noexcept -> bool
        {
            auto Expected = Phase_.load(std::memory_order_acquire);
            for (;;)
            {
                if (Expected == Phase::Completed || Expected == Phase::Quarantined ||
                    Expected == Phase::Completing)
                {
                    return false;
                }
                if (Phase_.compare_exchange_weak(
                        Expected, Phase::Completing, std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    break;
                }
            }

            const bool Cancelled = Expected == Phase::CancelPending || Expected == Phase::CancelRequested;
            const auto Outcome = Failure && !Cancelled
                                     ? TaskOutcome::Failed
                                     : (Cancelled ? TaskOutcome::Cancelled : TaskOutcome::Succeeded);
            Failure_ = Cancelled ? std::exception_ptr{} : std::move(Failure);
            Outcome_.store(Outcome, std::memory_order_release);
            CompletionCount_.fetch_add(1, std::memory_order_acq_rel);
            Phase_.store(Phase::Completed, std::memory_order_release);
            NotifyCompletion();
            return true;
        }

        /**
         * @brief owner 销毁时隔离任务
         * @details 不调用 completion sink，迟到 completion 因状态已终态而成为 no-op。
         */
        [[nodiscard]] auto Quarantine() noexcept -> bool
        {
            auto Expected = Phase_.load(std::memory_order_acquire);
            for (;;)
            {
                if (Expected == Phase::Completed || Expected == Phase::Quarantined ||
                    Expected == Phase::Completing)
                {
                    return false;
                }
                if (Phase_.compare_exchange_weak(
                        Expected,
                        Phase::Completing,
                        std::memory_order_acq_rel,
                        std::memory_order_acquire))
                {
                    break;
                }
            }
            Failure_ = {};
            Outcome_.store(TaskOutcome::Quarantined, std::memory_order_release);
            CompletionCount_.fetch_add(1, std::memory_order_acq_rel);
            Phase_.store(Phase::Quarantined, std::memory_order_release);
            return true;
        }

        [[nodiscard]] auto IsStarted() const noexcept -> bool
        {
            return Started_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto IsCompleted() const noexcept -> bool
        {
            const auto Current = Phase_.load(std::memory_order_acquire);
            return Current == Phase::Completed || Current == Phase::Quarantined;
        }

        [[nodiscard]] auto IsCancelRequested() const noexcept -> bool
        {
            return CancelRequested_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto IsCancelDispatchFailed() const noexcept -> bool
        {
            return CancelDispatchFailed_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Outcome() const noexcept -> TaskOutcome
        {
            return Outcome_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Failure() const noexcept -> std::exception_ptr
        {
            if (Outcome_.load(std::memory_order_acquire) == TaskOutcome::Pending)
            {
                return {};
            }
            return Failure_;
        }

        [[nodiscard]] auto CompletionCount() const noexcept -> std::size_t
        {
            return CompletionCount_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Domain() const noexcept -> const std::shared_ptr<CancellationDomain> &
        {
            return Domain_;
        }

        [[nodiscard]] auto CancellationSlot() noexcept -> Net::cancellation_slot
        {
            return Domain_->Slot();
        }

    private:
        auto InvokeCancel() noexcept -> void
        {
            if (CancelInvoked_.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            try
            {
                if (Cancel_)
                {
                    Cancel_();
                }
            }
            catch (...)
            {
            }
        }

        auto NotifyCompletion() noexcept -> void
        {
            if (!Completion_)
            {
                return;
            }
            try
            {
                if (const auto Self = weak_from_this().lock())
                {
                    Completion_(Self);
                }
            }
            catch (...)
            {
            }
        }

        TaskIdentity Identity_;
        std::shared_ptr<CancellationDomain> Domain_;
        std::shared_ptr<Preview::Resource::ExecutorReclaimer> Reclaimer_;
        CancelFn Cancel_;
        bool StartOnSubmit_{false};
        CompletionSink Completion_;
        std::atomic<Phase> Phase_{Phase::Pending};
        std::atomic<bool> Started_{false};
        std::atomic<bool> CancelRequested_{false};
        std::atomic<bool> CancelInvoked_{false};
        std::atomic<bool> CancelDispatchFailed_{false};
        std::atomic<std::size_t> CompletionCount_{0};
        std::atomic<TaskOutcome> Outcome_{TaskOutcome::Pending};
        std::exception_ptr Failure_;
    };

} // namespace Preview::Lifecycle

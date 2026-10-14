/** @file TaskState.hpp @brief 任务身份、值结果与稳定观察句柄。 */
#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Lifecycle/CancellationDomain.hpp>
#include <Preview/Lifecycle/TaskRetirementReceipt.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>

namespace Preview::Lifecycle
{
    /** @brief 发布后不可变的任务身份，父身份保留在独立字段。 */
    struct TaskIdentity final
    {
        Preview::TaskId TaskId{};
        Preview::SessionId SessionId{};
        Preview::StreamId StreamId{};
        Preview::WorkerId WorkerId{};
        Preview::GenerationId Generation{};
        Preview::TaskId ParentTaskId{};

        friend auto operator==(const TaskIdentity &, const TaskIdentity &) noexcept -> bool = default;
    };

    /** @brief 提交上下文不接受调用者指定任务 ID；所有字段按值转移。 */
    struct TaskContext final
    {
        Preview::SessionId SessionId{};
        Preview::StreamId StreamId{};
        Preview::WorkerId WorkerId{};
        Preview::GenerationId Generation{};
        Preview::TaskId ParentTaskId{};
    };

    /** @brief 从固定父身份构造子任务上下文，父 ID 不成为新任务 ID。 */
    [[nodiscard]] inline auto FromParent(const TaskIdentity& Parent) noexcept -> TaskContext
    { return {Parent.SessionId, Parent.StreamId, Parent.WorkerId, Parent.Generation, Parent.TaskId}; }

    /** @brief 在任务真正交付到原 executor 后发布分配出的身份。 */
    class TaskIdentityObserver
    {
    public:
        virtual ~TaskIdentityObserver() = default;
        virtual auto PublishIdentity(const TaskIdentity& Identity) -> void = 0;
    };

    using TaskCancelFn = std::function<void()>;

    struct TaskRequest final
    {
        TaskContext Context{};
        TaskCancelFn Cancel;
        bool StartOnSubmit{false};
        std::shared_ptr<TaskIdentityObserver> IdentityObserver;
    };

    enum class TaskOutcome { Pending, Succeeded, Cancelled, Failed, Quarantined };

    struct TaskResult final
    {
        TaskOutcome Outcome{TaskOutcome::Pending};
        Preview::Fault::Failure Failure{};
    };

    /** @brief 对活动任务状态的按值观察；不延长 TaskSubmission 或用户协程寿命。 */
    struct TaskObservation final
    {
        TaskIdentity Identity{};
        TaskResult Result{};
        std::uint64_t StartedAt{0};
        std::uint64_t CompletedAt{0};
        bool Started{false};
        bool CancelRequested{false};
        bool DrainBlocked{false};
        Preview::Fault::Failure DrainFailure{};
        bool Cancellable{false};
    };

    /** @brief 任务的单调 phase；终态只能由一个原子 CAS 获胜者发布。 */
    enum class TaskPhase : std::uint8_t
    {
        Pending,
        Started,
        Completing,
        Completed,
        Quarantined,
    };

    /** @brief 观察状态不拥有 drain 预约；只有协程真正退栈后预约才释放。 */
    class TaskState final : public CancellationObserver, public std::enable_shared_from_this<TaskState>
    {
        [[nodiscard]] static auto CurrentTimestamp() noexcept -> std::uint64_t
        {
            const auto Value = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if (Value > 0)
            {
                return static_cast<std::uint64_t>(Value);
            }
            return 0U;
        }

        [[nodiscard]] auto BeginCompletion() noexcept -> bool
        {
            auto Expected = TaskPhase::Pending;
            if (Phase_.compare_exchange_strong(Expected, TaskPhase::Completing)) return true;
            Expected = TaskPhase::Started;
            return Phase_.compare_exchange_strong(Expected, TaskPhase::Completing);
        }

        [[nodiscard]] auto CancellationPreventsStart() const noexcept -> bool
        {
            const auto Domain = Domain_.load();
            return !StartOnSubmit_ && Domain && Domain->IsCancellationRequested();
        }

    public:
        struct Options final
        {
            TaskIdentity Identity;
            std::shared_ptr<CancellationDomain> Domain;
            TaskCancelFn Cancel;
            bool StartOnSubmit{false};
            std::shared_ptr<TaskIdentityObserver> IdentityObserver;
            std::shared_ptr<TaskRetirementReceipt> Retirement;
        };

        explicit TaskState(Options Value)
            : Identity_(Value.Identity), Domain_(std::move(Value.Domain)),
              Cancel_(std::move(Value.Cancel)), StartOnSubmit_(Value.StartOnSubmit),
              IdentityObserver_(std::move(Value.IdentityObserver)),
              Retirement_(std::move(Value.Retirement)) {}

        /** @brief 按值返回发布后不变的身份；不借出资源，不触发取消或关闭。 */
        [[nodiscard]] auto Identity() const noexcept -> TaskIdentity { return Identity_; }

        /** @brief 读取提交门控策略的不可变值。 */
        [[nodiscard]] auto StartOnSubmit() const noexcept -> bool { return StartOnSubmit_; }

        /** @brief 已交付命令在协程启动前发布身份；未交付的拒绝路径绝不发布。 */
        auto PublishAcceptedIdentity() -> void
        {
            if (IdentityObserver_) IdentityObserver_->PublishIdentity(Identity_);
            IdentityObserver_.reset();
        }

        /** @brief 原 executor 取得执行权；CAS 后再次检查取消，避免启动竞态。 */
        [[nodiscard]] auto TryStart() -> bool
        {
            if (IsCompleted()) return false;
            if (CancellationPreventsStart())
            {
                (void)RequestCancel();
                return false;
            }
            auto Expected = TaskPhase::Pending;
            if (!Phase_.compare_exchange_strong(Expected, TaskPhase::Started)) return false;
            StartedAt_.store(CurrentTimestamp(), std::memory_order_release);
            Started_.store(true, std::memory_order_release);
            if (CancellationPreventsStart())
            {
                (void)RequestCancel();
                if (IsCancelDispatchFailed()) return false;
                (void)Complete({Preview::Fault::Code::Canceled});
                return false;
            }
            return true;
        }

        /** @brief 任意线程请求取消；只排队一次 hook，原 executor 保持唯一关闭权。 */
        [[nodiscard]] auto RequestCancel() -> bool
        {
            if (IsCompleted() || CancelRequested_.exchange(true)) return false;
            auto Domain = Domain_.load();
            if (!Domain) return false;
            (void)Domain->Cancel();
            const auto Weak = weak_from_this();
            if (!Domain->Reclaimer()->Post([Weak]
                {
                    if (const auto Self = Weak.lock()) Self->InvokeCancel();
                })) CancelDispatchFailed_.store(true, std::memory_order_release);
            return true;
        }

        /** @brief 父域取消从同一 executor 到达，只执行一次 hook。 */
        auto OnCancellation() -> void override
        {
            if (IsCompleted()) return;
            CancelRequested_.store(true, std::memory_order_release);
            (void)InvokeCancel();
        }

        /** @brief 原 executor 发布成功、取消或失败；重复发布不会覆盖第一终态。 */
        [[nodiscard]] auto Complete(Preview::Fault::Failure Failure = {}) noexcept -> bool
        {
            if (!BeginCompletion()) return false;
            TaskOutcome Result = TaskOutcome::Succeeded;
            if (Failure.Failed()) Result = TaskOutcome::Failed;
            if (Failure.Code == Preview::Fault::Code::Canceled) Result = TaskOutcome::Cancelled;
            const auto Domain = Domain_.load();
            if (Failure.Succeeded() && (CancelRequested_.load() || (Domain && Domain->IsCancellationRequested())))
            {
                Result = TaskOutcome::Cancelled;
                Failure.Code = Preview::Fault::Code::Canceled;
            }
            CompletedAt_.store(CurrentTimestamp(), std::memory_order_release);
            Failure_ = Failure;
            Outcome_.store(Result, std::memory_order_release);
            CompletionCount_.fetch_add(1, std::memory_order_relaxed);
            Phase_.store(TaskPhase::Completed, std::memory_order_release);
            Completed_.store(true, std::memory_order_release);
            return true;
        }

        /** @brief 原 executor 清理完 queued operation 后发布隔离终态，不调用完成回调。 */
        [[nodiscard]] auto Quarantine() noexcept -> bool
        {
            if (!BeginCompletion()) return false;
            CompletedAt_.store(CurrentTimestamp(), std::memory_order_release);
            Failure_ = {};
            Outcome_.store(TaskOutcome::Quarantined, std::memory_order_release);
            CompletionCount_.fetch_add(1, std::memory_order_relaxed);
            Phase_.store(TaskPhase::Quarantined, std::memory_order_release);
            Completed_.store(true, std::memory_order_release);
            return true;
        }

        [[nodiscard]] auto IsStarted() const noexcept -> bool { return Started_.load(std::memory_order_acquire); }

        /** @brief Completed 与 Quarantined 都是观察层终态，slot 退休仍由 submission 完成。 */
        [[nodiscard]] auto IsCompleted() const noexcept -> bool
        {
            const auto Phase = Phase_.load(std::memory_order_acquire);
            return Phase == TaskPhase::Completed || Phase == TaskPhase::Quarantined;
        }

        [[nodiscard]] auto IsCancelRequested() const noexcept -> bool { return CancelRequested_.load(); }

        [[nodiscard]] auto IsCancelDispatchFailed() const noexcept -> bool
        {
            const auto Value = Domain_.load();
            return CancelDispatchFailed_.load() || (Value && Value->IsDispatchBlocked());
        }

        [[nodiscard]] auto Outcome() const noexcept -> TaskOutcome { return Outcome_.load(std::memory_order_acquire); }

        [[nodiscard]] auto Result() const noexcept -> TaskResult
        { if (!IsCompleted()) return {}; return {Outcome(), Failure_}; }

        /** @brief 按值观察任务终态与取消事实；不暴露内部状态或活动槽引用。 */
        [[nodiscard]] auto Observation() const noexcept -> TaskObservation
        {
            const bool Cancellable = Cancellable_.load(std::memory_order_acquire) &&
                !IsCancelRequested() && !IsCompleted();
            const auto Failure = DrainFailure_.load(std::memory_order_acquire);
            const bool IsDrainBlocked = DrainBlocked_.load(std::memory_order_acquire) ||
                static_cast<bool>(Failure) || IsCancelDispatchFailed();
            auto DrainFailure = Preview::Fault::Failure{Preview::Fault::Code::Success};
            if (Failure)
            {
                DrainFailure = *Failure;
            }
            else if (IsDrainBlocked)
            {
                DrainFailure.Code = Preview::Fault::Code::Blocked;
            }
            return {Identity_, Result(), StartedAt_.load(std::memory_order_acquire),
                CompletedAt_.load(std::memory_order_acquire), IsStarted(),
                IsCancelRequested(), IsDrainBlocked, DrainFailure,
                Cancellable};
        }

        /** @brief 保留真实 cleanup 失败，并发布任务仍不能退休的观察状态。 */
        auto MarkDrainBlocked(Preview::Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Succeeded())
            {
                Failure.Code = Preview::Fault::Code::Blocked;
            }
            try
            {
                auto Cause = std::make_shared<const Preview::Fault::Failure>(
                    std::move(Failure));
                std::shared_ptr<const Preview::Fault::Failure> Empty;
                (void)DrainFailure_.compare_exchange_strong(
                    Empty, std::move(Cause), std::memory_order_acq_rel,
                    std::memory_order_acquire);
            }
            catch (...)
            {
            }
            DrainBlocked_.store(true, std::memory_order_release);
        }

        /** @brief 返回 TaskSubmission 共享的真实退休回执 owner。 */
        [[nodiscard]] auto Retirement() const noexcept
            -> std::shared_ptr<TaskRetirementReceipt>
        {
            return Retirement_;
        }

        /** @brief 真正的终态发布次数；重复 Complete/Quarantine 保持一次。 */
        [[nodiscard]] auto CompletionCount() const noexcept -> std::size_t
        { return CompletionCount_.load(std::memory_order_acquire); }

        [[nodiscard]] auto Domain() const noexcept -> std::shared_ptr<CancellationDomain> { return Domain_.load(); }

        [[nodiscard]] auto CancellationSlot() noexcept -> Net::cancellation_slot
        { if (const auto Value = Domain_.load()) return Value->Slot(); return {}; }

        /** @brief 未启动输入在原 executor 退休前执行一次取消 hook。 */
        [[nodiscard]] auto CancelBeforeRetirement() -> std::expected<void, Preview::Fault::Failure>
        {
            CancelRequested_.store(true, std::memory_order_release);
            if (!InvokeCancel()) return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::IoError});
            if (IsCancelDispatchFailed())
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            if (!CancelFinished_.load(std::memory_order_acquire))
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            return {};
        }

        /** @brief 完成 handler 析构时释放取消闭包/节点；句柄只保留值结果。 */
        auto Retire() noexcept -> void
        {
            Cancel_ = {};
            Cancellable_.store(false, std::memory_order_release);
            Domain_.store({});
            IdentityObserver_.reset();
        }

    private:
        friend class TaskRegistry;

        /** @brief 仅在 cleanup owner 已接管 TaskState 后移入取消实物。 */
        auto Install(TaskRequest Request) noexcept -> void
        {
            Cancel_ = std::move(Request.Cancel);
            Cancellable_.store(static_cast<bool>(Cancel_), std::memory_order_release);
            IdentityObserver_ = std::move(Request.IdentityObserver);
        }

        /** @brief 取消 hook 异常只能变成可观察失败，不能穿过 executor 命令边界。 */
        auto InvokeCancel() noexcept -> bool
        {
            if (CancelInvoked_.exchange(true)) return !CancelHookFailed_.load();
            try
            {
                if (Cancel_) Cancel_();
            }
            catch (...)
            {
                CancelHookFailed_.store(true, std::memory_order_release);
                CancelDispatchFailed_.store(true, std::memory_order_release);
            }
            CancelFinished_.store(true, std::memory_order_release);
            return !CancelHookFailed_.load(std::memory_order_acquire);
        }

        TaskIdentity Identity_;
        std::atomic<std::shared_ptr<CancellationDomain>> Domain_;
        TaskCancelFn Cancel_;
        bool StartOnSubmit_;
        std::shared_ptr<TaskIdentityObserver> IdentityObserver_;
        std::shared_ptr<TaskRetirementReceipt> Retirement_;
        std::atomic<bool> DrainBlocked_{false};
        std::atomic<std::shared_ptr<const Preview::Fault::Failure>> DrainFailure_;
        std::atomic<TaskPhase> Phase_{TaskPhase::Pending};
        std::atomic<bool> Started_{false};
        std::atomic<bool> CancelRequested_{false};
        std::atomic<bool> CancelInvoked_{false};
        std::atomic<bool> Cancellable_{false};
        std::atomic<bool> CancelFinished_{false};
        std::atomic<bool> CancelHookFailed_{false};
        std::atomic<bool> CancelDispatchFailed_{false};
        std::atomic<bool> Completed_{false};
        std::atomic<std::uint64_t> StartedAt_{0};
        std::atomic<std::uint64_t> CompletedAt_{0};
        std::atomic<std::size_t> CompletionCount_{0};
        std::atomic<TaskOutcome> Outcome_{TaskOutcome::Pending};
        Preview::Fault::Failure Failure_{};
    };

    /** @brief 持有稳定观察状态；释放句柄不取消任务，也不占用已退栈 slot。 */
    class TaskHandle final
    {
    public:
        /** @brief 按值返回不可变身份；不借用 executor 或延长任务 slot。 */
        [[nodiscard]] auto Identity() const noexcept -> TaskIdentity { return State_->Identity(); }

        /** @brief 异步请求取消，只排队一次 hook，不表示任务已完成或资源已关闭。
         * @details hook 在原任务 executor 执行；此方法不做半关闭，最终关闭仍归任务 owner。
         * @return 首次发布请求为 true；任务已完成或已请求时为 false。
         */
        [[nodiscard]] auto RequestCancel() const -> bool { return State_->RequestCancel(); }

        /** @brief 读取任务逻辑终态；不代表异步清理已退栈或最终资源已关闭。 */
        [[nodiscard]] auto IsCompleted() const noexcept -> bool { return State_->IsCompleted(); }

        /** @brief 读取单一终态发布次数，用于确认 CAS 获胜者数量。 */
        [[nodiscard]] auto CompletionCount() const noexcept -> std::size_t { return State_->CompletionCount(); }

        /** @brief 按值返回唯一任务结果；Pending 表示任务尚未发布终态。 */
        [[nodiscard]] auto Result() const noexcept -> TaskResult { return State_->Result(); }

        /** @brief 按值读取状态、取消和真实排空失败；不拥有活动 slot。 */
        [[nodiscard]] auto Observation() const noexcept -> TaskObservation { return State_->Observation(); }

        /** @brief 在调用方 executor 等待任务清理与 completion handler 真实退栈。
         * @details 返回资源或调度失败；取消等待不会释放 retirement owner，也不代替 carrier close/half-close。
         * @return 实际任务 retirement 回执；等待协程继续使用调用方 executor。
         */
        [[nodiscard]] auto WaitForRetirementAsync() const
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            const auto Retirement = State_->Retirement();
            if (!Retirement)
            {
                return FailedRetirementWait(Preview::Fault::Failure{
                    Preview::Fault::Code::Blocked});
            }
            return Retirement->WaitAsync();
        }
    private:
        friend class TaskRegistry;
        friend class TaskHandleTestAccess;

        explicit TaskHandle(std::shared_ptr<TaskState> Value) : State_(std::move(Value)) {}

        [[nodiscard]] static auto FailedRetirementWait(
            Preview::Fault::Failure Failure)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_return std::unexpected(std::move(Failure));
        }

        std::shared_ptr<TaskState> State_;
    };
}

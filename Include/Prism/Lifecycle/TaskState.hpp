/** @file TaskState.hpp @brief 任务身份、值结果与稳定观察句柄。 */
#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Lifecycle/CancellationDomain.hpp>
#include <Prism/Lifecycle/TaskRetirementReceipt.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <utility>

namespace Prism::Lifecycle
{
    /** @brief 发布后不可变的任务身份，父身份保留在独立字段。 */
    struct TaskIdentity final
    {
        Prism::TaskId TaskId{};
        Prism::SessionId SessionId{};
        Prism::StreamId StreamId{};
        Prism::WorkerId WorkerId{};
        Prism::GenerationId Generation{};
        Prism::TaskId ParentTaskId{};

        friend auto operator==(const TaskIdentity &, const TaskIdentity &) noexcept -> bool = default;
    };

    /** @brief 提交上下文不接受调用者指定任务 ID；所有字段按值转移。 */
    struct TaskContext final
    {
        Prism::SessionId SessionId{};
        Prism::StreamId StreamId{};
        Prism::WorkerId WorkerId{};
        Prism::GenerationId Generation{};
        Prism::TaskId ParentTaskId{};
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
        Prism::Fault::Failure Failure{};
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
        Prism::Fault::Failure DrainFailure{};
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

    /**
     * @brief 单一任务的状态与取消 hook owner；只发布逻辑终态，不拥有 drain reservation。
     * @details TaskSubmission 拥有 coroutine、预约及异步清理，只有实际 runner/completion 退栈后才释放。
     *          任务状态与取消域绑定同一 executor；RequestCancel 可跨线程，但 hook 在该 executor 执行。
     *          取消不执行 half-close 或最终关闭，实际资源的 owning task/resource owner 必须继续 drain。
     */
    class TaskState final : public CancellationObserver, public std::enable_shared_from_this<TaskState>
    {
        [[nodiscard]] static auto CurrentTimestamp() noexcept -> std::uint64_t;
        [[nodiscard]] auto BeginCompletion() noexcept -> bool;
        [[nodiscard]] auto CancellationPreventsStart() const noexcept -> bool;

    public:
        struct Options final
        {
            TaskIdentity Identity; ///< registry 分配且发布后不变的完整任务身份。
            std::shared_ptr<CancellationDomain> Domain; ///< 可空取消域 shared owner，不拥有 task/resource。
            TaskCancelFn Cancel; ///< 按值接管的取消 hook；在 Domain 的 executor 调用，不代替最终关闭。
            bool StartOnSubmit{false}; ///< 是否允许提交时启动；false 时先检查父域取消请求。
            std::shared_ptr<TaskIdentityObserver> IdentityObserver; ///< 接纳投递后通知的 observer owner。
            std::shared_ptr<TaskRetirementReceipt> Retirement; ///< 可空回执 owner；非空时由 TaskSubmission 发布真实退休。
        };

        /** @brief 按值接管状态选项；task/coroutine 与 drain reservation 仍归 TaskSubmission。 */
        explicit TaskState(Options Value);

        /** @brief 按值返回发布后不变的身份；不借出资源，不触发取消或关闭。 */
        [[nodiscard]] auto Identity() const noexcept -> TaskIdentity { return Identity_; }

        /** @brief 读取提交门控策略的不可变值。 */
        [[nodiscard]] auto StartOnSubmit() const noexcept -> bool { return StartOnSubmit_; }

        /** @brief 在绑定 executor 的已接纳命令中发布一次身份；未交付的拒绝路径绝不发布。 */
        auto PublishAcceptedIdentity() -> void;

        /**
         * @brief 原 executor 取得执行权；CAS 后再次检查取消，避免启动竞态。
         * @return 仅从 Pending 成功转为 Started 时为 true；已完成、取消或竞争失败为 false。
         * @note 不表示 coroutine 已退栈或资源已关闭。
         */
        [[nodiscard]] auto TryStart() -> bool;

        /**
         * @brief 任意线程记录取消并请求在原 executor 执行 hook。
         * @return 有 Domain 且首次发起请求时为 true，即使投递失败也为 true；已完成、已请求或无 Domain 时为 false。
         *         投递失败须通过 IsCancelDispatchFailed 观察。
         * @note 只请求取消，不执行 half-close/drain/最终关闭；资源仍归实际 owning task/resource owner。
         */
        [[nodiscard]] auto RequestCancel() -> bool;

        /** @brief 父域 signal 在绑定 executor 到达时执行一次 hook；异常被转为可观察 dispatch failure。 */
        auto OnCancellation() -> void override;

        /**
         * @brief 原 executor 发布成功、取消或失败；重复发布不会覆盖第一终态。
         * @param Failure 本次运行的正式首因；默认值表示成功。
         * @return 本次赢得单一终态发布为 true；已有 Completing/终态时为 false。
         * @note 取消已记录且输入 Failure 成功时会发布 Canceled；只发布逻辑结果，不等待 completion
         *       handler 退栈或关闭资源。
         */
        [[nodiscard]] auto Complete(Prism::Fault::Failure Failure = {}) noexcept -> bool;

        /**
         * @brief 原 executor 清理完 queued operation 后发布隔离终态，不调用完成回调。
         * @return 首次成功发布 Quarantined 为 true；状态已进入 Completing/终态时为 false。
         * @note 不代表资源已经关闭；实际清理由 TaskSubmission owner 继续完成。
         */
        [[nodiscard]] auto Quarantine() noexcept -> bool;

        /** @brief 读取 runner 是否已在绑定 executor 开始；不表示任务完成或资源退休。 */
        [[nodiscard]] auto IsStarted() const noexcept -> bool { return Started_.load(std::memory_order_acquire); }

        /** @brief Completed 与 Quarantined 都是观察层终态，slot 退休仍由 submission 完成。 */
        [[nodiscard]] auto IsCompleted() const noexcept -> bool
        {
            const auto Phase = Phase_.load(std::memory_order_acquire);
            return Phase == TaskPhase::Completed || Phase == TaskPhase::Quarantined;
        }

        /** @brief 读取取消请求是否已记录；不表示 hook 已运行、I/O 已停止或资源已关闭。 */
        [[nodiscard]] auto IsCancelRequested() const noexcept -> bool { return CancelRequested_.load(); }

        /** @brief 读取取消命令投递或取消域 dispatch 是否失败；失败时不能提前释放 reservation。 */
        [[nodiscard]] auto IsCancelDispatchFailed() const noexcept -> bool
        {
            const auto Value = Domain_.load();
            return CancelDispatchFailed_.load() || (Value && Value->IsDispatchBlocked());
        }

        /** @brief 按值读取逻辑 Outcome；Completed/Quarantined 不代替真实 retirement。 */
        [[nodiscard]] auto Outcome() const noexcept -> TaskOutcome { return Outcome_.load(std::memory_order_acquire); }

        /** @brief Pending 时返回默认结果；终态时按值返回唯一 Outcome 与 Failure。 */
        [[nodiscard]] auto Result() const noexcept -> TaskResult
        { if (!IsCompleted()) return {}; return {Outcome(), Failure_}; }

        /** @brief 按值观察任务终态与取消事实；不暴露内部状态或活动槽引用。 */
        [[nodiscard]] auto Observation() const noexcept -> TaskObservation;

        /**
         * @brief 保留真实 cleanup 失败，并发布任务仍不能退休的观察状态。
         * @param Failure 首个 cleanup/dispatch Failure；Success 会规范化为 Blocked。
         * @note 不覆盖 TaskOutcome，也不释放 TaskSubmission reservation 或资源 owner。
         */
        auto MarkDrainBlocked(Prism::Fault::Failure Failure) noexcept -> void;

        /** @brief 返回 TaskSubmission 共享的真实退休回执 owner；未提供时为空。 */
        [[nodiscard]] auto Retirement() const noexcept
            -> std::shared_ptr<TaskRetirementReceipt>
        {
            return Retirement_;
        }

        /** @brief 真正的终态发布次数；重复 Complete/Quarantine 保持一次。 */
        [[nodiscard]] auto CompletionCount() const noexcept -> std::size_t
        { return CompletionCount_.load(std::memory_order_acquire); }

        /** @brief 返回取消域 shared owner；可能为空，不延长任务 slot，也不取得资源关闭权。 */
        [[nodiscard]] auto Domain() const noexcept -> std::shared_ptr<CancellationDomain> { return Domain_.load(); }

        /** @brief 借用 Domain cancellation slot；无 Domain 时为空，不取得取消域或资源 owner。 */
        [[nodiscard]] auto CancellationSlot() noexcept -> Net::cancellation_slot
        { if (const auto Value = Domain_.load()) return Value->Slot(); return {}; }

        /**
         * @brief 未启动输入在原 executor 退休前执行一次取消 hook。
         * @return hook 完成时成功；hook 失败返回 IoError，dispatch 失败或 hook 尚未完成返回 Blocked。
         * @note 不执行实际资源关闭；失败时调用者必须保留 TaskSubmission 与资源 owner。
         */
        [[nodiscard]] auto CancelBeforeRetirement() -> std::expected<void, Prism::Fault::Failure>;

        /**
         * @brief 完成 handler 退栈后释放取消闭包/节点；句柄只保留值结果。
         * @details 只释放本状态持有的回调与取消引用，不执行 half-close、drain 或最终关闭。
         */
        auto Retire() noexcept -> void;

    private:
        friend class TaskRegistry;

        /** @brief 仅在 cleanup owner 已接管 TaskState 后移入取消实物。 */
        auto Install(TaskRequest Request) noexcept -> void;

        /** @brief 取消 hook 异常只能变成可观察失败，不能穿过 executor 命令边界。 */
        auto InvokeCancel() noexcept -> bool;

        TaskIdentity Identity_;
        std::atomic<std::shared_ptr<CancellationDomain>> Domain_;
        TaskCancelFn Cancel_;
        bool StartOnSubmit_;
        std::shared_ptr<TaskIdentityObserver> IdentityObserver_;
        std::shared_ptr<TaskRetirementReceipt> Retirement_;
        std::atomic<bool> DrainBlocked_{false};
        std::atomic<std::shared_ptr<const Prism::Fault::Failure>> DrainFailure_;
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
        Prism::Fault::Failure Failure_{};
    };

    /**
     * @brief 持有稳定观察状态；释放句柄不取消任务，也不占用已退栈 slot。
     * @details Handle 不拥有 task coroutine、reservation 或传输关闭权；取消由 TaskState 请求，
     *          实际 drain/关闭仍归 TaskSubmission 与协议/资源 owner。
     */
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
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
    private:
        friend class TaskRegistry;
        friend class TaskHandleTestAccess;

        explicit TaskHandle(std::shared_ptr<TaskState> Value) : State_(std::move(Value)) {}

        [[nodiscard]] static auto FailedRetirementWait(
            Prism::Fault::Failure Failure)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        std::shared_ptr<TaskState> State_;
    };
}

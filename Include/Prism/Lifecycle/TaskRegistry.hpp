/** @file TaskRegistry.hpp @brief 有界任务准入、单调身份及真实退栈排空。 */
#pragma once

#include <Prism/Lifecycle/TaskSubmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace Prism::Lifecycle
{
    namespace Net = boost::asio;

    /** @brief worker root registry 下按完整 Session/Worker/Generation 父身份分页的查询。 */
    struct TaskRegistryListRequest final
    {
        Prism::SessionId Session{}; ///< 完整父 scope 的 session 身份。
        Prism::WorkerId Worker{}; ///< 完整父 scope 的 worker 身份。
        Prism::GenerationId Generation{}; ///< 完整父 scope 的配置代次。
        std::uint64_t Cursor{0}; ///< 排除小于等于此 TaskId 的条目。
        std::size_t Limit{50}; ///< 返回上限；实现最多返回 256 条。
    };

    /** @brief root registry 的按值任务观察页；不拥有活动 slot。 */
    struct TaskRegistryListPage final
    {
        std::vector<TaskObservation> Items;
        std::uint64_t NextCursor{0};
        bool HasMore{false};
    };

    /**
     * @brief 注册表 owner；销毁只请求自身任务退休，完成 handler 保活实际任务至退栈。
     * @details TaskHandle 不延长 slot 寿命。父子共享串行 executor，父不以子任务身份等待自身。
     *          Drain 只等待本 scope，统计包含后代。Cancel 只分发取消 hook，不执行 half-close 或
     *          最终关闭；网络/业务资源始终由任务及其具体 resource owner 关闭。调用者须保活本 registry
     *          与 executor/context，直到 Drain 返回且相关资源 owner 真实退休。
     */
    class TaskRegistry final
    {
        using State = Detail::TaskRegistryState;
        using TaskLookupResult =
            std::expected<std::optional<TaskHandle>, Prism::Fault::Failure>;
        static std::atomic<std::uint64_t> NextTaskId_;

        [[nodiscard]] static auto AllocateId() noexcept
            -> std::expected<Prism::TaskId, Prism::Fault::Failure>;
        static auto CancelOnExecutor(const std::shared_ptr<State>& Value) -> void;
        [[nodiscard]] static auto BelongsToRootScope(
            const State *Root, const State *Scope) noexcept -> bool;
        [[nodiscard]] static auto FindTaskOnExecutor(
            std::shared_ptr<State> Root, const TaskIdentity Identity)
            -> Net::awaitable<TaskLookupResult>;
        [[nodiscard]] static auto MatchesListScope(
            const TaskObservation &Observation,
            const TaskRegistryListRequest &Request) noexcept -> bool;
        [[nodiscard]] static auto ListTasksOnExecutor(
            std::shared_ptr<State> Root, TaskRegistryListRequest Request)
            -> Net::awaitable<std::expected<TaskRegistryListPage, Prism::Fault::Failure>>;
        [[nodiscard]] static auto ListTasksOnOwner(
            std::shared_ptr<State> Root, TaskRegistryListRequest Request)
            -> Net::awaitable<std::expected<TaskRegistryListPage, Prism::Fault::Failure>>;
        [[nodiscard]] static auto FindTaskOnOwner(
            std::shared_ptr<State> Root, const TaskIdentity Identity)
            -> Net::awaitable<TaskLookupResult>;

        struct CancelCommand final
        {
            std::shared_ptr<State> Value;
            auto operator()() const noexcept -> void;
            auto OnQuarantine() const noexcept -> void;
        };

    public:
        /** @brief 失败终态通知；回调在任务完成通知路径运行，不拥有 task/resource。 */
        using FailureHandler = std::function<void(const TaskIdentity&, Prism::Fault::Failure)>;

        /**
         * @brief 在指定 executor 建立独立根 scope，并创建串行命令 strand。
         * @param Executor 任务 runner 的基础 executor；命令、取消 hook 与状态机在其 strand 执行。
         * @param Failure 可选失败观察回调；在任务完成通知路径调用，不取得任务或网络资源 owner。
         * @note Registry 不拥有外部 context，调用者负责保持它到任务与 drain 全部退栈。
         */
        explicit TaskRegistry(Net::any_io_executor Executor, FailureHandler Failure = {});
        ~TaskRegistry();
        TaskRegistry(const TaskRegistry&) = delete;
        auto operator=(const TaskRegistry&) -> TaskRegistry& = delete;

        /** @brief 冷路径给独立根 scope 绑定唯一统计 sink；必须先于任务准入。
         * @details 只接受尚未准入任务的根 registry；子 scope 在创建时继承该强引用。
         *          此绑定只提供数值观察服务，不拥有任务或网络资源。
         * @param Sink 按值转移的统计服务 owner。
         * @return 成功绑定或明确的 InvalidArgument/Blocked；失败时不发布新 sink。
         */
        [[nodiscard]] auto BindTrafficSink(std::shared_ptr<Prism::Foundation::TrafficSink> Sink)
            -> std::expected<void, Prism::Fault::Failure>;

        /**
         * @brief 冷装配子 scope；共享父串行 executor，取消传播但 drain 不等待父自身。
         * @param Failure 子 scope 的可选失败观察回调；不接管任务资源。
         * @return 子 registry shared owner；调用方负责保活到子 scope 的 Drain 完成。
         */
        [[nodiscard]] auto CreateChild(FailureHandler Failure = {}) -> std::shared_ptr<TaskRegistry>;

        /**
         * @brief 按值接管上下文与协程；普通拒绝返回 Failure，成功保活至真实退栈。
         * @param Request 按值转移的任务上下文、取消 hook 与启动策略。
         * @param Operation 按值转移的 awaitable；成功接纳后由 TaskSubmission 保活到真实清理完成。
         * @return 成功仅表示投递命令已接收并返回观察句柄，不表示任务已启动；Blocked/Canceled、预约
         *         或身份分配错误按 Failure 返回。拒绝时调用方已移交的输入由本调用释放。
         * @details slot、取消节点、drain reservation 归同一 submission；hook 在原 executor 执行。
         *          取消只请求 hook，不负责 half-close 或最终关闭；资源关闭仍归 operation/resource owner。
         *          ID 单调不复用、不接受外部指定。
         */
        template<class Coro>
        [[nodiscard]] auto SpawnTracked(TaskRequest Request, Coro Operation)
            -> std::expected<TaskHandle, Prism::Fault::Failure>
        {
            if (State_->Blocked.load() || !State_->Reclaimer->CanDispatch())
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            if (!State_->Accepting.load() || State_->Domain->IsCancellationRequested())
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
            auto Reservation = TaskReservation::Acquire(State_);
            if (!Reservation) return std::unexpected(Reservation.error());
            auto Id = AllocateId();
            if (!Id) return std::unexpected(Id.error());
            auto Domain = State_->Domain->CreateChild();
            Reservation->Attach(Domain);
            if (Domain->IsDispatchBlocked())
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            const auto& Context = Request.Context;
            TaskIdentity Identity{*Id, Context.SessionId, Context.StreamId, Context.WorkerId,
                Context.Generation, Context.ParentTaskId};
            auto Submission = std::make_shared<Detail::TaskSubmission<Coro>>(
                std::move(*Reservation), std::move(Operation));
            Submission->Retain();
            Detail::TaskSetup<Coro> Setup{Submission};
            auto Retirement = std::make_shared<TaskRetirementReceipt>();
            auto Task = std::make_shared<TaskState>(TaskState::Options{
                Identity, std::move(Domain), {}, Request.StartOnSubmit, {}, std::move(Retirement)});
            Submission->Attach(Task);
            Task->Install(std::move(Request));
            Submission->InstallQuarantine();
            Task->Domain()->Observe(Task);
            Setup.Ready = true;
            auto Command = Detail::TaskDelivery<Coro>(Submission);
            if (!Detail::PostTaskRegistryCommand(State_, std::move(Command)))
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            return TaskHandle(std::move(Task));
        }

        /**
         * @brief 在 root registry 的有界任务槽中按完整身份查找活动任务。
         * @param Identity 完整任务身份；不拥有或延长活动 slot。
         * @return 找到时返回观察句柄；无匹配项是成功的空 optional。仅 root 可查询；身份无效返回
         *         InvalidArgument，交付阻断返回 Blocked，原生查询异常保留其 Failure。
         * @note 查询不取消任务、不关闭资源；句柄不延长 slot 寿命。
         */
        [[nodiscard]] auto FindTask(TaskIdentity Identity) const
            -> Net::awaitable<std::expected<std::optional<TaskHandle>, Prism::Fault::Failure>>;
        /**
         * @brief 按完整 session 父身份分页返回 root registry 的实际活动任务观察值。
         * @param Request 按值接收的完整父身份、游标与页上限。
         * @return 返回值页；仅 root 可查询，子 scope/交付阻断返回 Blocked，无效父身份返回
         *         InvalidArgument，分配失败或原生查询异常返回对应 Failure。Limit 至多 256；NextCursor
         *         为末项 TaskId，空页时保留输入 Cursor。
         * @note 只复制观察值，不延长任务 slot，也不执行取消或资源关闭。
         */
        [[nodiscard]] auto ListTasks(TaskRegistryListRequest Request) const
            -> Net::awaitable<std::expected<TaskRegistryListPage, Prism::Fault::Failure>>;
        /** @brief 原子封止并请求在原 executor 取消本 scope 的活动任务。
         * @details 返回 true 只表示首次取消请求已记录，不表示 hook 已执行、任务已退栈、
         *          I/O 已半关闭或传输已最终关闭。交付失败通过 IsDrainBlocked/Drain 保留。
         * @return 本次是否首次登记取消请求。
         */
        [[nodiscard]] auto Cancel() -> bool;
        /** @brief 封止新 task/drain reservation 准入；不取消已接纳任务或关闭其资源。 */
        auto Seal() noexcept -> void;
        /**
         * @brief 封止新准入并等待本 scope 的任务真实退栈。
         * @return 空 expected 表示本 scope 活动预约归零；Blocked 或等待取消返回 Failure，计数和 owner
         *         不会被清零/释放。
         * @note 调用方保持 registry 与 executor；此方法不执行资源 half-close 或最终关闭。
         */
        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;
        /** @brief 按值读取本 scope 及后代的累计统计；活动预约只统计未真实退栈任务。 */
        [[nodiscard]] auto Stats() const noexcept -> TaskStats;
        /** @brief 读取不能继续排空的事实；调用方必须保留资源并处理失败。 */
        [[nodiscard]] auto IsDrainBlocked() const noexcept -> bool { return Stats().DrainBlocked; }
        /**
         * @brief 标记本 scope 无法继续证明排空，并阻断后续准入/Drain 成功。
         * @details 不分发取消、不清除 reservation，也不关闭资源；调用方必须继续保留各实际 owner。
         */
        auto Block() noexcept -> void;

        /** @brief 借用本 registry 的取消域 shared owner，不授予资源关闭权。 */
        [[nodiscard]] auto Domain() const noexcept
            -> const std::shared_ptr<CancellationDomain>& { return State_->Domain; }
        /** @brief 返回可共享的原 executor 命令投递 owner。 */
        [[nodiscard]] auto Reclaimer() const noexcept
            -> std::shared_ptr<Prism::Executor::ExecutorReclaimer> { return State_->Reclaimer; }
        /** @brief 返回本任务 scope 的 executor handle；不转移 context 生命周期。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor { return State_->CommandExecutor; }

    private:
        friend class TaskRegistryTestAccess;
        TaskRegistry(std::shared_ptr<State> Parent, FailureHandler Failure);
        std::shared_ptr<State> State_;
    };
}

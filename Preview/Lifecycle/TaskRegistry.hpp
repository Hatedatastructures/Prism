/** @file TaskRegistry.hpp @brief 有界任务准入、单调身份及真实退栈排空。 */
#pragma once
#include <Preview/Lifecycle/TaskSubmission.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>
#include <algorithm>
#include <limits>
#include <expected>
#include <new>
#include <optional>
#include <system_error>
#include <vector>

namespace Preview::Lifecycle
{
    namespace Net = boost::asio;

    /** @brief worker root registry 下按完整 Session/Worker/Generation 父身份分页的查询。 */
    struct TaskRegistryListRequest final
    {
        Preview::SessionId Session{};
        Preview::WorkerId Worker{};
        Preview::GenerationId Generation{};
        std::uint64_t Cursor{0};
        std::size_t Limit{50};
    };

    struct TaskRegistryListPage final
    {
        std::vector<TaskObservation> Items;
        std::uint64_t NextCursor{0};
        bool HasMore{false};
    };

    /** @brief 注册表 owner；销毁只退休自身任务，完成 handler 保活实际任务至退栈。
     * @details TaskHandle 不延长 slot 寿命。父子共享串行 executor，父不以子任务
     * 身份等待自身。Drain 只等待本 scope，统计包含后代，最终关闭由资源 owner 完成。
     */
    class TaskRegistry final
    {
        using State = Detail::TaskRegistryState;
        using TaskLookupResult =
            std::expected<std::optional<TaskHandle>, Preview::Fault::Failure>;
        inline static std::atomic<std::uint64_t> NextTaskId_{1};
        [[nodiscard]] static auto AllocateId() noexcept -> std::expected<Preview::TaskId, Preview::Fault::Failure>
        {
            auto Current = NextTaskId_.load();
            while (Current != 0)
            {
                std::uint64_t Next = 0;
                if (Current != std::numeric_limits<std::uint64_t>::max()) Next = Current + 1;
                if (NextTaskId_.compare_exchange_weak(Current, Next)) return Preview::TaskId{Current};
            }
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable});
        }
        static auto CancelOnExecutor(const std::shared_ptr<State>& Value) -> void
        {
            (void)Value->Domain->Cancel();
            for (const auto& Slot : Value->Pool->Slots)
                if (Slot.Scope.load() == Value.get()) Detail::RequestTaskCancel(Value, Slot.Task);
        }
        [[nodiscard]] static auto BelongsToRootScope(
            const State *Root, const State *Scope) noexcept -> bool
        {
            for (auto Current = Scope; Current; Current = Current->Parent.get())
            {
                if (Current == Root) return true;
            }
            return false;
        }
        [[nodiscard]] static auto FindTaskOnExecutor(
            std::shared_ptr<State> Root,
            const TaskIdentity Identity)
            -> Net::awaitable<TaskLookupResult>
        {
            if (!Root || Root->Parent || !Identity.TaskId)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (!Root->Reclaimer->CanDispatch())
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            for (const auto &Slot : Root->Pool->Slots)
            {
                if (!Slot.Used.load(std::memory_order_acquire)) continue;
                const auto *Scope = Slot.Scope.load(std::memory_order_acquire);
                if (!Scope || !BelongsToRootScope(Root.get(), Scope)) continue;
                const auto Task = Slot.Task;
                if (Task && Task->Identity() == Identity)
                {
                    co_return std::optional<TaskHandle>{TaskHandle{Task}};
                }
            }
            co_return std::optional<TaskHandle>{};
        }
        [[nodiscard]] static auto MatchesListScope(
            const TaskObservation &Observation,
            const TaskRegistryListRequest &Request) noexcept -> bool
        {
            const auto &Identity = Observation.Identity;
            return Identity.SessionId == Request.Session &&
                Identity.WorkerId == Request.Worker &&
                Identity.Generation == Request.Generation &&
                Identity.TaskId.Value() > Request.Cursor;
        }
        [[nodiscard]] static auto ListTasksOnExecutor(
            std::shared_ptr<State> Root,
            TaskRegistryListRequest Request)
            -> Net::awaitable<std::expected<TaskRegistryListPage, Preview::Fault::Failure>>
        {
            using Failure = Preview::Fault::Failure;
            if (!Root || Root->Parent || !Request.Session || !Request.Worker ||
                !Request.Generation)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (!Root->Reclaimer->CanDispatch())
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            }
            constexpr std::size_t MaxPageSize{256U};
            const auto Limit = (std::min)(Request.Limit, MaxPageSize);
            std::vector<TaskObservation> Matches;
            for (const auto &Slot : Root->Pool->Slots)
            {
                if (!Slot.Used.load(std::memory_order_acquire)) continue;
                const auto *Scope = Slot.Scope.load(std::memory_order_acquire);
                if (!Scope || !BelongsToRootScope(Root.get(), Scope)) continue;
                const auto Task = Slot.Task;
                if (!Task) continue;
                auto Observation = Task->Observation();
                if (MatchesListScope(Observation, Request))
                    Matches.push_back(std::move(Observation));
            }
            std::sort(Matches.begin(), Matches.end(), [](const auto &Left, const auto &Right)
            { return Left.Identity.TaskId.Value() < Right.Identity.TaskId.Value(); });
            TaskRegistryListPage Result;
            Result.NextCursor = Request.Cursor;
            Result.HasMore = Matches.size() > Limit;
            if (Matches.size() > Limit) Matches.resize(Limit);
            if (!Matches.empty()) Result.NextCursor = Matches.back().Identity.TaskId.Value();
            Result.Items = std::move(Matches);
            co_return Result;
        }
        [[nodiscard]] static auto ListTasksOnOwner(
            std::shared_ptr<State> Root,
            TaskRegistryListRequest Request)
            -> Net::awaitable<std::expected<TaskRegistryListPage, Preview::Fault::Failure>>
        {
            if (!Root || Root->Parent || !Root->Reclaimer->CanDispatch())
            {
                co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            try
            {
                co_return co_await Net::co_spawn(Root->CommandExecutor,
                    ListTasksOnExecutor(Root, std::move(Request)), Net::use_awaitable);
            }
            catch (const std::bad_alloc &)
            {
                co_return std::unexpected(Preview::Fault::Failure{
                    Preview::Fault::Code::ResourceUnavailable});
            }
            catch (const boost::system::system_error &Error)
            {
                co_return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            catch (const std::system_error &Error)
            {
                co_return std::unexpected(Preview::Fault::FromNative(Error.code()));
            }
        }
        [[nodiscard]] static auto FindTaskOnOwner(
            std::shared_ptr<State> Root,
            const TaskIdentity Identity) -> Net::awaitable<TaskLookupResult>
        {
            if (!Root || Root->Parent || !Identity.TaskId)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (!Root->Reclaimer->CanDispatch())
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            try
            {
                co_return co_await Net::co_spawn(
                    Root->CommandExecutor,
                    FindTaskOnExecutor(Root, Identity),
                    Net::use_awaitable);
            }
            catch (const boost::system::system_error &Error)
            {
                co_return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            catch (const std::system_error &Error)
            {
                co_return std::unexpected(Preview::Fault::FromNative(Error.code()));
            }
            catch (...)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::IoError});
            }
        }
        struct CancelCommand final
        {
            std::shared_ptr<State> Value;

            auto operator()() const noexcept -> void
            {
                try { CancelOnExecutor(Value); }
                catch (...) { if (Value) Detail::MarkTaskRegistryBlocked(Value); }
            }

            auto OnQuarantine() const noexcept -> void
            {
                if (Value) Detail::MarkTaskRegistryBlocked(Value);
            }
        };
    public:
        using FailureHandler = std::function<void(const TaskIdentity&, Preview::Fault::Failure)>;
        explicit TaskRegistry(Net::any_io_executor Executor, FailureHandler Failure = {})
            : State_(std::make_shared<State>(std::move(Executor), std::move(Failure))) {}
        /** @brief 析构封止并在原 executor 退休自身 slot；独立后代 owner 继续运行。
         * @details 子树取消只由显式 Cancel 发起；不可交付时仍保留实物并阻断。
         */
        ~TaskRegistry()
        {
            Seal();
            State_->CancelRequested.store(true, std::memory_order_release);
            State_->TearingDown.store(true, std::memory_order_release);
            State_->RetainClosing();
            const auto Self = State_;
            if (!State_->Reclaimer->Post(Detail::TaskRegistryRetirementCommand(Self)))
            {
                State_->Blocked.store(true, std::memory_order_release);
                State_->Barrier.Block();
                State_->ClosingStorage->Retain(Self);
            }
        }
        TaskRegistry(const TaskRegistry&) = delete;
        auto operator=(const TaskRegistry&) -> TaskRegistry& = delete;
        /**
         * @brief 冷路径给独立根 scope 绑定唯一统计 sink；必须先于任务准入。
         * @details 只接受尚未准入任务的根 registry；子 scope 在创建时继承该强引用。
         *          此绑定只提供数值观察服务，不拥有任务或网络资源。
         * @param Sink 按值转移的统计服务 owner。
         * @return 成功绑定或明确的 InvalidArgument/Blocked；失败时不发布新 sink。
         */
        [[nodiscard]] auto BindTrafficSink(std::shared_ptr<Preview::Foundation::TrafficSink> Sink)
            -> std::expected<void, Preview::Fault::Failure>
        {
            using Failure = Preview::Fault::Failure;
            if (!Sink || State_->Parent || !State_->Accepting.load(std::memory_order_acquire))
                return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            if (State_->Traffic || State_->Barrier.Active() != 0U ||
                State_->Descendants.Active.load(std::memory_order_acquire) != 0U)
                return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            State_->Traffic = std::move(Sink);
            return {};
        }
        /** @brief 冷装配子 scope；共享父串行域，取消传播但 drain 不等待父自身。 */
        [[nodiscard]] auto CreateChild(FailureHandler Failure = {}) -> std::shared_ptr<TaskRegistry>
        { return std::shared_ptr<TaskRegistry>(new TaskRegistry(State_, std::move(Failure))); }
        /** @brief 按值接管上下文与协程；普通拒绝返回 Failure，成功保活至真实退栈。
         * @details slot/取消节点/drain 同预约；ID 单调不复用、不接受外部指定。
         */
        template<class Coro>
        [[nodiscard]] auto SpawnTracked(TaskRequest Request, Coro Operation)
            -> std::expected<TaskHandle, Preview::Fault::Failure>
        {
            if (State_->Blocked.load() || !State_->Reclaimer->CanDispatch())
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            if (!State_->Accepting.load() || State_->Domain->IsCancellationRequested())
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            auto Reservation = TaskReservation::Acquire(State_);
            if (!Reservation) return std::unexpected(Reservation.error());
            auto Id = AllocateId();
            if (!Id) return std::unexpected(Id.error());
            auto Domain = State_->Domain->CreateChild();
            Reservation->Attach(Domain);
            if (Domain->IsDispatchBlocked())
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            const auto& Context = Request.Context;
            TaskIdentity Identity{*Id, Context.SessionId, Context.StreamId, Context.WorkerId,
                Context.Generation, Context.ParentTaskId};
            auto Submission = std::make_shared<Detail::TaskSubmission<Coro>>(std::move(*Reservation), std::move(Operation));
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
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            return TaskHandle(std::move(Task));
        }
        /** @brief 在 root worker executor 的有界任务槽中按完整身份查找活动任务。 */
        [[nodiscard]] auto FindTask(TaskIdentity Identity) const
            -> Net::awaitable<std::expected<std::optional<TaskHandle>, Preview::Fault::Failure>>
        {
            const auto Root = State_;
            return FindTaskOnOwner(Root, Identity);
        }
        /** @brief 按完整 session 父身份分页返回 root registry 的实际活动任务观察值。 */
        [[nodiscard]] auto ListTasks(TaskRegistryListRequest Request) const
            -> Net::awaitable<std::expected<TaskRegistryListPage, Preview::Fault::Failure>>
        {
            return ListTasksOnOwner(State_, std::move(Request));
        }
        /**
         * @brief 原子封止并请求在原 executor 取消本 scope 的活动任务。
         * @details 返回 true 只表示首次取消请求已记录，不表示 hook 已执行、任务已退栈、
         *          I/O 已半关闭或传输已最终关闭。交付失败通过 IsDrainBlocked/Drain 保留。
         * @return 本次是否首次登记取消请求。
         */
        [[nodiscard]] auto Cancel() -> bool
        {
            if (State_->CancelRequested.exchange(true)) return false;
            Seal();
            State_->Domain->RequestCancellation();
            (void)Detail::PostTaskRegistryCommand(State_, CancelCommand{State_});
            return true;
        }
        auto Seal() noexcept -> void { Detail::SealTaskRegistryState(State_); }
        /** @brief 调用方保持 owner，等待本 scope 真实退栈；Blocked/取消均返回失败。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            auto Value = State_;
            Detail::SealTaskRegistryState(Value);
            if (Value->Blocked.load()) co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            co_return co_await Value->Barrier.Drain();
        }
        /** @brief 按值读取本 scope 及后代的累计统计；活动预约只统计未真实退栈任务。 */
        [[nodiscard]] auto Stats() const noexcept -> TaskStats
        { TaskStats Value; Detail::AddTaskStats(Value, State_); return Value; }
        /** @brief 读取不能继续排空的事实；调用方必须保留资源并处理失败。 */
        [[nodiscard]] auto IsDrainBlocked() const noexcept -> bool { return Stats().DrainBlocked; }
        auto Block() noexcept -> void { Detail::MarkTaskRegistryBlocked(State_); }
        /**
         * @brief 借用本 registry 的取消域 shared owner。
         * @details 返回的 shared_ptr 引用由 registry 持有；跨 await 使用时调用方须复制
         *          owner。取消域只管理任务取消，不授予 socket 半关闭或最终关闭权。
         */
        [[nodiscard]] auto Domain() const noexcept -> const std::shared_ptr<CancellationDomain>& { return State_->Domain; }
        /** @brief 借用原 executor 的交付 owner；不转移 context 的最终释放责任。 */
        /**
         * @brief 共享本任务域的命令投递 owner。
         * @details 返回独立 shared owner，可用于把协议子任务或 drain receipt 投递到
         *          本 registry 的串行域。它不拥有 io_context，也不转移 socket 最终关闭权；
         *          WorkerResources/进程 owner 必须保活执行器 context，直到全部 task 退栈。
         * @return 可共享的 executor reclaimer owner。
         */
        [[nodiscard]] auto Reclaimer() const noexcept
            -> std::shared_ptr<Preview::Executor::ExecutorReclaimer>
        {
            return State_->Reclaimer;
        }

        /**
         * @brief 返回本任务 scope 固定的命令执行域值。
         * @details 协议 writer 和 teardown 在该域驱动本 registry 的任务与实际 drain；
         *          返回值复制 Asio handle，不拥有 io_context，不授予 socket 关闭权。
         *          调用者保留 registry 与 context owner 到自身任务和回执全部退栈；
         *          查询没有取消或半关闭副作用，最终 scope drain 仍归 registry owner。
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return State_->CommandExecutor;
        }

    private:
        friend class TaskRegistryTestAccess;

        TaskRegistry(std::shared_ptr<State> Parent, FailureHandler Failure)
            : State_(std::make_shared<State>(Parent->Executor, std::move(Failure), Parent)) {}
        std::shared_ptr<State> State_;
    };
}

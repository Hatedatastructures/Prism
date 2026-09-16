/**
 * @file TaskRegistry.hpp
 * @brief Preview 任务注册表及其协程完成边界
 * @details Active map 只由绑定 executor 上的 command path 访问。外部线程只
 *          发布任务请求和原子生命周期标志，不能直接读写注册表容器。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <type_traits>
#include <utility>
#include <vector>

#include <Preview/Lifecycle/DrainBarrier.hpp>
#include <Preview/Lifecycle/FailureBoundary.hpp>
#include <Preview/Lifecycle/TaskState.hpp>

namespace Preview::Lifecycle
{

    namespace Net = boost::asio;

    struct TaskStats final
    {
        std::size_t Active{0};
        std::size_t Started{0};
        std::size_t Completed{0};
        std::size_t Cancelled{0};
        std::size_t Failed{0};
        std::size_t Quarantined{0};
        bool DrainBlocked{false};
    };

    class TaskRegistry final
    {
    private:
        struct State final
        {
            State(Net::any_io_executor ExecutorValue,
                  std::function<void(const TaskIdentity &, std::exception_ptr)> Failure)
                : Executor(std::move(ExecutorValue)),
                  CommandExecutor(Net::make_strand(Executor)),
                  Reclaimer(std::make_shared<Preview::Resource::ExecutorReclaimer>(CommandExecutor)),
                  Domain(std::make_shared<CancellationDomain>(CommandExecutor, Reclaimer)),
                  Barrier(Reclaimer),
                  Reservations(std::make_shared<const IdReservations>()),
                  OnFailure(std::move(Failure))
            {
            }

            State(Net::any_io_executor ExecutorValue,
                  std::function<void(const TaskIdentity &, std::exception_ptr)> Failure,
                  std::shared_ptr<CancellationDomain> ParentDomain)
                : Executor(std::move(ExecutorValue)),
                  CommandExecutor(Net::make_strand(Executor)),
                  Reclaimer(std::make_shared<Preview::Resource::ExecutorReclaimer>(CommandExecutor)),
                  Domain(ParentDomain ? ParentDomain->CreateChild()
                                      : std::make_shared<CancellationDomain>(CommandExecutor, Reclaimer)),
                  Barrier(Reclaimer),
                  Reservations(std::make_shared<const IdReservations>()),
                  OnFailure(std::move(Failure))
            {
            }

            using ActiveMap = std::map<Preview::TaskId, std::shared_ptr<TaskState>>;

            struct IdReservations final
            {
                std::uint64_t Next{1};
                std::set<std::uint64_t> Used;
            };

            struct GlobalIdReservations final
            {
                std::uint64_t Next{1};
                std::set<std::uint64_t> Used;
            };

            Net::any_io_executor Executor;
            Net::any_io_executor CommandExecutor;
            std::shared_ptr<Preview::Resource::ExecutorReclaimer> Reclaimer;
            std::shared_ptr<CancellationDomain> Domain;
            DrainBarrier Barrier;
            ActiveMap Active;
            std::atomic<std::shared_ptr<const IdReservations>> Reservations;
            std::atomic<std::size_t> Started{0};
            std::atomic<std::size_t> Completed{0};
            std::atomic<std::size_t> Cancelled{0};
            std::atomic<std::size_t> Failed{0};
            std::atomic<std::size_t> Quarantined{0};
            std::atomic<bool> Accepting{true};
            std::atomic<bool> CancelRequested{false};
            std::atomic<bool> CommandCancelled{false};
            std::atomic<bool> TearingDown{false};
            std::atomic<bool> Blocked{false};
            std::function<void(const TaskIdentity &, std::exception_ptr)> OnFailure;
        };

        using IdReservations = State::IdReservations;
        using GlobalIdReservations = State::GlobalIdReservations;

        static auto AddStats(TaskStats &Result, const std::shared_ptr<State> &StateValue) noexcept
            -> void
        {
            if (!StateValue)
            {
                return;
            }
            Result.Active += StateValue->Barrier.Active();
            Result.Started += StateValue->Started.load(std::memory_order_acquire);
            Result.Completed += StateValue->Completed.load(std::memory_order_acquire);
            Result.Cancelled += StateValue->Cancelled.load(std::memory_order_acquire);
            Result.Failed += StateValue->Failed.load(std::memory_order_acquire);
            Result.Quarantined += StateValue->Quarantined.load(std::memory_order_acquire);
            Result.DrainBlocked = Result.DrainBlocked ||
                                  StateValue->Blocked.load(std::memory_order_acquire) ||
                                  StateValue->Barrier.IsBlocked();
        }

        inline static std::atomic<std::shared_ptr<const GlobalIdReservations>>
            GlobalTaskIds_{std::make_shared<const GlobalIdReservations>()};

        [[nodiscard]] static auto ReserveGlobalTaskId(const Preview::TaskId Requested)
            -> std::optional<Preview::TaskId>
        {
            for (;;)
            {
                auto Current = GlobalTaskIds_.load(std::memory_order_acquire);
                std::uint64_t Candidate = Requested ? Requested.Value() : Current->Next;
                if (Candidate == 0 || Current->Used.contains(Candidate))
                {
                    return {};
                }
                if (!Requested)
                {
                    while (Current->Used.contains(Candidate))
                    {
                        if (Candidate == std::numeric_limits<std::uint64_t>::max())
                        {
                            return {};
                        }
                        ++Candidate;
                    }
                }

                auto Next = std::make_shared<GlobalIdReservations>(*Current);
                Next->Used.insert(Candidate);
                if (Candidate == std::numeric_limits<std::uint64_t>::max())
                {
                    Next->Next = 0;
                }
                else if (Next->Next == 0 || Next->Next <= Candidate)
                {
                    Next->Next = Candidate + 1U;
                }
                if (GlobalTaskIds_.compare_exchange_weak(
                        Current,
                        std::shared_ptr<const GlobalIdReservations>(std::move(Next)),
                        std::memory_order_acq_rel,
                        std::memory_order_acquire))
                {
                    return Preview::TaskId{Candidate};
                }
            }
        }

        static auto MarkBlocked(const std::shared_ptr<State> &StateValue) noexcept -> void
        {
            StateValue->Blocked.store(true, std::memory_order_release);
            StateValue->Barrier.Block();
        }

        static auto SealState(const std::shared_ptr<State> &StateValue) noexcept -> void
        {
            if (!StateValue)
            {
                return;
            }
            StateValue->Accepting.store(false, std::memory_order_release);
            StateValue->Barrier.Seal();
        }

        static auto PostCommand(const std::shared_ptr<State> &StateValue,
                                Preview::Resource::ExecutorReclaimer::Action Command) noexcept -> bool
        {
            if (!StateValue->Reclaimer->Post(std::move(Command)))
            {
                MarkBlocked(StateValue);
                return false;
            }
            return true;
        }

        [[nodiscard]] static auto ReserveTaskId(const std::shared_ptr<State> &StateValue,
                                                 Preview::TaskId Requested)
            -> std::optional<Preview::TaskId>
        {
            const auto GlobalTaskId = ReserveGlobalTaskId(Requested);
            if (!GlobalTaskId)
            {
                return {};
            }

            const auto Candidate = GlobalTaskId->Value();
            for (;;)
            {
                auto Current = StateValue->Reservations.load(std::memory_order_acquire);
                if (Current->Used.contains(Candidate))
                {
                    return {};
                }
                auto Next = std::make_shared<IdReservations>(*Current);
                Next->Used.insert(Candidate);
                Next->Next = Candidate == std::numeric_limits<std::uint64_t>::max()
                                 ? 0
                                 : Candidate + 1;
                if (StateValue->Reservations.compare_exchange_weak(
                        Current,
                        std::shared_ptr<const IdReservations>(std::move(Next)),
                        std::memory_order_acq_rel,
                        std::memory_order_acquire))
                {
                    return GlobalTaskId;
                }
            }
        }

        static auto ReleaseGlobalTaskIds(const std::shared_ptr<State> &StateValue) noexcept -> void
        {
            if (!StateValue)
            {
                return;
            }
            const auto Reservations = StateValue->Reservations.load(std::memory_order_acquire);
            for (const auto Value : Reservations->Used)
            {
                for (;;)
                {
                    auto Current = GlobalTaskIds_.load(std::memory_order_acquire);
                    if (!Current->Used.contains(Value))
                    {
                        break;
                    }
                    auto Next = std::make_shared<GlobalIdReservations>(*Current);
                    Next->Used.erase(Value);
                    if (Value == std::numeric_limits<std::uint64_t>::max() && Next->Next == 0)
                    {
                        Next->Next = 1;
                    }
                    if (GlobalTaskIds_.compare_exchange_weak(
                            Current,
                            std::shared_ptr<const GlobalIdReservations>(std::move(Next)),
                            std::memory_order_acq_rel,
                            std::memory_order_acquire))
                    {
                        break;
                    }
                }
            }
        }

        template <typename Coro>
        [[nodiscard]] static auto RunTracked(std::shared_ptr<TaskState> Task,
                                              Coro Operation) -> Net::awaitable<void>
        {
            co_await FailureBoundary::Execute(
                [Task](std::exception_ptr Failure) { (void)Task->Complete(std::move(Failure)); },
                std::move(Operation));
            (void)Task->Complete();
        }

        [[nodiscard]] static auto DrainState(const std::shared_ptr<State> &StateValue)
            -> Net::awaitable<void>
        {
            StateValue->Accepting.store(false, std::memory_order_release);
            StateValue->Barrier.Seal();
            if (StateValue->Blocked.load(std::memory_order_acquire))
            {
                co_return;
            }
            co_await StateValue->Barrier.Drain();
        }

        static auto QuarantineActive(const std::shared_ptr<State> &StateValue) noexcept -> void
        {
            for (const auto &[TaskId, Task] : StateValue->Active)
            {
                (void)TaskId;
                if (Task && Task->Quarantine())
                {
                    StateValue->Quarantined.fetch_add(1, std::memory_order_relaxed);
                    StateValue->Barrier.Leave();
                }
            }
            StateValue->Active.clear();
        }

        static auto FinishTeardown(const std::shared_ptr<State> &StateValue) noexcept -> void
        {
            QuarantineActive(StateValue);
            ReleaseGlobalTaskIds(StateValue);
            StateValue->Reclaimer->Quarantine();
        }

        static auto RequestTaskCancel(const std::shared_ptr<State> &StateValue,
                                      const std::shared_ptr<TaskState> &Task) noexcept -> void
        {
            if (!Task)
            {
                return;
            }
            (void)Task->RequestCancel();
            if (Task->IsCancelDispatchFailed())
            {
                MarkBlocked(StateValue);
            }
        }

        static auto CancelOnExecutor(const std::shared_ptr<State> &StateValue) noexcept -> void
        {
            StateValue->CommandCancelled.store(true, std::memory_order_release);
            (void)StateValue->Domain->Cancel();
            if (StateValue->Domain->IsDispatchBlocked())
            {
                MarkBlocked(StateValue);
            }
            for (const auto &[TaskId, Task] : StateValue->Active)
            {
                (void)TaskId;
                RequestTaskCancel(StateValue, Task);
            }
        }

        static auto CancelState(const std::shared_ptr<State> &StateValue) noexcept -> bool
        {
            if (!StateValue ||
                StateValue->CancelRequested.exchange(true, std::memory_order_acq_rel))
            {
                return false;
            }
            StateValue->Accepting.store(false, std::memory_order_release);
            StateValue->Barrier.Seal();
            StateValue->Domain->RequestCancellation();
            const auto Posted =
                PostCommand(StateValue, [StateValue] { CancelOnExecutor(StateValue); });
            if (!Posted)
            {
                (void)StateValue->Domain->Cancel();
                if (StateValue->Domain->IsDispatchBlocked())
                {
                    MarkBlocked(StateValue);
                }
            }
            return true;
        }

        static auto BeginTeardown(const std::shared_ptr<State> &StateValue) noexcept -> void
        {
            for (const auto &[TaskId, Task] : StateValue->Active)
            {
                (void)TaskId;
                RequestTaskCancel(StateValue, Task);
            }
            if (!PostCommand(StateValue, [StateValue] { FinishTeardown(StateValue); }))
            {
                QuarantineActive(StateValue);
                MarkBlocked(StateValue);
            }
        }

        static auto CompleteTask(const std::shared_ptr<State> &StateValue,
                                 const std::shared_ptr<TaskState> &Task) noexcept -> void
        {
            if (!Task)
            {
                return;
            }
            const auto Identity = Task->Identity();
            const auto It = StateValue->Active.find(Identity.TaskId);
            if (It == StateValue->Active.end())
            {
                return;
            }
            if (It->second.get() != Task.get())
            {
                MarkBlocked(StateValue);
                return;
            }
            StateValue->Active.erase(It);
            StateValue->Completed.fetch_add(1, std::memory_order_relaxed);
            switch (Task->Outcome())
            {
            case TaskOutcome::Cancelled:
                StateValue->Cancelled.fetch_add(1, std::memory_order_relaxed);
                break;
            case TaskOutcome::Failed:
                StateValue->Failed.fetch_add(1, std::memory_order_relaxed);
                if (StateValue->OnFailure)
                {
                    try
                    {
                        StateValue->OnFailure(Identity, Task->Failure());
                    }
                    catch (...)
                    {
                    }
                }
                break;
            case TaskOutcome::Quarantined:
                StateValue->Quarantined.fetch_add(1, std::memory_order_relaxed);
                break;
            case TaskOutcome::Pending:
            case TaskOutcome::Succeeded:
                break;
            }
            StateValue->Barrier.Leave();
        }

    public:
        using FailureHandler = std::function<void(const TaskIdentity &, std::exception_ptr)>;

        explicit TaskRegistry(Net::any_io_executor Executor, FailureHandler OnFailure = {})
            : State_(std::make_shared<State>(std::move(Executor), std::move(OnFailure)))
        {
        }

        /**
         * @brief 创建由当前 registry owner 持有的子 registry。
         * @details 子 registry 拥有独立的 active map、barrier 和 reclaimer，
         *          但其 cancellation domain 挂在父 registry 下；子级 Cancel/
         *          Seal/Drain 只作用于自身，父级 Cancel 可传播取消信号。
         */
        [[nodiscard]] auto CreateChild(FailureHandler OnFailure = {})
            -> std::shared_ptr<TaskRegistry>
        {
            auto Child = std::shared_ptr<TaskRegistry>(
                new TaskRegistry(State_->Executor, std::move(OnFailure), State_->Domain));
            return Child;
        }

        ~TaskRegistry() noexcept
        {
            const auto StateValue = State_;
            (void)CancelState(StateValue);
            StateValue->TearingDown.store(true, std::memory_order_release);
            StateValue->Barrier.Seal();
            if (StateValue->Barrier.Active() == 0)
            {
                ReleaseGlobalTaskIds(StateValue);
                StateValue->Reclaimer->Quarantine();
                return;
            }
            (void)StateValue->Domain->Cancel();
            if (StateValue->Domain->IsDispatchBlocked())
            {
                MarkBlocked(StateValue);
            }
            if (!PostCommand(StateValue, [StateValue] { BeginTeardown(StateValue); }))
            {
                StateValue->Reclaimer->Quarantine();
                ReleaseGlobalTaskIds(StateValue);
            }
        }

        TaskRegistry(const TaskRegistry &) = delete;
        auto operator=(const TaskRegistry &) -> TaskRegistry & = delete;
        TaskRegistry(TaskRegistry &&) = delete;
        auto operator=(TaskRegistry &&) -> TaskRegistry & = delete;

        /**
         * @brief 提交一条受追踪协程请求
         * @param Request 任务身份和取消 hook
         * @param Operation 返回 awaitable<void> 的协程对象
         * @return 已提交的 TaskState；registry 封止、ID 冲突或 executor 投递失败时为空
         * @note Active map 的登记、取消、完成和删除均由同一个 executor command path 执行。
         */
        template <typename Coro>
        [[nodiscard]] auto SpawnTracked(TaskRequest Request, Coro &&Operation)
            -> std::shared_ptr<TaskState>
        {
            const auto StateValue = State_;
            if (!StateValue->Accepting.load(std::memory_order_acquire) ||
                StateValue->Blocked.load(std::memory_order_acquire) ||
                StateValue->Domain->IsCancellationRequested())
            {
                return {};
            }
            const auto TaskId = ReserveTaskId(StateValue, Request.Identity.TaskId);
            if (!TaskId)
            {
                return {};
            }
            Request.Identity.TaskId = *TaskId;

            if (!StateValue->Barrier.Enter())
            {
                return {};
            }

            auto Domain = StateValue->Domain->CreateChild();
            const auto WeakState = std::weak_ptr<State>(StateValue);
            auto Completion = [WeakState](const std::shared_ptr<TaskState> &Task) noexcept
            {
                if (const auto StateValue = WeakState.lock())
                {
                    (void)PostCommand(
                        StateValue,
                        [StateValue, Task] { CompleteTask(StateValue, Task); });
                }
            };

            std::shared_ptr<TaskState> Task;
            try
            {
                Task = std::make_shared<TaskState>(
                    TaskState::Options{
                        Request.Identity,
                        std::move(Domain),
                        StateValue->Reclaimer,
                        std::move(Request.Cancel),
                        Request.StartOnSubmit},
                    std::move(Completion));
            }
            catch (...)
            {
                StateValue->Barrier.Leave();
                throw;
            }

            using OperationType = std::decay_t<Coro>;
            std::shared_ptr<OperationType> OperationValue;
            try
            {
                OperationValue =
                    std::make_shared<OperationType>(std::forward<Coro>(Operation));
            }
            catch (...)
            {
                StateValue->Barrier.Leave();
                throw;
            }
            if (!PostCommand(
                    StateValue,
                    [StateValue, Task, OperationValue]() mutable
                    {
                        if (StateValue->Reclaimer->IsQuarantined() ||
                            StateValue->Blocked.load(std::memory_order_acquire))
                        {
                            RequestTaskCancel(StateValue, Task);
                            (void)Task->Complete();
                            StateValue->Barrier.Leave();
                            return;
                        }
                        try
                        {
                            const auto [It, Inserted] =
                                StateValue->Active.emplace(Task->Identity().TaskId, Task);
                            (void)It;
                            if (!Inserted)
                            {
                                RequestTaskCancel(StateValue, Task);
                                (void)Task->Complete();
                                StateValue->Barrier.Leave();
                                return;
                            }
                        }
                        catch (...)
                        {
                            (void)Task->Complete(std::current_exception());
                            StateValue->Barrier.Leave();
                            return;
                        }
                        if (StateValue->TearingDown.load(std::memory_order_acquire) ||
                            (!Task->StartOnSubmit() &&
                             (StateValue->CommandCancelled.load(std::memory_order_acquire) ||
                              StateValue->CancelRequested.load(std::memory_order_acquire))))
                        {
                            RequestTaskCancel(StateValue, Task);
                            if (!StateValue->TearingDown.load(std::memory_order_acquire))
                            {
                                (void)Task->Complete();
                            }
                            return;
                        }
                        if (!Task->TryStart())
                        {
                            if (!Task->IsCompleted())
                            {
                                (void)Task->Complete();
                            }
                            const auto It =
                                StateValue->Active.find(Task->Identity().TaskId);
                            if (It != StateValue->Active.end() && It->second.get() == Task.get())
                            {
                                StateValue->Active.erase(It);
                                StateValue->Barrier.Leave();
                            }
                            return;
                        }
                        StateValue->Started.fetch_add(1, std::memory_order_relaxed);
                        try
                        {
                            auto CompletionHandler = [Task](std::exception_ptr Failure) noexcept
                            { (void)Task->Complete(std::move(Failure)); };
                            Net::co_spawn(
                                StateValue->Executor,
                                RunTracked(Task, std::move(*OperationValue)),
                                std::move(CompletionHandler));
                        }
                        catch (...)
                        {
                            (void)Task->Complete(std::current_exception());
                        }
                    }))
            {
                StateValue->Barrier.Leave();
                return {};
            }
            return Task;
        }

        /**
         * @brief 请求一次全注册表取消
         * @return 首次请求返回 true；重复调用返回 false
         */
        [[nodiscard]] auto Cancel() noexcept -> bool
        {
            return CancelState(State_);
        }

        /**
         * @brief 封止新任务但不主动取消现有任务
         */
        auto Seal() noexcept -> void
        {
            SealState(State_);
        }

        /**
         * @brief 等待所有已登记任务真实完成或被隔离
         */
        [[nodiscard]] auto Drain() -> Net::awaitable<void>
        {
            return DrainState(State_);
        }

        [[nodiscard]] auto Stats() const noexcept -> TaskStats
        {
            TaskStats Result;
            AddStats(Result, State_);
            return Result;
        }

        [[nodiscard]] auto IsDrainBlocked() const noexcept -> bool
        {
            return Stats().DrainBlocked;
        }

        /**
         * @brief 显式标记 executor 投递失败后的不完整收口
         */
        auto Block() noexcept -> void
        {
            MarkBlocked(State_);
        }

        [[nodiscard]] auto Domain() const noexcept -> const std::shared_ptr<CancellationDomain> &
        {
            return State_->Domain;
        }

        [[nodiscard]] auto Reclaimer() const noexcept
            -> const std::shared_ptr<Preview::Resource::ExecutorReclaimer> &
        {
            return State_->Reclaimer;
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return State_->Executor;
        }

    private:
        TaskRegistry(Net::any_io_executor Executor,
                     FailureHandler OnFailure,
                     std::shared_ptr<CancellationDomain> ParentDomain)
            : State_(std::make_shared<State>(
                  std::move(Executor), std::move(OnFailure), std::move(ParentDomain)))
        {
        }

        std::shared_ptr<State> State_;
    };

} // namespace Preview::Lifecycle

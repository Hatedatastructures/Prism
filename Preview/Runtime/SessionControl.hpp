/**
 * @file SessionControl.hpp
 * @brief 会话级取消、关闭、异常与 tracked 操作排空控制
 * @details SessionControl 的 hooks、关闭回调和 metrics 回调均在绑定 executor
 *          上执行；外部线程只发布原子状态和 executor command。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Lifecycle/TaskRegistry.hpp>

namespace Preview::Runtime
{

    namespace Net = boost::asio;

    struct SessionMetrics final
    {
        std::size_t Started{0};
        std::size_t Completed{0};
        std::size_t Active{0};
        std::size_t CancelRequests{0};
        std::size_t ErrorCalls{0};
        std::size_t CloseCalls{0};
        bool DrainBlocked{false};
        bool CloseDispatchFailed{false};
    };

    class SessionControl final
    {
    private:
        using Registry = Preview::Lifecycle::TaskRegistry;
        using Identity = Preview::Lifecycle::TaskIdentity;
        using Request = Preview::Lifecycle::TaskRequest;
        using ErrorHookType = std::function<void(Preview::Fault::Code, std::exception_ptr)>;
        using IdentityErrorHookType =
            std::function<void(const Identity &, Preview::Fault::Code, std::exception_ptr)>;
        using MetricsHookType = std::function<void(const SessionMetrics &)>;

        struct CancelEntry final
        {
            explicit CancelEntry(std::function<void()> FunctionValue)
                : Function(std::move(FunctionValue))
            {
            }

            std::function<void()> Function;
            std::atomic<bool> Invoked{false};
        };

        struct Binding final
        {
            Binding(Net::any_io_executor ExecutorValue, std::shared_ptr<Registry> RegistryValue)
                : Executor(std::move(ExecutorValue)), RegistryValue(std::move(RegistryValue))
            {
            }

            Net::any_io_executor Executor;
            std::shared_ptr<Registry> RegistryValue;
        };

        struct State final
        {
            std::atomic<std::shared_ptr<Binding>> BindingValue;
            std::atomic<std::uint64_t> CurrentTaskId{0};
            std::atomic<std::uint64_t> CurrentSessionId{0};
            std::atomic<std::uint64_t> CurrentStreamId{0};
            std::atomic<std::uint64_t> CurrentWorkerId{0};
            std::atomic<std::uint64_t> CurrentGeneration{0};
            std::atomic<bool> CancelRequested{false};
            std::atomic<bool> Sealed{false};
            std::atomic<bool> Closed{false};
            std::atomic<bool> Blocked{false};
            std::atomic<bool> CloseDispatchFailed{false};
            std::atomic<std::size_t> CancelRequests{0};
            std::atomic<std::size_t> ErrorCalls{0};
            std::atomic<std::size_t> CloseCalls{0};
            std::vector<std::shared_ptr<CancelEntry>> CancelHooks;
            std::atomic<std::shared_ptr<ErrorHookType>> OnError{std::shared_ptr<ErrorHookType>{}};
            std::atomic<std::shared_ptr<IdentityErrorHookType>> OnIdentityError{
                std::shared_ptr<IdentityErrorHookType>{}};
            std::atomic<std::shared_ptr<MetricsHookType>> OnMetrics{std::shared_ptr<MetricsHookType>{}};
        };

        static auto MarkBlocked(const std::shared_ptr<State> &StateValue) noexcept -> void
        {
            StateValue->Blocked.store(true, std::memory_order_release);
        }

        static auto Post(const std::shared_ptr<State> &StateValue,
                         const std::shared_ptr<Binding> &BindingValue,
                         Preview::Resource::ExecutorReclaimer::Action Command) noexcept -> bool
        {
            if (!BindingValue || !BindingValue->RegistryValue->Reclaimer()->Post(std::move(Command)))
            {
                MarkBlocked(StateValue);
                if (BindingValue)
                {
                    BindingValue->RegistryValue->Block();
                }
                return false;
            }
            return true;
        }

        static auto MakeBinding(const std::shared_ptr<State> &StateValue,
                                Net::any_io_executor Executor,
                                std::shared_ptr<Registry> RegistryValue = {})
        {
            const auto WeakState = std::weak_ptr<State>(StateValue);
            if (!RegistryValue)
            {
                RegistryValue = std::make_shared<Registry>(
                    Executor,
                    [WeakState](const Identity &IdentityValue, std::exception_ptr Failure)
                    {
                        if (const auto StateValue = WeakState.lock())
                        {
                            ReportErrorOnExecutor(
                                StateValue, IdentityValue, Preview::Fault::Code::IoError,
                                std::move(Failure));
                        }
                    });
            }
            return std::make_shared<Binding>(std::move(Executor), std::move(RegistryValue));
        }

        [[nodiscard]] auto BindWithRegistry(
            Net::any_io_executor Executor,
            std::shared_ptr<Registry> RegistryValue) -> bool
        {
            const auto Candidate = MakeBinding(State_, std::move(Executor), std::move(RegistryValue));
            std::shared_ptr<Binding> Expected;
            if (!State_->BindingValue.compare_exchange_strong(
                    Expected, Candidate, std::memory_order_release, std::memory_order_acquire))
            {
                return true;
            }
            if (State_->CancelRequested.load(std::memory_order_acquire))
            {
                (void)Candidate->RegistryValue->Cancel();
                (void)Post(
                    State_, Candidate,
                    [StateValue = State_] { DispatchCancelOnExecutor(StateValue); });
            }
            return true;
        }

        static auto InvokeCancel(const std::shared_ptr<CancelEntry> &Entry) noexcept -> void
        {
            if (!Entry || Entry->Invoked.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            try
            {
                if (Entry->Function)
                {
                    Entry->Function();
                }
            }
            catch (...)
            {
            }
        }

        static auto DispatchCancelOnExecutor(const std::shared_ptr<State> &StateValue) noexcept -> void
        {
            for (const auto &Entry : StateValue->CancelHooks)
            {
                InvokeCancel(Entry);
            }
        }

        static auto EmitMetrics(const std::shared_ptr<State> &StateValue) noexcept -> void
        {
            const auto Hook = StateValue->OnMetrics.load(std::memory_order_acquire);
            if (!Hook || !*Hook)
            {
                return;
            }
            try
            {
                (*Hook)(MakeMetrics(StateValue));
            }
            catch (...)
            {
            }
        }

        static auto ReportErrorOnExecutor(const std::shared_ptr<State> &StateValue,
                                          const Identity &IdentityValue,
                                          Preview::Fault::Code Code,
                                          std::exception_ptr Failure) noexcept -> void
        {
            StateValue->ErrorCalls.fetch_add(1, std::memory_order_relaxed);
            const auto Hook = StateValue->OnError.load(std::memory_order_acquire);
            if (Hook && *Hook)
            {
                try
                {
                    (*Hook)(Code, Failure);
                }
                catch (...)
                {
                }
            }
            const auto IdentityHook = StateValue->OnIdentityError.load(std::memory_order_acquire);
            if (IdentityHook && *IdentityHook)
            {
                try
                {
                    (*IdentityHook)(IdentityValue, Code, std::move(Failure));
                }
                catch (...)
                {
                }
            }
            EmitMetrics(StateValue);
        }

        static auto MakeMetrics(const std::shared_ptr<State> &StateValue) noexcept -> SessionMetrics
        {
            const auto BindingValue = StateValue->BindingValue.load(std::memory_order_acquire);
            const auto Snapshot = BindingValue ? BindingValue->RegistryValue->Stats()
                                               : Preview::Lifecycle::TaskStats{};
            return SessionMetrics{
                Snapshot.Started,
                Snapshot.Completed,
                Snapshot.Active,
                StateValue->CancelRequests.load(std::memory_order_relaxed),
                StateValue->ErrorCalls.load(std::memory_order_relaxed),
                StateValue->CloseCalls.load(std::memory_order_relaxed),
                StateValue->Blocked.load(std::memory_order_acquire) || Snapshot.DrainBlocked,
                StateValue->CloseDispatchFailed.load(std::memory_order_acquire)};
        }

    public:
        using CancelFn = std::function<void()>;
        using CloseFn = std::function<void()>;
        using ErrorHook = ErrorHookType;
        using IdentityErrorHook = IdentityErrorHookType;
        using MetricsHook = MetricsHookType;
        using MetricsSnapshot = SessionMetrics;

        SessionControl() : State_(std::make_shared<State>()) {}

        explicit SessionControl(Net::any_io_executor Executor) : State_(std::make_shared<State>())
        {
            (void)Bind(std::move(Executor));
        }

        SessionControl(const SessionControl &) = delete;
        auto operator=(const SessionControl &) -> SessionControl & = delete;

        /**
         * @brief 绑定会话执行器
         * @return 当前控制器可用时返回 true
         * @note 只能在首次启动操作前绑定；重复绑定保留首次执行器。
         */
        [[nodiscard]] auto Bind(Net::any_io_executor Executor) -> bool
        {
            return BindWithRegistry(std::move(Executor), {});
        }

        /**
         * @brief 将会话绑定到 worker registry 的独立子 scope。
         */
        [[nodiscard]] auto Bind(
            Net::any_io_executor Executor,
            const std::shared_ptr<Registry> &WorkerRegistry) -> bool
        {
            if (!WorkerRegistry)
            {
                return Bind(std::move(Executor));
            }
            const auto WeakState = std::weak_ptr<State>(State_);
            auto Child = WorkerRegistry->CreateChild(
                [WeakState](const Identity &IdentityValue, std::exception_ptr Failure)
                {
                    if (const auto StateValue = WeakState.lock())
                    {
                        ReportErrorOnExecutor(
                            StateValue, IdentityValue, Preview::Fault::Code::IoError,
                            std::move(Failure));
                    }
                });
            return Child && BindWithRegistry(std::move(Executor), std::move(Child));
        }

        /**
         * @brief 绑定到 worker 持有的 registry；引用不转移 owner。
         * @note 调用方必须保证 Worker registry 的生命周期覆盖本控制器。
         */
        [[nodiscard]] auto Bind(
            Net::any_io_executor Executor,
            Registry &WorkerRegistry) -> bool
        {
            auto NonOwning = std::shared_ptr<Registry>(
                &WorkerRegistry, [](Registry *) {});
            return Bind(std::move(Executor), NonOwning);
        }

        auto SetErrorHook(ErrorHook Hook) -> void
        {
            State_->OnError.store(
                Hook ? std::make_shared<ErrorHookType>(std::move(Hook))
                     : std::shared_ptr<ErrorHookType>{},
                std::memory_order_release);
        }

        auto SetErrorHook(IdentityErrorHook Hook) -> void
        {
            State_->OnIdentityError.store(
                Hook ? std::make_shared<IdentityErrorHookType>(std::move(Hook))
                     : std::shared_ptr<IdentityErrorHookType>{},
                std::memory_order_release);
        }

        auto SetMetricsHook(MetricsHook Hook) -> void
        {
            State_->OnMetrics.store(
                Hook ? std::make_shared<MetricsHookType>(std::move(Hook))
                     : std::shared_ptr<MetricsHookType>{},
                std::memory_order_release);
        }

        /**
         * @brief 登记一个取消 hook
         * @return hook 已提交到绑定 executor 返回 true；空 hook、未绑定或投递失败返回 false
         */
        [[nodiscard]] auto AddCancelHook(CancelFn Hook) -> bool
        {
            if (!Hook)
            {
                return false;
            }
            const auto BindingValue = State_->BindingValue.load(std::memory_order_acquire);
            if (!BindingValue)
            {
                return false;
            }
            auto Entry = std::make_shared<CancelEntry>(std::move(Hook));
            return Post(
                State_,
                BindingValue,
                [StateValue = State_, Entry]
                {
                    if (StateValue->CancelRequested.load(std::memory_order_acquire))
                    {
                        InvokeCancel(Entry);
                    }
                    else
                    {
                        StateValue->CancelHooks.push_back(Entry);
                    }
                });
        }

        /**
         * @brief 启动一个受 registry 追踪的操作
         * @return 已接受并登记返回 true；未绑定、已取消或已封止返回 false
         */
        [[nodiscard]] auto Start(Net::awaitable<void> Operation) -> bool
        {
            return Start(Request{}, std::move(Operation));
        }

        /**
         * @brief 兼容旧调用的受追踪操作入口
         * @param Operation 返回 awaitable<void> 的协程对象
         * @param Cancel 任务取消 hook
         * @return 已接受并登记返回 true
         */
        [[nodiscard]] auto Start(Net::awaitable<void> Operation, CancelFn Cancel) -> bool
        {
            Request RequestValue;
            RequestValue.Cancel = std::move(Cancel);
            return Start(std::move(RequestValue), std::move(Operation));
        }

        /**
         * @brief 启动一个携带稳定任务身份的受 registry 追踪操作
         * @param RequestValue 任务身份和取消 hook
         * @param Operation 返回 awaitable<void> 的协程对象
         * @return 已接受并登记返回 true；未绑定、已取消或已封止返回 false
         */
        [[nodiscard]] auto Start(Request RequestValue, Net::awaitable<void> Operation) -> bool
        {
            const auto BindingValue = State_->BindingValue.load(std::memory_order_acquire);
            if (!BindingValue || State_->Sealed.load(std::memory_order_acquire))
            {
                return false;
            }
            RequestValue.StartOnSubmit = true;
            const auto Task = BindingValue->RegistryValue->SpawnTracked(
                std::move(RequestValue), std::move(Operation));
            if (!Task)
            {
                return false;
            }
            const auto IdentityValue = Task->Identity();
            State_->CurrentTaskId.store(IdentityValue.TaskId.Value(), std::memory_order_release);
            State_->CurrentSessionId.store(IdentityValue.SessionId.Value(), std::memory_order_release);
            State_->CurrentStreamId.store(IdentityValue.StreamId.Value(), std::memory_order_release);
            State_->CurrentWorkerId.store(IdentityValue.WorkerId.Value(), std::memory_order_release);
            State_->CurrentGeneration.store(IdentityValue.Generation.Value(), std::memory_order_release);
            (void)Post(State_, BindingValue, [StateValue = State_] { EmitMetrics(StateValue); });
            return true;
        }

        /**
         * @brief 请求一次会话取消；重复调用不重复派发
         */
        auto Cancel() noexcept -> void
        {
            if (State_->CancelRequested.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            State_->CancelRequests.fetch_add(1, std::memory_order_relaxed);
            State_->Sealed.store(true, std::memory_order_release);
            const auto BindingValue = State_->BindingValue.load(std::memory_order_acquire);
            if (!BindingValue)
            {
                MarkBlocked(State_);
                return;
            }
            (void)BindingValue->RegistryValue->Cancel();
            (void)Post(
                State_,
                BindingValue,
                [StateValue = State_] { DispatchCancelOnExecutor(StateValue); });
            (void)Post(State_, BindingValue, [StateValue = State_] { EmitMetrics(StateValue); });
        }

        [[nodiscard]] auto IsCancelled() const noexcept -> bool
        {
            const auto BindingValue = State_->BindingValue.load(std::memory_order_acquire);
            return State_->CancelRequested.load(std::memory_order_acquire) ||
                   (BindingValue &&
                    BindingValue->RegistryValue->Domain()->IsCancellationRequested());
        }

        /**
         * @brief 获取最近一次提交操作的稳定任务身份
         * @return listener 提交的 Session 任务身份；尚未提交时返回空值
         */
        [[nodiscard]] auto CurrentIdentity() const noexcept -> Identity
        {
            return Identity{
                Preview::TaskId{State_->CurrentTaskId.load(std::memory_order_acquire)},
                Preview::SessionId{State_->CurrentSessionId.load(std::memory_order_acquire)},
                Preview::StreamId{State_->CurrentStreamId.load(std::memory_order_acquire)},
                Preview::WorkerId{State_->CurrentWorkerId.load(std::memory_order_acquire)},
                Preview::GenerationId{State_->CurrentGeneration.load(std::memory_order_acquire)}};
        }

        auto SetIdentity(const Identity &IdentityValue) noexcept -> void
        {
            State_->CurrentTaskId.store(IdentityValue.TaskId.Value(), std::memory_order_release);
            State_->CurrentSessionId.store(IdentityValue.SessionId.Value(), std::memory_order_release);
            State_->CurrentStreamId.store(IdentityValue.StreamId.Value(), std::memory_order_release);
            State_->CurrentWorkerId.store(IdentityValue.WorkerId.Value(), std::memory_order_release);
            State_->CurrentGeneration.store(IdentityValue.Generation.Value(), std::memory_order_release);
        }

        /**
         * @brief 执行一次关闭回调
         * @return 首次取得关闭权且回调成功投递返回 true；重复调用或投递失败返回 false
         */
        [[nodiscard]] auto CloseOnce(CloseFn Close) -> bool
        {
            if (State_->Closed.exchange(true, std::memory_order_acq_rel))
            {
                return false;
            }
            State_->Sealed.store(true, std::memory_order_release);
            const auto BindingValue = State_->BindingValue.load(std::memory_order_acquire);
            if (BindingValue)
            {
                BindingValue->RegistryValue->Seal();
                State_->CloseCalls.fetch_add(1, std::memory_order_relaxed);
                const auto Delivered = Post(
                    State_,
                    BindingValue,
                    [StateValue = State_, Close = std::move(Close)]() mutable
                    {
                        try
                        {
                            if (Close)
                            {
                                Close();
                            }
                        }
                        catch (...)
                        {
                        }
                        EmitMetrics(StateValue);
                    });
                if (!Delivered)
                {
                    State_->CloseDispatchFailed.store(true, std::memory_order_release);
                }
                return Delivered;
            }
            State_->CloseDispatchFailed.store(true, std::memory_order_release);
            MarkBlocked(State_);
            return false;
        }

        /**
         * @brief 封止新操作并等待所有已登记操作真实结束
         */
        [[nodiscard]] auto Drain() -> Net::awaitable<void>
        {
            const auto BindingValue = State_->BindingValue.load(std::memory_order_acquire);
            if (!BindingValue)
            {
                co_return;
            }
            co_await BindingValue->RegistryValue->Drain();
        }

        auto ReportError(Preview::Fault::Code Code, std::exception_ptr Failure = {}) -> void
        {
            ReportError(CurrentIdentity(), Code, std::move(Failure));
        }

        auto ReportError(const Identity &IdentityValue,
                         Preview::Fault::Code Code,
                         std::exception_ptr Failure = {}) -> void
        {
            const auto BindingValue = State_->BindingValue.load(std::memory_order_acquire);
            if (!BindingValue)
            {
                State_->ErrorCalls.fetch_add(1, std::memory_order_relaxed);
                MarkBlocked(State_);
                return;
            }
            (void)Post(
                State_,
                BindingValue,
                [StateValue = State_, IdentityValue, Code, Failure = std::move(Failure)]() mutable
                {
                    ReportErrorOnExecutor(
                        StateValue, IdentityValue, Code, std::move(Failure));
                });
        }

        [[nodiscard]] auto Metrics() const noexcept -> SessionMetrics
        {
            return MakeMetrics(State_);
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool
        {
            return State_->Closed.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto IsDrainBlocked() const noexcept -> bool
        {
            const auto BindingValue = State_->BindingValue.load(std::memory_order_acquire);
            return State_->Blocked.load(std::memory_order_acquire) ||
                   (BindingValue && BindingValue->RegistryValue->IsDrainBlocked());
        }

        [[nodiscard]] auto IsCloseDispatchFailed() const noexcept -> bool
        {
            return State_->CloseDispatchFailed.load(std::memory_order_acquire);
        }

    private:
        std::shared_ptr<State> State_;
    };

} // namespace Preview::Runtime

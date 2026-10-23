/**
 * @file Listener.cpp
 * @brief TCP listener 接受、准入与关闭状态机。
 */
#include <Prism/Runtime/Listener.hpp>

#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Executor/PreparedAction.hpp>
#include <Prism/Foundation/Identifier/SessionIdAllocator.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>
#include <Prism/Runtime/ListenerAdmissionOwner.hpp>
#include <Prism/Runtime/Detail/ListenerCompletion.hpp>
#include <Prism/Runtime/ListenerConnectionDrain.hpp>
#include <Prism/Runtime/ListenerConnectionGate.hpp>
#include <Prism/Runtime/Detail/ListenerTrace.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Runtime/SessionRegistry.hpp>
#include <Prism/Runtime/SessionTraceRing.hpp>
#include <Prism/Runtime/WorkerDispatchResult.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace Prism::Runtime
{
    namespace Detail
    {
        auto ListenerCompletion::Reset() noexcept -> void
        {
            Completed.store(false, std::memory_order_release);
        }

        auto ListenerCompletion::Complete() noexcept -> void
        {
            if (Completed.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            (void)Signal.try_send(boost::system::error_code{});
        }

        auto ListenerCompletion::IsComplete() const noexcept -> bool
        {
            return Completed.load(std::memory_order_acquire);
        }

        auto ListenerCompletion::Wait() -> Net::awaitable<void>
        {
            if (IsComplete())
            {
                co_return;
            }
            boost::system::error_code Error;
            co_await Signal.async_receive(Net::redirect_error(Net::use_awaitable, Error));
        }

        /**
         * @brief 判定 accept 错误是否属于本地资源耗尽。
         * @details 这一类必须退避后重试，否则 fd 短缺期间会形成忙等自旋。
         */
        [[nodiscard]] auto IsAcceptResourceExhaustion(const boost::system::error_code Error) noexcept
            -> bool
        {
            using boost::system::errc::make_error_code;
            using boost::system::errc::no_buffer_space;
            using boost::system::errc::too_many_files_open;
            using boost::system::errc::too_many_files_open_in_system;

            return Error == make_error_code(too_many_files_open) ||
                Error == make_error_code(too_many_files_open_in_system) ||
                Error == make_error_code(no_buffer_space);
        }

        /**
         * @brief 判定 accept 错误能否在不关闭监听 socket 的前提下重试。
         * @details 对端在建连阶段放弃（RST/中断）与本地资源瞬时耗尽都只影响本次
         *          accept；监听 socket 本身仍然可用，关闭它会让服务永久停服。
         */
        [[nodiscard]] auto IsRecoverableAcceptError(const boost::system::error_code Error) noexcept
            -> bool
        {
            if (Error == Net::error::connection_aborted || Error == Net::error::interrupted)
            {
                return true;
            }
            return IsAcceptResourceExhaustion(Error);
        }

        /** @brief 资源耗尽后的指数退避，封顶 1 秒，避免长期占满一个 worker 线程。 */
        [[nodiscard]] auto AcceptBackoffDelay(const std::size_t ConsecutiveFailures) noexcept
            -> std::chrono::milliseconds
        {
            constexpr std::size_t MaxExponentialFailures = 8U;
            if (ConsecutiveFailures > MaxExponentialFailures)
            {
                return std::chrono::seconds(1);
            }
            return std::chrono::milliseconds(2) *
                (std::size_t{1} << ConsecutiveFailures);
        }

        struct ListenerSessionRunRequest final
        {
            std::shared_ptr<Session> SessionOwner;
            Prism::SharedTransmission Transport;
            std::shared_ptr<ListenerConnectionDrain> Drain;
        };

        /** @brief 投递 Session 终态错误并确认 error hook 已完成交付。 */
        [[nodiscard]] auto ReportListenerFailure(
            const std::shared_ptr<SessionControl> &Control,
            const Prism::Fault::Failure Failure)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            try
            {
                co_await Net::this_coro::throw_if_cancelled(false);
                co_await Net::this_coro::reset_cancellation_state(
                    Net::disable_cancellation());
                Control->ReportError(Control->CurrentIdentity(), Failure);
                co_return co_await Control->AwaitDelivery();
            }
            catch (...)
            {
                co_return std::unexpected(
                    Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception()));
            }
        }

        /** @brief 等待 Session 与 control delivery 真实终态后退休统计键。 */
        [[nodiscard]] auto RunListenerSession(ListenerSessionRunRequest Input)
            -> Net::awaitable<Prism::Fault::Failure>
        {
            const auto Control = Input.SessionOwner->Control();
            Prism::Fault::Failure ExceptionFailure;
            bool CaughtException = false;
            try
            {
                co_await Net::this_coro::throw_if_cancelled(false);
                if (Input.Drain)
                {
                    Input.Drain->RetainSession(Input.SessionOwner);
                    Input.Drain->MarkSessionStarted();
                }
                const auto Result = co_await Input.SessionOwner->Run(Input.Transport);
                std::expected<void, Prism::Fault::Failure> Delivered;
                if (Result.Failed())
                {
                    Delivered = co_await ReportListenerFailure(Control, Result);
                }
                else
                {
                    co_await Net::this_coro::reset_cancellation_state(
                        Net::disable_cancellation());
                    Delivered = co_await Control->AwaitDelivery();
                }
                if (!Delivered)
                {
                    if (Input.Drain) Input.Drain->MarkSessionTerminalFailure(Delivered.error());
                    co_return Delivered.error();
                }
                if (!Input.SessionOwner->IsDrained())
                {
                    auto Failure = Result;
                    if (!Failure.Failed())
                    {
                        Failure = Prism::Fault::Failure{Prism::Fault::Code::Blocked};
                        const auto FailureDelivery = co_await ReportListenerFailure(
                            Control, Failure);
                        if (!FailureDelivery) Failure = FailureDelivery.error();
                    }
                    if (Input.Drain) Input.Drain->MarkSessionTerminalFailure(Failure);
                    co_return Failure;
                }
                if (Input.Drain) Input.Drain->MarkSessionDrained();
                const auto Identity = Control->CurrentIdentity();
                const auto Services = Input.SessionOwner->Services();
                Input.SessionOwner.reset();
                if (Services && Services->Traffic && Identity.SessionId.Value() != 0U)
                {
                    const auto TrafficRetirement = co_await Prism::Foundation::RetireTraffic(
                        Services->Traffic, Prism::Foundation::TrafficRetirement{
                            Prism::Foundation::SessionTrafficOwner{Identity.WorkerId, Identity.SessionId}});
                    if (!TrafficRetirement)
                    {
                        const auto FailureDelivery = co_await ReportListenerFailure(
                            Control, TrafficRetirement.error());
                        if (!FailureDelivery) co_return FailureDelivery.error();
                        if (Result.Failed()) co_return Result;
                        co_return TrafficRetirement.error();
                    }
                }
                co_return Result;
            }
            catch (const std::system_error& Error)
            {
                ExceptionFailure = Prism::Fault::FromNative(Error.code());
                CaughtException = true;
            }
            catch (...)
            {
                ExceptionFailure = Prism::Fault::Failure{Prism::Fault::Code::IoError};
                CaughtException = true;
            }
            if (!CaughtException)
                co_return Prism::Fault::Failure{Prism::Fault::Code::Blocked};
            if (Input.Drain) Input.Drain->MarkSessionTerminalFailure(ExceptionFailure);
            std::expected<void, Prism::Fault::Failure> FailureDelivery;
            try
            {
                FailureDelivery = co_await ReportListenerFailure(
                    Control, ExceptionFailure);
            }
            catch (...)
            {
                FailureDelivery = std::unexpected(
                    Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception()));
            }
            if (!FailureDelivery)
            {
                if (Input.Drain)
                    Input.Drain->MarkSessionTerminalFailure(FailureDelivery.error());
                co_return FailureDelivery.error();
            }
            co_return ExceptionFailure;
        }
    }

    struct TcpListener::Lifetime final
    {
        explicit Lifetime(TcpListener::Options OptionsValue)
            : Ex(std::move(OptionsValue.Executor)), Factory(std::move(OptionsValue.Factory)),
              OnFailure(std::move(OptionsValue.OnFailure)), Workers(OptionsValue.Workers),
              StandaloneTasks(Workers ? std::shared_ptr<Prism::Lifecycle::TaskRegistry>{}
                                      : std::make_shared<Prism::Lifecycle::TaskRegistry>(Ex)),
              Publication(std::move(OptionsValue.Publication)),
              Balancer(Workers ? Workers->Size() : 1),
              MaxConnections(OptionsValue.MaxConnections),
              ConnectionQuota(std::make_shared<Detail::ListenerConnectionGate::Quota>(
                  OptionsValue.MaxConnections, Ex)),
              Acceptor(Ex),
              AcceptCompletion(std::make_shared<Detail::ListenerCompletion>(Ex))
        {
        }

        Net::any_io_executor Ex;
        TcpListener::SessionFactory Factory;
        TcpListener::FailureHandler OnFailure;
        WorkerGroup* Workers{nullptr};
        /** @brief 无 Worker 的独立 listener root scope；拥有会话 runner 与其有界 task slot。 */
        std::shared_ptr<Prism::Lifecycle::TaskRegistry> StandaloneTasks;
        std::shared_ptr<GenerationPublication> Publication;
        AffinityBalancer Balancer;
        SessionRegistry Registry;
        std::size_t MaxConnections{0};
        std::shared_ptr<Detail::ListenerConnectionGate::Quota> ConnectionQuota;
        Net::ip::tcp::acceptor Acceptor;
        std::shared_ptr<Detail::ListenerCompletion> AcceptCompletion;
        std::atomic<bool> Started{false};
        std::atomic<bool> AcceptLoopStarted{false};
        std::atomic<bool> Ready{false};
        std::atomic<bool> Failed{false};
        std::atomic<bool> Stopped{false}; ///< Stop/析构后禁止新会话进入工厂
    };

    struct TcpListener::AdmissionRequest final
    {
        /** @brief admission 的 owning 输入；factory 与 State 覆盖请求执行期。 */
        struct Options final
        {
            Prism::SharedTransmission Transport;
            std::shared_ptr<Detail::ListenerConnectionGate::Reservation> ConnectionSlot;
            std::shared_ptr<Detail::ListenerConnectionDrain> RejectionDrain;
            TcpListener::SessionFactory Factory;
            std::shared_ptr<TcpListener::Lifetime> State;
            SessionInfo Info;
            Prism::WorkerId Worker{};
            Prism::Foundation::GenerationPin GenerationPin;
            Detail::ListenerSessionTraceTiming TraceTiming{};
        };

        explicit AdmissionRequest(Options Input);
        ~AdmissionRequest() noexcept;
        AdmissionRequest(const AdmissionRequest&) = delete;
        auto operator=(const AdmissionRequest&) -> AdmissionRequest& = delete;
        auto Reject() noexcept -> void;
        auto RejectUntransferred() noexcept -> void;
        auto RejectTransferred(Prism::SharedTransmission RejectedTransport) noexcept -> void;
        [[nodiscard]] auto TakeTransport() noexcept -> Prism::SharedTransmission;
        auto RejectOwnedTransport() noexcept -> void;
        [[nodiscard]] auto Generation() const noexcept -> Prism::GenerationId;
        [[nodiscard]] static auto Make(Options Input) noexcept
            -> std::shared_ptr<AdmissionRequest>;

        Prism::SharedTransmission Transport;
        std::shared_ptr<Detail::ListenerConnectionGate::Reservation> ConnectionSlot;
        std::shared_ptr<Detail::ListenerConnectionDrain> RejectionDrain;
        std::atomic<bool> Pending{true};
        TcpListener::SessionFactory Factory;
        std::shared_ptr<TcpListener::Lifetime> State;
        SessionInfo Info;
        Prism::WorkerId Worker{};
        Prism::Foundation::GenerationPin GenerationPin;
        Detail::ListenerSessionTraceTiming TraceTiming{};
    };

    struct TcpListener::AcceptCompletionToken final
    {
        explicit AcceptCompletionToken(std::shared_ptr<TcpListener::Lifetime> Value) noexcept;
        AcceptCompletionToken(AcceptCompletionToken&& Other) noexcept;
        ~AcceptCompletionToken() noexcept;
        auto operator()(std::exception_ptr Error) noexcept -> void;

        std::shared_ptr<TcpListener::Lifetime> State;
        bool Invoked{false};
        bool Failed{false};
    };

    AffinityBalancer::AffinityBalancer(const std::size_t WorkerCount)
        : WorkerCount_(WorkerCount < 1 ? 1 : WorkerCount)
    {
    }

    auto AffinityBalancer::Select(const std::string_view Key) const noexcept -> std::size_t
    {
        std::uint64_t Hash = 14695981039346656037ULL;
        for (const char Character : Key)
        {
            Hash ^= static_cast<unsigned char>(Character);
            Hash *= 1099511628211ULL;
        }
        return static_cast<std::size_t>(Hash % WorkerCount_);
    }

    auto AffinityBalancer::WorkerCount() const noexcept -> std::size_t
    {
        return WorkerCount_;
    }

    TcpListener::AdmissionRequest::AdmissionRequest(Options Input)
        : Transport(std::move(Input.Transport)),
          ConnectionSlot(std::move(Input.ConnectionSlot)),
          RejectionDrain(std::move(Input.RejectionDrain)),
          Factory(std::move(Input.Factory)),
          State(std::move(Input.State)),
          Info(std::move(Input.Info)),
          Worker(Input.Worker),
          GenerationPin(std::move(Input.GenerationPin)),
          TraceTiming(Input.TraceTiming)
    {
    }

    TcpListener::AdmissionRequest::~AdmissionRequest() noexcept
    {
        Reject();
    }

    auto TcpListener::AdmissionRequest::Reject() noexcept -> void
    {
        if (Pending.exchange(false, std::memory_order_acq_rel)) RejectUntransferred();
    }

    auto TcpListener::AdmissionRequest::RejectUntransferred() noexcept -> void
    {
        RejectOwnedTransport();
    }

    auto TcpListener::AdmissionRequest::RejectTransferred(
        Prism::SharedTransmission RejectedTransport) noexcept -> void
    {
        Transport = std::move(RejectedTransport);
        RejectOwnedTransport();
    }

    auto TcpListener::AdmissionRequest::TakeTransport() noexcept -> Prism::SharedTransmission
    {
        Pending.store(false, std::memory_order_release);
        return std::move(Transport);
    }

    auto TcpListener::AdmissionRequest::RejectOwnedTransport() noexcept -> void
    {
        if (RejectionDrain)
        {
            if (ConnectionSlot) ConnectionSlot->ReleaseTransport();
            RejectionDrain->Start();
            Transport.reset();
            return;
        }
        if (ConnectionSlot)
        {
            ConnectionSlot->AdoptTransport(std::move(Transport));
            ConnectionSlot->RequestRetirement();
        }
    }

    auto TcpListener::AdmissionRequest::Generation() const noexcept -> Prism::GenerationId
    {
        return GenerationPin ? GenerationPin->Id() : Prism::GenerationId{};
    }

    auto TcpListener::AdmissionRequest::Make(Options Input) noexcept
        -> std::shared_ptr<AdmissionRequest>
    {
        const auto StableSlot = Input.ConnectionSlot;
        const auto StableDrain = Input.RejectionDrain;
        try
        {
            return std::make_shared<AdmissionRequest>(std::move(Input));
        }
        catch (...)
        {
            if (StableDrain)
            {
                if (StableSlot) StableSlot->ReleaseTransport();
                StableDrain->Start();
            }
            else if (StableSlot)
            {
                StableSlot->RequestRetirement();
            }
            return {};
        }
    }

    auto TcpListener::NotifyFailure(const std::shared_ptr<TcpListener::Lifetime>& State,
        const Prism::Fault::Code Code) noexcept -> void
    {
        if (!State->OnFailure) return;
        try
        {
            State->OnFailure(Code);
        }
        catch (...)
        {
        }
    }

    TcpListener::AcceptCompletionToken::AcceptCompletionToken(
        std::shared_ptr<TcpListener::Lifetime> Value) noexcept : State(std::move(Value))
    {
    }

    TcpListener::AcceptCompletionToken::AcceptCompletionToken(
        AcceptCompletionToken&& Other) noexcept
        : State(std::move(Other.State)), Invoked(Other.Invoked), Failed(Other.Failed)
    {
        Other.Invoked = true;
    }

    TcpListener::AcceptCompletionToken::~AcceptCompletionToken() noexcept
    {
        if (!State) return;
        if (!Invoked || Failed)
        {
            State->Ready.store(false);
            State->Failed.store(true);
            State->AcceptLoopStarted.store(false);
            TcpListener::NotifyFailure(State, Prism::Fault::Code::IoError);
        }
        State->AcceptCompletion->Complete();
    }

    auto TcpListener::AcceptCompletionToken::operator()(std::exception_ptr Error) noexcept -> void
    {
        Invoked = true;
        Failed = static_cast<bool>(Error);
    }

    TcpListener::TcpListener(Options OptionsValue)
        : State_(std::make_shared<Lifetime>(std::move(OptionsValue)))
    {
    }

    TcpListener::~TcpListener() noexcept
    {
        const auto State = State_;
        StopOwned(State);
        State->Registry.RequestShutdown();
    }

    auto TcpListener::Start(const Net::ip::tcp::endpoint& BindEp)
        -> Net::awaitable<Prism::Fault::Code>
    {
        // 普通包装函数先按值捕获 Lifetime；不能依赖 awaitable 的延迟首帧读取 this。
        return StartOwned(State_, BindEp);
    }

    auto TcpListener::StartOwned(std::shared_ptr<TcpListener::Lifetime> State,
        Net::ip::tcp::endpoint BindEp) -> Net::awaitable<Prism::Fault::Code>
    {
        if (!State) co_return Prism::Fault::Code::InvalidArgument;
        if (State->Stopped.load(std::memory_order_acquire) ||
            State->Started.exchange(true, std::memory_order_acq_rel))
            co_return Prism::Fault::Code::InvalidArgument;
        boost::system::error_code Error;
        State->Acceptor.open(BindEp.protocol(), Error);
        if (!Error) State->Acceptor.set_option(Net::ip::tcp::acceptor::reuse_address(true), Error);
        if (!Error) State->Acceptor.bind(BindEp, Error);
        if (!Error) State->Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        if (Error)
        {
            boost::system::error_code CloseError;
            State->Acceptor.close(CloseError);
            State->Failed.store(true, std::memory_order_release);
            co_return Prism::Fault::Code::IoError;
        }
        State->AcceptCompletion->Reset();
        State->AcceptLoopStarted.store(true, std::memory_order_release);
        try
        {
            Net::co_spawn(State->Ex, AcceptLoop(State), AcceptCompletionToken(State));
        }
        catch (...)
        {
            State->AcceptLoopStarted.store(false, std::memory_order_release);
            State->Failed.store(true, std::memory_order_release);
            boost::system::error_code CloseError;
            State->Acceptor.close(CloseError);
            co_return Prism::Fault::Code::IoError;
        }
        if (!State->Failed.load(std::memory_order_acquire))
            State->Ready.store(true, std::memory_order_release);
        co_return Prism::Fault::Code::Success;
    }

    auto TcpListener::Stop() noexcept -> void
    {
        StopOwned(State_);
    }

    auto TcpListener::StopOwned(const std::shared_ptr<TcpListener::Lifetime>& State) noexcept -> void
    {
        if (!State) return;
        State->Ready.store(false, std::memory_order_release);
        if (State->Stopped.exchange(true, std::memory_order_acq_rel)) return;
        boost::system::error_code Error;
        State->Acceptor.cancel(Error);
        State->Acceptor.close(Error);
    }

    auto TcpListener::IsReady() const noexcept -> bool
    {
        return State_->Ready.load(std::memory_order_acquire) &&
            !State_->Stopped.load(std::memory_order_acquire) &&
            !State_->Failed.load(std::memory_order_acquire);
    }

    auto TcpListener::IsFailed() const noexcept -> bool
    {
        return State_->Failed.load(std::memory_order_acquire);
    }

    auto TcpListener::Registry() noexcept -> SessionRegistry&
    {
        return State_->Registry;
    }

    auto TcpListener::Shutdown()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        // 调用即接管 Lifetime，使未立即 await 的 Shutdown 不受 Listener 析构影响。
        return ShutdownOwned(State_);
    }

    auto TcpListener::ShutdownOwned(std::shared_ptr<TcpListener::Lifetime> State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        if (!State)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        StopOwned(State);
        if (State->AcceptLoopStarted.load(std::memory_order_acquire))
            co_await State->AcceptCompletion->Wait();
        State->ConnectionQuota->Drain.Seal();
        const auto Sessions = co_await State->Registry.Shutdown();
        const auto Connections = co_await State->ConnectionQuota->Drain.Drain();
        std::expected<void, Prism::Fault::Failure> Standalone;
        if (State->StandaloneTasks)
        {
            State->StandaloneTasks->Seal();
            Standalone = co_await State->StandaloneTasks->Drain();
        }
        if (!Sessions) co_return Sessions;
        if (!Connections) co_return Connections;
        co_return Standalone;
    }

    auto TcpListener::LocalEndpoint() const -> Net::ip::tcp::endpoint
    {
        return State_->Acceptor.local_endpoint();
    }

    auto TcpListener::MaxConnections() const noexcept -> std::size_t
    {
        return State_->MaxConnections;
    }

    auto TcpListener::RejectAdmission(const std::shared_ptr<AdmissionRequest>& Request,
        const std::shared_ptr<Session>& SessionOwner) noexcept -> void
    {
        if (SessionOwner) SessionOwner->SetDeferredCleanup({});
        if (Request) Request->RejectTransferred({});
    }

    auto TcpListener::StartSession(const std::shared_ptr<AdmissionRequest>& Request) -> void
    {
        if (!Request || !Request->State) return;
        Worker* WorkerValue = Request->State->Workers
            ? Request->State->Workers->Find(Request->Worker) : nullptr;
        auto Trace = Detail::MakeListenerSessionTraceWriter(*Request, WorkerValue);
        if (Trace) Trace->Record(SessionTraceStage::SessionAdmissionStarted);
        if (Request->State->Workers && (!WorkerValue || !WorkerValue->IsAccepting())) return;
        if (!Request->GenerationPin || Request->GenerationPin->Id() != Request->Info.Generation)
        {
            RejectAdmission(Request, {});
            NotifyFailure(Request->State, Prism::Fault::Code::Blocked);
            return;
        }
        const auto SessionId = Request->Info.Id;
        auto Transport = Request->TakeTransport();
        auto Drain = Request->RejectionDrain;
        std::shared_ptr<Session> SessionOwner;
        try
        {
            auto SessionValue = Request->Factory
                ? Request->Factory(SessionAdmission{Transport, Request->Worker,
                    Request->Info.peer == "unknown" ? "Unknown" : Request->Info.peer,
                    Request->GenerationPin})
                : SessionAdmissionResult{};
            if (!SessionValue)
            {
                RejectAdmission(Request, {});
                NotifyFailure(Request->State, SessionValue.error().Code);
                return;
            }
            SessionOwner = std::move(*SessionValue);
            if (!SessionOwner)
            {
                RejectAdmission(Request, {});
                NotifyFailure(Request->State, Prism::Fault::Code::Blocked);
                return;
            }
            SessionOwner->SetTraceWriter(Trace);
            auto InitialState = std::make_shared<Detail::SessionAdmissionState>();
            auto Control = SessionOwner->Control();
            if (!Control)
            {
                RejectAdmission(Request, SessionOwner);
                return;
            }
            auto StandaloneRoot = Request->State->Workers
                ? std::shared_ptr<Prism::Lifecycle::TaskRegistry>{}
                : Request->State->StandaloneTasks;
            auto* SessionRoot = WorkerValue ? &WorkerValue->TaskRegistry() : StandaloneRoot.get();
            const auto Bound = WorkerValue
                ? Control->Bind(WorkerValue->Executor(), *SessionRoot)
                : SessionRoot && Control->Bind(Request->State->Ex, *SessionRoot);
            if (!Bound)
            {
                RejectAdmission(Request, SessionOwner);
                return;
            }
            auto Registration = Request->State->Registry.Register(std::move(Request->Info), Control);
            if (!Registration)
            {
                RejectAdmission(Request, SessionOwner);
                return;
            }
            SessionOwner->SetRegistration(std::move(Registration));
            Prism::Lifecycle::TaskRequest TaskRequest;
            TaskRequest.Context.SessionId = Prism::SessionId{SessionId};
            TaskRequest.Context.WorkerId = Request->Worker;
            TaskRequest.Context.Generation = Request->Generation();
            auto CloseAction = std::make_shared<Prism::Executor::PreparedAction>(
                std::make_shared<Prism::Executor::ExecutorReclaimer>(Transport->Executor()),
                [Transport]() -> std::expected<void, Prism::Fault::Failure>
                {
                    const auto Canceled = Transport->Cancel();
                    const auto Closed = Transport->Close();
                    if (!Canceled) return Canceled;
                    if (!Closed) return Closed;
                    return {};
                });
            if (!Drain)
            {
                RejectAdmission(Request, SessionOwner);
                return;
            }
            Drain->ConfigureSession(CloseAction, InitialState);
            SessionOwner->SetDeferredCleanup(Drain);
            if (Request->ConnectionSlot) Request->ConnectionSlot->ReleaseTransport();
            TaskRequest.Cancel = [Drain, Owner = SessionOwner] { (void)Owner; Drain->Start(); };
            const auto Started = Control->StartSession(*SessionRoot, std::move(TaskRequest),
                Detail::RunListenerSession(
                    Detail::ListenerSessionRunRequest{SessionOwner, Transport, Drain}));
            if (!Started) RejectAdmission(Request, SessionOwner);
        }
        catch (...)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
            RejectAdmission(Request, SessionOwner);
            NotifyFailure(Request->State, Failure.Code);
        }
    }

    auto TcpListener::AcceptLoop(std::shared_ptr<TcpListener::Lifetime> State) -> Net::awaitable<void>
    {
        Detail::ListenerCompletionGuard Guard(State->AcceptCompletion);
        std::size_t ConsecutiveFailures = 0;
        while (true)
        {
            boost::system::error_code Error;
            auto Socket = co_await State->Acceptor.async_accept(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                if (State->Stopped.load(std::memory_order_acquire))
                {
                    co_return;
                }
                if (Detail::IsRecoverableAcceptError(Error))
                {
                    ++ConsecutiveFailures;
                    if (Detail::IsAcceptResourceExhaustion(Error))
                    {
                        NotifyFailure(State, Prism::Fault::Code::ResourceUnavailable);
                        auto Backoff = Net::steady_timer(State->Ex, Detail::AcceptBackoffDelay(
                            ConsecutiveFailures));
                        boost::system::error_code TimerError;
                        co_await Backoff.async_wait(
                            Net::redirect_error(Net::use_awaitable, TimerError));
                    }
                    if (State->Stopped.load(std::memory_order_acquire))
                    {
                        co_return;
                    }
                    continue;
                }
                if (!State->Failed.exchange(true, std::memory_order_acq_rel))
                {
                    State->Ready.store(false, std::memory_order_release);
                    NotifyFailure(State, Prism::Fault::Code::IoError);
                }
                co_return;
            }
            ConsecutiveFailures = 0;
            const auto AcceptedMonotonic = std::chrono::steady_clock::now();
            const auto AcceptedWall = std::chrono::system_clock::now();
            if (State->Stopped.load(std::memory_order_acquire))
            {
                boost::system::error_code CloseError;
                Socket.close(CloseError);
                co_return;
            }
            auto Prepared = Detail::ListenerAdmissionOwner::Prepare(std::move(Socket),
                {State->Ex, State->ConnectionQuota, State->Balancer,
                    State->Workers, State->Publication, State->OnFailure});
            if (!Prepared) continue;
            auto [Transport, ConnectionSlot, RejectionDrain, Peer, WorkerValue, GenerationPin] =
                std::move(*Prepared);
            if (!State->Factory || State->Stopped.load(std::memory_order_acquire))
            {
                ConnectionSlot->ReleaseTransport();
                RejectionDrain->Start();
                if (State->Stopped.load(std::memory_order_acquire)) co_return;
                continue;
            }
            SessionInfo Info;
            const auto SessionId = Prism::Foundation::Identifier::ReserveSessionId();
            if (!SessionId)
            {
                ConnectionSlot->ReleaseTransport();
                RejectionDrain->Start();
                NotifyFailure(State, Prism::Fault::Code::ResourceUnavailable);
                continue;
            }
            Info.Id = SessionId.Value();
            Info.peer = Peer;
            Info.Worker = WorkerValue;
            Info.Generation = GenerationPin->Id();
            Info.StartedAt = static_cast<std::uint64_t>(AcceptedMonotonic.time_since_epoch().count());
            const auto StartedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
                AcceptedWall.time_since_epoch()).count();
            Info.StartedAtUnixMilliseconds = StartedAt > 0 ? static_cast<std::uint64_t>(StartedAt) : 0U;
            auto Request = AdmissionRequest::Make(AdmissionRequest::Options{
                std::move(Transport), std::move(ConnectionSlot), std::move(RejectionDrain),
                State->Factory, State, std::move(Info), WorkerValue, std::move(GenerationPin),
                Detail::ListenerSessionTraceTiming{AcceptedWall, AcceptedMonotonic}});
            if (!Request) continue;
            auto Result = WorkerDispatchResult::Accepted;
            if (State->Workers)
            {
                Request->TraceTiming.DispatchMonotonic = std::chrono::steady_clock::now();
                Request->TraceTiming.DispatchWall = std::chrono::system_clock::now();
                Result = State->Workers->Dispatch(WorkerValue, Request->Generation(),
                    [Request] { StartSession(Request); });
            }
            if (Result != WorkerDispatchResult::Accepted)
            {
                Request->Reject();
                if (State->Stopped.load(std::memory_order_acquire)) co_return;
            }
            else if (!State->Workers)
            {
                StartSession(Request);
            }
        }
    }
}

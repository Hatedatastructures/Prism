/**
 * @file Listener.hpp
 * @brief TCP 监听、亲和性分发和会话 admission owner。
 * @details accept loop 只发布 worker command；Stop/析构关闭 acceptor，
 *          session 由 SessionControl 取消、delivery 和最终 close 收口。
 */
#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <exception>
#include <system_error>
#include <functional>
#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>
#include <Prism/Runtime/SessionAdmission.hpp>
#include <Prism/Runtime/AffinityBalancer.hpp>
#include <Prism/Runtime/ListenerConnectionGate.hpp>
#include <Prism/Runtime/ListenerConnectionDrain.hpp>
#include <Prism/Runtime/ListenerCompletion.hpp>
#include <Prism/Runtime/ListenerAdmissionOwner.hpp>
#include <Prism/Runtime/ListenerTrace.hpp>
#include <Prism/Runtime/ListenerSessionRunner.hpp>
#include <Prism/Foundation/Identifier/SessionIdAllocator.hpp>
#include <Prism/Lifecycle/TaskRegistry.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Runtime/SessionRegistry.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>
#include <Prism/Runtime/WorkerDispatchResult.hpp>
#include <Prism/Runtime/SessionTraceRing.hpp>
#include <Prism/Transport/Transmission.hpp>
namespace Prism::Runtime
{
    namespace Net = boost::asio;
    /**
     * @class TcpListener
     * @brief TCP 监听器
     * @details 绑定端点后进入 Accept 循环，每个连接按远端地址
     *          亲和性分发到 worker 并启动会话。
     */
    class TcpListener
    {
    public:
        /// 会话工厂签名：传入远端 IP 仅在调用期间借用；会话需自行复制以延长生命周期。
        using SessionFactory = std::function<SessionAdmissionResult(SessionAdmission)>;
        using FailureHandler = std::function<void(Prism::Fault::Code)>;
        struct Options final
        {
            Net::any_io_executor Executor;
            SessionFactory Factory;
            std::size_t WorkerCount{1};
            std::size_t MaxConnections{0};
            /// 借用唯一 Process worker 集合；调用方必须保持其存活到 Shutdown 和已提交 admission 排空。
            WorkerGroup *Workers{nullptr};
            std::shared_ptr<GenerationPublication> Publication;
            Prism::ProcessId Process{};
            std::size_t MailboxCapacity{64};
            FailureHandler OnFailure;
        };
    private:
        using Completion = Detail::ListenerCompletion;
        /**
         * @struct Lifetime
         * @brief detached accept loop 的共享状态
         * @details accept loop 不捕获 TcpListener 的 this；Stop 或析构后，
         *          状态对象仍由协程持有，直到取消完成。
         */
        struct Lifetime
        {
            explicit Lifetime(Options OptionsValue)
                : Ex(std::move(OptionsValue.Executor)), Factory(std::move(OptionsValue.Factory)),
                  OnFailure(std::move(OptionsValue.OnFailure)),
                  Workers(OptionsValue.Workers),
                  StandaloneTasks(Workers ? std::shared_ptr<Prism::Lifecycle::TaskRegistry>{} :
                      std::make_shared<Prism::Lifecycle::TaskRegistry>(Ex)),
                  Publication(std::move(OptionsValue.Publication)),
                  Balancer(Workers ? Workers->Size() : 1),
                  MaxConnections(OptionsValue.MaxConnections),
                  ConnectionQuota(std::make_shared<Detail::ListenerConnectionGate::Quota>(
                      OptionsValue.MaxConnections, Ex)),
                  Acceptor(Ex),
                  AcceptCompletion(std::make_shared<Completion>(Ex))
            {
            }
            Net::any_io_executor Ex;
            SessionFactory Factory;
            FailureHandler OnFailure;
            WorkerGroup *Workers{nullptr};
            /** @brief 无 Worker 的独立 listener root scope；拥有会话 runner 与其有界 task slot。 */
            std::shared_ptr<Prism::Lifecycle::TaskRegistry> StandaloneTasks;
            std::shared_ptr<GenerationPublication> Publication;
            AffinityBalancer Balancer;
            SessionRegistry Registry;
            std::size_t MaxConnections{0};
            std::shared_ptr<Detail::ListenerConnectionGate::Quota> ConnectionQuota;
            Net::ip::tcp::acceptor Acceptor;
            std::shared_ptr<Completion> AcceptCompletion;
            std::atomic<bool> Started{false};
            std::atomic<bool> AcceptLoopStarted{false};
            std::atomic<bool> Ready{false};
            std::atomic<bool> Failed{false};
            std::atomic<bool> Stopped{false}; ///< Stop/析构后禁止新会话进入工厂
        };
        /**
         * @struct AdmissionRequest
         * @brief listener 到 worker 的一次性 owning admission 请求。
         * @details transport 的移交不改变连接槽位 owner；未完成 admission 时析构
         *          分别处理 transport 和 reservation。
         */
        struct AdmissionRequest final
        {
            /** @brief admission 的 owning 输入；factory 与 State 覆盖请求执行期。 */
            struct Options final
            {
                Prism::SharedTransmission Transport;
                std::shared_ptr<Detail::ListenerConnectionGate::Reservation> ConnectionSlot;
                std::shared_ptr<Detail::ListenerConnectionDrain> RejectionDrain;
                SessionFactory Factory;
                std::shared_ptr<Lifetime> State;
                SessionInfo Info;
                Prism::WorkerId Worker{};
                Prism::Foundation::GenerationPin GenerationPin;
                Detail::ListenerSessionTraceTiming TraceTiming{};
            };
            explicit AdmissionRequest(Options Input)
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
            ~AdmissionRequest() noexcept
            {
                Reject();
            }
            AdmissionRequest(const AdmissionRequest &) = delete;
            auto operator=(const AdmissionRequest &) -> AdmissionRequest & = delete;
            auto Reject() noexcept -> void
            {
                if (Pending.exchange(false, std::memory_order_acq_rel))
                {
                    RejectUntransferred();
                }
            }
            auto RejectUntransferred() noexcept -> void { RejectOwnedTransport(); }
            /** @brief transport 已移交后的显式异常完成；quota 交给真实 Activity owner。 */
            auto RejectTransferred(Prism::SharedTransmission RejectedTransport) noexcept -> void
            { Transport = std::move(RejectedTransport); RejectOwnedTransport(); }
            [[nodiscard]] auto TakeTransport() noexcept -> Prism::SharedTransmission
            {
                Pending.store(false, std::memory_order_release);
                return std::move(Transport);
            }
            auto RejectOwnedTransport() noexcept -> void
            {
                if (RejectionDrain)
                {
                    if (ConnectionSlot) ConnectionSlot->ReleaseTransport();
                    RejectionDrain->Start(); Transport.reset(); return;
                }
                if (ConnectionSlot)
                { ConnectionSlot->AdoptTransport(std::move(Transport)); ConnectionSlot->RequestRetirement(); return; }
            }
            Prism::SharedTransmission Transport;
            std::shared_ptr<Detail::ListenerConnectionGate::Reservation> ConnectionSlot;
            std::shared_ptr<Detail::ListenerConnectionDrain> RejectionDrain;
            std::atomic<bool> Pending{true};
            SessionFactory Factory;
            std::shared_ptr<Lifetime> State;
            SessionInfo Info;
            Prism::WorkerId Worker{};
            Prism::Foundation::GenerationPin GenerationPin;
            Detail::ListenerSessionTraceTiming TraceTiming{};

            [[nodiscard]] auto Generation() const noexcept -> Prism::GenerationId
            {
                if (!GenerationPin)
                {
                    return {};
                }
                return GenerationPin->Id();
            }
        };
        static auto MakeAdmission(AdmissionRequest::Options Input) noexcept
            -> std::shared_ptr<AdmissionRequest>
        {
            const auto StableSlot = Input.ConnectionSlot;
            const auto StableDrain = Input.RejectionDrain;
            try { return std::make_shared<AdmissionRequest>(std::move(Input)); }
            catch (...)
            {
                if (StableDrain) { StableSlot->ReleaseTransport(); StableDrain->Start(); }
                else if (StableSlot) StableSlot->RequestRetirement();
                return {};
            }
        }
        static auto NotifyFailure(const std::shared_ptr<Lifetime> &State,
                                  const Prism::Fault::Code Code) noexcept -> void
        {
            if (!State->OnFailure) return;
            try { State->OnFailure(Code); }
            catch (...) {}
        }
        struct AcceptCompletionToken final
        {
            std::shared_ptr<Lifetime> State; bool Invoked{false}, Failed{false};
            explicit AcceptCompletionToken(std::shared_ptr<Lifetime> Value) noexcept : State(std::move(Value)) {}
            AcceptCompletionToken(AcceptCompletionToken&& Other) noexcept : State(std::move(Other.State)), Invoked(Other.Invoked), Failed(Other.Failed) { Other.Invoked = true; }
            ~AcceptCompletionToken() noexcept { if (!State) return; if (!Invoked || Failed) { State->Ready.store(false); State->Failed.store(true); State->AcceptLoopStarted.store(false); NotifyFailure(State, Prism::Fault::Code::IoError); } State->AcceptCompletion->Complete(); }
            auto operator()(std::exception_ptr Error) noexcept -> void { Invoked = true; Failed = static_cast<bool>(Error); }
        };
    public:
        /** @brief 构造 listener owner；Options 接管 factory 和 worker 配置。 */
        explicit TcpListener(Options OptionsValue)
            : State_(std::make_shared<Lifetime>(std::move(OptionsValue))) {}
        TcpListener(const TcpListener &) = delete;
        auto operator=(const TcpListener &) -> TcpListener & = delete;
        TcpListener(TcpListener &&) = delete;
        auto operator=(TcpListener &&) -> TcpListener & = delete;
        /**
         * @brief 析构即停止监听（RAII）
         * @details 不依赖调用方显式 Stop()：关闭 acceptor 让 Accept 循环退出；
         *          detached 循环持有的共享状态在取消完成后自行释放。
         * @note 必须在执行器线程调用（与单 executor 约束一致）。
         */
        ~TcpListener() { Stop(); State_->Registry.BeginShutdown(); }
        /**
         * @brief 绑定并启动监听
         * @param BindEp 绑定端点（端口 0 = 随机）
         * @return 成功或 io_error
         */
        [[nodiscard]] auto Start(const Net::ip::tcp::endpoint &BindEp)
            -> Net::awaitable<Prism::Fault::Code>
        {
            const auto State = State_;
            if (State->Stopped.load(std::memory_order_acquire) ||
                State->Started.exchange(true, std::memory_order_acq_rel))
            {
                co_return Prism::Fault::Code::InvalidArgument; // 已停止：不允许重新启动
            }
            boost::system::error_code ec;
            State->Acceptor.open(BindEp.protocol(), ec);
            if (!ec)
            {
                State->Acceptor.set_option(Net::ip::tcp::acceptor::reuse_address(true), ec);
            }
            if (!ec)
            {
                State->Acceptor.bind(BindEp, ec);
            }
            if (!ec)
            {
                State->Acceptor.listen(Net::socket_base::max_listen_connections, ec);
            }
            if (ec)
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
                State->AcceptLoopStarted.store(false, std::memory_order_release); State->Failed.store(true, std::memory_order_release);
                boost::system::error_code CloseError; State->Acceptor.close(CloseError);
                co_return Prism::Fault::Code::IoError;
            }
            if (!State->Failed.load(std::memory_order_acquire))
                State->Ready.store(true, std::memory_order_release);
            co_return Prism::Fault::Code::Success;
        }
        /**
         * @brief 停止监听（关闭 acceptor，Accept 循环退出）
         */
        void Stop()
        {
            State_->Ready.store(false, std::memory_order_release);
            if (State_->Stopped.exchange(true, std::memory_order_acq_rel))
            { return; }
            boost::system::error_code ec;
            State_->Acceptor.cancel(ec);
            State_->Acceptor.close(ec);
        }
        [[nodiscard]] auto IsReady() const noexcept -> bool
        {
            return State_->Ready.load(std::memory_order_acquire) &&
                   !State_->Stopped.load(std::memory_order_acquire) &&
                   !State_->Failed.load(std::memory_order_acquire);
        }
        [[nodiscard]] auto IsFailed() const noexcept -> bool
        {
            return State_->Failed.load(std::memory_order_acquire);
        }
        /**
         * @brief 获取活动会话注册表
         * @return listener 所有的注册表引用
         */
        [[nodiscard]] auto Registry() noexcept -> SessionRegistry &
        { return State_->Registry; }
        /**
         * @brief 停止接收并取消、排空活动会话
         * @details Stop 只关闭 acceptor；Registry Shutdown 等待实际会话
         *          子 scope；连接屏障等待已接收 admission 与拒绝 owner 退栈。
         *          独立 listener root 另行等待会话 runner 的真实 completion handler 退栈。
         */
        [[nodiscard]] auto Shutdown()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            Stop();
            if (State_->AcceptLoopStarted.load(std::memory_order_acquire))
            {
                co_await State_->AcceptCompletion->Wait();
            }
            State_->ConnectionQuota->Drain.Seal();
            const auto Sessions = co_await State_->Registry.Shutdown();
            const auto Connections = co_await State_->ConnectionQuota->Drain.Drain();
            std::expected<void, Prism::Fault::Failure> Standalone;
            if (State_->StandaloneTasks)
            {
                State_->StandaloneTasks->Seal();
                Standalone = co_await State_->StandaloneTasks->Drain();
            }
            if (!Sessions) co_return Sessions;
            if (!Connections) co_return Connections;
            co_return Standalone;
        }
        /**
         * @brief 本地端点
         */
        [[nodiscard]] auto LocalEndpoint() const -> Net::ip::tcp::endpoint
        {
            return State_->Acceptor.local_endpoint();
        }
        /**
         * @brief 返回连接并发上限
         * @return 0 表示不限制，否则为允许保持的活动 Session 数
         */
        [[nodiscard]] auto MaxConnections() const noexcept -> std::size_t
        {
            return State_->MaxConnections;
        }
    private:
        static auto RejectAdmission(const std::shared_ptr<AdmissionRequest> &Request,
                                    const std::shared_ptr<Session> &SessionOwner) noexcept -> void
        {
            if (SessionOwner) SessionOwner->SetDeferredCleanup({});
            if (Request) Request->RejectTransferred({});
        }

        /** @brief 在选定 worker executor 上完成 factory、registry 和 tracked start。 */
        static auto StartSession(const std::shared_ptr<AdmissionRequest> &Request) -> void
        {
            if (!Request || !Request->State) return;
            Worker *WorkerValue = nullptr;
            if (Request->State->Workers)
            {
                WorkerValue = Request->State->Workers->Find(Request->Worker);
            }
            auto Trace = Detail::MakeListenerSessionTraceWriter(*Request, WorkerValue);
            if (Trace)
            {
                Trace->Record(SessionTraceStage::SessionAdmissionStarted);
            }
            if (Request->State->Workers &&
                (!WorkerValue || !WorkerValue->IsAccepting()))
            {
                return;
            }
            if (!Request->GenerationPin || Request->GenerationPin->Id() != Request->Info.Generation)
            {
                RejectAdmission(Request, {});
                NotifyFailure(Request->State, Prism::Fault::Code::Blocked);
                return;
            }
            const auto SessionId = Request->Info.Id;
            auto Transport = Request->TakeTransport();
            auto Drain = Request->RejectionDrain;
            std::shared_ptr<Session> Sess, SessionOwner;
            try
            {
                if (Request->Factory)
                {
                    auto SourceIp = std::string{"Unknown"};
                    if (Request->Info.peer != "unknown")
                    {
                        SourceIp = Request->Info.peer;
                    }
                    auto Built = Request->Factory(SessionAdmission{
                        Transport, Request->Worker, SourceIp, Request->GenerationPin});
                    if (!Built)
                    {
                        RejectAdmission(Request, SessionOwner);
                        NotifyFailure(Request->State, Built.error().Code);
                        return;
                    }
                    Sess = std::move(*Built);
                }
                if (!Sess)
                {
                    RejectAdmission(Request, SessionOwner);
                    NotifyFailure(Request->State, Prism::Fault::Code::Blocked);
                    return;
                }
                SessionOwner = Sess;
                Sess->SetTraceWriter(Trace);
                auto InitialState = std::make_shared<Detail::SessionAdmissionState>();
                auto Control = Sess->Control();
                if (!Control) { RejectAdmission(Request, SessionOwner); return; }
                std::shared_ptr<Prism::Lifecycle::TaskRegistry> StandaloneRoot;
                Prism::Lifecycle::TaskRegistry *SessionRoot = nullptr;
                bool Bound = false;
                if (WorkerValue)
                {
                    SessionRoot = &WorkerValue->TaskRegistry();
                    Bound = Control->Bind(
                        WorkerValue->Executor(), *SessionRoot);
                }
                else
                {
                    StandaloneRoot = Request->State->StandaloneTasks;
                    if (!StandaloneRoot) { RejectAdmission(Request, SessionOwner); return; }
                    SessionRoot = StandaloneRoot.get();
                    Bound = Control->Bind(Request->State->Ex, *SessionRoot);
                }
                if (!Bound) { RejectAdmission(Request, SessionOwner); return; }
                auto Registration =
                    Request->State->Registry.Register(std::move(Request->Info), Control);
                if (!Registration) { RejectAdmission(Request, SessionOwner); return; }
                Sess->SetRegistration(std::move(Registration));
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
                if (!Drain) { RejectAdmission(Request, SessionOwner); return; }
                Drain->ConfigureSession(CloseAction, InitialState);
                Sess->SetDeferredCleanup(Drain);
                if (Request->ConnectionSlot) Request->ConnectionSlot->ReleaseTransport();
                // task 预约保活 Session/注册 token，直到终态 hook 发布和真实完成 handler 退栈。
                TaskRequest.Cancel = [Drain, SessionOwner = Sess]
                    { (void)SessionOwner; Drain->Start(); };
                const auto Started = Control->StartSession(
                    *SessionRoot,
                    std::move(TaskRequest),
                    Detail::RunListenerSession(
                        Detail::ListenerSessionRunRequest{std::move(Sess), Transport, Drain}));
                if (!Started)
                {
                    RejectAdmission(Request, SessionOwner);
                }
            }
            catch (...)
            {
                RejectAdmission(Request, SessionOwner);
            }
        }
        /**
         * @brief Accept 循环：接受 → 亲和性分发 → 启动会话
         */
        [[nodiscard]] static auto AcceptLoop(std::shared_ptr<Lifetime> State)
            -> Net::awaitable<void>
        {
            Detail::ListenerCompletionGuard Guard(State->AcceptCompletion);
            while (true)
            {
                boost::system::error_code ec;
                auto Sock = co_await State->Acceptor.async_accept(
                    Net::redirect_error(Net::use_awaitable, ec));
                if (ec)
                {
                    if (!State->Stopped.load(std::memory_order_acquire))
                    {
                        if (!State->Failed.exchange(true, std::memory_order_acq_rel))
                        {
                            State->Ready.store(false, std::memory_order_release);
                            if (State->OnFailure)
                            {
                                try
                                {
                                    State->OnFailure(Prism::Fault::Code::IoError);
                                }
                                catch (...)
                                {
                                }
                            }
                        }
                    }
                    co_return;
                }
                const auto AcceptedMonotonic = std::chrono::steady_clock::now();
                const auto AcceptedWall = std::chrono::system_clock::now();
                if (State->Stopped.load(std::memory_order_acquire))
                {
                    // 析构/Stop 后已接受的连接不再进入工厂
                    boost::system::error_code CloseError;
                    Sock.close(CloseError);
                    co_return;
                }
                auto Prepared = Detail::ListenerAdmissionOwner::Prepare(
                    std::move(Sock),
                    {State->Ex, State->ConnectionQuota, State->Balancer,
                     State->Workers, State->Publication, State->OnFailure});
                if (!Prepared) continue;
                auto [Transport, ConnectionSlot, RejectionDrain, Peer, Worker,
                    GenerationPin] =
                    std::move(*Prepared);
                if (!State->Factory ||
                    State->Stopped.load(std::memory_order_acquire))
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
                Info.Worker = Worker;
                Info.Generation = GenerationPin->Id();
                Info.StartedAt = static_cast<std::uint64_t>(
                    AcceptedMonotonic.time_since_epoch().count());
                const auto StartedAtUnixMilliseconds =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        AcceptedWall.time_since_epoch()).count();
                Info.StartedAtUnixMilliseconds = StartedAtUnixMilliseconds > 0
                    ? static_cast<std::uint64_t>(StartedAtUnixMilliseconds)
                    : 0U;
                auto Request = MakeAdmission(AdmissionRequest::Options{
                    std::move(Transport), std::move(ConnectionSlot), std::move(RejectionDrain), State->Factory,
                    State, std::move(Info), Worker, std::move(GenerationPin),
                    Detail::ListenerSessionTraceTiming{AcceptedWall, AcceptedMonotonic}});
                if (!Request) continue;
                auto Result = WorkerDispatchResult::Accepted;
                if (State->Workers)
                {
                    Request->TraceTiming.DispatchMonotonic = std::chrono::steady_clock::now();
                    Request->TraceTiming.DispatchWall = std::chrono::system_clock::now();
                    Result = State->Workers->Dispatch(
                        Worker, Request->Generation(),
                        [Request] { StartSession(Request); });
                }
                if (Result != WorkerDispatchResult::Accepted)
                {
                    Request->Reject();
                    if (State->Stopped.load(std::memory_order_acquire))
                    {
                        co_return;
                    }
                }
                else if (!State->Workers)
                {
                    StartSession(Request);
                }
            }
        }
        std::shared_ptr<Lifetime> State_; ///< accept loop 生命周期状态
    };
} // namespace Prism::Runtime

/**
 * @file ListenerAdmissionTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ListenerTestSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>

#include <chrono>
#include <exception>
#include <expected>
#include <optional>
#include <variant>

namespace
{
    struct FullChainState final
    {
        Net::any_io_executor Executor;
        std::uint16_t EchoPort{0};
        std::atomic<bool> FactoryCalled{false};
        std::atomic<bool> PrepareCalled{false};
        std::atomic<bool> DialCalled{false};
        std::string EchoBack;
    };

    auto RunEchoAcceptor(std::shared_ptr<Tcp::acceptor> Acceptor,
                         Net::any_io_executor Executor) -> Net::awaitable<void>
    {
        while (true)
        {
            boost::system::error_code Error;
            auto Socket = co_await Acceptor->async_accept(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return;
            }
            Net::co_spawn(Executor, TcpEchoServer(std::move(Socket)), Net::detached);
        }
    }

    auto AcceptFullChain(
        std::shared_ptr<FullChainState> State,
        Preview::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::StreamDataPlane{std::move(Input.Inbound)};
        State->PrepareCalled.store(true, std::memory_order_release);
        Plane.Target.Route = Preview::Network::RouteKind::Forward;
        Plane.Target.Host = *Preview::Network::ParseHost("127.0.0.1");
        Plane.Target.Port = 0;
        co_return Plane;
    }

    auto DialFullChain(std::shared_ptr<FullChainState> State,
                       const Preview::Network::Target &) -> Net::awaitable<
        std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
    {
        State->DialCalled.store(true, std::memory_order_release);
        std::error_code Error;
        Preview::Network::Dialer::Dialer Dialer(State->Executor);
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), State->EchoPort});
        Preview::SharedTransmission Connection;
        if (Dialed)
        {
            Connection = std::move(*Dialed);
            Error.clear();
        }
        else
        {
            Error = Preview::Fault::ToNative(Dialed.error());
        }
        if (Error)
        {
            co_return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Unreachable});
        }
        co_return std::move(Connection);
    }

    struct FullChainAcceptFactory final
    {
        std::shared_ptr<FullChainState> State;

        auto operator()(Preview::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            return AcceptFullChain(State, std::move(Input));
        }
    };

    struct FullChainDialFactory final
    {
        std::shared_ptr<FullChainState> State;

        auto operator()(const Preview::Network::Target &Target) const
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        {
            return DialFullChain(State, Target);
        }
    };

    auto MakeFullChainSession(const std::shared_ptr<FullChainState> &State,
        Preview::Runtime::WorkerGroup *Workers, const std::size_t WorkerIndex)
        -> std::shared_ptr<Preview::Runtime::Session>
    {
        State->FactoryCalled.store(true, std::memory_order_release);
        auto Options = MakeListenerWorkerSessionOptions(Workers, WorkerIndex);
        Options.Services->RelayIdleTimeout = std::chrono::milliseconds(200);
        Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
            FullChainAcceptFactory{State});
        Options.Services->Dial = FullChainDialFactory{State};
        return std::make_shared<Preview::Runtime::Session>(std::move(Options));
    }

    struct FullChainSessionFactory final
    {
        std::shared_ptr<FullChainState> State;
        Preview::Runtime::WorkerGroup *Workers;

        auto operator()(Preview::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Preview::Runtime::Session>
        {
            return MakeFullChainSession(
                State, Workers, static_cast<std::size_t>(Admission.Worker.Value() - 1U));
        }
    };

    struct FullChainProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Runtime::TcpListener> Listener;
        std::shared_ptr<Tcp::acceptor> EchoAcceptor;
        std::shared_ptr<FullChainState> State;
    };

    auto RunFullChainProbe(FullChainProbeRequest Request) -> Net::awaitable<void>
    {
        const auto StartResult = co_await Request.Listener->Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
        if (StartResult != Preview::Fault::Code::Success)
        {
            co_return;
        }

        std::error_code Error;
        Preview::Network::Dialer::Dialer Dialer(Request.Executor);
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Preview::SharedTransmission Connection;
        if (Dialed)
        {
            Connection = std::move(*Dialed);
            Error.clear();
        }
        else
        {
            Error = Preview::Fault::ToNative(Dialed.error());
        }
        if (Error || !Connection)
        {
            co_await Request.Listener->Shutdown();
            boost::system::error_code CloseError;
            Request.EchoAcceptor->close(CloseError);
            co_return;
        }

        const auto Payload = Socks5Greeting();
        const auto Write = co_await Connection->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Payload.data()),
                                       Payload.size()));
        Error = Preview::Fault::ToNative(Write.Failure);
        std::array<std::byte, 64> Buffer{};
        const auto BytesRead = co_await Preview::Testing::TailReadGuarded(Connection, Buffer, Error);
        Request.State->EchoBack.assign(
            reinterpret_cast<const char *>(Buffer.data()), BytesRead);
        (void)Connection->Close();
        co_await Request.Listener->Shutdown();
        boost::system::error_code CloseError;
        Request.EchoAcceptor->close(CloseError);
    }

    using HeldAdmissionEvents =
        Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    struct MaxConnectionsState final
    {
        explicit MaxConnectionsState(Net::any_io_executor Executor)
            : Entered(std::make_shared<HeldAdmissionEvents>(std::move(Executor), 1))
        {
        }

        std::shared_ptr<HeldAdmissionEvents> Entered;
        Preview::Fault::Code StartResult{Preview::Fault::Code::GenericError};
        std::atomic<std::size_t> FactoryCalls{0};
    };

    struct HeldAdmissionFactory final
    {
        std::shared_ptr<HeldAdmissionEvents> Entered;

        auto operator()(Preview::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            return AwaitHeldAdmission(std::move(Input.Inbound), Entered);
        }
    };

    struct MaxConnectionsSessionFactory final
    {
        std::shared_ptr<MaxConnectionsState> State;
        Preview::Runtime::WorkerGroup *Workers;

        auto operator()(Preview::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Preview::Runtime::Session>
        {
            State->FactoryCalls.fetch_add(1, std::memory_order_relaxed);
            auto Options = MakeListenerWorkerSessionOptions(
                Workers, static_cast<std::size_t>(Admission.Worker.Value() - 1U));
            Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
                HeldAdmissionFactory{State->Entered});
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        }
    };

    struct MaxConnectionsProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Runtime::TcpListener> Listener;
        std::shared_ptr<MaxConnectionsState> State;
    };

    auto RunMaxConnectionsProbe(MaxConnectionsProbeRequest Request) -> Net::awaitable<void>
    {
        Request.State->StartResult = co_await Request.Listener->Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Request.State->StartResult, Preview::Fault::Code::Success);
        if (Request.State->StartResult != Preview::Fault::Code::Success)
        {
            co_return;
        }

        const auto Port = Request.Listener->LocalEndpoint().port();
        std::error_code Error;
        Preview::Network::Dialer::Dialer Dialer(Request.Executor);
        auto FirstDialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Port});
        Preview::SharedTransmission First;
        if (FirstDialed)
        {
            First = std::move(*FirstDialed);
            Error.clear();
        }
        else
        {
            Error = Preview::Fault::ToNative(FirstDialed.error());
        }
        EXPECT_FALSE(Error);
        EXPECT_NE(First, nullptr);
        if (Error || !First)
        {
            Request.Listener->Stop();
            co_return;
        }

        co_await Request.State->Entered->async_receive(Net::use_awaitable);
        EXPECT_EQ(Request.State->FactoryCalls.load(std::memory_order_acquire), std::size_t{1});

        auto SecondDialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Port});
        Preview::SharedTransmission Second;
        if (SecondDialed)
        {
            Second = std::move(*SecondDialed);
            Error.clear();
        }
        else
        {
            Error = Preview::Fault::ToNative(SecondDialed.error());
        }
        EXPECT_FALSE(Error);
        if (Second)
        {
            std::array<std::byte, 1> Byte{};
            Net::steady_timer Rejected(Request.Executor);
            Rejected.expires_after(std::chrono::seconds(1));
            auto ReadIntoSocket = [&]() -> Net::awaitable<std::size_t>
            {
                const auto Read = co_await Second->ReadSome(Byte);
                Error = Preview::Fault::ToNative(Read.Failure);
                co_return Read.Bytes;
            };
            using Net::experimental::awaitable_operators::operator||;
            auto Closed = co_await (ReadIntoSocket() ||
                                    Rejected.async_wait(Net::use_awaitable));
            EXPECT_EQ(Closed.index(), 0U);
            if (Closed.index() == 0)
            {
                EXPECT_TRUE(std::get<0>(Closed) == 0U || Error);
            }
            (void)Second->Close();
        }
        EXPECT_EQ(Request.State->FactoryCalls.load(std::memory_order_acquire), std::size_t{1});

        (void)First->Close();
        co_await Request.Listener->Shutdown();
    }

    struct FactoryRejectState final
    {
        Preview::Fault::Code StartResult{Preview::Fault::Code::GenericError};
        std::atomic<Preview::SharedTransmission> Accepted{nullptr};
        std::atomic<std::size_t> FactoryCalls{0};
    };

    struct FactoryRejectSessionFactory final
    {
        std::shared_ptr<FactoryRejectState> State;

        auto operator()(Preview::Runtime::SessionAdmission Admission) const
            -> Preview::Runtime::SessionAdmissionResult
        {
            State->FactoryCalls.fetch_add(1, std::memory_order_relaxed);
            State->Accepted.store(std::move(Admission.Inbound), std::memory_order_release);
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable});
        }
    };

    struct FactoryRejectProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Runtime::TcpListener> Listener;
        std::shared_ptr<FactoryRejectState> State;
    };

    auto RunFactoryRejectProbe(FactoryRejectProbeRequest Request) -> Net::awaitable<void>
    {
        Request.State->StartResult = co_await Request.Listener->Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Request.State->StartResult, Preview::Fault::Code::Success);
        if (Request.State->StartResult != Preview::Fault::Code::Success)
        {
            co_return;
        }

        std::error_code Error;
        Preview::Network::Dialer::Dialer Dialer(Request.Executor);
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Preview::SharedTransmission Client;
        if (Dialed)
        {
            Client = std::move(*Dialed);
            Error.clear();
        }
        else
        {
            Error = Preview::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(Error);
        EXPECT_NE(Client, nullptr);
        if (Error || !Client)
        {
            co_return;
        }
        Net::steady_timer Tick(Request.Executor);
        Tick.expires_after(std::chrono::milliseconds(10));
        co_await Tick.async_wait(Net::use_awaitable);
        const auto AcceptedTransport = Request.State->Accepted.load(std::memory_order_acquire);
        EXPECT_NE(AcceptedTransport, nullptr);
        EXPECT_EQ(Request.State->FactoryCalls.load(std::memory_order_acquire), std::size_t{1});
        if (!AcceptedTransport)
        {
            (void)Client->Close();
            Request.Listener->Stop();
            co_return;
        }
        EXPECT_FALSE(AcceptedTransport->IsOpen());
        (void)Client->Close();
        auto SecondDialed = co_await Dialer.Connect(
            {*Preview::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Preview::SharedTransmission Second;
        if (SecondDialed) { Second = std::move(*SecondDialed); Error.clear(); }
        else { Error = Preview::Fault::ToNative(SecondDialed.error()); }
        EXPECT_FALSE(Error);
        EXPECT_NE(Second, nullptr);
        Tick.expires_after(std::chrono::milliseconds(10));
        co_await Tick.async_wait(Net::use_awaitable);
        EXPECT_EQ(Request.State->FactoryCalls.load(std::memory_order_acquire), std::size_t{2});
        if (Second) (void)Second->Close();
        co_await Request.Listener->Shutdown();
    }

    auto ThrowAcceptFailure(Preview::Contract::StreamAcceptInput)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        throw std::runtime_error("accept failure");
        co_return std::unexpected(Preview::Contract::FailureFromProtocolError(Preview::Error::IoError));
    }

    auto MakeExceptionSession() -> std::shared_ptr<Preview::Runtime::Session>
    {
        Preview::Runtime::SessionOptions Options;
        Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
            ThrowAcceptFailure);
        return std::make_shared<Preview::Runtime::Session>(std::move(Options));
    }

    struct ExceptionSessionState final
    {
        Preview::Fault::Code StartResult{Preview::Fault::Code::GenericError};
        std::atomic<Preview::SharedTransmission> Accepted{nullptr};
        std::atomic<std::size_t> FactoryCalls{0};
    };

    struct ExceptionSessionFactory final
    {
        std::shared_ptr<ExceptionSessionState> State;

        auto operator()(Preview::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Preview::Runtime::Session>
        {
            State->FactoryCalls.fetch_add(1, std::memory_order_relaxed);
            State->Accepted.store(Admission.Inbound, std::memory_order_release);
            return MakeExceptionSession();
        }
    };

    struct ExceptionProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Runtime::TcpListener> Listener;
        std::shared_ptr<ExceptionSessionState> State;
    };

    auto RunExceptionProbe(ExceptionProbeRequest Request) -> Net::awaitable<void>
    {
        Request.State->StartResult = co_await Request.Listener->Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Request.State->StartResult, Preview::Fault::Code::Success);
        if (Request.State->StartResult != Preview::Fault::Code::Success)
        {
            co_return;
        }

        std::error_code Error;
        Preview::Network::Dialer::Dialer Dialer(Request.Executor);
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Preview::SharedTransmission Client;
        if (Dialed)
        {
            Client = std::move(*Dialed);
            Error.clear();
        }
        else
        {
            Error = Preview::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(Error);
        EXPECT_NE(Client, nullptr);
        if (Error || !Client)
        {
            co_return;
        }

        const auto Greeting = Socks5Greeting();
        const auto Write = co_await Client->WriteSome(
            std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                       Greeting.size()));
        Error = Preview::Fault::ToNative(Write.Failure);
        Net::steady_timer Tick(Request.Executor);
        Tick.expires_after(std::chrono::milliseconds(10));
        co_await Tick.async_wait(Net::use_awaitable);
        const auto AcceptedTransport = Request.State->Accepted.load(std::memory_order_acquire);
        EXPECT_NE(AcceptedTransport, nullptr);
        if (AcceptedTransport)
        {
            EXPECT_FALSE(AcceptedTransport->IsOpen());
        }
        (void)Client->Close();

        auto SecondDialed = co_await Dialer.Connect(
            {*Preview::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Preview::SharedTransmission Second;
        if (SecondDialed)
        {
            Second = std::move(*SecondDialed);
            Error.clear();
        }
        else
        {
            Error = Preview::Fault::ToNative(SecondDialed.error());
        }
        EXPECT_FALSE(Error);
        EXPECT_NE(Second, nullptr);
        if (Second)
        {
            const auto SecondWrite = co_await Second->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                           Greeting.size()));
            EXPECT_FALSE(Preview::Fault::ToNative(SecondWrite.Failure));
            Tick.expires_after(std::chrono::milliseconds(10));
            co_await Tick.async_wait(Net::use_awaitable);
            (void)Second->Close();
        }
        EXPECT_EQ(Request.State->FactoryCalls.load(std::memory_order_acquire), std::size_t{2});
        co_await Request.Listener->Shutdown();
    }


}

TEST(AffinityBalancer, StableAndUniform)
    {
        Preview::Runtime::AffinityBalancer Balancer(4);
        // 相同 key 稳定
        EXPECT_EQ(Balancer.Select("1.2.3.4"), Balancer.Select("1.2.3.4"));
        EXPECT_EQ(Balancer.Select("10.0.0.1"), Balancer.Select("10.0.0.1"));
        // 分布覆盖全部 worker
        std::array<std::size_t, 4> Buckets{};
        for (int Index = 1; Index <= 64; ++Index)
        {
            ++Buckets[Balancer.Select("192.168.0." + std::to_string(Index))];
        }
        for (const auto Bucket : Buckets)
        {
            EXPECT_GT(Bucket, std::size_t{0});
        }
        // 单 worker 恒为 0
        Preview::Runtime::AffinityBalancer Single(1);
        EXPECT_EQ(Single.Select("any"), std::size_t{0});
    }

TEST(TcpListener, FullChainE2E)
    {
        Net::io_context Ioc;

        // 真实 echo 上游
        auto EchoAcceptor = std::make_shared<Tcp::acceptor>(
            Ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        auto State = std::make_shared<FullChainState>();
        State->Executor = Ioc.get_executor();
        State->EchoPort = EchoAcceptor->local_endpoint().port();
        Net::co_spawn(Ioc, RunEchoAcceptor(EchoAcceptor, State->Executor), Net::detached);

        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{11};
        ProcessOptions.Generation = Preview::GenerationId{21};
        ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        ProcessOptions.WorkerCount = 2;
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        // listener：会话（识别 socks5 + Dial 到 echo 上游）
        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.Factory = FullChainSessionFactory{State, &ProcessValue.Workers()};
        auto Listener = std::make_shared<Preview::Runtime::TcpListener>(
            std::move(ListenerOptions));

        // RunCoro 完整等待场景协程，Listener 和 State 可安全借用于请求期间。
        RunCoro(Ioc, RunFullChainProbe(FullChainProbeRequest{
                            Ioc.get_executor(), Listener, EchoAcceptor, State}));
        EXPECT_TRUE(State->FactoryCalled.load(std::memory_order_acquire));
        EXPECT_TRUE(State->PrepareCalled.load(std::memory_order_acquire));
        EXPECT_TRUE(State->DialCalled.load(std::memory_order_acquire));
        EXPECT_EQ(State->EchoBack, Socks5Greeting());
    }

TEST(TcpListener, MaxConnectionsRejectsAdditionalSessions)
    {
        Net::io_context Ioc;
        auto State = std::make_shared<MaxConnectionsState>(Ioc.get_executor());
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{13};
        ProcessOptions.Generation = Preview::GenerationId{23};
        ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        ProcessOptions.WorkerCount = 1;
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.MaxConnections = 1;
        ListenerOptions.Factory = MaxConnectionsSessionFactory{State, &ProcessValue.Workers()};
        auto Listener = std::make_shared<Preview::Runtime::TcpListener>(
            std::move(ListenerOptions));

        RunCoro(Ioc, RunMaxConnectionsProbe(MaxConnectionsProbeRequest{
                            Ioc.get_executor(), Listener, State}));
        EXPECT_EQ(State->StartResult, Preview::Fault::Code::Success);
    }

TEST(TcpListener, FactoryRejectClosesAcceptedTransport)
    {
        Net::io_context Ioc;
        auto State = std::make_shared<FactoryRejectState>();
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{14};
        ProcessOptions.Generation = Preview::GenerationId{24};
        ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.MaxConnections = 1;
        ListenerOptions.Factory = FactoryRejectSessionFactory{State};
        auto Listener = std::make_shared<Preview::Runtime::TcpListener>(
            std::move(ListenerOptions));

        RunCoro(Ioc, RunFactoryRejectProbe(FactoryRejectProbeRequest{
                            Ioc.get_executor(), Listener, State}));
        EXPECT_EQ(State->StartResult, Preview::Fault::Code::Success);
    }

TEST(TcpListener, SessionExceptionClosesAcceptedTransport)
    {
        Net::io_context Ioc;
        auto State = std::make_shared<ExceptionSessionState>();
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{15};
        ProcessOptions.Generation = Preview::GenerationId{25};
        ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.MaxConnections = 1;
        ListenerOptions.Factory = ExceptionSessionFactory{State};
        auto Listener = std::make_shared<Preview::Runtime::TcpListener>(
            std::move(ListenerOptions));

        RunCoro(Ioc, RunExceptionProbe(ExceptionProbeRequest{
                            Ioc.get_executor(), Listener, State}));
        EXPECT_EQ(State->StartResult, Preview::Fault::Code::Success);
    }


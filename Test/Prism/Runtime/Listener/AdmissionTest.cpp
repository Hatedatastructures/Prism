/**
 * @file AdmissionTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ListenerTestSupport.hpp"

#include <Prism/Runtime/ListenerAdmissionOwner.hpp>

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
        Prism::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Root = Prism::Contract::StreamDataPlane{std::move(Input.Inbound)};
        State->PrepareCalled.store(true, std::memory_order_release);
        Plane.Target.Route = Prism::Network::RouteKind::Forward;
        Plane.Target.Host = *Prism::Network::ParseHost("127.0.0.1");
        Plane.Target.Port = 0;
        co_return Plane;
    }

    auto DialFullChain(std::shared_ptr<FullChainState> State,
                       const Prism::Network::Target &) -> Net::awaitable<
        std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        State->DialCalled.store(true, std::memory_order_release);
        std::error_code Error;
        Prism::Network::Dialer::Dialer Dialer(State->Executor);
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), State->EchoPort});
        Prism::SharedTransmission Connection;
        if (Dialed)
        {
            Connection = std::move(*Dialed);
            Error.clear();
        }
        else
        {
            Error = Prism::Fault::ToNative(Dialed.error());
        }
        if (Error)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Unreachable});
        }
        co_return std::move(Connection);
    }

    struct FullChainAcceptFactory final
    {
        std::shared_ptr<FullChainState> State;

        auto operator()(Prism::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            return AcceptFullChain(State, std::move(Input));
        }
    };

    struct FullChainDialFactory final
    {
        std::shared_ptr<FullChainState> State;

        auto operator()(const Prism::Network::Target &Target) const
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            return DialFullChain(State, Target);
        }
    };

    auto MakeFullChainSession(const std::shared_ptr<FullChainState> &State,
        Prism::Runtime::WorkerGroup *Workers, const std::size_t WorkerIndex)
        -> std::shared_ptr<Prism::Runtime::Session>
    {
        State->FactoryCalled.store(true, std::memory_order_release);
        auto Options = MakeListenerWorkerSessionOptions(Workers, WorkerIndex);
        Options.Services->RelayIdleTimeout = std::chrono::milliseconds(200);
        Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
            FullChainAcceptFactory{State});
        Options.Services->Dial = FullChainDialFactory{State};
        return std::make_shared<Prism::Runtime::Session>(std::move(Options));
    }

    struct FullChainSessionFactory final
    {
        std::shared_ptr<FullChainState> State;
        Prism::Runtime::WorkerGroup *Workers;

        auto operator()(Prism::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Prism::Runtime::Session>
        {
            return MakeFullChainSession(
                State, Workers, static_cast<std::size_t>(Admission.Worker.Value() - 1U));
        }
    };

    struct FullChainProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::Runtime::TcpListener> Listener;
        std::shared_ptr<Tcp::acceptor> EchoAcceptor;
        std::shared_ptr<FullChainState> State;
    };

    auto RunFullChainProbe(FullChainProbeRequest Request) -> Net::awaitable<void>
    {
        const auto StartResult = co_await Request.Listener->Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartResult, Prism::Fault::Code::Success);
        if (StartResult != Prism::Fault::Code::Success)
        {
            co_return;
        }

        std::error_code Error;
        Prism::Network::Dialer::Dialer Dialer(Request.Executor);
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Prism::SharedTransmission Connection;
        if (Dialed)
        {
            Connection = std::move(*Dialed);
            Error.clear();
        }
        else
        {
            Error = Prism::Fault::ToNative(Dialed.error());
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
        Error = Prism::Fault::ToNative(Write.Failure);
        std::array<std::byte, 64> Buffer{};
        const auto BytesRead = co_await Prism::Testing::TailReadGuarded(Connection, Buffer, Error);
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
        Prism::Fault::Code StartResult{Prism::Fault::Code::GenericError};
        std::atomic<std::size_t> FactoryCalls{0};
    };

    struct HeldAdmissionFactory final
    {
        std::shared_ptr<HeldAdmissionEvents> Entered;

        auto operator()(Prism::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            return AwaitHeldAdmission(std::move(Input.Inbound), Entered);
        }
    };

    struct MaxConnectionsSessionFactory final
    {
        std::shared_ptr<MaxConnectionsState> State;
        Prism::Runtime::WorkerGroup *Workers;

        auto operator()(Prism::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Prism::Runtime::Session>
        {
            State->FactoryCalls.fetch_add(1, std::memory_order_relaxed);
            auto Options = MakeListenerWorkerSessionOptions(
                Workers, static_cast<std::size_t>(Admission.Worker.Value() - 1U));
            Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
                HeldAdmissionFactory{State->Entered});
            return std::make_shared<Prism::Runtime::Session>(std::move(Options));
        }
    };

    struct MaxConnectionsProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::Runtime::TcpListener> Listener;
        std::shared_ptr<MaxConnectionsState> State;
    };

    auto RunMaxConnectionsProbe(MaxConnectionsProbeRequest Request) -> Net::awaitable<void>
    {
        Request.State->StartResult = co_await Request.Listener->Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Request.State->StartResult, Prism::Fault::Code::Success);
        if (Request.State->StartResult != Prism::Fault::Code::Success)
        {
            co_return;
        }

        const auto Port = Request.Listener->LocalEndpoint().port();
        std::error_code Error;
        Prism::Network::Dialer::Dialer Dialer(Request.Executor);
        auto FirstDialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Port});
        Prism::SharedTransmission First;
        if (FirstDialed)
        {
            First = std::move(*FirstDialed);
            Error.clear();
        }
        else
        {
            Error = Prism::Fault::ToNative(FirstDialed.error());
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

        auto SecondDialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Port});
        Prism::SharedTransmission Second;
        if (SecondDialed)
        {
            Second = std::move(*SecondDialed);
            Error.clear();
        }
        else
        {
            Error = Prism::Fault::ToNative(SecondDialed.error());
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
                Error = Prism::Fault::ToNative(Read.Failure);
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
        Prism::Fault::Code StartResult{Prism::Fault::Code::GenericError};
        std::atomic<Prism::SharedTransmission> Accepted{nullptr};
        std::atomic<std::size_t> FactoryCalls{0};
    };

    struct FactoryRejectSessionFactory final
    {
        std::shared_ptr<FactoryRejectState> State;

        auto operator()(Prism::Runtime::SessionAdmission Admission) const
            -> Prism::Runtime::SessionAdmissionResult
        {
            State->FactoryCalls.fetch_add(1, std::memory_order_relaxed);
            State->Accepted.store(std::move(Admission.Inbound), std::memory_order_release);
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
    };

    struct FactoryRejectProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::Runtime::TcpListener> Listener;
        std::shared_ptr<FactoryRejectState> State;
    };

    auto RunFactoryRejectProbe(FactoryRejectProbeRequest Request) -> Net::awaitable<void>
    {
        Request.State->StartResult = co_await Request.Listener->Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Request.State->StartResult, Prism::Fault::Code::Success);
        if (Request.State->StartResult != Prism::Fault::Code::Success)
        {
            co_return;
        }

        std::error_code Error;
        Prism::Network::Dialer::Dialer Dialer(Request.Executor);
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Prism::SharedTransmission Client;
        if (Dialed)
        {
            Client = std::move(*Dialed);
            Error.clear();
        }
        else
        {
            Error = Prism::Fault::ToNative(Dialed.error());
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
            {*Prism::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Prism::SharedTransmission Second;
        if (SecondDialed) { Second = std::move(*SecondDialed); Error.clear(); }
        else { Error = Prism::Fault::ToNative(SecondDialed.error()); }
        EXPECT_FALSE(Error);
        EXPECT_NE(Second, nullptr);
        Tick.expires_after(std::chrono::milliseconds(10));
        co_await Tick.async_wait(Net::use_awaitable);
        EXPECT_EQ(Request.State->FactoryCalls.load(std::memory_order_acquire), std::size_t{2});
        if (Second) (void)Second->Close();
        co_await Request.Listener->Shutdown();
    }

    auto ThrowAcceptFailure(Prism::Contract::StreamAcceptInput)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        throw std::runtime_error("accept failure");
        co_return std::unexpected(Prism::Contract::FailureFromProtocolError(Prism::Error::IoError));
    }

    auto MakeExceptionSession() -> std::shared_ptr<Prism::Runtime::Session>
    {
        Prism::Runtime::SessionOptions Options;
        Options.Services->Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
            ThrowAcceptFailure);
        return std::make_shared<Prism::Runtime::Session>(std::move(Options));
    }

    struct ExceptionSessionState final
    {
        Prism::Fault::Code StartResult{Prism::Fault::Code::GenericError};
        std::atomic<Prism::SharedTransmission> Accepted{nullptr};
        std::atomic<std::size_t> FactoryCalls{0};
    };

    struct ExceptionSessionFactory final
    {
        std::shared_ptr<ExceptionSessionState> State;

        auto operator()(Prism::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Prism::Runtime::Session>
        {
            State->FactoryCalls.fetch_add(1, std::memory_order_relaxed);
            State->Accepted.store(Admission.Inbound, std::memory_order_release);
            return MakeExceptionSession();
        }
    };

    struct ExceptionProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Prism::Runtime::TcpListener> Listener;
        std::shared_ptr<ExceptionSessionState> State;
    };

    auto RunExceptionProbe(ExceptionProbeRequest Request) -> Net::awaitable<void>
    {
        Request.State->StartResult = co_await Request.Listener->Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(Request.State->StartResult, Prism::Fault::Code::Success);
        if (Request.State->StartResult != Prism::Fault::Code::Success)
        {
            co_return;
        }

        std::error_code Error;
        Prism::Network::Dialer::Dialer Dialer(Request.Executor);
        auto Dialed = co_await Dialer.Connect({*Prism::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Prism::SharedTransmission Client;
        if (Dialed)
        {
            Client = std::move(*Dialed);
            Error.clear();
        }
        else
        {
            Error = Prism::Fault::ToNative(Dialed.error());
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
        Error = Prism::Fault::ToNative(Write.Failure);
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
            {*Prism::Network::ParseHost("127.0.0.1"), Request.Listener->LocalEndpoint().port()});
        Prism::SharedTransmission Second;
        if (SecondDialed)
        {
            Second = std::move(*SecondDialed);
            Error.clear();
        }
        else
        {
            Error = Prism::Fault::ToNative(SecondDialed.error());
        }
        EXPECT_FALSE(Error);
        EXPECT_NE(Second, nullptr);
        if (Second)
        {
            const auto SecondWrite = co_await Second->WriteSome(
                std::span<const std::byte>(reinterpret_cast<const std::byte *>(Greeting.data()),
                                           Greeting.size()));
            EXPECT_FALSE(Prism::Fault::ToNative(SecondWrite.Failure));
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
        Prism::Runtime::AffinityBalancer Balancer(4);
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
        Prism::Runtime::AffinityBalancer Single(1);
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

        Prism::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Prism::ProcessId{11};
        ProcessOptions.Generation = Prism::GenerationId{21};
        ProcessOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        ProcessOptions.WorkerCount = 2;
        Prism::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        // listener：会话（识别 socks5 + Dial 到 echo 上游）
        Prism::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.Factory = FullChainSessionFactory{State, &ProcessValue.Workers()};
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
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
        Prism::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Prism::ProcessId{13};
        ProcessOptions.Generation = Prism::GenerationId{23};
        ProcessOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        ProcessOptions.WorkerCount = 1;
        Prism::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Prism::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.MaxConnections = 1;
        ListenerOptions.Factory = MaxConnectionsSessionFactory{State, &ProcessValue.Workers()};
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
            std::move(ListenerOptions));

        RunCoro(Ioc, RunMaxConnectionsProbe(MaxConnectionsProbeRequest{
                            Ioc.get_executor(), Listener, State}));
        EXPECT_EQ(State->StartResult, Prism::Fault::Code::Success);
    }

TEST(TcpListener, FactoryRejectClosesAcceptedTransport)
    {
        Net::io_context Ioc;
        auto State = std::make_shared<FactoryRejectState>();
        Prism::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Prism::ProcessId{14};
        ProcessOptions.Generation = Prism::GenerationId{24};
        ProcessOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        Prism::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Prism::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.MaxConnections = 1;
        ListenerOptions.Factory = FactoryRejectSessionFactory{State};
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
            std::move(ListenerOptions));

        RunCoro(Ioc, RunFactoryRejectProbe(FactoryRejectProbeRequest{
                            Ioc.get_executor(), Listener, State}));
        EXPECT_EQ(State->StartResult, Prism::Fault::Code::Success);
    }

TEST(TcpListener, SessionExceptionClosesAcceptedTransport)
    {
        Net::io_context Ioc;
        auto State = std::make_shared<ExceptionSessionState>();
        Prism::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Prism::ProcessId{15};
        ProcessOptions.Generation = Prism::GenerationId{25};
        ProcessOptions.Publication = Prism::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        Prism::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Prism::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.MaxConnections = 1;
        ListenerOptions.Factory = ExceptionSessionFactory{State};
        auto Listener = std::make_shared<Prism::Runtime::TcpListener>(
            std::move(ListenerOptions));

        RunCoro(Ioc, RunExceptionProbe(ExceptionProbeRequest{
                            Ioc.get_executor(), Listener, State}));
        EXPECT_EQ(State->StartResult, Prism::Fault::Code::Success);
    }

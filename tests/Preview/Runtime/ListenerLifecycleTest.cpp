/**
 * @file ListenerLifecycleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ListenerTestSupport.hpp"

#include <Preview/Runtime/WorkerDispatchResult.hpp>

namespace
{

    auto AcceptConnectionStorm(
        std::atomic<int> &SourceIpCaptured,
        Preview::Contract::StreamAcceptInput Input)
        -> Net::awaitable<Preview::Contract::AcceptOutcome>
    {
        Preview::Contract::ProtocolDataPlane Plane;
        Plane.Root = Preview::Contract::StreamDataPlane{std::move(Input.Inbound)};
        if (Input.Metadata.SourceIp == "127.0.0.1")
        {
            SourceIpCaptured.fetch_add(1, std::memory_order_relaxed);
        }
        Plane.Target.Route = Preview::Network::RouteKind::Forward;
        Plane.Target.Host = *Preview::Network::ParseHost("127.0.0.1");
        Plane.Target.Port = 0;
        co_return Plane;
    }

    auto DialConnectionStorm(
        Net::io_context &Io,
        const unsigned short EchoPort,
        const Preview::Network::Target &)
        -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
    {
        std::error_code Error;
        Preview::Network::Dialer::Dialer Dialer(Io.get_executor());
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), EchoPort});
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

    struct ConnectionStormSessionFactory final
    {
        Net::io_context *Io{};
        unsigned short EchoPort{0};
        std::atomic<int> *SourceIpCaptured{};
        Preview::Runtime::WorkerGroup *Workers{};

        auto operator()(Preview::Runtime::SessionAdmission Admission) const
            -> std::shared_ptr<Preview::Runtime::Session>
        {
            Preview::Runtime::SessionOptions Options;
            Options.SourceIp = std::move(Admission.SourceIp);
            Options.Services->Generation = Admission.Generation;
            Options.Services->Bytes = RequireWorkerBytePool(
                Workers, static_cast<std::size_t>(Admission.Worker.Value() - 1U));
            Options.Services->RelayIdleTimeout = std::chrono::milliseconds(300);
            Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
                [SourceIpCaptured = SourceIpCaptured](
                    Preview::Contract::StreamAcceptInput Input)
                {
                    return AcceptConnectionStorm(*SourceIpCaptured, std::move(Input));
                });
            Options.Services->Dial = [Io = Io, EchoPort = EchoPort](
                const Preview::Network::Target &Target)
            {
                return DialConnectionStorm(*Io, EchoPort, Target);
            };
            return std::make_shared<Preview::Runtime::Session>(std::move(Options));
        }
    };

    auto RunConnectionStormEcho(
        const std::shared_ptr<Tcp::acceptor> &Acceptor,
        const Net::any_io_executor Executor) -> Net::awaitable<void>
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

    struct ConnectionStormClients final
    {
        Net::any_io_executor Executor;
        unsigned short Port{0};
        int Count{0};
        std::shared_ptr<std::atomic<int>> Done;
        std::shared_ptr<std::atomic<int>> Success;
        std::string Payload;
    };

    auto RunConnectionStormClient(
        const std::shared_ptr<ConnectionStormClients> &Options,
        const int) -> Net::awaitable<void>
    {
        std::error_code Error;
        Preview::Network::Dialer::Dialer Dialer(Options->Executor);
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Options->Port});
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
            Options->Done->fetch_add(1, std::memory_order_relaxed);
            co_return;
        }
        const auto Write = co_await Connection->WriteSome(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Options->Payload.data()), Options->Payload.size()));
        Error = Preview::Fault::ToNative(Write.Failure);
        std::array<std::byte, 64> Buffer{};
        const auto Read = co_await Connection->ReadSome(Buffer);
        Error = Preview::Fault::ToNative(Read.Failure);
        const auto Bytes = Read.Bytes;
        if (!Error && std::string_view(reinterpret_cast<const char *>(Buffer.data()), Bytes) == Options->Payload)
        {
            Options->Success->fetch_add(1, std::memory_order_relaxed);
        }
        (void)Connection->Close();
        Options->Done->fetch_add(1, std::memory_order_relaxed);
    }

    auto RunConnectionStormClients(const std::shared_ptr<ConnectionStormClients> &Options)
        -> Net::awaitable<void>
    {
        for (int Index = 0; Index < Options->Count; ++Index)
        {
            Net::co_spawn(Options->Executor, RunConnectionStormClient(Options, Index), Net::detached);
        }
        while (Options->Done->load(std::memory_order_acquire) < Options->Count)
        {
            Net::steady_timer Timer(Options->Executor);
            Timer.expires_after(std::chrono::milliseconds(10));
            co_await Timer.async_wait(Net::use_awaitable);
        }
    }

    struct StopAcceptingRequest final
    {
        Net::io_context &IoContext;
        Preview::Runtime::TcpListener &Listener;
        Preview::Fault::Code &StartResult;
        bool &Connected;
        bool &Refused;
    };

    /**
     * @brief 验证 listener 启动后接受连接，Stop 后拒绝新连接。
     * @param Request listener、执行器和连接结果槽。
     * @return 完成启动、连接、停止和拒绝检查的异步操作。
     */
    auto RunStopAcceptingScenario(StopAcceptingRequest Request)
        -> Net::awaitable<void>
    {
        Request.StartResult = co_await Request.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto ListenPort = Request.Listener.LocalEndpoint().port();

        std::error_code ErrorCode;
        Preview::Network::Dialer::Dialer Dialer(Request.IoContext.get_executor());
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), ListenPort});
        Preview::SharedTransmission Connection;
        if (Dialed)
        {
            Connection = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Preview::Fault::ToNative(Dialed.error());
        }
        Request.Connected = !ErrorCode;
        if (Connection)
        {
            (void)Connection->Close();
        }

        Request.Listener.Stop();
        ErrorCode.clear();
        auto RejectedDialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), ListenPort});
        Preview::SharedTransmission RejectedConnection;
        if (RejectedDialed)
        {
            RejectedConnection = std::move(*RejectedDialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Preview::Fault::ToNative(RejectedDialed.error());
        }
        Request.Refused = static_cast<bool>(ErrorCode) || RejectedConnection == nullptr;
        if (RejectedConnection)
        {
            (void)RejectedConnection->Close();
        }
    }

    struct ConnectionStormRequest final
    {
        Net::io_context &IoContext;
        Preview::Runtime::TcpListener &Listener;
        std::shared_ptr<Tcp::acceptor> EchoAcceptor;
        int ConnectionCount;
        std::shared_ptr<std::atomic<int>> Counters;
        std::shared_ptr<std::atomic<int>> Success;
    };

    /**
     * @brief 驱动多连接 accept、session 发布、echo 和自然 Shutdown。
     * @param Request listener、echo acceptor、连接数和统计 owner。
     * @return 完成启动、并发客户端、关闭 echo acceptor 的异步操作。
     */
    auto RunConnectionStormScenario(ConnectionStormRequest Request)
        -> Net::awaitable<void>
    {
        const auto StartResult = co_await Request.Listener.Start(
            Tcp::endpoint(Tcp::v4(), 0));
        EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
        if (StartResult != Preview::Fault::Code::Success)
        {
            co_return;
        }
        ConnectionStormClients Options{
            Request.IoContext.get_executor(), Request.Listener.LocalEndpoint().port(),
            Request.ConnectionCount, Request.Counters, Request.Success, Socks5Greeting()};
        co_await RunConnectionStormClients(
            std::make_shared<ConnectionStormClients>(std::move(Options)));
        co_await Request.Listener.Shutdown();
        boost::system::error_code ErrorCode;
        Request.EchoAcceptor->close(ErrorCode);
    }

    struct StopRaceRequest final
    {
        Net::io_context &IoContext;
        Preview::Runtime::TcpListener &Listener;
        Preview::Runtime::WorkerGroup &Workers;
        std::atomic<bool> &ReleaseBlocker;
    };

    /**
     * @brief 验证停止竞态丢弃排队 admission 并关闭 inbound transport。
     * @param Request listener、worker mailbox 和阻塞释放信号。
     * @return 完成启动、排队、Stop、worker 停止和尾部读取检查的异步操作。
     */
    auto RunStopRaceScenario(StopRaceRequest Request) -> Net::awaitable<void>
    {
        const auto StartResult = co_await Request.Listener.Start(
            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
        if (StartResult != Preview::Fault::Code::Success)
        {
            co_return;
        }

        std::error_code ErrorCode;
        Preview::Network::Dialer::Dialer Dialer(Request.IoContext.get_executor());
        auto Dialed = co_await Dialer.Connect({*Preview::Network::ParseHost("127.0.0.1"), Request.Listener.LocalEndpoint().port()});
        Preview::SharedTransmission Client;
        if (Dialed)
        {
            Client = std::move(*Dialed);
            ErrorCode.clear();
        }
        else
        {
            ErrorCode = Preview::Fault::ToNative(Dialed.error());
        }
        EXPECT_FALSE(ErrorCode);
        EXPECT_NE(Client, nullptr);
        if (ErrorCode || !Client)
        {
            co_return;
        }

        for (int Attempt = 0;
             Attempt < 100 && Request.Workers.Snapshot().front().MailboxSize == 0;
             ++Attempt)
        {
            Net::steady_timer Tick(Request.IoContext);
            Tick.expires_after(std::chrono::milliseconds(1));
            co_await Tick.async_wait(Net::use_awaitable);
        }
        EXPECT_EQ(Request.Workers.Snapshot().front().MailboxSize, std::size_t{1});
        if (Request.Workers.Snapshot().front().MailboxSize != std::size_t{1})
        {
            (void)Client->Close();
            co_return;
        }

        Request.Listener.Stop();
        Request.Workers.Stop();
        Request.ReleaseBlocker.store(true, std::memory_order_release);
        Request.ReleaseBlocker.notify_all();

        std::array<std::byte, 1> Buffer{};
        std::error_code ReadError;
        (void)co_await Preview::Testing::TailReadGuarded(Client, Buffer, ReadError);
        EXPECT_TRUE(ReadError);
        (void)Client->Close();
    }

} // namespace

TEST(TcpListener, StopStopsAccepting)
    {
        Net::io_context Ioc;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{12};
        ProcessOptions.Generation = Preview::GenerationId{22};
        ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.Factory =
            [](Preview::Runtime::SessionAdmission)
                -> std::shared_ptr<Preview::Runtime::Session>
        { return nullptr; };
        Preview::Runtime::TcpListener Listener(std::move(ListenerOptions));

        Preview::Fault::Code StartResult = Preview::Fault::Code::Success;
        bool Connected = false;
        bool Refused = false;
        RunCoro(Ioc, RunStopAcceptingScenario(
                         StopAcceptingRequest{Ioc, Listener, StartResult, Connected, Refused}));
        EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
        EXPECT_TRUE(Connected);
        EXPECT_TRUE(Refused);
    }

TEST(TcpListener, StartAfterStopIsRejected)
    {
        Net::io_context Ioc;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{33};
        ProcessOptions.Generation = Preview::GenerationId{49};
        ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.Factory =
            [](Preview::Runtime::SessionAdmission)
                -> std::shared_ptr<Preview::Runtime::Session>
        { return nullptr; };
        Preview::Runtime::TcpListener Listener(std::move(ListenerOptions));

        Preview::Fault::Code FirstResult = Preview::Fault::Code::GenericError;
        Preview::Fault::Code SecondResult = Preview::Fault::Code::GenericError;
        RunCoro(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                FirstResult = co_await Listener.Start(
                    Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                Listener.Stop();
                SecondResult = co_await Listener.Start(
                    Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
            });

        EXPECT_EQ(FirstResult, Preview::Fault::Code::Success);
        EXPECT_EQ(SecondResult, Preview::Fault::Code::InvalidArgument);
    }

TEST(TcpListener, DestroyAfterStopKeepsAcceptLoopStateAlive)
    {
        Net::io_context Ioc;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{16};
        ProcessOptions.Generation = Preview::GenerationId{26};
        ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());
        Preview::Fault::Code StartResult = Preview::Fault::Code::GenericError;
        {
            Preview::Runtime::TcpListener::Options ListenerOptions;
            ListenerOptions.Executor = Ioc.get_executor();
            ListenerOptions.Workers = &ProcessValue.Workers();
            ListenerOptions.Publication = ProcessOptions.Publication;
            ListenerOptions.Factory =
                [](Preview::Runtime::SessionAdmission)
                    -> std::shared_ptr<Preview::Runtime::Session>
            { return nullptr; };
            auto Listener = std::make_unique<Preview::Runtime::TcpListener>(
                std::move(ListenerOptions));
            RunCoro(Ioc,
                    [&]() -> Net::awaitable<void>
                    {
                        StartResult = co_await Listener->Start(
                            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                        Listener->Stop();
                    });
        }

        // Stop 的 accept completion 可能尚未被调度；共享 Lifetime 必须独立完成。
        Ioc.restart();
        Ioc.run();
        EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
        SUCCEED();
    }

TEST(TcpListener, DestructorStopsAccepting)
    {
        // P-H13：不显式 Stop()，listener 析构必须关闭 acceptor，
        // 且残留的 accept completion 不得再进入会话工厂。
        Net::io_context Ioc;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{17};
        ProcessOptions.Generation = Preview::GenerationId{27};
        ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());
        Tcp::endpoint Bound;
        std::atomic<int> FactoryCalls{0};
        {
            Preview::Runtime::TcpListener::Options ListenerOptions;
            ListenerOptions.Executor = Ioc.get_executor();
            ListenerOptions.Workers = &ProcessValue.Workers();
            ListenerOptions.Publication = ProcessOptions.Publication;
            ListenerOptions.Factory =
                [&FactoryCalls](Preview::Runtime::SessionAdmission)
                    -> std::shared_ptr<Preview::Runtime::Session>
            {
                FactoryCalls.fetch_add(1, std::memory_order_relaxed);
                return nullptr;
            };
            Preview::Runtime::TcpListener Listener(std::move(ListenerOptions));
            Preview::Fault::Code StartResult = Preview::Fault::Code::IoError;
            RunCoro(Ioc,
                    [&]() -> Net::awaitable<void>
                    {
                        StartResult = co_await Listener.Start(
                            Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
                        Bound = Listener.LocalEndpoint();
                    });
            EXPECT_EQ(StartResult, Preview::Fault::Code::Success);
            // 不调用 Stop()，直接让 listener 离开作用域
        }

        Tcp::socket Probe(Ioc);
        boost::system::error_code ErrorCode;
        const Tcp::endpoint Target(Net::ip::make_address("127.0.0.1"), Bound.port());
        Probe.connect(Target, ErrorCode);
        const bool Refused = static_cast<bool>(ErrorCode);
        if (!ErrorCode)
        {
            Probe.close();
        }
        EXPECT_TRUE(Refused) << "listener 析构后 acceptor 仍接受连接";

        // 让可能残留的 accept completion 有机会被调度
        Ioc.restart();
        RunCoro(Ioc,
                []() -> Net::awaitable<void>
                {
                    Net::steady_timer Timer(co_await Net::this_coro::executor);
                    Timer.expires_after(std::chrono::milliseconds(50));
                    boost::system::error_code TimerError;
                    co_await Timer.async_wait(
                        Net::redirect_error(Net::use_awaitable, TimerError));
                });
        EXPECT_EQ(FactoryCalls.load(std::memory_order_relaxed), 0) << "析构后仍有会话进入工厂";
    }

TEST(TcpListener, ConnectionStorm)
    {
        Net::io_context Ioc;
        auto EchoAcceptor = std::make_shared<Tcp::acceptor>(
            Ioc, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0));
        const auto EchoPort = EchoAcceptor->local_endpoint().port();
        Net::co_spawn(Ioc, RunConnectionStormEcho(EchoAcceptor, Ioc.get_executor()), Net::detached);

        constexpr int ConnectionCount = 20;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{18};
        ProcessOptions.Generation = Preview::GenerationId{28};
        ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        ProcessOptions.WorkerCount = 4;
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = Ioc.get_executor();
        ListenerOptions.Workers = &ProcessValue.Workers();
        ListenerOptions.Publication = ProcessOptions.Publication;
        std::atomic<int> SourceIpCaptured{0};
        ListenerOptions.Factory = ConnectionStormSessionFactory{
            &Ioc, EchoPort, &SourceIpCaptured, &ProcessValue.Workers()};
        Preview::Runtime::TcpListener Listener(std::move(ListenerOptions));

        auto Counters = std::make_shared<std::atomic<int>>(0);
        auto Success = std::make_shared<std::atomic<int>>(0);
        RunCoro(Ioc, RunConnectionStormScenario(ConnectionStormRequest{
                         Ioc, Listener, EchoAcceptor, ConnectionCount, Counters, Success}));
        EXPECT_EQ(Success->load(std::memory_order_relaxed), ConnectionCount);
        EXPECT_EQ(SourceIpCaptured.load(std::memory_order_relaxed), ConnectionCount);
    }

TEST(TcpListener, SessionIdsAreUniqueAcrossListenersInOneProcess)
    {
        Net::io_context ListenerIo;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{41};
        ProcessOptions.Generation = Preview::GenerationId{57};
        ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        ProcessOptions.WorkerCount = 1;
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        WorkerGroupRunner WorkerRunner(ProcessValue.Workers());

        auto Events = std::make_shared<SessionIdentityEvents>(ListenerIo.get_executor(), 2);
        auto Captured = std::make_shared<SessionIdentityCapture>();
        Preview::Runtime::TcpListener::Options FirstOptions;
        FirstOptions.Executor = ListenerIo.get_executor();
        FirstOptions.Workers = &ProcessValue.Workers();
        FirstOptions.Publication = ProcessOptions.Publication;
        FirstOptions.Factory = SessionIdentityFactory{
            Events, Captured, 0, &ProcessValue.Workers()};
        Preview::Runtime::TcpListener::Options SecondOptions;
        SecondOptions.Executor = ListenerIo.get_executor();
        SecondOptions.Workers = &ProcessValue.Workers();
        SecondOptions.Publication = ProcessOptions.Publication;
        SecondOptions.Factory = SessionIdentityFactory{
            Events, Captured, 1, &ProcessValue.Workers()};

        auto First = std::make_shared<Preview::Runtime::TcpListener>(std::move(FirstOptions));
        auto Second = std::make_shared<Preview::Runtime::TcpListener>(std::move(SecondOptions));
        auto Result = std::make_shared<SessionIdentityProbeResult>();
        RunCoro(ListenerIo, RunSessionIdentityProbe(SessionIdentityProbeRequest{
                                                         ListenerIo.get_executor(), First, Second,
                                                         Events, Result}));

        EXPECT_EQ(Result->FirstStart, Preview::Fault::Code::Success);
        EXPECT_EQ(Result->SecondStart, Preview::Fault::Code::Success);
        EXPECT_TRUE(Result->FirstConnected);
        EXPECT_TRUE(Result->SecondConnected);
        EXPECT_TRUE(Result->GreetingsWritten);
        EXPECT_EQ(Result->EventsReceived, 2U);
        const auto FirstSession = Captured->Values[0].load(std::memory_order_acquire);
        const auto SecondSession = Captured->Values[1].load(std::memory_order_acquire);
        EXPECT_GT(FirstSession, 0U);
        EXPECT_GT(SecondSession, 0U);
        EXPECT_NE(FirstSession, SecondSession);
        ASSERT_TRUE(Captured->PeerIpCaptured[0].load(std::memory_order_acquire));
        ASSERT_TRUE(Captured->PeerIpCaptured[1].load(std::memory_order_acquire));
        EXPECT_EQ(Captured->PeerIps[0], "127.0.0.1");
        EXPECT_EQ(Captured->PeerIps[1], "127.0.0.1");
    }

TEST(TcpListener, StopRaceDiscardsQueuedAdmissionAndClosesTransport)
    {
        Net::io_context ListenerIo;
        Preview::Runtime::Process::Options ProcessOptions;
        ProcessOptions.Id = Preview::ProcessId{32};
        ProcessOptions.Generation = Preview::GenerationId{48};
        ProcessOptions.Publication = Preview::Testing::Runtime::MakeListenerTestPublication(
            ProcessOptions.Generation);
        ProcessOptions.WorkerCount = 1;
        ProcessOptions.MailboxCapacity = 2;
        Preview::Runtime::Process ProcessValue(ProcessOptions);
        auto &Workers = ProcessValue.Workers();
        auto *WorkerValue = Workers.Find(Preview::WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        WorkerGroupRunner Runner(Workers);

        std::atomic<bool> BlockerStarted{false};
        std::atomic<bool> ReleaseBlocker{false};
        ASSERT_EQ(Workers.Dispatch(
                      Preview::WorkerId{1}, Preview::GenerationId{48},
                      [&BlockerStarted, &ReleaseBlocker]
                      {
                          BlockerStarted.store(true, std::memory_order_release);
                          BlockerStarted.notify_all();
                          while (!ReleaseBlocker.load(std::memory_order_acquire))
                          {
                              ReleaseBlocker.wait(false, std::memory_order_acquire);
                          }
                      }),
                  Preview::Runtime::WorkerDispatchResult::Accepted);
        while (!BlockerStarted.load(std::memory_order_acquire))
        {
            BlockerStarted.wait(false, std::memory_order_acquire);
        }

        std::atomic<int> FactoryCalls{0};
        Preview::Runtime::TcpListener::Options ListenerOptions;
        ListenerOptions.Executor = ListenerIo.get_executor();
        ListenerOptions.Workers = &Workers;
        ListenerOptions.Publication = ProcessOptions.Publication;
        ListenerOptions.Factory =
            [&FactoryCalls](Preview::Runtime::SessionAdmission)
                -> std::shared_ptr<Preview::Runtime::Session>
        {
            FactoryCalls.fetch_add(1, std::memory_order_relaxed);
            return std::make_shared<Preview::Runtime::Session>(Preview::Runtime::SessionOptions{});
        };
        Preview::Runtime::TcpListener Listener(std::move(ListenerOptions));

        RunCoro(ListenerIo, RunStopRaceScenario(
                              StopRaceRequest{ListenerIo, Listener, Workers, ReleaseBlocker}));
        EXPECT_EQ(FactoryCalls.load(std::memory_order_acquire), 0);
        ReleaseBlocker.store(true, std::memory_order_release);
        ReleaseBlocker.notify_all();
    }

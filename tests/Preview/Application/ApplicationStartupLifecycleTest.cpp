/**
 * @file ApplicationStartupLifecycleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ApplicationTestSupport.hpp"

#include <Preview/Application/BoundaryStartup.hpp>
#include <Preview/Application/OperationsBootstrap.hpp>

namespace
{

    /**
     * @brief 等待应用运行线程自然返回或达到原有 watchdog 上限。
     * @details io_context、运行状态和完成标志均由调用测试持有至 run 返回；
     *          该命名协程本身不借用临时 coroutine lambda 的 closure。
     */
    auto WaitForApplicationRun(
        Net::io_context &Io,
        const std::atomic<bool> &RunReturned,
        bool &WaitFinished) -> Net::awaitable<void>
    {
        for (std::size_t Attempt = 0; Attempt < 100 &&
                                             !RunReturned.load(std::memory_order_acquire);
             ++Attempt)
        {
            Net::steady_timer Timer(Io);
            Timer.expires_after(std::chrono::milliseconds(2));
            co_await Timer.async_wait(Net::use_awaitable);
        }
        WaitFinished = true;
    }

}

TEST(PreviewApplication, BootstrapIdentityCreationUsesFreshValues)
{
    const auto First = Preview::Application::OperationsBootstrap::CreateIdentity(
        Preview::ProcessId{7});
    const auto Second = Preview::Application::OperationsBootstrap::CreateIdentity(
        Preview::ProcessId{7});

    ASSERT_TRUE(First.has_value());
    ASSERT_TRUE(Second.has_value());
    EXPECT_NE((*First)->ProcessIncarnation(), (*Second)->ProcessIncarnation());
    EXPECT_NE((*First)->Token(), (*Second)->Token());
}

TEST(PreviewApplication, SuccessfulStopReleasesBackendBeforeApplicationDestruction)
{
    TemporaryConfiguration FirstConfig(FindFreePort(), ConfigurationShape{.OperationsPort = FindFreePort()});
    Preview::Application::Application First(MakeOptions(FirstConfig.Path()));
    ASSERT_TRUE(First.Start().has_value());
    First.Stop();
    ASSERT_EQ(First.Run(), 0);
    TemporaryConfiguration NextConfig(FindFreePort(), ConfigurationShape{.OperationsPort = FindFreePort()});
    Preview::Application::Application Next(MakeOptions(NextConfig.Path()));
    const auto Started = Next.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Next.Stop();
    EXPECT_EQ(Next.Run(), 0);
}

TEST(PreviewApplication, OperationsBindFailureReleasesListenerAndBackendWhileApplicationLives)
{
    Net::io_context Io;
    Tcp::acceptor Occupied(Io);
    Occupied.open(Tcp::v4());
#if defined(_WIN32)
    const BOOL Exclusive = TRUE;
    ASSERT_EQ(::setsockopt(Occupied.native_handle(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char*>(&Exclusive), sizeof(Exclusive)), 0);
#endif
    Occupied.bind(Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
    Occupied.listen();
    const auto TcpPort = FindFreePort();
    TemporaryConfiguration Invalid(TcpPort,
        ConfigurationShape{.OperationsPort = Occupied.local_endpoint().port()});
    std::ostringstream Output;
    Preview::Application::Application Failed(MakeOptions(Invalid.Path(), &Output));
    const auto Rejected = Failed.Start();
    ASSERT_FALSE(Rejected.has_value());
    EXPECT_EQ(Rejected.error().Code, Preview::Application::StartupErrorCode::Bind);
    EXPECT_TRUE(Output.str().empty());
    EXPECT_FALSE(Failed.IsReady());
    TemporaryConfiguration Valid(TcpPort, ConfigurationShape{.OperationsPort = FindFreePort()});
    Preview::Application::Application Next(MakeOptions(Valid.Path()));
    const auto Started = Next.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Next.Stop();
    EXPECT_EQ(Next.Run(), 0);
}

TEST(PreviewApplication, NativeTlsConstructionFailureReleasesBackendWhileApplicationLives)
{
    TemporaryConfiguration Invalid(FindFreePort(), ConfigurationShape{
        .NativeTls = R"({"Enabled":true,"CertificateFile":"MissingTask2Certificate.pem","PrivateKeyFile":"MissingTask2Key.pem"})",
        .OperationsPort = FindFreePort()});
    std::ostringstream Output;
    Preview::Application::Application Failed(MakeOptions(Invalid.Path(), &Output));
    const auto Rejected = Failed.Start();
    ASSERT_FALSE(Rejected.has_value());
    EXPECT_TRUE(Rejected.error().Path.starts_with("NativeTls"));
    EXPECT_TRUE(Output.str().empty());
    EXPECT_FALSE(Failed.IsReady());
    TemporaryConfiguration Valid(FindFreePort(), ConfigurationShape{.OperationsPort = FindFreePort()});
    Preview::Application::Application Next(MakeOptions(Valid.Path()));
    const auto Started = Next.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Next.Stop();
    EXPECT_EQ(Next.Run(), 0);
}

TEST(PreviewApplication, DatagramBindFailureReleasesTcpAndBackendWhileApplicationLives)
{
    Net::io_context Io;
    Net::ip::udp::socket Occupied(Io, Net::ip::udp::v4());
#if defined(_WIN32)
    const BOOL Exclusive = TRUE;
    ASSERT_EQ(::setsockopt(Occupied.native_handle(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
        reinterpret_cast<const char*>(&Exclusive), sizeof(Exclusive)), 0);
#endif
    Occupied.bind(Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
    const auto Udp = std::string(R"([{"Id":"udp-task2","Address":"127.0.0.1","Port":)") +
        std::to_string(Occupied.local_endpoint().port()) + R"(,"Timeout":5000}])";
    const auto TcpPort = FindFreePort();
    TemporaryConfiguration Invalid(TcpPort,
        ConfigurationShape{.Udp = Udp, .OperationsPort = FindFreePort()});
    std::ostringstream Output;
    Preview::Application::Application Failed(MakeOptions(Invalid.Path(), &Output));
    const auto Rejected = Failed.Start();
    ASSERT_FALSE(Rejected.has_value());
    EXPECT_EQ(Rejected.error().Code, Preview::Application::StartupErrorCode::Bind);
    EXPECT_EQ(Rejected.error().Path, "Listeners.Udp[0]");
    EXPECT_TRUE(Output.str().empty());
    EXPECT_FALSE(Failed.IsReady());
    Occupied.close();
    TemporaryConfiguration Valid(TcpPort,
        ConfigurationShape{.Udp = Udp, .OperationsPort = FindFreePort()});
    Preview::Application::Application Next(MakeOptions(Valid.Path()));
    const auto Started = Next.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    EXPECT_TRUE(Started->UdpReady);
    Next.Stop();
    EXPECT_EQ(Next.Run(), 0);
}

TEST(PreviewApplication, ReadinessOutputExceptionRollsBackBoundRuntime)
{
    class RejectOutput final : public std::streambuf
    {
        auto overflow(const int_type) -> int_type override { return traits_type::eof(); }
    } Buffer;
    std::ostream Output(&Buffer);
    Output.exceptions(std::ios::badbit | std::ios::failbit);
    const auto TcpPort = FindFreePort();
    const auto OperationsPort = FindFreePort();
    TemporaryConfiguration Invalid(TcpPort, ConfigurationShape{.OperationsPort = OperationsPort});
    Preview::Application::Application Failed(MakeOptions(Invalid.Path(), &Output));
    const auto Rejected = Failed.Start();
    ASSERT_FALSE(Rejected.has_value());
    EXPECT_EQ(Rejected.error().Code, Preview::Application::StartupErrorCode::Runtime);
    EXPECT_FALSE(Failed.IsReady());
    TemporaryConfiguration Valid(TcpPort, ConfigurationShape{.OperationsPort = OperationsPort});
    Preview::Application::Application Next(MakeOptions(Valid.Path()));
    const auto Started = Next.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Next.Stop();
    EXPECT_EQ(Next.Run(), 0);
}

TEST(PreviewApplication, RejectsInvalidConfiguration)
{
    const auto Path = std::filesystem::temp_directory_path() / "PrismPreview-invalid.json";
    {
        std::ofstream File(Path, std::ios::binary);
        File << R"({"SchemaVersion":1})";
    }

    Preview::Application::Application Application(MakeOptions(Path));
    const auto Result = Application.Start();

    EXPECT_FALSE(Result);
    ASSERT_FALSE(Application.IsReady());
    if (!Result)
    {
        EXPECT_EQ(Result.error().Code,
                  Preview::Application::StartupErrorCode::InvalidConfiguration);
    }

    std::error_code Error;
    std::filesystem::remove(Path, Error);
}

TEST(PreviewApplication, InjectsAccountSecretIntoGeneration)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Protocols = ValidVlessProtocol,
                           .Credential = "not-a-uuid",
                           .SecretRef = "application-account-secret"});

    Preview::Application::Application WithoutResolver(MakeOptions(Configuration.Path()));
    const auto Missing = WithoutResolver.Start();

    ASSERT_FALSE(Missing);
    EXPECT_EQ(Missing.error().Code,
              Preview::Application::StartupErrorCode::InvalidConfiguration);
    EXPECT_EQ(Missing.error().Path, "Accounts[0].SecretRef");

    auto Options = MakeOptions(Configuration.Path());
    Options.SecretResolver = [](const std::string_view Reference)
        -> std::optional<std::string>
    {
        if (Reference == "application-account-secret")
        {
            return std::string(VmessUuid);
        }
        return std::nullopt;
    };
    Preview::Application::Application WithResolver(Options);
    const auto Started = WithResolver.Start();

    ASSERT_TRUE(Started)
        << (Started ? std::string{} : Started.error().Path + ": " + Started.error().Message);
    EXPECT_TRUE(WithResolver.IsReady());
    WithResolver.Stop();
    EXPECT_EQ(WithResolver.Run(), 0);
    EXPECT_TRUE(WithResolver.IsStopped());
}

TEST(PreviewApplication, RejectsMissingConfiguration)
{
    const auto Path = std::filesystem::temp_directory_path() / "PrismPreview-missing.json";
    std::error_code Error;
    std::filesystem::remove(Path, Error);

    Preview::Application::Application Application(MakeOptions(Path));
    const auto Result = Application.Start();

    EXPECT_FALSE(Result);
    ASSERT_FALSE(Application.IsReady());
    if (!Result)
    {
        EXPECT_EQ(Result.error().Code,
                  Preview::Application::StartupErrorCode::MissingConfiguration);
    }
}

TEST(PreviewApplication, BindsLoopbackAndPublishesReadiness)
{
    TemporaryConfiguration Configuration(19081);
    std::ostringstream Output;
    Preview::Application::Application Application(MakeOptions(Configuration.Path(), &Output));

    const auto Result = Application.Start();

    ASSERT_TRUE(Result);
    EXPECT_TRUE(Application.IsReady());
    EXPECT_EQ(Result->Port, 19081U);
    EXPECT_NE(Output.str().find(
                  "PrismPreview READY tcp_port=19081 udp_port=0 udp_ready=false quic_ready=false generation=1"),
              std::string::npos);

    boost::asio::io_context Io;
    boost::asio::ip::tcp::socket Socket(Io);
    boost::system::error_code Error;
    const boost::asio::ip::tcp::endpoint Endpoint{
        boost::asio::ip::make_address("127.0.0.1"), Result->Port};
    Socket.connect(Endpoint, Error);
    EXPECT_FALSE(Error);
    Socket.close(Error);

    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
    EXPECT_TRUE(Application.IsStopped());
}

TEST(PreviewApplication, ServesOperationsHealthOverLoopback)
{
    ConfigurationShape Shape;
    Shape.OperationsPort = FindFreePort();
    TemporaryConfiguration Configuration(FindFreePort(), Shape);
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_TRUE(Result)
        << (Result ? std::string{} :
            Result.error().Path + ": " + Result.error().Message);
    ASSERT_NE(Result->OperationsPort, 0U);
    int ExitCode = 0;
    std::thread Thread([&]
                        { ExitCode = Application.Run(); });
    Net::io_context Io;
    Tcp::socket Socket(Io);
    boost::system::error_code Error;
    Socket.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Result->OperationsPort), Error);
    ASSERT_FALSE(Error);
    ASSERT_TRUE(WriteBytes(Socket,
                           "GET /Operations/Health HTTP/1.1\r\nHost: 127.0.0.1:" +
                               std::to_string(Result->OperationsPort) + "\r\n\r\n"));
    const auto Response = ReadHttpResponse(Socket);
    EXPECT_NE(Response.find("HTTP/1.1 200"), std::string::npos);
    EXPECT_NE(Response.find("\"ready\":true"), std::string::npos);

    Application.Stop();
    Thread.join();
    EXPECT_EQ(ExitCode, 0);
}

TEST(PreviewApplication, StopIsIdempotent)
{
    TemporaryConfiguration Configuration(19082);
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));
    ASSERT_TRUE(Application.Start());

    Application.Stop();
    Application.Stop();

    EXPECT_EQ(Application.Run(), 0);
    EXPECT_TRUE(Application.IsStopped());
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}

TEST(PreviewApplication, RejectsStartAfterStop)
{
    TemporaryConfiguration Configuration(FindFreePort());
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));
    ASSERT_TRUE(Application.Start());

    Application.Stop();

    const auto Restart = Application.Start();

    EXPECT_FALSE(Restart);
    EXPECT_FALSE(Application.IsReady());
}

TEST(PreviewApplication, EnforcesShutdownTimeoutForStalledOperationsConnection)
{
    ConfigurationShape Shape;
    Shape.OperationsPort = FindFreePort();
    Shape.ShutdownTimeout = 50;
    TemporaryConfiguration Configuration(FindFreePort(), Shape);
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Started = Application.Start();
    ASSERT_TRUE(Started);
    ASSERT_NE(Started->OperationsPort, 0U);

    std::atomic<bool> RunReturned{false};
    std::thread Thread([&]
                       {
                           (void)Application.Run();
                           RunReturned.store(true, std::memory_order_release);
                       });

    Net::io_context Io;
    Tcp::socket Socket(Io);
    boost::system::error_code Error;
    Socket.connect(
        Tcp::endpoint(Net::ip::address_v4::loopback(), Started->OperationsPort), Error);
    ASSERT_FALSE(Error);

    Application.Stop();

    bool WaitFinished = false;
    Net::co_spawn(
        Io,
        WaitForApplicationRun(Io, RunReturned, WaitFinished),
        Net::detached);
    Io.run();

    EXPECT_TRUE(WaitFinished);
    EXPECT_TRUE(RunReturned.load(std::memory_order_acquire));

    boost::system::error_code CloseError;
    Socket.close(CloseError);
    if (Thread.joinable())
    {
        Thread.join();
    }
}

TEST(PreviewApplication, HandlesSigintAndStopsIdempotently)
{
    TemporaryConfiguration Configuration(19085);
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));
    ASSERT_TRUE(Application.Start());

    EXPECT_EQ(std::raise(SIGINT), 0);
    EXPECT_EQ(Application.Run(), 0);
    EXPECT_TRUE(Application.IsStopped());
    Application.Stop();
}

TEST(PreviewApplication, RejectsFailedBindWithoutReadiness)
{
    TemporaryConfiguration Configuration(
        19083, ConfigurationShape{.Address = "invalid-bind-address"});

    std::ostringstream Output;
    Preview::Application::Application Second(MakeOptions(Configuration.Path(), &Output));
    const auto Result = Second.Start();

    EXPECT_FALSE(Result);
    EXPECT_FALSE(Second.IsReady());
    EXPECT_TRUE(Output.str().empty());
    if (!Result)
    {
        EXPECT_EQ(Result.error().Code, Preview::Application::StartupErrorCode::Bind);
    }

}

TEST(PreviewApplication, BindPreflightAllowsRecentlyClosedListenerPort)
{
    Net::io_context Io;
    Tcp::acceptor Listener(Io);
    boost::system::error_code Error;
    Listener.open(Tcp::v4(), Error);
    ASSERT_FALSE(Error);
    Listener.set_option(Tcp::acceptor::reuse_address(true), Error);
    ASSERT_FALSE(Error);
    Listener.bind(Tcp::endpoint(Net::ip::address_v4::loopback(), 0), Error);
    ASSERT_FALSE(Error);
    Listener.listen(Net::socket_base::max_listen_connections, Error);
    ASSERT_FALSE(Error);
    const auto Endpoint = Listener.local_endpoint(Error);
    ASSERT_FALSE(Error);

    const auto Occupied = Preview::Application::BoundaryStartup::CheckBindAvailable(Endpoint);
    ASSERT_FALSE(Occupied.has_value()) << "preflight accepted a listener that is still bound";

    Tcp::socket Client(Io);
    Client.connect(Endpoint, Error);
    ASSERT_FALSE(Error);
    Tcp::socket Accepted(Io);
    Listener.accept(Accepted, Error);
    ASSERT_FALSE(Error);

    const std::array<char, 1> Payload{'x'};
    ASSERT_EQ(Accepted.write_some(Net::buffer(Payload), Error), Payload.size());
    ASSERT_FALSE(Error);
    Accepted.shutdown(Tcp::socket::shutdown_send, Error);
    ASSERT_FALSE(Error);

    std::array<char, 1> Received{};
    EXPECT_EQ(Client.read_some(Net::buffer(Received), Error), Payload.size());
    EXPECT_FALSE(Error);
    Error.clear();
    EXPECT_EQ(Client.read_some(Net::buffer(Received), Error), 0U);
    EXPECT_EQ(Error, Net::error::eof);

    Client.close(Error);
    ASSERT_FALSE(Error);
    Error.clear();
    EXPECT_EQ(Accepted.read_some(Net::buffer(Received), Error), 0U);
    EXPECT_EQ(Error, Net::error::eof);

    Accepted.close(Error);
    ASSERT_FALSE(Error);
    Listener.close(Error);
    ASSERT_FALSE(Error);

    const auto Available = Preview::Application::BoundaryStartup::CheckBindAvailable(Endpoint);
    ASSERT_TRUE(Available.has_value()) << Available.error().Message;

    TemporaryConfiguration Config(Endpoint.port(),
        ConfigurationShape{.OperationsPort = FindFreePort()});
    Preview::Application::Application Application(MakeOptions(Config.Path()));
    const auto Started = Application.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}

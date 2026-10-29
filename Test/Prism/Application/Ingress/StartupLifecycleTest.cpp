/**
 * @file StartupLifecycleTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "../Startup/StartupSupport.hpp"

#include <Prism/Application/Startup/Detail/BoundaryServices.hpp>
#include <Prism/Application/Startup/Detail/Operations.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <utility>

namespace
{

    class TemporaryWebDirectory final
    {
    public:
        explicit TemporaryWebDirectory(const std::filesystem::path &ConfigurationPath)
            : Path_(ConfigurationPath.parent_path() /
                   (ConfigurationPath.stem().string() + "-web"))
        {
        }

        ~TemporaryWebDirectory()
        {
            if (Created_)
            {
                std::error_code Error;
                std::filesystem::remove_all(Path_, Error);
            }
        }

        TemporaryWebDirectory(const TemporaryWebDirectory &) = delete;
        auto operator=(const TemporaryWebDirectory &) -> TemporaryWebDirectory & = delete;

        [[nodiscard]] auto Path() const -> const std::filesystem::path &
        {
            return Path_;
        }

        [[nodiscard]] auto RelativeEmptyChild() const -> std::filesystem::path
        {
            return Path_.filename() / "empty";
        }

        [[nodiscard]] auto CreateInvalidCatalog() const -> bool
        {
            std::error_code Error;
            Created_ = std::filesystem::create_directory(Path_, Error);
            if (Error || !Created_)
            {
                return false;
            }
            std::ofstream File(Path_ / "catalog.json", std::ios::binary);
            File << "invalid catalog";
            File.flush();
            return static_cast<bool>(File);
        }

        [[nodiscard]] auto CreateEmptyChild() const -> bool
        {
            if (!Created_)
            {
                return false;
            }
            std::error_code Error;
            return std::filesystem::create_directory(Path_ / "empty", Error) && !Error;
        }

    private:
        std::filesystem::path Path_;
        mutable bool Created_{false};
    };

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

TEST(PrismApplication, WebDirectoryIsOptionalAndConfigurableAtStartup)
{
    {
        TemporaryConfiguration Configuration(FindFreePort(), ConfigurationShape{
            .OperationsPort = FindFreePort(),
            .OperationsWebDirectoryJson = "null"});
        TemporaryWebDirectory WebDirectory(Configuration.Path());
        auto Options = MakeOptions(Configuration.Path());
        Options.OperationsWebDirectory = WebDirectory.Path() / "missing";
        Prism::Application::Application Application(std::move(Options));

        const auto Started = Application.Start();

        ASSERT_TRUE(Started.has_value()) << "missing optional web directory blocked startup";
        Application.Stop();
        EXPECT_EQ(Application.Run(), 0);
    }
    {
        TemporaryConfiguration Configuration(FindFreePort(), ConfigurationShape{
            .OperationsPort = FindFreePort(),
            .OperationsWebDirectoryJson = "null"});
        TemporaryWebDirectory WebDirectory(Configuration.Path());
        ASSERT_TRUE(WebDirectory.CreateInvalidCatalog());
        auto Options = MakeOptions(Configuration.Path());
        Options.OperationsWebDirectory = WebDirectory.Path();
        Prism::Application::Application Application(std::move(Options));

        const auto Started = Application.Start();

        ASSERT_FALSE(Started.has_value());
        EXPECT_EQ(Started.error().Code, Prism::Application::StartupErrorCode::Runtime);
        EXPECT_EQ(Started.error().Path, "Operations.Web");
    }
    {
        TemporaryConfiguration Configuration(FindFreePort(), ConfigurationShape{
            .OperationsPort = FindFreePort(),
            .OperationsWebDirectoryJson = "\"\""});
        TemporaryWebDirectory WebDirectory(Configuration.Path());
        ASSERT_TRUE(WebDirectory.CreateInvalidCatalog());
        auto Options = MakeOptions(Configuration.Path());
        Options.OperationsWebDirectory = WebDirectory.Path();
        Prism::Application::Application Application(std::move(Options));

        const auto Started = Application.Start();

        ASSERT_TRUE(Started.has_value()) << "empty web directory enabled host fallback";
        Application.Stop();
        EXPECT_EQ(Application.Run(), 0);
    }
    {
        TemporaryWebDirectory WebDirectory(std::filesystem::temp_directory_path() /
            ("PrismApplication-" + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()) + ".json"));
        ASSERT_TRUE(WebDirectory.CreateInvalidCatalog());
        ASSERT_TRUE(WebDirectory.CreateEmptyChild());
        const auto RelativeDirectory = WebDirectory.RelativeEmptyChild().generic_string();
        const auto WebDirectoryJson = std::string("\"") + RelativeDirectory + "\"";
        TemporaryConfiguration Configuration(FindFreePort(), ConfigurationShape{
            .OperationsPort = FindFreePort(),
            .OperationsWebDirectoryJson = WebDirectoryJson});
        auto Options = MakeOptions(Configuration.Path());
        Options.OperationsWebDirectory = WebDirectory.Path();
        Prism::Application::Application Application(std::move(Options));

        const auto Started = Application.Start();

        ASSERT_TRUE(Started.has_value()) << "missing catalog in configured directory blocked startup";
        Application.Stop();
        EXPECT_EQ(Application.Run(), 0);
    }
}

TEST(PrismApplication, BootstrapIdentityCreationUsesFreshValues)
{
    const auto First = Prism::Application::Startup::OperationsPhase::CreateIdentity(
        Prism::ProcessId{7});
    const auto Second = Prism::Application::Startup::OperationsPhase::CreateIdentity(
        Prism::ProcessId{7});

    ASSERT_TRUE(First.has_value());
    ASSERT_TRUE(Second.has_value());
    EXPECT_NE((*First)->ProcessIncarnation(), (*Second)->ProcessIncarnation());
    EXPECT_NE((*First)->Token(), (*Second)->Token());
}

TEST(PrismApplication, SuccessfulStopReleasesBackendBeforeApplicationDestruction)
{
    TemporaryConfiguration FirstConfig(FindFreePort(), ConfigurationShape{.OperationsPort = FindFreePort()});
    Prism::Application::Application First(MakeOptions(FirstConfig.Path()));
    ASSERT_TRUE(First.Start().has_value());
    First.Stop();
    ASSERT_EQ(First.Run(), 0);
    TemporaryConfiguration NextConfig(FindFreePort(), ConfigurationShape{.OperationsPort = FindFreePort()});
    Prism::Application::Application Next(MakeOptions(NextConfig.Path()));
    const auto Started = Next.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Next.Stop();
    EXPECT_EQ(Next.Run(), 0);
}

TEST(PrismApplication, OperationsBindFailureReleasesListenerAndBackendWhileApplicationLives)
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
    Prism::Application::Application Failed(MakeOptions(Invalid.Path(), &Output));
    const auto Rejected = Failed.Start();
    ASSERT_FALSE(Rejected.has_value());
    EXPECT_EQ(Rejected.error().Code, Prism::Application::StartupErrorCode::Bind);
    EXPECT_TRUE(Output.str().empty());
    EXPECT_FALSE(Failed.IsReady());
    TemporaryConfiguration Valid(TcpPort, ConfigurationShape{.OperationsPort = FindFreePort()});
    Prism::Application::Application Next(MakeOptions(Valid.Path()));
    const auto Started = Next.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Next.Stop();
    EXPECT_EQ(Next.Run(), 0);
}

TEST(PrismApplication, NativeTlsConstructionFailureReleasesBackendWhileApplicationLives)
{
    TemporaryConfiguration Invalid(FindFreePort(), ConfigurationShape{
        .NativeTls = R"({"Enabled":true,"CertificateFile":"MissingTask2Certificate.pem","PrivateKeyFile":"MissingTask2Key.pem"})",
        .OperationsPort = FindFreePort()});
    std::ostringstream Output;
    Prism::Application::Application Failed(MakeOptions(Invalid.Path(), &Output));
    const auto Rejected = Failed.Start();
    ASSERT_FALSE(Rejected.has_value());
    EXPECT_TRUE(Rejected.error().Path.starts_with("NativeTls"));
    EXPECT_TRUE(Output.str().empty());
    EXPECT_FALSE(Failed.IsReady());
    TemporaryConfiguration Valid(FindFreePort(), ConfigurationShape{.OperationsPort = FindFreePort()});
    Prism::Application::Application Next(MakeOptions(Valid.Path()));
    const auto Started = Next.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Next.Stop();
    EXPECT_EQ(Next.Run(), 0);
}

TEST(PrismApplication, DatagramBindFailureReleasesTcpAndBackendWhileApplicationLives)
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
    Prism::Application::Application Failed(MakeOptions(Invalid.Path(), &Output));
    const auto Rejected = Failed.Start();
    ASSERT_FALSE(Rejected.has_value());
    EXPECT_EQ(Rejected.error().Code, Prism::Application::StartupErrorCode::Bind);
    EXPECT_EQ(Rejected.error().Path, "Listeners.Udp[0]");
    EXPECT_TRUE(Output.str().empty());
    EXPECT_FALSE(Failed.IsReady());
    Occupied.close();
    TemporaryConfiguration Valid(TcpPort,
        ConfigurationShape{.Udp = Udp, .OperationsPort = FindFreePort()});
    Prism::Application::Application Next(MakeOptions(Valid.Path()));
    const auto Started = Next.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    EXPECT_TRUE(Started->UdpReady);
    Next.Stop();
    EXPECT_EQ(Next.Run(), 0);
}

TEST(PrismApplication, ReadinessOutputExceptionRollsBackBoundRuntime)
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
    Prism::Application::Application Failed(MakeOptions(Invalid.Path(), &Output));
    const auto Rejected = Failed.Start();
    ASSERT_FALSE(Rejected.has_value());
    EXPECT_EQ(Rejected.error().Code, Prism::Application::StartupErrorCode::Runtime);
    EXPECT_FALSE(Failed.IsReady());
    TemporaryConfiguration Valid(TcpPort, ConfigurationShape{.OperationsPort = OperationsPort});
    Prism::Application::Application Next(MakeOptions(Valid.Path()));
    const auto Started = Next.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Next.Stop();
    EXPECT_EQ(Next.Run(), 0);
}

TEST(PrismApplication, RejectsInvalidConfiguration)
{
    const auto Path = std::filesystem::temp_directory_path() / "Prism-invalid.json";
    {
        std::ofstream File(Path, std::ios::binary);
        File << R"({"SchemaVersion":1})";
    }

    Prism::Application::Application Application(MakeOptions(Path));
    const auto Result = Application.Start();

    EXPECT_FALSE(Result);
    ASSERT_FALSE(Application.IsReady());
    if (!Result)
    {
        EXPECT_EQ(Result.error().Code,
                  Prism::Application::StartupErrorCode::InvalidConfiguration);
    }

    std::error_code Error;
    std::filesystem::remove(Path, Error);
}

TEST(PrismApplication, InjectsAccountSecretIntoGeneration)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Protocols = ValidVlessProtocol,
                           .Credential = "not-a-uuid",
                           .SecretRef = "application-account-secret"});

    Prism::Application::Application WithoutResolver(MakeOptions(Configuration.Path()));
    const auto Missing = WithoutResolver.Start();

    ASSERT_FALSE(Missing);
    EXPECT_EQ(Missing.error().Code,
              Prism::Application::StartupErrorCode::InvalidConfiguration);
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
    Prism::Application::Application WithResolver(Options);
    const auto Started = WithResolver.Start();

    ASSERT_TRUE(Started)
        << (Started ? std::string{} : Started.error().Path + ": " + Started.error().Message);
    EXPECT_TRUE(WithResolver.IsReady());
    WithResolver.Stop();
    EXPECT_EQ(WithResolver.Run(), 0);
    EXPECT_TRUE(WithResolver.IsStopped());
}

TEST(PrismApplication, RejectsMissingConfiguration)
{
    const auto Path = std::filesystem::temp_directory_path() / "Prism-missing.json";
    std::error_code Error;
    std::filesystem::remove(Path, Error);

    Prism::Application::Application Application(MakeOptions(Path));
    const auto Result = Application.Start();

    EXPECT_FALSE(Result);
    ASSERT_FALSE(Application.IsReady());
    if (!Result)
    {
        EXPECT_EQ(Result.error().Code,
                  Prism::Application::StartupErrorCode::MissingConfiguration);
    }
}

TEST(PrismApplication, BindsLoopbackAndPublishesReadiness)
{
    TemporaryConfiguration Configuration(19081);
    std::ostringstream Output;
    Prism::Application::Application Application(MakeOptions(Configuration.Path(), &Output));

    const auto Result = Application.Start();

    ASSERT_TRUE(Result);
    EXPECT_TRUE(Application.IsReady());
    EXPECT_EQ(Result->Port, 19081U);
    EXPECT_NE(Output.str().find(
                  "Prism READY tcp_port=19081 udp_port=0 udp_ready=false quic_ready=false generation=1"),
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

TEST(PrismApplication, ServesOperationsHealthOverLoopback)
{
    ConfigurationShape Shape;
    Shape.OperationsPort = FindFreePort();
    TemporaryConfiguration Configuration(FindFreePort(), Shape);
    Prism::Application::Application Application(MakeOptions(Configuration.Path()));

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

TEST(PrismApplication, StopIsIdempotent)
{
    TemporaryConfiguration Configuration(19082);
    Prism::Application::Application Application(MakeOptions(Configuration.Path()));
    ASSERT_TRUE(Application.Start());

    Application.Stop();
    Application.Stop();

    EXPECT_EQ(Application.Run(), 0);
    EXPECT_TRUE(Application.IsStopped());
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}

TEST(PrismApplication, RejectsStartAfterStop)
{
    TemporaryConfiguration Configuration(FindFreePort());
    Prism::Application::Application Application(MakeOptions(Configuration.Path()));
    ASSERT_TRUE(Application.Start());

    Application.Stop();

    const auto Restart = Application.Start();

    EXPECT_FALSE(Restart);
    EXPECT_FALSE(Application.IsReady());
}

TEST(PrismApplication, EnforcesShutdownTimeoutForStalledOperationsConnection)
{
    ConfigurationShape Shape;
    Shape.OperationsPort = FindFreePort();
    Shape.ShutdownTimeout = 50;
    TemporaryConfiguration Configuration(FindFreePort(), Shape);
    Prism::Application::Application Application(MakeOptions(Configuration.Path()));

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

TEST(PrismApplication, HandlesSigintAndStopsIdempotently)
{
    TemporaryConfiguration Configuration(19085);
    Prism::Application::Application Application(MakeOptions(Configuration.Path()));
    ASSERT_TRUE(Application.Start());

    EXPECT_EQ(std::raise(SIGINT), 0);
    EXPECT_EQ(Application.Run(), 0);
    EXPECT_TRUE(Application.IsStopped());
    Application.Stop();
}

TEST(PrismApplication, RejectsFailedBindWithoutReadiness)
{
    TemporaryConfiguration Configuration(
        19083, ConfigurationShape{.Address = "invalid-bind-address"});

    std::ostringstream Output;
    Prism::Application::Application Second(MakeOptions(Configuration.Path(), &Output));
    const auto Result = Second.Start();

    EXPECT_FALSE(Result);
    EXPECT_FALSE(Second.IsReady());
    EXPECT_TRUE(Output.str().empty());
    if (!Result)
    {
        EXPECT_EQ(Result.error().Code, Prism::Application::StartupErrorCode::Bind);
    }

}

TEST(PrismApplication, BindPreflightAllowsRecentlyClosedListenerPort)
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

    const auto Occupied = Prism::Application::BoundaryStartup::CheckBindAvailable(Endpoint);
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

    const auto Available = Prism::Application::BoundaryStartup::CheckBindAvailable(Endpoint);
    ASSERT_TRUE(Available.has_value()) << Available.error().Message;

    TemporaryConfiguration Config(Endpoint.port(),
        ConfigurationShape{.OperationsPort = FindFreePort()});
    Prism::Application::Application Application(MakeOptions(Config.Path()));
    const auto Started = Application.Start();
    ASSERT_TRUE(Started.has_value()) << Started.error().Message;
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}

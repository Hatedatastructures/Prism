/**
 * @file ApplicationTest.cpp
 * @brief PrismPreview 应用启动与停机契约测试。
 */

#include <gtest/gtest.h>

#include <Preview/Application/Application.hpp>
#include <Preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Protocols/Socks5/Types.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    inline constexpr std::string_view ValidSocks5Protocol =
        R"([{"Id":"protocol-socks5","Name":"socks5","Builtin":"socks5","Requires":[]}])";
    inline constexpr std::string_view ValidHttpProtocol =
        R"([{"Id":"protocol-http","Name":"http","Builtin":"http","Requires":[]}])";
    inline constexpr std::string_view ValidVlessProtocol =
        R"([{"Id":"protocol-vless","Name":"vless","Builtin":"vless","Requires":[]}])";
    inline constexpr std::string_view ValidTrojanProtocol =
        R"([{"Id":"protocol-trojan","Name":"trojan","Builtin":"trojan","Requires":[]}])";
    inline constexpr std::string_view ValidVmessProtocol =
        R"([{"Id":"protocol-vmess","Name":"vmess","Builtin":"vmess","Requires":[]}])";
    inline constexpr std::string_view ValidShadowsocks2022Protocol =
        R"([{"Id":"protocol-shadowsocks2022","Name":"shadowsocks2022","Builtin":"shadowsocks2022","Requires":[]}])";
    inline constexpr std::string_view ValidAnyTlsProtocol =
        R"([{"Id":"protocol-anytls","Name":"anytls","Builtin":"anytls","Requires":[]}])";
    inline constexpr std::string_view ValidMixedTcpProtocols =
        R"([{"Id":"protocol-http","Name":"http","Builtin":"http","Requires":[]},{"Id":"protocol-socks5","Name":"socks5","Builtin":"socks5","Requires":[]},{"Id":"protocol-trojan","Name":"trojan","Builtin":"trojan","Requires":[]}])";

    inline constexpr std::string_view VmessUuid = "123e4567-e89b-12d3-a456-426614174000";
    inline constexpr std::string_view Shadowsocks2022Psk = "5n5ESu953i/pjIp02oZvHA==";

    struct ConfigurationShape final
    {
        std::string_view Address{"127.0.0.1"};
        std::string_view Protocols{ValidSocks5Protocol};
        std::string_view Udp{};
        std::string_view Quic{};
        std::string_view Carriers{};
        std::string_view Bindings{};
        std::string_view NativeTls{};
        std::string_view Builtins{};
        std::string_view LoggingDirectory{};
        std::string_view LoggingFileName{"preview.log"};
        std::string_view Routes{};
        std::string_view Credential{"local-token"};
        std::string_view SecretRef{};
        std::uint16_t OperationsPort{9090};
        std::uint32_t ShutdownTimeout{5000};
    };

    [[nodiscard]] auto MakeOptions(const std::filesystem::path &Path,
                                   std::ostream *Output = nullptr)
        -> Preview::Application::Options;

    class TemporaryConfiguration final
    {
    public:
        explicit TemporaryConfiguration(const std::uint16_t Port,
                                        const ConfigurationShape Shape = {})
            : Path_(std::filesystem::temp_directory_path() /
                   ("PrismPreviewApplication-" +
                    std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
                    ".json")),
              LoggingDirectory_(Shape.LoggingDirectory.empty()
                                    ? std::filesystem::path{}
                                    : std::filesystem::path(Shape.LoggingDirectory))
        {
            std::ofstream File(Path_, std::ios::binary);
            File << R"json({
    "SchemaVersion": 1,
    "Runtime": {
        "WorkerCount": 2,
        "RequiredCapabilities": [],
        "SessionTimeout": 30000
    },
    "Listeners": {
        "Tcp": [{
            "Id": "tcp-main",
            "Address": ")json"
                 << Shape.Address << R"json(",
            "Port": )json"
                 << Port << R"json(,
            "Timeout": 5000
        }],
        "Udp": )json"
                 << (Shape.Udp.empty() ? std::string_view("[]") : Shape.Udp) << R"json(,
        "Quic": )json"
                 << (Shape.Quic.empty() ? std::string_view("[]") : Shape.Quic) << R"json(,
        "Timeout": 5000
    },
    "NativeTls": )json"
                 << (Shape.NativeTls.empty()
                         ? std::string_view(R"json({"Enabled":false,"CertificateFile":"","PrivateKeyFile":""})json")
                         : Shape.NativeTls) << R"json(,
    "Builtins": )json"
                 << (Shape.Builtins.empty() ? std::string_view("[]") : Shape.Builtins) << R"json(,
    "Protocols": )json"
                 << Shape.Protocols << R"json(,
    "Carriers": )json"
                 << (Shape.Carriers.empty() ? std::string_view("[]") : Shape.Carriers) << R"json(,
    "ProtocolBindings": )json"
                 << (Shape.Bindings.empty() ? std::string_view("[]") : Shape.Bindings) << R"json(,
    "Accounts": [{
        "Id": "local",
        "SecretRef": ")json"
                 << Shape.SecretRef << R"json(",
        "Credential": ")json"
                 << Shape.Credential << R"json("
    }],
    "Routes": )json"
                 << (Shape.Routes.empty() ? std::string_view("[]") : Shape.Routes) << R"json(,
    "Dns": {"Servers": ["1.1.1.1"], "Timeout": 1000},
    "Logging": {
        "Level": "Trace",
        "Directory": ")json"
                 << (Shape.LoggingDirectory.empty() ? std::string_view("logs")
                                                    : Shape.LoggingDirectory) << R"json(",
        "FileName": ")json"
                 << Shape.LoggingFileName << R"json(",
        "Console": false
    },
    "Statistics": {"Enabled": true, "Interval": 1000},
    "Operations": {"Enabled": true, "Endpoint": "127.0.0.1:)json"
                 << Shape.OperationsPort << R"json(", "Timeout": 1000},
    "HotReload": {"Enabled": true, "AckTimeout": 5000},
    "Shutdown": {"Timeout": )json"
                 << Shape.ShutdownTimeout << R"json(}
})json";
        }

        ~TemporaryConfiguration()
        {
            std::error_code Error;
            std::filesystem::remove(Path_, Error);
            if (!LoggingDirectory_.empty())
            {
                std::filesystem::remove_all(LoggingDirectory_, Error);
            }
        }

        [[nodiscard]] auto Path() const -> const std::filesystem::path &
        {
            return Path_;
        }

    private:
        std::filesystem::path Path_;
        std::filesystem::path LoggingDirectory_;
    };

    [[nodiscard]] auto FindFreePort() -> std::uint16_t
    {
        Net::io_context Io;
        Tcp::acceptor Acceptor(Io, Tcp::endpoint(Tcp::v4(), 0));
        return Acceptor.local_endpoint().port();
    }

    auto MakeUnsupportedCipherClientHello() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> ClientHello{
            0x16, 0x03, 0x01, 0x00, 0x53,
            0x01, 0x00, 0x00, 0x4f,
            0x03, 0x03};
        ClientHello.insert(ClientHello.end(), 32, 0x42);
        constexpr std::array<std::uint8_t, 45> Tail{
            0x00,
            0x00, 0x02, 0xff, 0xff,
            0x01, 0x00,
            0x00, 0x24,
            0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b,
            'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
            0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2',
            0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04};
        ClientHello.insert(ClientHello.end(), Tail.begin(), Tail.end());
        return ClientHello;
    }

    auto QueryOperationsSessions(const std::uint16_t Port) -> std::string
    {
        Net::io_context Io;
        Tcp::socket Socket(Io);
        boost::system::error_code Error;
        Socket.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Port), Error);
        if (Error)
        {
            return {};
        }

        constexpr std::string_view Request =
            "GET /Operations/Sessions?correlation=1 HTTP/1.1\r\n"
            "Host: localhost\r\nConnection: close\r\n\r\n";
        Net::write(Socket, Net::buffer(Request), Error);
        if (Error)
        {
            return {};
        }

        std::array<char, 2048> Buffer{};
        std::string Response;
        for (;;)
        {
            const auto Count = Socket.read_some(Net::buffer(Buffer), Error);
            Response.append(Buffer.data(), Count);
            if (Error || Count == 0U)
            {
                break;
            }
        }
        return Response;
    }

    class RunningApplication final
    {
    public:
        explicit RunningApplication(const std::filesystem::path &Path)
            : Application_(MakeOptions(Path))
        {
        }

        ~RunningApplication()
        {
            Stop();
        }

        RunningApplication(const RunningApplication &) = delete;
        auto operator=(const RunningApplication &) -> RunningApplication & = delete;

        [[nodiscard]] auto Start() -> bool
        {
            const auto Result = Application_.Start();
            if (!Result)
            {
                return false;
            }
            Port_ = Result->Port;
            Thread_ = std::thread([this]
                                  { ExitCode_ = Application_.Run(); });
            return true;
        }

        auto Stop() -> void
        {
            Application_.Stop();
            if (Thread_.joinable())
            {
                Thread_.join();
            }
        }

        [[nodiscard]] auto Port() const noexcept -> std::uint16_t
        {
            return Port_;
        }

        [[nodiscard]] auto ExitCode() const noexcept -> int
        {
            return ExitCode_;
        }

    private:
        Preview::Application::Application Application_;
        std::thread Thread_;
        std::uint16_t Port_{0};
        int ExitCode_{0};
    };

    class LoopbackEchoServer final
    {
    public:
        LoopbackEchoServer()
            : Acceptor_(Io_, Tcp::endpoint(Net::ip::address_v4::loopback(), 0))
        {
            Net::co_spawn(Io_, AcceptLoop(), Net::detached);
            Thread_ = std::thread([this]
                                  { Io_.run(); });
        }

        ~LoopbackEchoServer()
        {
            boost::system::error_code Error;
            Acceptor_.close(Error);
            Io_.stop();
            if (Thread_.joinable())
            {
                Thread_.join();
            }
        }

        LoopbackEchoServer(const LoopbackEchoServer &) = delete;
        auto operator=(const LoopbackEchoServer &) -> LoopbackEchoServer & = delete;

        [[nodiscard]] auto Port() const -> std::uint16_t
        {
            return Acceptor_.local_endpoint().port();
        }

    private:
        [[nodiscard]] auto AcceptLoop() -> Net::awaitable<void>
        {
            while (true)
            {
                boost::system::error_code Error;
                auto Socket = co_await Acceptor_.async_accept(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    co_return;
                }
                Net::co_spawn(Io_, Echo(std::move(Socket)), Net::detached);
            }
        }

        [[nodiscard]] static auto Echo(Tcp::socket Socket) -> Net::awaitable<void>
        {
            std::array<char, 4096> Buffer{};
            while (true)
            {
                boost::system::error_code ReadError;
                const auto Size = co_await Socket.async_read_some(
                    Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, ReadError));
                if (ReadError)
                {
                    co_return;
                }
                boost::system::error_code WriteError;
                co_await Net::async_write(
                    Socket, Net::buffer(Buffer.data(), Size),
                    Net::redirect_error(Net::use_awaitable, WriteError));
                if (WriteError)
                {
                    co_return;
                }
            }
        }

        Net::io_context Io_;
        Tcp::acceptor Acceptor_;
        std::thread Thread_;
    };

    [[nodiscard]] auto WriteBytes(Tcp::socket &Socket, const std::string_view Bytes) -> bool
    {
        boost::system::error_code Error;
        Net::write(Socket, Net::buffer(Bytes.data(), Bytes.size()), Error);
        return !Error;
    }

    [[nodiscard]] auto ReadHttpResponse(Tcp::socket &Socket) -> std::string
    {
        std::array<char, 4096> Buffer{};
        std::string Response;
        while (Response.find("\r\n\r\n") == std::string::npos)
        {
            boost::system::error_code Error;
            const auto Count = Socket.read_some(Net::buffer(Buffer), Error);
            if (Error || Count == 0U)
            {
                break;
            }
            Response.append(Buffer.data(), Count);
        }
        const auto HeadersEnd = Response.find("\r\n\r\n");
        const auto LengthStart = Response.find("Content-Length:");
        if (HeadersEnd == std::string::npos || LengthStart == std::string::npos)
        {
            return Response;
        }
        const auto ValueStart = Response.find_first_not_of(" \t", LengthStart + 15U);
        const auto ValueEnd = Response.find("\r\n", ValueStart);
        std::size_t Length{};
        const auto [End, Error] = std::from_chars(
            Response.data() + ValueStart, Response.data() + ValueEnd, Length, 10);
        if (Error != std::errc{} || End != Response.data() + ValueEnd)
        {
            return Response;
        }
        const auto BodyStart = HeadersEnd + 4U;
        while (Response.size() < BodyStart + Length)
        {
            boost::system::error_code ReadError;
            const auto Count = Socket.read_some(Net::buffer(Buffer), ReadError);
            if (ReadError || Count == 0U)
            {
                break;
            }
            Response.append(Buffer.data(), Count);
        }
        return Response;
    }

    template <std::size_t Size>
    [[nodiscard]] auto ReadBytes(Tcp::socket &Socket, std::array<std::uint8_t, Size> &Bytes) -> bool
    {
        boost::system::error_code Error;
        Net::read(Socket, Net::buffer(Bytes), Error);
        return !Error;
    }

    [[nodiscard]] auto ReadSocks5Reply(Tcp::socket &Socket, std::uint8_t &Reply) -> bool
    {
        std::array<std::uint8_t, 4> Head{};
        if (!ReadBytes(Socket, Head))
        {
            return false;
        }
        Reply = Head[1];
        std::size_t Remaining = Head[3] == 0x01 ? 6U : Head[3] == 0x04 ? 18U : 0U;
        if (Head[3] == 0x03)
        {
            std::array<std::uint8_t, 1> Length{};
            if (!ReadBytes(Socket, Length))
            {
                return false;
            }
            Remaining = static_cast<std::size_t>(Length[0]) + 2U;
        }
        std::vector<std::uint8_t> Tail(Remaining);
        if (Tail.empty())
        {
            return true;
        }
        boost::system::error_code Error;
        Net::read(Socket, Net::buffer(Tail), Error);
        return !Error;
    }

    [[nodiscard]] auto Authenticate(Tcp::socket &Socket, const std::string_view Password,
                                    std::uint8_t &Status) -> bool
    {
        if (!WriteBytes(Socket, std::string("\x05\x01\x02", 3)))
        {
            Status = 0xfe;
            return false;
        }
        std::array<std::uint8_t, 2> MethodReply{};
        if (!ReadBytes(Socket, MethodReply))
        {
            Status = 0xfd;
            return false;
        }
        if (MethodReply[1] != 0x02)
        {
            Status = MethodReply[1];
            return false;
        }
        std::string Authentication("\x01\x05local", 7);
        Authentication.push_back(static_cast<char>(Password.size()));
        Authentication.append(Password);
        if (!WriteBytes(Socket, Authentication))
        {
            Status = 0xfc;
            return false;
        }
        std::array<std::uint8_t, 2> AuthenticationReply{};
        if (!ReadBytes(Socket, AuthenticationReply))
        {
            Status = 0xfb;
            return false;
        }
        Status = AuthenticationReply[1];
        return true;
    }

    [[nodiscard]] auto Socks5Connect(Tcp::socket &Socket, const std::string_view Host,
                                     const std::uint16_t Port, std::uint8_t &Reply) -> bool
    {
        std::string Request("\x05\x01\x00\x03", 4);
        Request.push_back(static_cast<char>(Host.size()));
        Request.append(Host);
        Request.push_back(static_cast<char>((Port >> 8U) & 0xffU));
        Request.push_back(static_cast<char>(Port & 0xffU));
        return WriteBytes(Socket, Request) && ReadSocks5Reply(Socket, Reply);
    }

    template <typename Stream>
    [[nodiscard]] auto Socks5AuthMethod(Stream &Socket) -> std::optional<std::uint8_t>
    {
        constexpr std::array<std::uint8_t, 3> Greeting{0x05, 0x01, 0x02};
        std::array<std::uint8_t, 2> Reply{};
        boost::system::error_code Error;
        Net::write(Socket, Net::buffer(Greeting), Error);
        if (Error)
        {
            return std::nullopt;
        }
        Net::read(Socket, Net::buffer(Reply), Error);
        if (Error || Reply[0] != 0x05)
        {
            return std::nullopt;
        }
        return Reply[1];
    }

    [[nodiscard]] auto MakeOptions(const std::filesystem::path &Path, std::ostream *Output)
        -> Preview::Application::Options
    {
        Preview::Application::Options Options;
        Options.ConfigurationPath = Path;
        Options.Output = Output;
        return Options;
    }

} // namespace

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
                           "GET /Operations/Health HTTP/1.1\r\nHost: localhost\r\n\r\n"));
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
        [&]() -> Net::awaitable<void>
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
        },
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

TEST(PreviewApplication, AcceptsConfiguredSocks5Protocol)
{
    TemporaryConfiguration Configuration(19084);
    RunningApplication Application(Configuration.Path());

    ASSERT_TRUE(Application.Start());
    EXPECT_EQ(Application.Port(), 19084U);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(PreviewApplication, SelectsConfiguredTcpProtocolFactory)
{
    struct ProtocolCase final
    {
        std::string_view Protocols;
        std::string_view Credential;
    };

    constexpr std::array Cases{
        ProtocolCase{ValidHttpProtocol, "local-token"},
        ProtocolCase{ValidSocks5Protocol, "local-token"},
        ProtocolCase{ValidVlessProtocol, VmessUuid},
        ProtocolCase{ValidTrojanProtocol, "local-token"},
        ProtocolCase{ValidVmessProtocol, VmessUuid},
        ProtocolCase{ValidShadowsocks2022Protocol, Shadowsocks2022Psk},
    };

    for (const auto &Case : Cases)
    {
        SCOPED_TRACE(Case.Protocols);
        TemporaryConfiguration Configuration(
            FindFreePort(), ConfigurationShape{.Protocols = Case.Protocols,
                                                .Credential = Case.Credential});
        RunningApplication Application(Configuration.Path());

        ASSERT_TRUE(Application.Start());
        Application.Stop();
        EXPECT_EQ(Application.ExitCode(), 0);
    }
}

TEST(PreviewApplication, StartsConfiguredAnyTlsProtocol)
{
    const auto Repository = std::filesystem::path(__FILE__)
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path();
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto NativeTls = std::string("{\"Enabled\":true,\"CertificateFile\":\"") +
                           Certificate + "\",\"PrivateKeyFile\":\"" + PrivateKey + "\"}";
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Protocols = ValidAnyTlsProtocol,
                           .NativeTls = NativeTls,
                           .Credential = "anytls-application-password"});
    RunningApplication Application(Configuration.Path());

    ASSERT_TRUE(Application.Start());
    EXPECT_NE(Application.Port(), 0U);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(PreviewApplication, RejectsBareAnyTlsWithoutNativeTls)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Protocols = ValidAnyTlsProtocol,
                           .Credential = "anytls-application-password"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::UnsupportedService);
    EXPECT_EQ(Result.error().Path, "Protocols[0]");
    EXPECT_NE(Result.error().Message.find("NativeTls"), std::string::npos);
}

TEST(PreviewApplication, ConstructsNonSocks5ProtocolHandlers)
{
    const auto Http = Preview::Composition::Recognition::CandidateFactory::MakeHttp();
    EXPECT_EQ(Http.Spec.Name, "http");
    EXPECT_TRUE(Http.Accept);
    EXPECT_TRUE(Preview::Runtime::MakeAcceptVless());
    EXPECT_TRUE(Preview::Runtime::MakeAcceptTrojan());
    EXPECT_TRUE(Preview::Runtime::MakeAcceptVmess());
    EXPECT_TRUE(Preview::Runtime::MakeAcceptSs2022());
}

TEST(PreviewApplication, RejectsZeroConfiguredProtocols)
{
    TemporaryConfiguration Configuration(
        FindFreePort(), ConfigurationShape{.Protocols = "[]"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::InvalidConfiguration);
}

TEST(PreviewApplication, RejectsUnsupportedTcpProtocol)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Protocols = R"([{"Id":"protocol-hysteria2","Name":"hysteria2","Builtin":"hysteria2","Requires":[]}])"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::UnsupportedService);
}

TEST(PreviewApplication, RejectsTuicProtocolUntilQuicFrontIsWired)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Protocols = R"([{"Id":"protocol-tuic","Name":"tuic","Builtin":"tuic","Requires":[]}])"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::UnsupportedService);
}

TEST(PreviewApplication, RejectsMismatchedProtocolBuiltin)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Protocols = R"([{"Id":"protocol-http","Name":"http","Builtin":"socks5","Requires":[]}])"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::UnsupportedService);
}

TEST(PreviewApplication, RejectsStaticBuiltinWithoutRuntimeCallback)
{
    constexpr std::string_view Builtins =
        R"([{"Id":"builtin-socks5","Kind":"protocol","Name":"socks5","Requires":[],"Provides":[]}])";
    const auto LoggingDirectory = std::filesystem::temp_directory_path() /
                                  ("PrismPreviewBuiltinCallback-" +
                                   std::to_string(std::chrono::steady_clock::now()
                                                      .time_since_epoch()
                                                      .count()));
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Builtins = Builtins,
                           .LoggingDirectory = LoggingDirectory.generic_string()});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::UnsupportedService);
    EXPECT_EQ(Result.error().Path, "Builtins.builtin-socks5");
    EXPECT_NE(Result.error().Message.find("callback"), std::string::npos);
}

TEST(PreviewApplication, RejectsInvalidVlessCredentialMaterial)
{
    TemporaryConfiguration Configuration(
        FindFreePort(), ConfigurationShape{.Protocols = ValidVlessProtocol});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::InvalidConfiguration);
}

TEST(PreviewApplication, RejectsInvalidShadowsocks2022CredentialMaterial)
{
    TemporaryConfiguration Configuration(
        FindFreePort(), ConfigurationShape{.Protocols = ValidShadowsocks2022Protocol});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::InvalidConfiguration);
}

TEST(PreviewApplication, StartsMixedTrialForConfiguredTcpProtocols)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Protocols = ValidMixedTcpProtocols});
    RunningApplication Application(Configuration.Path());

    ASSERT_TRUE(Application.Start());
    EXPECT_NE(Application.Port(), 0U);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(PreviewApplication, StartsConfiguredUdpFront)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Udp = R"([{"Id":"udp-main","Address":"127.0.0.1","Port":19090,"Timeout":5000}])"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_TRUE(Result);
    EXPECT_EQ(Result->UdpPort, 19090U);
    EXPECT_TRUE(Result->UdpReady);
    EXPECT_FALSE(Result->QuicReady);
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}

TEST(PreviewApplication, StartsConfiguredQuicFrontWithHandshakePending)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Quic = R"([{"Id":"quic-main","Address":"127.0.0.1","Port":19091,"Timeout":5000}])"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_TRUE(Result);
    EXPECT_EQ(Result->UdpPort, 19091U);
    EXPECT_TRUE(Result->UdpReady);
    EXPECT_FALSE(Result->QuicReady);
    Application.Stop();
    EXPECT_EQ(Application.Run(), 0);
}

TEST(PreviewApplication, StartsConfiguredNativeCarrier)
{
    const auto Repository = std::filesystem::path(__FILE__)
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path();
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto Carriers = std::string(
        R"json([{"Id":"carrier-native","Name":"native","Builtin":"native","Requires":[],"Match":{"ServerNames":["example.com"],"Alpn":["h2"],"Priority":4,"Fallback":false},"Options":{"Type":"NativeTls","CertificateFile":")json") +
        Certificate +
        R"json(","PrivateKeyFile":")json" + PrivateKey + R"json("}}])json";
    constexpr std::string_view Bindings =
        R"([{"Id":"binding-native","ProtocolId":"protocol-socks5","CarrierId":"carrier-native","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":3,"Recognition":{}}])";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewNativeCarrierSuccess-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto LogDirectoryText = LogDirectory.generic_string();
    const auto TcpPort = FindFreePort();
    auto OperationsPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(
        TcpPort,
        ConfigurationShape{
            .Carriers = Carriers,
            .Bindings = Bindings,
            .LoggingDirectory = LogDirectoryText,
            .LoggingFileName = "native-carrier-success.log",
            .OperationsPort = OperationsPort});
    std::string LogContents;
    {
        RunningApplication Application(Configuration.Path());
        ASSERT_TRUE(Application.Start());

        Net::io_context Io;
        Net::ssl::context ClientContext(Net::ssl::context::tls_client);
        ClientContext.set_verify_mode(Net::ssl::verify_none);
        Net::ssl::stream<Tcp::socket> Stream(Io, ClientContext);
        boost::system::error_code Error;
        Stream.lowest_layer().connect(
            Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()), Error);
        ASSERT_FALSE(Error) << Error.message();
        ASSERT_EQ(SSL_set_tlsext_host_name(Stream.native_handle(), "example.com"), 1);
        constexpr std::array<unsigned char, 3> Alpn{2U, 'h', '2'};
        ASSERT_EQ(SSL_set_alpn_protos(
                      Stream.native_handle(), Alpn.data(), static_cast<unsigned int>(Alpn.size())),
                  0);
        Stream.handshake(Net::ssl::stream_base::client, Error);
        ASSERT_FALSE(Error) << Error.message();
        const auto Method = Socks5AuthMethod(Stream);
        ASSERT_TRUE(Method.has_value());
        EXPECT_EQ(*Method, 0x02U);
        Stream.lowest_layer().close(Error);

        Application.Stop();
        EXPECT_EQ(Application.ExitCode(), 0);
        std::ifstream LogFile(LogDirectory / "native-carrier-success.log", std::ios::binary);
        std::stringstream Contents;
        Contents << LogFile.rdbuf();
        LogContents = Contents.str();
    }

    std::error_code CleanupError;
    std::filesystem::remove_all(LogDirectory, CleanupError);
    EXPECT_FALSE(CleanupError) << CleanupError.message();
    EXPECT_NE(LogContents.find("[Carrier=native]"), std::string::npos) << LogContents;
    EXPECT_NE(LogContents.find("[Sni=example.com]"), std::string::npos) << LogContents;
    EXPECT_NE(LogContents.find("[TlsVersion="), std::string::npos) << LogContents;
}

TEST(PreviewApplication, ProtocolBindingRecognitionRoutesInnerProtocolBySni)
{
    const auto Repository = std::filesystem::path(__FILE__)
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path();
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto Carriers = std::string(
        R"json([{"Id":"carrier-native","Name":"native","Builtin":"native","Requires":[],"Match":{"ServerNames":[],"Alpn":[],"Priority":0,"Fallback":true},"Options":{"Type":"NativeTls","CertificateFile":")json") +
        Certificate +
        R"json(","PrivateKeyFile":")json" + PrivateKey + R"json("}}])json";
    constexpr std::string_view Protocols = R"([
        {"Id":"protocol-http","Name":"http","Builtin":"http","Requires":[]},
        {"Id":"protocol-socks5","Name":"socks5","Builtin":"socks5","Requires":[]}
    ])";
    constexpr std::string_view Bindings = R"([
        {"Id":"binding-http","ProtocolId":"protocol-http","CarrierId":"carrier-native",
         "TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":100,
         "Recognition":{"Pattern":"http.example"}},
        {"Id":"binding-socks5","ProtocolId":"protocol-socks5","CarrierId":"carrier-native",
         "TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,
         "Recognition":{"Domain":"socks.example"}}
    ])";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewProtocolSniRoute-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto OperationsPort = FindFreePort();
    const auto TcpPort = FindFreePort();
    TemporaryConfiguration Configuration(
        TcpPort,
        ConfigurationShape{
            .Protocols = Protocols,
            .Carriers = Carriers,
            .Bindings = Bindings,
            .LoggingDirectory = LogDirectory.generic_string(),
            .LoggingFileName = "protocol-sni-route.log",
            .OperationsPort = OperationsPort});
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Net::ssl::context ClientContext(Net::ssl::context::tls_client);
    ClientContext.set_verify_mode(Net::ssl::verify_none);
    Net::ssl::stream<Tcp::socket> Stream(Io, ClientContext);
    boost::system::error_code Error;
    Stream.lowest_layer().connect(
        Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()), Error);
    ASSERT_FALSE(Error) << Error.message();
    ASSERT_EQ(SSL_set_tlsext_host_name(Stream.native_handle(), "socks.example"), 1);
    Stream.handshake(Net::ssl::stream_base::client, Error);
    ASSERT_FALSE(Error) << Error.message();

    constexpr std::array<std::uint8_t, 5> Greeting{0x05, 0x01, 0x02, '\r', '\n'};
    std::array<std::uint8_t, 2> Reply{};
    Net::write(Stream, Net::buffer(Greeting), Error);
    ASSERT_FALSE(Error) << Error.message();
    Net::read(Stream, Net::buffer(Reply), Error);
    ASSERT_FALSE(Error) << Error.message();
    EXPECT_EQ(Reply, (std::array<std::uint8_t, 2>{0x05, 0x02}));

    Stream.lowest_layer().close(Error);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);
}

TEST(PreviewApplication, GlobalNativeTlsRemainsFallbackForExplicitProtocolBindings)
{
    const auto Repository = std::filesystem::path(__FILE__)
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path();
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto NativeTls = std::string("{\"Enabled\":true,\"CertificateFile\":\"") +
                           Certificate + "\",\"PrivateKeyFile\":\"" + PrivateKey + "\"}";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewNativeTlsFallback-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto LogDirectoryText = LogDirectory.generic_string();
    constexpr std::string_view Bindings =
        R"([{"Id":"binding-socks5","ProtocolId":"protocol-socks5","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,"Recognition":{}}])";
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Bindings = Bindings,
                           .NativeTls = NativeTls,
                           .LoggingDirectory = LogDirectoryText,
                           .LoggingFileName = "native-fallback.log"});
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Net::ssl::context ClientContext(Net::ssl::context::tls_client);
    ClientContext.set_verify_mode(Net::ssl::verify_none);
    Net::ssl::stream<Tcp::socket> Stream(Io, ClientContext);
    boost::system::error_code Error;
    Stream.lowest_layer().connect(
        Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()), Error);
    ASSERT_FALSE(Error);
    Stream.handshake(Net::ssl::stream_base::client, Error);
    EXPECT_FALSE(Error) << Error.message();
    const auto Method = Socks5AuthMethod(Stream);
    ASSERT_TRUE(Method.has_value());
    EXPECT_EQ(*Method, 0x02U);

    Stream.lowest_layer().close(Error);
    Application.Stop();
    EXPECT_EQ(Application.ExitCode(), 0);

    std::ifstream LogFile(LogDirectory / "native-fallback.log", std::ios::binary);
    std::stringstream LogContents;
    LogContents << LogFile.rdbuf();
    EXPECT_NE(LogContents.str().find("candidate_name=protocol-socks5"),
              std::string::npos);
    EXPECT_NE(LogContents.str().find("[Carrier=native]"), std::string::npos)
        << LogContents.str();
    EXPECT_NE(LogContents.str().find("stage=carrier_commit outcome=success"),
              std::string::npos)
        << LogContents.str();
}

TEST(PreviewApplication, NativeTlsHandshakeFailureKeepsStructuredError)
{
    const auto Repository = std::filesystem::path(__FILE__)
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path();
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto NativeTls = std::string("{\"Enabled\":true,\"CertificateFile\":\"") +
                           Certificate + "\",\"PrivateKeyFile\":\"" + PrivateKey + "\"}";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewNativeTlsFailure-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto LogDirectoryText = LogDirectory.generic_string();
    constexpr std::string_view Bindings =
        R"([{"Id":"binding-socks5","ProtocolId":"protocol-socks5","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,"Recognition":{}}])";
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{.Bindings = Bindings,
                           .NativeTls = NativeTls,
                           .LoggingDirectory = LogDirectoryText,
                           .LoggingFileName = "native-tls-failure.log"});
    std::string LogText;
    {
        RunningApplication Application(Configuration.Path());
        ASSERT_TRUE(Application.Start());

        Net::io_context Io;
        Tcp::socket Client(Io);
        boost::system::error_code Error;
        Client.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()), Error);
        ASSERT_FALSE(Error) << Error.message();

        const auto ClientHello = MakeUnsupportedCipherClientHello();
        ASSERT_EQ(ClientHello.size(), 88U);
        Net::write(Client, Net::buffer(ClientHello), Error);
        ASSERT_FALSE(Error) << Error.message();

        std::array<std::uint8_t, 8> Alert{};
        std::size_t AlertBytes = 0;
        for (;;)
        {
            boost::system::error_code ReadError;
            const auto Read = Client.read_some(Net::buffer(Alert), ReadError);
            AlertBytes += Read;
            if (ReadError || Read == 0U)
            {
                break;
            }
        }
        EXPECT_GT(AlertBytes, 0U);
        Client.close(Error);
        Application.Stop();

        std::ifstream LogFile(LogDirectory / "native-tls-failure.log", std::ios::binary);
        std::stringstream LogContents;
        LogContents << LogFile.rdbuf();
        LogText = LogContents.str();
    }

    std::error_code CleanupError;
    std::filesystem::remove_all(LogDirectory, CleanupError);
    EXPECT_FALSE(CleanupError) << CleanupError.message();
    EXPECT_NE(LogText.find("stage=carrier_commit"), std::string::npos) << LogText;
        EXPECT_NE(LogText.find("[Status=tls_alert]"), std::string::npos) << LogText;
        EXPECT_NE(LogText.find("[FaultCode=tls_hsfail]"), std::string::npos) << LogText;
        EXPECT_NE(LogText.find("[NativeError="), std::string::npos) << LogText;
        EXPECT_NE(LogText.find("[Sni=example.com]"), std::string::npos) << LogText;
}

TEST(PreviewApplication, ConfiguredNativeTlsCarrierKeepsStructuredError)
{
    const auto Repository = std::filesystem::path(__FILE__)
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path();
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto Carriers = std::string(
        R"json([{"Id":"carrier-native","Name":"native","Builtin":"native","Requires":[],"Match":{},"Options":{"Type":"NativeTls","CertificateFile":")json") +
        Certificate + R"json(","PrivateKeyFile":")json" + PrivateKey + R"json("}}])json";
    constexpr std::string_view Bindings =
        R"([{"Id":"binding-native","ProtocolId":"protocol-socks5","CarrierId":"carrier-native","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":3,"Recognition":{}}])";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewNativeTlsCarrierFailure-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto LogDirectoryText = LogDirectory.generic_string();
    auto OperationsPort = FindFreePort();
    const auto TcpPort = FindFreePort();
    while (OperationsPort == TcpPort)
    {
        OperationsPort = FindFreePort();
    }
    TemporaryConfiguration Configuration(
        TcpPort,
        ConfigurationShape{.Carriers = Carriers,
                           .Bindings = Bindings,
                           .LoggingDirectory = LogDirectoryText,
                           .LoggingFileName = "native-tls-carrier-failure.log",
                           .OperationsPort = OperationsPort});
    std::string LogText;
    {
        RunningApplication Application(Configuration.Path());
        ASSERT_TRUE(Application.Start());

        Net::io_context Io;
        Tcp::socket Client(Io);
        boost::system::error_code Error;
        Client.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()), Error);
        ASSERT_FALSE(Error) << Error.message();

        std::string OperationsResponse;
        bool SessionObserved = false;
        for (std::size_t Attempt = 0; Attempt < 100U; ++Attempt)
        {
            OperationsResponse = QueryOperationsSessions(OperationsPort);
            if (OperationsResponse.find("\"items\":[{") != std::string::npos)
            {
                SessionObserved = true;
                break;
            }
        }
        ASSERT_TRUE(SessionObserved) << OperationsResponse;

        const auto ClientHello = MakeUnsupportedCipherClientHello();
        ASSERT_EQ(ClientHello.size(), 88U);
        Net::write(Client, Net::buffer(ClientHello), Error);
        ASSERT_FALSE(Error) << Error.message();

        std::array<std::uint8_t, 8> Alert{};
        std::size_t AlertBytes = 0;
        for (;;)
        {
            boost::system::error_code ReadError;
            const auto Read = Client.read_some(Net::buffer(Alert), ReadError);
            AlertBytes += Read;
            if (ReadError || Read == 0U)
            {
                break;
            }
        }
        EXPECT_GT(AlertBytes, 0U);

        bool SessionDrained = false;
        for (std::size_t Attempt = 0; Attempt < 100U; ++Attempt)
        {
            OperationsResponse = QueryOperationsSessions(OperationsPort);
            if (OperationsResponse.find("\"items\":[]") != std::string::npos)
            {
                SessionDrained = true;
                break;
            }
        }
        ASSERT_TRUE(SessionDrained) << OperationsResponse;
        Client.close(Error);
        Application.Stop();

        std::ifstream LogFile(LogDirectory / "native-tls-carrier-failure.log", std::ios::binary);
        std::stringstream LogContents;
        LogContents << LogFile.rdbuf();
        LogText = LogContents.str();
    }

    std::error_code CleanupError;
    std::filesystem::remove_all(LogDirectory, CleanupError);
    EXPECT_FALSE(CleanupError) << CleanupError.message();
    EXPECT_NE(LogText.find("[Event=tls_alert]"), std::string::npos) << LogText;
    EXPECT_NE(LogText.find("[Stage=carrier_commit]"), std::string::npos) << LogText;
    EXPECT_NE(LogText.find("[Status=tls_alert]"), std::string::npos) << LogText;
    EXPECT_NE(LogText.find("[FaultCode=tls_hsfail]"), std::string::npos) << LogText;
    EXPECT_NE(LogText.find("[NativeError=NO_SHARED_CIPHER"), std::string::npos) << LogText;
    EXPECT_NE(LogText.find("[Sni=example.com]"), std::string::npos) << LogText;
}

TEST(PreviewApplication, NativeTlsFallbackHandlesMultipleProtocolBindings)
{
    const auto Repository = std::filesystem::path(__FILE__)
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path()
                                .parent_path();
    const auto Certificate = (Repository / "cert.pem").generic_string();
    const auto PrivateKey = (Repository / "key.pem").generic_string();
    const auto NativeTls = std::string("{\"Enabled\":true,\"CertificateFile\":\"") +
                           Certificate + "\",\"PrivateKeyFile\":\"" + PrivateKey + "\"}";
    const auto LogDirectory = std::filesystem::temp_directory_path() /
                              ("PrismPreviewNativeTlsMultiProtocol-" +
                               std::to_string(std::chrono::steady_clock::now()
                                                  .time_since_epoch()
                                                  .count()));
    const auto LogDirectoryText = LogDirectory.generic_string();
    constexpr std::string_view Bindings = R"([{"Id":"binding-http","ProtocolId":"protocol-http","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,"Recognition":{}},{"Id":"binding-socks5","ProtocolId":"protocol-socks5","TcpEnabled":true,"UdpEnabled":false,"MuxModes":[],"Priority":0,"Recognition":{}}])";
    ConfigurationShape Shape{
        .Protocols = ValidMixedTcpProtocols,
        .Bindings = Bindings,
        .NativeTls = NativeTls,
        .LoggingDirectory = LogDirectoryText,
        .LoggingFileName = "native-multi-protocol.log"};
    const auto TcpPort = FindFreePort();
    do
    {
        Shape.OperationsPort = FindFreePort();
    } while (Shape.OperationsPort == TcpPort);
    TemporaryConfiguration Configuration(TcpPort, Shape);
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));
    const auto Started = Application.Start();
    ASSERT_TRUE(Started)
        << (Started ? std::string{} : Started.error().Path + ": " + Started.error().Message);
    std::atomic<int> ExitCode{-1};
    std::thread Thread([&]
                       { ExitCode.store(Application.Run(), std::memory_order_release); });

    Net::io_context Io;
    Net::ssl::context ClientContext(Net::ssl::context::tls_client);
    ClientContext.set_verify_mode(Net::ssl::verify_none);
    Net::ssl::stream<Tcp::socket> Stream(Io, ClientContext);
    boost::system::error_code Error;
    Stream.lowest_layer().connect(
        Tcp::endpoint(Net::ip::address_v4::loopback(), Started->Port), Error);
    ASSERT_FALSE(Error);
    Stream.handshake(Net::ssl::stream_base::client, Error);
    EXPECT_FALSE(Error) << Error.message();
    const auto Method = Socks5AuthMethod(Stream);
    ASSERT_TRUE(Method.has_value());
    EXPECT_EQ(*Method, 0x02U);

    Stream.lowest_layer().close(Error);

    Tcp::socket Plain(Io);
    Plain.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Started->Port), Error);
    ASSERT_FALSE(Error);
    const auto PlainMethod = Socks5AuthMethod(Plain);
    ASSERT_TRUE(PlainMethod.has_value());
    EXPECT_EQ(*PlainMethod, 0x02U);
    Plain.close(Error);

    Application.Stop();
    Thread.join();
    EXPECT_EQ(ExitCode.load(std::memory_order_acquire), 0);
}

TEST(PreviewApplication, RejectsConfiguredRoute)
{
    TemporaryConfiguration Configuration(
        FindFreePort(),
        ConfigurationShape{
            .Routes = R"([{"Id":"route-default","Match":"*","Target":"direct","Requires":[]}])"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::UnsupportedService);
}

TEST(PreviewApplication, RejectsUnsafeSampleCredentialOnNonLoopback)
{
    TemporaryConfiguration Configuration(
        FindFreePort(), ConfigurationShape{.Address = "0.0.0.0"});
    Preview::Application::Application Application(MakeOptions(Configuration.Path()));

    const auto Result = Application.Start();

    ASSERT_FALSE(Result);
    EXPECT_FALSE(Application.IsReady());
    EXPECT_EQ(Result.error().Code,
              Preview::Application::StartupErrorCode::InvalidConfiguration);
}

TEST(PreviewApplication, RejectsInvalidSocks5Credentials)
{
    TemporaryConfiguration Configuration(FindFreePort());
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Tcp::socket Socket(Io);
    Socket.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()));

    std::uint8_t Status = 0xff;
    ASSERT_TRUE(Authenticate(Socket, "wrong-token", Status)) << static_cast<unsigned>(Status);
    EXPECT_EQ(Status, 0x01U);
    Socket.close();
    Application.Stop();
}

TEST(PreviewApplication, MapsDialFailureToConnectionRefused)
{
    TemporaryConfiguration Configuration(FindFreePort());
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Tcp::socket Socket(Io);
    Socket.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()));

    std::uint8_t Status = 0xff;
    ASSERT_TRUE(Authenticate(Socket, "local-token", Status)) << static_cast<unsigned>(Status);
    ASSERT_EQ(Status, 0x00U);

    std::uint8_t Reply = 0xff;
    ASSERT_TRUE(Socks5Connect(Socket, "127.0.0.1", 1, Reply));
    EXPECT_EQ(Reply, static_cast<std::uint8_t>(Preview::Socks5::ReplyCode::ConnectionRefused));
    Socket.close();
    Application.Stop();
}

TEST(PreviewApplication, RelaysAuthenticatedLoopbackEcho)
{
    LoopbackEchoServer Echo;
    TemporaryConfiguration Configuration(FindFreePort());
    RunningApplication Application(Configuration.Path());
    ASSERT_TRUE(Application.Start());

    Net::io_context Io;
    Tcp::socket Socket(Io);
    Socket.connect(Tcp::endpoint(Net::ip::address_v4::loopback(), Application.Port()));

    std::uint8_t Status = 0xff;
    ASSERT_TRUE(Authenticate(Socket, "local-token", Status)) << static_cast<unsigned>(Status);
    ASSERT_EQ(Status, 0x00U);

    std::uint8_t Reply = 0xff;
    ASSERT_TRUE(Socks5Connect(Socket, "127.0.0.1", Echo.Port(), Reply));
    ASSERT_EQ(Reply, static_cast<std::uint8_t>(Preview::Socks5::ReplyCode::Success));

    constexpr std::string_view Payload = "preview-socks5-loopback";
    ASSERT_TRUE(WriteBytes(Socket, Payload));
    std::string Received(Payload.size(), '\0');
    boost::system::error_code Error;
    Net::read(Socket, Net::buffer(Received), Error);
    EXPECT_FALSE(Error);
    EXPECT_EQ(Received, Payload);

    Socket.close();
    Application.Stop();
}

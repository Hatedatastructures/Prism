/**
 * @file ApplicationTestSupport.hpp
 * @brief ApplicationTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
/**
 * @file ApplicationTest.cpp
 * @brief Prism 应用启动与停机契约测试。
 */

#include <gtest/gtest.h>

#include <glaze/glaze.hpp>

#include <Prism/Application/Application.hpp>
#include <Prism/Net/Services/StreamRelay.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Protocols/Mux/SingMux/Stream.hpp>
#include <Prism/Application/Startup/ProcessServices.hpp>
#include <Prism/Application/Assembly/ProviderAssembly.hpp>
#include <Prism/Application/Startup/ProtocolServices.hpp>
#include <Prism/Application/Startup/StartupTransaction.hpp>
#include <tests/TestSupport/Prism/PrismMockTransport.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Vless/IngressFactory.hpp>
#include <Prism/Protocols/Trojan/IngressFactory.hpp>
#include <Prism/Protocols/Vmess/IngressFactory.hpp>
#include <Prism/Composition/Recognition/CandidateFactory.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>

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
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;

    [[nodiscard]] auto FindStructuredValue(const glz::generic &Document,
                                           const std::string_view Key) -> const glz::generic *
    {
        if (!Document.is_object())
        {
            return nullptr;
        }
        const auto &Object = Document.get_object();
        const auto Found = Object.find(Key);
        return Found == Object.end() ? nullptr : &Found->second;
    }

    [[nodiscard]] auto FindStructuredString(const glz::generic &Document,
                                             const std::string_view Key) -> std::string_view
    {
        const auto *Value = FindStructuredValue(Document, Key);
        return Value != nullptr && Value->is_string() ? std::string_view{Value->get<std::string>()}
                                                       : std::string_view{};
    }

    [[nodiscard]] auto FindStructuredField(const glz::generic &Document,
                                           const std::string_view Key) -> std::string_view
    {
        const auto *Fields = FindStructuredValue(Document, "Fields");
        if (Fields == nullptr || !Fields->is_object())
        {
            return {};
        }
        const auto &Object = Fields->get_object();
        const auto Found = Object.find(Key);
        return Found == Object.end() || !Found->second.is_string()
                   ? std::string_view{}
                   : std::string_view{Found->second.get<std::string>()};
    }

    [[nodiscard]] auto FindStructuredWarnRecord(const std::string_view Contents,
                                                const std::string_view MessagePrefix)
        -> std::optional<glz::generic>
    {
        std::size_t RecordStart = 0;
        while (RecordStart < Contents.size())
        {
            const auto RecordEnd = Contents.find('\n', RecordStart);
            const auto Line = Contents.substr(
                RecordStart, RecordEnd == std::string_view::npos
                                 ? Contents.size() - RecordStart
                                 : RecordEnd - RecordStart);
            glz::generic Record;
            if (const auto Error = glz::read_json(Record, Line); !Error &&
                FindStructuredString(Record, "Level") == "Warn" &&
                FindStructuredString(Record, "Message").starts_with(MessagePrefix))
            {
                return Record;
            }
            if (RecordEnd == std::string_view::npos)
            {
                break;
            }
            RecordStart = RecordEnd + 1U;
        }
        return {};
    }

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
        R"([{"Id":"protocol-shadowsocks2022","Name":"ss2022","Builtin":"ss2022","Requires":[]}])";
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
        std::string_view LoggingFileName{"prism.log"};
        std::string_view LoggingRenderMode{"CompactHuman"};
        std::string_view Routes{};
        std::string_view Credential{"local-token"};
        std::string_view Credentials{};
        std::string_view SecretRef{};
        std::string_view Recognition{};
        std::uint16_t OperationsPort{9090};
        std::uint32_t ShutdownTimeout{5000};
        bool StatisticsEnabled{true};
        std::uint32_t StatisticsInterval{1000};
    };

    [[nodiscard]] auto MakeOptions(const std::filesystem::path &Path,
                                   std::ostream *Output = nullptr)
        -> Prism::Application::Options;

    class TemporaryConfiguration final
    {
    public:
        explicit TemporaryConfiguration(const std::uint16_t Port,
                                        const ConfigurationShape Shape = {})
            : Path_(std::filesystem::temp_directory_path() /
                   ("PrismApplication-" +
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
                 << Shape.Credential << R"json(",
        "Credentials": )json"
                 << (Shape.Credentials.empty() ? std::string_view("{}") : Shape.Credentials) << R"json(
    }],
    "Routes": )json"
                 << (Shape.Routes.empty() ? std::string_view("[]") : Shape.Routes) << R"json(,
    "Recognition": )json"
                 << (Shape.Recognition.empty() ? std::string_view("{}") : Shape.Recognition) << R"json(,
    "Dns": {"Servers": ["1.1.1.1"], "Timeout": 1000},
    "Logging": {
        "Level": "Trace",
        "Directory": ")json"
                 << (Shape.LoggingDirectory.empty() ? std::string_view("logs")
                                                    : Shape.LoggingDirectory) << R"json(",
        "FileName": ")json"
                 << Shape.LoggingFileName << R"json(",
         "RenderMode": ")json"
                  << Shape.LoggingRenderMode << R"json(",
         "Console": false
    },
    "Statistics": {"Enabled": )json"
                 << (Shape.StatisticsEnabled ? "true" : "false") << R"json(, "Interval": )json"
                 << Shape.StatisticsInterval << R"json(},
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

        const auto Request = "GET /Operations/Sessions?correlation=1 HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(Port) +
            "\r\nConnection: close\r\n\r\n";
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
        Prism::Application::Application Application_;
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
        -> Prism::Application::Options
    {
        Prism::Application::Options Options;
        Options.ConfigurationPath = Path;
        Options.Output = Output;
        return Options;
    }

} // namespace





namespace
{
    auto ObserveTrafficInterval(std::shared_ptr<Prism::Application::Application::RuntimeState> Runtime)
        -> Net::awaitable<void>
    {
        Net::steady_timer AfterFlush(Runtime->Io);
        AfterFlush.expires_at(Runtime->StatisticsFlushTimer.expiry() + std::chrono::milliseconds{10});
        co_await AfterFlush.async_wait(Net::use_awaitable);
        EXPECT_EQ(Runtime->Traffic->Value(Prism::Statistics::Scope::Account, 11).UpBytes, 37U);
        EXPECT_EQ(Runtime->Traffic->Value(Prism::Statistics::Scope::Worker, 1).DownBytes, 41U);
        EXPECT_EQ(Runtime->Traffic->ConsumedObservations(), 1U);
        Prism::Application::Shutdown::ScheduleShutdown(Runtime);
    }
}




















































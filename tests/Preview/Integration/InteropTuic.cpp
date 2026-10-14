/**
 * @file InteropTuic.cpp
 * @brief Preview TUIC v5 与独立 reference 的双向 TCP/UDP 互操作端点
 * @details 使用 Preview 原生 QUIC 的单向认证流、bidi Connect 流、DATAGRAM
 *          packet 和 TLS exporter，覆盖服务端与客户端两个方向。
 * @note standalone Native harness；不启动 Preview::Application，不能作为
 *       Application ingress 路径的互操作证据。
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Quic/Native.hpp>
#include "../../TestSupport/Preview/QuicFactory.hpp"
#include <Preview/Protocols/Quic/StreamAdapter.hpp>
#include <Preview/Protocols/Tuic/Tuic.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    using Udp = Net::ip::udp;

    auto CaptureDrainFailure(std::exception_ptr& FirstError,
        std::expected<void, Preview::Fault::Failure> Result) -> void
    {
        if (!Result && !FirstError)
            FirstError = std::make_exception_ptr(std::system_error(Preview::Fault::ToNative(Result.error())));
    }

    struct Options
    {
        std::string Mode{"server"};
        std::string Address{"127.0.0.1:19087"};
        std::string Password{"tuic_password"};
        bool Udp{false};
        std::array<std::uint8_t, 16> Uuid{
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3,
            0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
    };

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    [[nodiscard]] auto ParsePort(std::string_view Value) -> std::optional<std::uint16_t>
    {
        std::uint32_t Port = 0;
        if (Value.empty())
        {
            return std::nullopt;
        }
        const auto [End, Error] = std::from_chars(Value.data(), Value.data() + Value.size(), Port);
        if (Error != std::errc{} || End != Value.data() + Value.size() || Port > 65535)
        {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(Port);
    }

    [[nodiscard]] auto SplitHostPort(std::string_view Value) -> std::optional<HostPort>
    {
        if (Value.starts_with('['))
        {
            const auto Close = Value.find(']');
            if (Close == std::string_view::npos || Close + 1 >= Value.size() || Value[Close + 1] != ':')
            {
                return std::nullopt;
            }
            const auto Port = ParsePort(Value.substr(Close + 2));
            if (!Port)
            {
                return std::nullopt;
            }
            return HostPort{std::string(Value.substr(1, Close - 1)), *Port};
        }
        const auto Colon = Value.rfind(':');
        if (Colon == std::string_view::npos || Colon == 0)
        {
            return std::nullopt;
        }
        const auto Port = ParsePort(Value.substr(Colon + 1));
        if (!Port)
        {
            return std::nullopt;
        }
        return HostPort{std::string(Value.substr(0, Colon)), *Port};
    }

    [[nodiscard]] auto Hex(std::uint8_t Value) noexcept -> std::optional<std::uint8_t>
    {
        if (Value >= '0' && Value <= '9')
        {
            return static_cast<std::uint8_t>(Value - '0');
        }
        if (Value >= 'a' && Value <= 'f')
        {
            return static_cast<std::uint8_t>(Value - 'a' + 10);
        }
        if (Value >= 'A' && Value <= 'F')
        {
            return static_cast<std::uint8_t>(Value - 'A' + 10);
        }
        return std::nullopt;
    }

    [[nodiscard]] auto ParseUuid(std::string_view Value) -> std::optional<std::array<std::uint8_t, 16>>
    {
        std::array<std::uint8_t, 16> Result{};
        std::size_t Offset = 0;
        bool High = true;
        std::uint8_t Nibble = 0;
        for (const auto Character : Value)
        {
            if (Character == '-')
            {
                continue;
            }
            const auto Digit = Hex(static_cast<std::uint8_t>(Character));
            if (!Digit || Offset >= Result.size())
            {
                return std::nullopt;
            }
            if (High)
            {
                Nibble = static_cast<std::uint8_t>(*Digit << 4);
                High = false;
            }
            else
            {
                Result[Offset++] = static_cast<std::uint8_t>(Nibble | *Digit);
                High = true;
            }
        }
        if (Offset != Result.size() || !High)
        {
            return std::nullopt;
        }
        return Result;
    }

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> std::optional<Options>
    {
        Options Result;
        for (int Index = 1; Index + 1 < Argc; Index += 2)
        {
            const std::string_view Key = Argv[Index];
            const std::string_view Value = Argv[Index + 1];
            if (Key == "-mode")
            {
                Result.Mode = Value;
            }
            else if (Key == "-addr")
            {
                Result.Address = Value;
            }
            else if (Key == "-password")
            {
                Result.Password = Value;
            }
            else if (Key == "-udp")
            {
                Result.Udp = Value == "1" || Value == "true";
            }
            else if (Key == "-uuid")
            {
                const auto Uuid = ParseUuid(Value);
                if (!Uuid)
                {
                    return std::nullopt;
                }
                Result.Uuid = *Uuid;
            }
        }
        return Result;
    }

    [[nodiscard]] auto WriteAll(const Preview::Tuic::SharedConn &Conn,
                                std::span<const std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            std::error_code Error;
            const auto Written = co_await Conn->async_write_some(Data.subspan(Offset), Error);
            if (Error || Written == 0 || Written > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Written;
        }
        co_return true;
    }

    struct ClientContext final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Quic::Client> Connection;
        Preview::Tuic::ClientConfig Config;
    };

    auto RunTcpClient(ClientContext &Context) -> Net::awaitable<bool>
    {
        auto DataProvider = co_await Context.Connection->OpenBidirectionalStream();
        if (!DataProvider)
        {
            std::fprintf(stderr, "FAIL: TUIC data stream\n");
            co_return false;
        }
        auto DataStream = std::make_shared<Preview::Quic::StreamAdapter>(
            Context.Executor, DataProvider);
        const Preview::Tuic::Address Target{
            Preview::Tuic::AddressType::Domain, "example.com", 443};
        auto [HandshakeError, Conn] = co_await Preview::Tuic::Connect(
            DataStream, Context.Config, Target);
        if (HandshakeError != Preview::Error::None || !Conn)
        {
            std::fprintf(stderr, "FAIL: TUIC TCP handshake (%u)\n",
                         static_cast<unsigned>(HandshakeError));
            co_return false;
        }
        constexpr std::string_view Text{"prism-tuic-external-tcp-payload"};
        const auto Payload = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Text.data()), Text.size());
        if (!co_await WriteAll(Conn, Payload))
        {
            Conn->Close();
            co_return false;
        }
        std::vector<std::byte> Echo(Text.size());
        std::size_t Offset = 0;
        while (Offset < Echo.size())
        {
            std::error_code Error;
            const auto Read = co_await Conn->async_read_some(
                std::span<std::byte>(Echo).subspan(Offset), Error);
            if (Error || Read == 0)
            {
                Conn->Close();
                co_return false;
            }
            Offset += Read;
        }
        Conn->Close();
        if (std::memcmp(Echo.data(), Payload.data(), Payload.size()) != 0)
        {
            std::fprintf(stderr, "FAIL: TUIC TCP echo mismatch\n");
            co_return false;
        }
        co_return true;
    }

    auto RunUdpClient(ClientContext &Context) -> Net::awaitable<bool>
    {
        auto Datagram = Preview::Tuic::ConnectPacket(
            Context.Connection->Datagram(), Context.Config);
        if (!Datagram)
        {
            std::fprintf(stderr, "FAIL: TUIC UDP datagram provider\n");
            co_return false;
        }
        const std::string Text{"prism-tuic-external-udp-payload"};
        const auto Payload = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Text.data()), Text.size());
        const Preview::Tuic::Address Target{
            Preview::Tuic::AddressType::Ipv4, "127.0.0.1", 53};
        const auto SendError = co_await Datagram->AsyncSendTo(Target, Payload);
        if (SendError != Preview::Error::None)
        {
            Datagram->Close();
            co_return false;
        }
        Preview::Tuic::Address EchoTarget;
        std::vector<std::uint8_t> Echo;
        const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(EchoTarget, Echo);
        const bool Valid = ReceiveError == Preview::Error::None &&
                           Echo.size() == Payload.size() &&
                           std::equal(Echo.begin(), Echo.end(), Payload.begin());
        Datagram->Close();
        if (!Valid)
        {
            std::fprintf(stderr, "FAIL: TUIC UDP echo mismatch\n");
            co_return false;
        }
        co_return true;
    }

    auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Remote = SplitHostPort(OptionsValue.Address);
        if (!Remote)
        {
            std::fprintf(stderr, "FAIL: malformed TUIC reference address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Remote->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: TUIC reference address is not an IP literal\n");
            co_return 2;
        }
        auto Tls = std::make_shared<Ssl::context>(Ssl::context::tlsv13_client);
        Tls->set_verify_mode(Ssl::verify_none);
        static constexpr unsigned char H3Alpn[] = {0x02, 'h', '3'};
        if (SSL_CTX_set_alpn_protos(Tls->native_handle(), H3Alpn, sizeof(H3Alpn)) != 0)
        {
            std::fprintf(stderr, "FAIL: cannot configure TUIC ALPN\n");
            co_return 1;
        }
        const auto Executor = co_await Net::this_coro::executor;
        auto Connection = std::make_shared<Preview::Quic::Client>(
            Preview::Quic::ClientOptions{
                Executor, std::make_shared<Udp::socket>(Executor, Udp::endpoint(Udp::v4(), 0)),
                Udp::endpoint(Address, Remote->Port), Tls, "tuic"});
        Connection->Start();
        if (!co_await Connection->WaitHandshake())
        {
            Connection->Close();
            std::fprintf(stderr, "FAIL: TUIC QUIC handshake\n");
            co_return 1;
        }
        auto AuthProvider = co_await Connection->OpenUnidirectionalStream();
        if (!AuthProvider)
        {
            Connection->Close();
            std::fprintf(stderr, "FAIL: TUIC auth stream\n");
            co_return 1;
        }
        auto AuthStream = std::make_shared<Preview::Quic::StreamAdapter>(Executor, AuthProvider);
        const auto Exporter = [Connection](std::span<std::uint8_t> Output,
                                            std::span<const std::uint8_t> Label,
                                            std::string_view Context)
        {
            return Connection->ExportKeyingMaterial(Output, Label, Context);
        };
        ClientContext Context{Executor, Connection, {}};
        Context.Config.uuid = OptionsValue.Uuid;
        Context.Config.password = OptionsValue.Password;
        Context.Config.AuthStream = AuthStream;
        Context.Config.Exporter = Exporter;
        if (OptionsValue.Udp)
        {
            auto AuthOnly = std::make_shared<Preview::Tuic::Conn<>>(
                Preview::SharedTransmission{}, Context.Config.uuid);
            const auto AuthError = co_await AuthOnly->WriteAuthentication(
                Context.Config.AuthStream, Context.Config.Exporter, Context.Config.password);
            if (AuthError != Preview::Error::None)
            {
                Connection->Close();
                std::fprintf(stderr, "FAIL: TUIC UDP authentication (%u)\n",
                             static_cast<unsigned>(AuthError));
                co_return 1;
            }
        }
        if (!OptionsValue.Udp)
        {
            const auto TcpSucceeded = co_await RunTcpClient(Context);
            if (!TcpSucceeded)
            {
                Connection->Close();
                co_return 1;
            }
        }
        const bool UdpOk = co_await RunUdpClient(Context);
        Connection->Close();
        if (!UdpOk)
        {
            co_return 1;
        }
        std::printf("PASS: Preview TUIC client -> reference server TCP+UDP\n");
        co_return 0;
    }

    [[nodiscard]] auto LoadSelfSigned(Ssl::context &Context) -> bool
    {
        auto *KeyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY *Key = nullptr;
        if (!KeyContext || EVP_PKEY_keygen_init(KeyContext) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(KeyContext, 2048) <= 0 ||
            EVP_PKEY_keygen(KeyContext, &Key) <= 0)
        {
            EVP_PKEY_CTX_free(KeyContext);
            return false;
        }
        EVP_PKEY_CTX_free(KeyContext);
        auto *Certificate = X509_new();
        auto *Name = X509_NAME_new();
        const bool Ready = Certificate && Name && X509_set_version(Certificate, 2) > 0 &&
                           ASN1_INTEGER_set(X509_get_serialNumber(Certificate), 1) > 0 &&
                           X509_gmtime_adj(X509_get_notBefore(Certificate), 0) != nullptr &&
                           X509_gmtime_adj(X509_get_notAfter(Certificate), 3600) != nullptr &&
                           X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC,
                                                      reinterpret_cast<const unsigned char *>("localhost"), -1, -1,
                                                      0) > 0 &&
                           X509_set_subject_name(Certificate, Name) > 0 &&
                           X509_set_issuer_name(Certificate, Name) > 0 &&
                           X509_set_pubkey(Certificate, Key) > 0 &&
                           X509_sign(Certificate, Key, EVP_sha256()) > 0 &&
                           SSL_CTX_use_certificate(Context.native_handle(), Certificate) == 1 &&
                           SSL_CTX_use_PrivateKey(Context.native_handle(), Key) == 1;
        X509_NAME_free(Name);
        X509_free(Certificate);
        EVP_PKEY_free(Key);
        return Ready;
    }

    auto Echo(Preview::Tuic::SharedConn Conn) -> Net::awaitable<bool>
    {
        std::array<std::byte, 4096> Buffer{};
        std::error_code ReadError;
        const auto Count = co_await Conn->async_read_some(Buffer, ReadError);
        if (ReadError || Count == 0)
        {
            Conn->Close();
            co_return false;
        }
        std::size_t Offset = 0;
        while (Offset < Count)
        {
            std::error_code WriteError;
            const auto WriteWindow = std::span<const std::byte>(Buffer).subspan(
                Offset, Count - Offset);
            const auto Written = co_await Conn->async_write_some(WriteWindow, WriteError);
            if (WriteError || Written == 0)
            {
                Conn->Close();
                co_return false;
            }
            Offset += Written;
        }
        // 保持连接直到对端收完响应并主动关闭，避免仅入队的 QUIC 包
        // 在本端立即 Close 时被丢弃。
        std::array<std::byte, 1> Drain{};
        std::error_code CloseError;
        (void)co_await Conn->async_read_some(Drain, CloseError);
        Conn->Close();
        co_return true;
    }

    auto RunUdpServer(std::shared_ptr<Preview::Quic::Server> Server,
                      Preview::Tuic::ServerConfig Config) -> Net::awaitable<bool>
    {
        auto AuthOnly = std::make_shared<Preview::Tuic::Conn<>>(
            Preview::SharedTransmission{}, Config.uuid);
        const auto AuthError = co_await AuthOnly->ReadAuthentication(
            std::move(Config.AuthStream),
            Preview::Tuic::ServerAuthenticationMaterial{
                .Exporter = Config.Exporter,
                .ExporterContext = Config.password,
                .Credential = {}});
        if (AuthError != Preview::Error::None)
        {
            co_return false;
        }
        auto Datagram = Preview::Tuic::AcceptPacket(Server->Datagram(), Config);
        if (!Datagram)
        {
            co_return false;
        }
        Preview::Tuic::Address Target;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Target, Payload);
        auto PacketError = ReceiveError;
        if (PacketError == Preview::Error::None)
        {
            PacketError = co_await Datagram->AsyncSendTo(
                Target, std::span<const std::uint8_t>(Payload));
        }
        Datagram->Close();
        co_return PacketError == Preview::Error::None;
    }

    auto RunTcpServer(Net::any_io_executor Executor,
                      std::shared_ptr<Preview::Quic::Server> Server,
                      Preview::Tuic::ServerConfig Config) -> Net::awaitable<bool>
    {
        const auto DataProvider = co_await Server->AcceptBidirectionalStream();
        if (!DataProvider)
        {
            co_return false;
        }
        auto DataStream = std::make_shared<Preview::Quic::StreamAdapter>(Executor, DataProvider);
        auto [AuthError, Request, Conn] = co_await Preview::Tuic::Accept(DataStream, Config);
        (void)Request;
        if (AuthError != Preview::Error::None || !Conn)
        {
            co_return false;
        }
        co_return co_await Echo(Conn);
    }

    /// 关闭并等待 TUIC server 的 QUIC native pump 完成。
    auto DrainTuicServer(const std::shared_ptr<Preview::Quic::Server> &Server)
        -> Net::awaitable<void>
    {
        std::exception_ptr FirstError;
        Server->Close();
        try
        {
            CaptureDrainFailure(FirstError, co_await Server->Drain());
        }
        catch (...)
        {
            FirstError = std::current_exception();
        }
        if (FirstError)
        {
            std::rethrow_exception(FirstError);
        }
    }

    struct TuicServerDataRequest final
    {
        Options OptionsValue;
        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Quic::Server> Server;
        Preview::Tuic::ServerConfig Config;
    };

    auto RunTuicServerData(TuicServerDataRequest Request) -> Net::awaitable<int>
    {
        std::exception_ptr FirstError;
        bool Succeeded = false;
        try
        {
            Succeeded = Request.OptionsValue.Udp
                            ? co_await RunUdpServer(Request.Server, std::move(Request.Config))
                            : co_await RunTcpServer(Request.Executor, Request.Server,
                                                     std::move(Request.Config));
        }
        catch (...)
        {
            FirstError = std::current_exception();
        }
        try
        {
            co_await DrainTuicServer(Request.Server);
        }
        catch (...)
        {
            if (!FirstError)
            {
                FirstError = std::current_exception();
            }
        }
        if (FirstError)
        {
            std::rethrow_exception(FirstError);
        }
        if (!Succeeded)
        {
            std::fprintf(stderr, "FAIL: TUIC %s echo\n",
                         Request.OptionsValue.Udp ? "UDP" : "TCP");
            co_return 1;
        }
        std::printf("PASS: Preview TUIC server authenticated %s echo\n",
                    Request.OptionsValue.Udp ? "UDP" : "TCP");
        co_return 0;
    }

    auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed TUIC listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: TUIC listen address is not an IP literal\n");
            co_return 2;
        }
        auto Tls = std::make_shared<Ssl::context>(Ssl::context::tlsv13_server);
        if (!LoadSelfSigned(*Tls))
        {
            std::fprintf(stderr, "FAIL: cannot create TUIC self-signed certificate\n");
            co_return 1;
        }
        const auto SelectH3 = [](SSL *, const unsigned char **Out, unsigned char *OutLength,
                                 const unsigned char *In, unsigned int InLength, void *) -> int
        {
            static constexpr unsigned char H3[] = {0x02, 'h', '3'};
            const auto Negotiated = SSL_select_next_proto(
                const_cast<unsigned char **>(Out), OutLength, H3, sizeof(H3), In, InLength);
            return Negotiated == OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK
                                                         : SSL_TLSEXT_ERR_ALERT_FATAL;
        };
        SSL_CTX_set_alpn_select_cb(Tls->native_handle(), SelectH3, nullptr);
        const auto Executor = co_await Net::this_coro::executor;
        auto Socket = std::make_shared<Udp::socket>(
            Executor, Udp::endpoint(Address, Listen->Port));
        auto Server = std::make_shared<Preview::Quic::Server>(
            Preview::Quic::ServerOptions{
                Executor, Socket, Tls, Preview::Testing::Quic::MakeSender(Socket)});
        Server->Start();
        std::printf("READY: Preview TUIC server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        std::exception_ptr StartupError;
        bool HandshakeReady = false;
        try
        {
            HandshakeReady = co_await Server->WaitHandshake();
        }
        catch (...)
        {
            StartupError = std::current_exception();
        }
        if (StartupError)
        {
            try
            {
                co_await DrainTuicServer(Server);
            }
            catch (...)
            {
            }
            std::rethrow_exception(StartupError);
        }
        if (!HandshakeReady)
        {
            co_await DrainTuicServer(Server);
            co_return 1;
        }
        Preview::Quic::SharedStreamProvider AuthProvider;
        std::exception_ptr AuthError;
        try
        {
            AuthProvider = co_await Server->AcceptUnidirectionalStream();
        }
        catch (...)
        {
            AuthError = std::current_exception();
        }
        if (AuthError)
        {
            try
            {
                co_await DrainTuicServer(Server);
            }
            catch (...)
            {
            }
            std::rethrow_exception(AuthError);
        }
        if (!AuthProvider)
        {
            co_await DrainTuicServer(Server);
            co_return 1;
        }
        auto AuthStream = std::make_shared<Preview::Quic::StreamAdapter>(Executor, AuthProvider);
        const auto Exporter = [Server](std::span<std::uint8_t> Output,
                                       std::span<const std::uint8_t> Label,
                                       std::string_view Context)
        {
            return Server->ExportKeyingMaterial(Output, Label, Context);
        };
        Preview::Tuic::ServerConfig Config;
        Config.uuid = OptionsValue.Uuid;
        Config.password = OptionsValue.Password;
        Config.AuthStream = std::move(AuthStream);
        Config.Exporter = Exporter;
        co_return co_await RunTuicServerData(
            TuicServerDataRequest{OptionsValue, Executor, Server, std::move(Config)});
    }

    auto RunInterop(Options OptionsValue, int &ExitCode) -> Net::awaitable<void>
    {
        if (OptionsValue.Mode == "client")
        {
            ExitCode = co_await RunClient(OptionsValue);
        }
        else
        {
            ExitCode = co_await RunServer(OptionsValue);
        }
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    const auto Options = ParseOptions(Argc, Argv);
    if (!Options)
    {
        std::fprintf(stderr, "FAIL: malformed TUIC options\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    Net::co_spawn(Io, RunInterop(*Options, ExitCode),
                  [&Failure](std::exception_ptr Exception) { Failure = std::move(Exception); });
    Io.run();
    if (Failure)
    {
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const std::exception &Error)
        {
            std::fprintf(stderr, "FAIL: TUIC interop coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: TUIC interop coroutine exception\n");
        }
        return 1;
    }
    return ExitCode;
}

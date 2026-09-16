/**
 * @file InteropTrusttunnel.cpp
 * @brief Preview TrustTunnel 标准 TLS/HTTP2 CONNECT 与 Go reference 双向互操作
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <Preview/Protocols/Trusttunnel/Trusttunnel.hpp>
#include <Preview/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    using Net::experimental::awaitable_operators::operator||;
    namespace Ssl = Net::ssl;
    using Tcp = Net::ip::tcp;
    constexpr std::string_view Payload{"prism-trusttunnel-http2-external-interop-payload"};

    struct Options
    {
        std::string Mode{"client"};
        std::string Address{"127.0.0.1:19097"};
    };

    struct HostPort
    {
        std::string Host;
        std::uint16_t Port{0};
    };

    [[nodiscard]] auto ParsePort(std::string_view Value) -> std::optional<std::uint16_t>
    {
        if (Value.empty())
        {
            return std::nullopt;
        }
        std::uint32_t Port = 0;
        const auto [End, Error] = std::from_chars(Value.data(), Value.data() + Value.size(), Port);
        if (Error != std::errc{} || End != Value.data() + Value.size() || Port > 65535)
        {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(Port);
    }

    [[nodiscard]] auto SplitHostPort(std::string_view Value) -> std::optional<HostPort>
    {
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
                                                      reinterpret_cast<const unsigned char *>("trusttunnel"),
                                                      -1, -1, 0) > 0 &&
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

    auto SelectH2(SSL *, const unsigned char **Out, unsigned char *OutLen,
                  const unsigned char *In, unsigned int InLen, void *) -> int
    {
        static constexpr unsigned char H2[] = {2, 'h', '2'};
        for (unsigned int Offset = 0; Offset + H2[0] < InLen; Offset += In[Offset] + 1)
        {
            if (In[Offset] == H2[0] && std::memcmp(In + Offset + 1, H2 + 1, H2[0]) == 0)
            {
                *Out = In + Offset + 1;
                *OutLen = H2[0];
                return SSL_TLSEXT_ERR_OK;
            }
        }
        return SSL_TLSEXT_ERR_NOACK;
    }

    [[nodiscard]] auto ReadExact(const Preview::SharedTransmission &Transport,
                                 std::span<std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            std::error_code Error;
            const auto Read = co_await Transport->async_read_some(Data.subspan(Offset), Error);
            if (Error || Read == 0 || Read > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Read;
        }
        co_return true;
    }

    [[nodiscard]] auto WriteAll(const Preview::SharedTransmission &Transport,
                                std::span<const std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            std::error_code Error;
            const auto Written = co_await Transport->async_write_some(Data.subspan(Offset), Error);
            if (Error || Written == 0 || Written > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Written;
        }
        co_return true;
    }

    [[nodiscard]] auto RunServer(Options Value) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(Value.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed TrustTunnel listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            co_return 2;
        }
        Ssl::context Tls(Ssl::context::tlsv13_server);
        if (!LoadSelfSigned(Tls))
        {
            std::fprintf(stderr, "FAIL: TrustTunnel certificate setup\n");
            co_return 1;
        }
        SSL_CTX_set_alpn_select_cb(Tls.native_handle(), SelectH2, nullptr);
        boost::system::error_code Error;
        Tcp::acceptor Acceptor(co_await Net::this_coro::executor);
        auto Protocol = Tcp::v4();
        if (!Address.is_v4())
        {
            Protocol = Tcp::v6();
        }
        Acceptor.open(Protocol, Error);
        Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
        Acceptor.bind(Tcp::endpoint(Address, Listen->Port), Error);
        Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        if (Error)
        {
            co_return 1;
        }
        std::printf("READY: Preview TrustTunnel server on %s\n", Value.Address.c_str());
        std::fflush(stdout);
        auto Socket = co_await Acceptor.async_accept(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return 1;
        }
        auto Raw = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        const Preview::Trusttunnel::ServerConfig Config{"user", "password"};
        auto [HandshakeError, Target, Transport] =
            co_await Preview::Trusttunnel::AcceptHttp2(Raw, Tls, Config);
        (void)Target;
        if (HandshakeError != Preview::Error::None || !Transport)
        {
            Raw->Close();
            std::fprintf(stderr, "FAIL: TrustTunnel server handshake\n");
            co_return 1;
        }
        std::array<std::byte, Payload.size()> Buffer{};
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        if (!co_await ReadExact(Transport, Buffer) || std::memcmp(Buffer.data(), Bytes.data(), Bytes.size()) != 0 ||
            !co_await WriteAll(Transport, Buffer))
        {
            Transport->Close();
            std::fprintf(stderr, "FAIL: TrustTunnel server echo\n");
            co_return 1;
        }

        // 等待客户端消费完响应并关闭 CONNECT stream，避免进程退出时重置连接。
        std::array<std::byte, 1> Drain{};
        Net::steady_timer Deadline(Transport->Executor());
        Deadline.expires_after(std::chrono::seconds(2));
        auto WaitForPeer = [&]() -> Net::awaitable<std::size_t>
        {
            std::error_code WaitError;
            co_return co_await Transport->async_read_some(Drain, WaitError);
        };
        auto WaitForPeerOperation = WaitForPeer();
        auto DeadlineOperation = Deadline.async_wait(Net::use_awaitable);
        const auto WaitResult = co_await (
            std::move(WaitForPeerOperation) || std::move(DeadlineOperation));
        if (WaitResult.index() == 1)
        {
            Transport->Cancel();
        }
        Transport->Close();
        std::printf("PASS: Preview TrustTunnel server echo (%zu bytes)\n", Payload.size());
        co_return 0;
    }

    [[nodiscard]] auto RunClient(Options Value) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(Value.Address);
        if (!Server)
        {
            co_return 2;
        }
        boost::system::error_code Error;
        Tcp::socket Socket(co_await Net::this_coro::executor);
        const auto ServerAddress = Net::ip::make_address(Server->Host, Error);
        const auto Endpoint = Tcp::endpoint(ServerAddress, Server->Port);
        co_await Socket.async_connect(
            Endpoint,
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            std::fprintf(stderr, "FAIL: TrustTunnel connect: %s\n", Error.message().c_str());
            co_return 1;
        }
        Ssl::context Tls(Ssl::context::tlsv13_client);
        Tls.set_verify_mode(Ssl::verify_none);
        auto Raw = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        const Preview::Trusttunnel::ClientConfig Config{"user", "password"};
        Preview::Trusttunnel::Http2ConnectParameters Parameters{
            Raw,
            Tls,
            Config,
            "example.com",
            443,
            "example.com"};
        auto [HandshakeError, Transport] = co_await Preview::Trusttunnel::ConnectHttp2(
            std::move(Parameters));
        if (HandshakeError != Preview::Error::None || !Transport)
        {
            std::fprintf(stderr, "FAIL: TrustTunnel client handshake\n");
            co_return 1;
        }
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        std::array<std::byte, Payload.size()> Buffer{};
        if (!co_await WriteAll(Transport, Bytes))
        {
            Transport->Close();
            std::fprintf(stderr, "FAIL: TrustTunnel client write\n");
            co_return 1;
        }
        try
        {
            co_await std::static_pointer_cast<Preview::Trusttunnel::Http2Transport>(Transport)->Finish();
        }
        catch (...)
        {
            Transport->Close();
            std::fprintf(stderr, "FAIL: TrustTunnel client half-close\n");
            co_return 1;
        }
        if (!co_await ReadExact(Transport, Buffer) ||
            std::memcmp(Buffer.data(), Bytes.data(), Bytes.size()) != 0)
        {
            Transport->Close();
            std::fprintf(stderr, "FAIL: TrustTunnel client echo\n");
            co_return 1;
        }
        Transport->Close();
        std::printf("PASS: Preview TrustTunnel client echo (%zu bytes)\n", Payload.size());
        co_return 0;
    }

} // namespace

auto main(int Argc, char **Argv) -> int
{
    Options Value;
    for (int Index = 1; Index + 1 < Argc; Index += 2)
    {
        if (std::string_view(Argv[Index]) == "-mode")
        {
            Value.Mode = Argv[Index + 1];
        }
        else if (std::string_view(Argv[Index]) == "-addr")
        {
            Value.Address = Argv[Index + 1];
        }
    }
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    auto Run = [&Io, &ExitCode, Value]() -> Net::awaitable<void>
    {
        if (Value.Mode == "server")
        {
            ExitCode = co_await RunServer(Value);
        }
        else
        {
            ExitCode = co_await RunClient(Value);
        }
        Io.stop();
    };
    auto OnComplete = [&Io, &Failure](std::exception_ptr Exception) -> void
    {
        Failure = std::move(Exception);
        Io.stop();
    };
    Net::co_spawn(Io, Run(), std::move(OnComplete));
    Io.run();
    if (Failure)
    {
        try
        {
            std::rethrow_exception(Failure);
        }
        catch (const std::exception &Exception)
        {
            std::fprintf(stderr, "FAIL: TrustTunnel interop exception: %s\n", Exception.what());
        }
        return 1;
    }
    return ExitCode;
}

/**
 * @file InteropTrusttunnel.cpp
 * @brief Prism TrustTunnel 标准 TLS/HTTP2 CONNECT 与 Go reference 双向互操作
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
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>

#include <Prism/Contract/Io/IoResult.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Trusttunnel/Http2.hpp>
#include <Prism/Protocols/Trusttunnel/IngressFactory.hpp>
#include <Prism/Protocols/Trusttunnel/Types.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <Prism/Transport/Transmission.hpp>

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

    [[nodiscard]] auto ReadExact(const Prism::SharedTransmission &Transport,
                                 std::span<std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            const auto Read = co_await Transport->ReadSome(Data.subspan(Offset));
            if (Read.Failure.Failed() || Read.Bytes == 0 || Read.Bytes > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Read.Bytes;
        }
        co_return true;
    }

    [[nodiscard]] auto WriteAll(const Prism::SharedTransmission &Transport,
                                std::span<const std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            const auto Written = co_await Transport->WriteSome(Data.subspan(Offset));
            if (Written.Failure.Failed() || Written.Bytes == 0 ||
                Written.Bytes > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Written.Bytes;
        }
        co_return true;
    }

    [[nodiscard]] auto CloseAndDrainCarrier(Prism::SharedTransmission Transport)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Transport)
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        const auto Activity = Transport->Activity();
        if (!Activity)
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        const auto Closed = Transport->Close();
        auto FirstFailure = Prism::Fault::Failure{};
        if (!Closed) FirstFailure = Closed.error();
        Activity->Seal();
        const auto Drained = co_await Activity->Drain();
        if (!Drained && FirstFailure.Succeeded()) FirstFailure = Drained.error();
        if (!Activity->IsRetired() && FirstFailure.Succeeded())
            FirstFailure = {Prism::Fault::Code::Blocked};
        if (FirstFailure.Failed()) co_return std::unexpected(FirstFailure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    /** @brief 等待客户端完成 CONNECT 关闭并排空服务端 carrier。 */
    [[nodiscard]] auto FinishServerExchange(Prism::SharedTransmission Transport)
        -> Net::awaitable<int>
    {
        // 等待客户端消费完响应并关闭 CONNECT stream，避免进程退出时重置连接。
        std::array<std::byte, 1> Drain{};
        Net::steady_timer Deadline(Transport->Executor());
        Deadline.expires_after(std::chrono::seconds(2));
        auto WaitForPeer = [&]() -> Net::awaitable<Prism::IoResult>
        {
            co_return co_await Transport->ReadSome(Drain);
        };
        auto WaitForPeerOperation = WaitForPeer();
        auto DeadlineOperation = Deadline.async_wait(Net::use_awaitable);
        const auto WaitResult = co_await (
            std::move(WaitForPeerOperation) || std::move(DeadlineOperation));
        Prism::Fault::Failure ControlFailure;
        Prism::Fault::Failure PeerReadFailure;
        if (WaitResult.index() == 0)
        {
            const auto PeerRead = std::get<0>(WaitResult);
            if (PeerRead.Bytes > Drain.size())
                PeerReadFailure = {Prism::Fault::Code::InvalidArgument};
            else if (PeerRead.Failure.Failed() &&
                PeerRead.Failure.Code != Prism::Fault::Code::Eof)
                PeerReadFailure = PeerRead.Failure;
        }
        if (WaitResult.index() == 1)
        {
            const auto Canceled = Transport->Cancel();
            if (!Canceled) ControlFailure = Canceled.error();
        }
        const auto Drained = co_await CloseAndDrainCarrier(Transport);
        if (ControlFailure.Failed())
        {
            std::fprintf(stderr,
                "FAIL: TrustTunnel peer cancel Code=%u Native=%s/%d\n",
                static_cast<unsigned>(ControlFailure.Code),
                ControlFailure.Native.category().name(), ControlFailure.Native.value());
            co_return 1;
        }
        if (!Drained)
        {
            const auto Failure = Drained.error();
            std::fprintf(stderr,
                "FAIL: TrustTunnel server retirement Code=%u Native=%s/%d\n",
                static_cast<unsigned>(Failure.Code), Failure.Native.category().name(),
                Failure.Native.value());
            co_return 1;
        }
        if (PeerReadFailure.Failed())
        {
            std::fprintf(stderr,
                "FAIL: TrustTunnel peer read Code=%u Native=%s/%d\n",
                static_cast<unsigned>(PeerReadFailure.Code),
                PeerReadFailure.Native.category().name(), PeerReadFailure.Native.value());
            co_return 1;
        }
        std::printf("PASS: Prism TrustTunnel server echo (%zu bytes)\n", Payload.size());
        co_return 0;
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
        std::printf("READY: Prism TrustTunnel server on %s\n", Value.Address.c_str());
        std::fflush(stdout);
        auto Socket = co_await Acceptor.async_accept(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return 1;
        }
        auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        const Prism::Trusttunnel::ServerConfig Config{"user", "password"};
        auto Accepted = co_await Prism::Trusttunnel::AcceptHttp2(
            Prism::Trusttunnel::Http2AcceptRequest{
                Raw, Tls, Prism::Trusttunnel::MakeWireAuthBinding(Config, {}),
                std::make_shared<Prism::Memory::BytePool>()});
        if (!Accepted)
        {
            const auto Drained = co_await CloseAndDrainCarrier(Raw);
            if (!Drained)
                std::fprintf(stderr, "FAIL: TrustTunnel raw cleanup Code=%u\n",
                    static_cast<unsigned>(Drained.error().Code));
            std::fprintf(stderr, "FAIL: TrustTunnel server handshake\n");
            co_return 1;
        }
        auto Transport = std::move(Accepted->Transport);
        std::array<std::byte, Payload.size()> Buffer{};
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        if (!co_await ReadExact(Transport, Buffer) || std::memcmp(Buffer.data(), Bytes.data(), Bytes.size()) != 0 ||
            !co_await WriteAll(Transport, Buffer))
        {
            const auto Drained = co_await CloseAndDrainCarrier(Transport);
            if (!Drained)
                std::fprintf(stderr, "FAIL: TrustTunnel server cleanup Code=%u\n",
                    static_cast<unsigned>(Drained.error().Code));
            std::fprintf(stderr, "FAIL: TrustTunnel server echo\n");
            co_return 1;
        }

        co_return co_await FinishServerExchange(std::move(Transport));
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
        auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        const Prism::Trusttunnel::ClientConfig Config{"user", "password"};
        Prism::Trusttunnel::Http2ConnectParameters Parameters{
            Raw,
            Tls,
            Config,
            "example.com",
            443,
            "example.com",
            std::make_shared<Prism::Memory::BytePool>()};
        auto Connected = co_await Prism::Trusttunnel::ConnectHttp2(std::move(Parameters));
        if (!Connected)
        {
            std::fprintf(stderr, "FAIL: TrustTunnel client handshake\n");
            co_return 1;
        }
        auto Transport = std::move(*Connected);
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        std::array<std::byte, Payload.size()> Buffer{};
        if (!co_await WriteAll(Transport, Bytes))
        {
            const auto Drained = co_await CloseAndDrainCarrier(Transport);
            if (!Drained)
                std::fprintf(stderr, "FAIL: TrustTunnel client cleanup Code=%u\n",
                    static_cast<unsigned>(Drained.error().Code));
            std::fprintf(stderr, "FAIL: TrustTunnel client write\n");
            co_return 1;
        }
        const auto Finish = co_await Transport->WriteShutdown();
        if (!Finish)
        {
            const auto Drained = co_await CloseAndDrainCarrier(Transport);
            if (!Drained)
                std::fprintf(stderr, "FAIL: TrustTunnel client cleanup Code=%u\n",
                    static_cast<unsigned>(Drained.error().Code));
            std::fprintf(stderr, "FAIL: TrustTunnel client half-close\n");
            co_return 1;
        }
        if (!co_await ReadExact(Transport, Buffer) ||
            std::memcmp(Buffer.data(), Bytes.data(), Bytes.size()) != 0)
        {
            const auto Drained = co_await CloseAndDrainCarrier(Transport);
            if (!Drained)
                std::fprintf(stderr, "FAIL: TrustTunnel client cleanup Code=%u\n",
                    static_cast<unsigned>(Drained.error().Code));
            std::fprintf(stderr, "FAIL: TrustTunnel client echo\n");
            co_return 1;
        }
        const auto Drained = co_await CloseAndDrainCarrier(Transport);
        if (!Drained)
        {
            std::fprintf(stderr, "FAIL: TrustTunnel client retirement Code=%u\n",
                static_cast<unsigned>(Drained.error().Code));
            co_return 1;
        }
        std::printf("PASS: Prism TrustTunnel client echo (%zu bytes)\n", Payload.size());
        co_return 0;
    }

    auto RunInterop(Options Value, int &ExitCode) -> Net::awaitable<void>
    {
        if (Value.Mode == "server")
        {
            ExitCode = co_await RunServer(Value);
        }
        else
        {
            ExitCode = co_await RunClient(Value);
        }
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
    Net::co_spawn(Io, RunInterop(Value, ExitCode),
                  [&Failure](std::exception_ptr Exception) { Failure = std::move(Exception); });
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

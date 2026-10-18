/**
 * @file InteropXhttp.cpp
 * @brief Prism XHTTP Stream-one 与 Go x/net/http2 reference client 的 TCP 互操作端点
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/steady_timer.hpp>
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

#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Xhttp/Xhttp.hpp>
#include <Prism/Protocols/Xhttp/Detail/StreamTransport.hpp>
#include <Prism/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    using Net::experimental::awaitable_operators::operator||;
    namespace Ssl = Net::ssl;
    using Tcp = Net::ip::tcp;
    constexpr std::string_view Payload{"prism-xhttp-http2-external-interop-payload"};

    auto ReportXhttpRetirementFailure(
        std::string_view Scope,
        const Prism::Fault::Failure &Failure) -> void
    {
        const auto Code = Prism::Fault::Describe(Failure.Code);
        std::fprintf(
            stderr, "FAIL: XHTTP %.*s retirement code=%.*s native=%s/%d\n",
            static_cast<int>(Scope.size()), Scope.data(),
            static_cast<int>(Code.size()), Code.data(),
            Failure.Native.category().name(), Failure.Native.value());
    }

    [[nodiscard]] auto CloseAndDrainXhttp(Prism::SharedTransmission Transport)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        if (!Transport)
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        Prism::Fault::Failure FirstFailure;
        const auto Closed = Transport->Close();
        if (!Closed) FirstFailure = Closed.error();
        const auto Activity = Transport->Activity();
        if (!Activity)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        const auto Drained = co_await Activity->Drain();
        if (!Drained && FirstFailure.Succeeded()) FirstFailure = Drained.error();
        if (!Activity->IsRetired() && FirstFailure.Succeeded())
        {
            FirstFailure = {Prism::Fault::Code::Blocked};
        }
        if (FirstFailure.Failed()) co_return std::unexpected(FirstFailure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    struct Options
    {
        std::string Address{"127.0.0.1:19096"};
        std::string Mode{"server"};
        std::string XhttpMode{"StreamOne"};
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
                                                      reinterpret_cast<const unsigned char *>("xhttp"), -1,
                                                      -1, 0) > 0 &&
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

    struct AlpnSelection final
    {
        const unsigned char **Output;
        unsigned char *OutputLength;
        const unsigned char *Input;
        unsigned int InputLength;
    };

    auto SelectH2Protocol(AlpnSelection Selection) -> int
    {
        static constexpr unsigned char H2[] = {2, 'h', '2'};
        for (unsigned int Offset = 0;
             Offset + H2[0] < Selection.InputLength;
             Offset += Selection.Input[Offset] + 1)
        {
            if (Selection.Input[Offset] == H2[0] &&
                std::memcmp(Selection.Input + Offset + 1, H2 + 1, H2[0]) == 0)
            {
                *Selection.Output = Selection.Input + Offset + 1;
                *Selection.OutputLength = H2[0];
                return SSL_TLSEXT_ERR_OK;
            }
        }
        return SSL_TLSEXT_ERR_NOACK;
    }

    auto SelectH2(SSL *, const unsigned char **Output, unsigned char *OutputLength,
                  const unsigned char *Input, unsigned int InputLength, void *) -> int
    {
        return SelectH2Protocol(AlpnSelection{Output, OutputLength, Input, InputLength});
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
            if (Written.Failure.Failed() || Written.Bytes == 0 || Written.Bytes > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Written.Bytes;
        }
        co_return true;
    }

    [[nodiscard]] auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed XHTTP listen address\n");
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
            std::fprintf(stderr, "FAIL: XHTTP certificate setup\n");
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
        std::printf("READY: Prism XHTTP server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto Socket = co_await Acceptor.async_accept(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return 1;
        }
        auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        Prism::Xhttp::Config Config;
        Config.Mode = OptionsValue.XhttpMode;
        auto Accepted = co_await Prism::Xhttp::Accept(
            Prism::Xhttp::AcceptRequest{
                std::move(Raw), Tls, Config,
                std::make_shared<Prism::Memory::BytePool>(
                    Prism::Memory::BytePoolOptions{.BlockCount = 8})});
        if (!Accepted)
        {
            std::fprintf(stderr, "FAIL: XHTTP handshake\n");
            co_return 1;
        }
        auto Transport = std::move(Accepted->Transport);
        std::array<std::byte, Payload.size()> Buffer{};
        if (!co_await ReadExact(Transport, Buffer) ||
            std::memcmp(Buffer.data(), Payload.data(), Payload.size()) != 0 ||
            !co_await WriteAll(Transport, Buffer))
        {
            const auto Retirement = co_await CloseAndDrainXhttp(Transport);
            if (!Retirement)
                ReportXhttpRetirementFailure("echo", Retirement.error());
            std::fprintf(stderr, "FAIL: XHTTP echo\n");
            co_return 1;
        }

        // 等待客户端关闭请求流，避免进程退出时尚未读取的响应被重置。
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
        if (WaitResult.index() == 1)
        {
            const auto Canceled = Transport->Cancel();
            if (!Canceled)
                ReportXhttpRetirementFailure("peer cancel", Canceled.error());
        }
        const auto Retirement = co_await CloseAndDrainXhttp(Transport);
        if (!Retirement)
        {
            ReportXhttpRetirementFailure("server", Retirement.error());
            co_return 1;
        }
        std::printf("PASS: Prism XHTTP server echo (%zu bytes)\n", Payload.size());
        co_return 0;
    }

    [[nodiscard]] auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed XHTTP connect address\n");
            co_return 2;
        }
        boost::system::error_code Error;
        const auto Address = Net::ip::make_address(Listen->Host, Error);
        if (Error)
        {
            std::fprintf(stderr, "FAIL: malformed XHTTP connect host\n");
            co_return 2;
        }
        Tcp::socket Socket(co_await Net::this_coro::executor);
        co_await Socket.async_connect(Tcp::endpoint(Address, Listen->Port),
                                      Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            std::fprintf(stderr, "FAIL: XHTTP connect: %s\n", Error.message().c_str());
            co_return 1;
        }

        Ssl::context Tls(Ssl::context::tlsv13_client);
        Tls.set_verify_mode(Ssl::verify_none);
        auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        Prism::Xhttp::Config Config;
        Config.Mode = OptionsValue.XhttpMode;
        auto Connected = co_await Prism::Xhttp::Connect(
            Prism::Xhttp::ClientConnectRequest{
                std::move(Raw), &Tls, Config, "example.com",
                std::make_shared<Prism::Memory::BytePool>(
                    Prism::Memory::BytePoolOptions{.BlockCount = 8})});
        if (!Connected)
        {
            std::fprintf(stderr, "FAIL: XHTTP client handshake\n");
            co_return 1;
        }
        auto Transport = std::move(*Connected);

        std::array<std::byte, Payload.size()> Buffer{};
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        if (!co_await WriteAll(Transport, PayloadBytes))
        {
            const auto Retirement = co_await CloseAndDrainXhttp(Transport);
            if (!Retirement)
                ReportXhttpRetirementFailure("client", Retirement.error());
            std::fprintf(stderr, "FAIL: XHTTP client request write\n");
            co_return 1;
        }
        if (Config.Mode == "StreamOne")
        {
            const auto Finish = co_await Transport->WriteShutdown();
            if (!Finish)
            {
                const auto Retirement = co_await CloseAndDrainXhttp(Transport);
                if (!Retirement)
                    ReportXhttpRetirementFailure("client", Retirement.error());
                std::fprintf(stderr, "FAIL: XHTTP client request half-close\n");
                co_return 1;
            }
        }
        if (!co_await ReadExact(Transport, Buffer) ||
            std::memcmp(Buffer.data(), Payload.data(), Payload.size()) != 0)
        {
            const auto Retirement = co_await CloseAndDrainXhttp(Transport);
            if (!Retirement)
                ReportXhttpRetirementFailure("client", Retirement.error());
            std::fprintf(stderr, "FAIL: XHTTP client echo\n");
            co_return 1;
        }
        const auto Retirement = co_await CloseAndDrainXhttp(Transport);
        if (!Retirement)
        {
            ReportXhttpRetirementFailure("client", Retirement.error());
            co_return 1;
        }
        std::printf("PASS: Prism XHTTP client echo (%zu bytes)\n", Payload.size());
        co_return 0;
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
    Options OptionsValue;
    for (int Index = 1; Index + 1 < Argc; Index += 2)
    {
        if (std::string_view(Argv[Index]) == "-addr")
        {
            OptionsValue.Address = Argv[Index + 1];
        }
        else if (std::string_view(Argv[Index]) == "-mode")
        {
            OptionsValue.Mode = Argv[Index + 1];
        }
        else if (std::string_view(Argv[Index]) == "-xhttp-mode")
        {
            OptionsValue.XhttpMode = Argv[Index + 1];
        }
    }
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    Net::co_spawn(Io, RunInterop(OptionsValue, ExitCode),
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
            std::fprintf(stderr, "FAIL: XHTTP interop exception: %s\n", Exception.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: XHTTP interop exception\n");
        }
        return 1;
    }
    return ExitCode;
}

/**
 * @file InteropNativeTls.cpp
 * @brief Preview native TLS carrier 与标准 Go TLS 的双向互操作端点
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
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
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Protocols/Native/Native.hpp>
#include <Preview/Transport/Reliable.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    using Tcp = Net::ip::tcp;

    constexpr std::string_view Payload{"prism-native-tls-external-interop-payload"};

    struct Options
    {
        std::string Mode{"client"};
        std::string Address{"127.0.0.1:19092"};
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
            else
            {
                return std::nullopt;
            }
        }
        return Result;
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
                                                      reinterpret_cast<const unsigned char *>("native"), -1, -1,
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

    [[nodiscard]] auto RunClient(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Server = SplitHostPort(OptionsValue.Address);
        if (!Server)
        {
            std::fprintf(stderr, "FAIL: malformed native TLS server address\n");
            co_return 2;
        }
        Preview::Network::Dialer::Dialer Dialer(co_await Net::this_coro::executor);
        std::error_code DialError;
        auto Raw = co_await Dialer.Connect(Server->Host, Server->Port, DialError);
        if (!Raw)
        {
            std::fprintf(stderr, "FAIL: native TLS TCP dial: %s\n", DialError.message().c_str());
            co_return 1;
        }
        Ssl::context Tls(Ssl::context::tlsv13_client);
        Tls.set_verify_mode(Ssl::verify_none);
        auto Transport = co_await Preview::Native::Connect(std::move(Raw), Tls, "native");
        if (!Transport)
        {
            std::fprintf(stderr, "FAIL: native TLS client handshake\n");
            co_return 1;
        }
        const auto Bytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        if (!co_await WriteAll(Transport, Bytes))
        {
            Transport->Close();
            std::fprintf(stderr, "FAIL: native TLS client write\n");
            co_return 1;
        }
        std::array<std::byte, Payload.size()> Echo{};
        if (!co_await ReadExact(Transport, Echo) ||
            std::memcmp(Echo.data(), Bytes.data(), Bytes.size()) != 0)
        {
            Transport->Close();
            std::fprintf(stderr, "FAIL: native TLS external echo mismatch\n");
            co_return 1;
        }
        Transport->Close();
        std::printf("PASS: Preview native TLS client -> Go reference server (%zu bytes)\n", Payload.size());
        co_return 0;
    }

    [[nodiscard]] auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed native TLS listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: native TLS listen address is not an IP literal\n");
            co_return 2;
        }
        Ssl::context Tls(Ssl::context::tlsv13_server);
        if (!LoadSelfSigned(Tls))
        {
            std::fprintf(stderr, "FAIL: native TLS certificate setup\n");
            co_return 1;
        }
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
            std::fprintf(stderr, "FAIL: native TLS listen: %s\n", Error.message().c_str());
            co_return 1;
        }
        std::printf("READY: Preview native TLS server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto Socket = co_await Acceptor.async_accept(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return 1;
        }
        auto Raw = std::make_shared<Preview::Transport::Reliable>(std::move(Socket));
        auto Transport = co_await Preview::Native::Accept(Raw, Tls);
        if (!Transport)
        {
            Raw->Close();
            std::fprintf(stderr, "FAIL: native TLS server handshake\n");
            co_return 1;
        }
        std::array<std::byte, Payload.size()> Buffer{};
        if (!co_await ReadExact(Transport, Buffer) || !co_await WriteAll(Transport, Buffer))
        {
            Transport->Close();
            co_return 1;
        }
        Transport->Close();
        std::printf("PASS: Preview native TLS server echo (%zu bytes)\n", Payload.size());
        co_return 0;
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    const auto Options = ParseOptions(Argc, Argv);
    if (!Options)
    {
        std::fprintf(stderr, "FAIL: malformed native TLS options\n");
        return 2;
    }
    Net::io_context Io;
    int ExitCode = 1;
    std::exception_ptr Failure;
    auto Run = [&Io, &ExitCode, OptionsValue = *Options]() -> Net::awaitable<void>
    {
        if (OptionsValue.Mode == "server")
        {
            ExitCode = co_await RunServer(OptionsValue);
        }
        else
        {
            ExitCode = co_await RunClient(OptionsValue);
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
        catch (const std::exception &Error)
        {
            std::fprintf(stderr, "FAIL: native TLS interop coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: native TLS interop coroutine exception\n");
        }
        return 1;
    }
    return ExitCode;
}

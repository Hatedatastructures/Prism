/**
 * @file TuicServer.cpp
 * @brief TUIC 互操作的 Prism server 端点与 reference echo 行为。
 */

#include "TuicOptions.hpp"
#include "TuicLifecycle.hpp"
#include "TuicTerminalIo.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/this_coro.hpp>

#include <boost/system/error_code.hpp>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Net/Dialer/Dialer.hpp>
#include <Prism/Net/Relay/Relay.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include "../../../TestSupport/Prism/QuicFactory.hpp"
#include <Prism/Protocols/Quic/StreamAdapter.hpp>

namespace Prism::Testing::TuicInterop
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    using Udp = Net::ip::udp;
    using DrainResult = std::expected<void, Prism::Fault::Failure>;

    auto CaptureDrainFailure(std::exception_ptr &FirstError, DrainResult Result) -> void
    {
        if (!Result && !FirstError)
        {
            FirstError = std::make_exception_ptr(
                std::system_error(Prism::Fault::ToNative(Result.error())));
        }
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

    auto Echo(Prism::Tuic::SharedConn Conn) -> Net::awaitable<bool>
    {
        auto &Carrier = static_cast<Prism::Transmission &>(*Conn);
        std::array<std::byte, 4096> Buffer{};
        const auto EchoResult = co_await Detail::EchoPeerStream(Carrier, Buffer);
        const bool EchoCompleted = EchoResult && EchoResult->Bytes != 0 &&
            EchoResult->Terminal.Code == Prism::Fault::Code::Eof;
        bool HalfCloseSucceeded = false;
        if (EchoCompleted)
        {
            const auto HalfClose = co_await Conn->WriteShutdown();
            HalfCloseSucceeded = static_cast<bool>(HalfClose);
            if (!HalfClose)
            {
                const auto Failure = HalfClose.error();
                std::fprintf(stderr,
                    "FAIL: TUIC server stream half-close code=%s native=%d\n",
                    Prism::Fault::Describe(Failure.Code).data(), Failure.Native.value());
            }
        }
        const auto Drained = co_await Detail::CloseAndDrainTuicConnection(Conn);
        if (!Drained)
        {
            std::fprintf(stderr, "FAIL: TUIC server stream activity drain\n");
        }
        co_return EchoCompleted && HalfCloseSucceeded && static_cast<bool>(Drained);
    }

    auto RunUdpServer(std::shared_ptr<Prism::Quic::Server> Server,
                      Prism::Tuic::ServerConfig Config) -> Net::awaitable<bool>
    {
        std::string_view Stage{"authenticate"};
        try
        {
            const auto AuthStream = Config.AuthStream;
            auto AuthOnly = std::make_shared<Prism::Tuic::Conn<>>(
                AuthStream, Config.uuid);
            const auto AuthResult = co_await AuthOnly->ReadAuthentication(
                AuthStream,
                Prism::Tuic::ServerAuthenticationMaterial{
                    .Exporter = Config.Exporter,
                    .ExporterContext = Config.password,
                    .Credential = {}});
            if (AuthResult.EffectiveStatus() != Prism::Error::None)
            {
                co_return false;
            }
            Stage = "authenticated";

            Stage = "obtain QUIC datagram provider";
            auto Provider = Server->Datagram();
            Stage = "create datagram adapter";
            auto DatagramResult = Prism::Tuic::AcceptPacket(std::move(Provider), Config);
            if (!DatagramResult)
            {
                co_return false;
            }
            auto Datagram = std::move(*DatagramResult);
            Prism::Tuic::Address Target;
            std::vector<std::uint8_t> Payload;

            Stage = "receive datagram";
            const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Target, Payload);
            auto PacketError = ReceiveError;
            if (PacketError == Prism::Error::None)
            {
                Stage = "send datagram";
                PacketError = co_await Datagram->AsyncSendTo(
        Target, std::span<const std::uint8_t>(Payload));
            }

            Stage = "close/drain datagram";
            const auto Closed = co_await CloseAndDrainTuicDgram(Datagram);
            co_return PacketError == Prism::Error::None && static_cast<bool>(Closed);
        }
        catch (const std::exception &Exception)
        {
            std::throw_with_nested(std::runtime_error(
                "TUIC UDP stage=" + std::string(Stage) + " original=" + Exception.what()));
        }
        catch (...)
        {
            std::throw_with_nested(std::runtime_error(
                "TUIC UDP stage=" + std::string(Stage) +
                " original=<non-standard exception>"));
        }
    }

    [[nodiscard]] auto ToNetworkTarget(const Prism::Tuic::Address &AddressValue)
        -> std::expected<Prism::Network::Target, Prism::Fault::Failure>
    {
        auto Encoding = Prism::Network::HostEncoding::Domain;
        if (AddressValue.Type == Prism::Tuic::AddressType::Ipv4)
        {
            Encoding = Prism::Network::HostEncoding::Ipv4Text;
        }
        else if (AddressValue.Type == Prism::Tuic::AddressType::Ipv6)
        {
            Encoding = Prism::Network::HostEncoding::Ipv6Bytes;
        }
        else if (AddressValue.Type != Prism::Tuic::AddressType::Domain)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::UnsupportedAddress});
        }
        auto Host = Prism::Network::DecodeHost(Encoding, AddressValue.Host);
        if (!Host)
        {
            return std::unexpected(Host.error());
        }
        return Prism::Network::Target{
            std::move(*Host), AddressValue.Port, Prism::Network::RouteKind::Forward};
    }

    [[nodiscard]] auto MakeRelayBytePool() -> std::shared_ptr<Prism::Memory::BytePool>
    {
        return std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{4096, 2});
    }

    auto RelayTarget(Net::any_io_executor Executor,
                     Prism::Tuic::SharedConn Conn,
                     const Prism::Tuic::Address &AddressValue) -> Net::awaitable<bool>
    {
        auto Target = ToNetworkTarget(AddressValue);
        if (!Target)
        {
            std::fprintf(stderr, "FAIL: TUIC server target conversion\n");
            (void)co_await Detail::CloseAndDrainTuicConnection(Conn);
            co_return false;
        }
        Prism::Network::Dialer::Dialer Dialer(Executor);
        auto Dialed = co_await Dialer.Connect(std::move(*Target));
        if (!Dialed)
        {
            auto Message = Prism::Fault::Describe(Dialed.error().Code);
            std::fprintf(stderr, "FAIL: TUIC server target dial: %s native=%d\n",
                Message.data(), Dialed.error().Native.value());
            (void)co_await Detail::CloseAndDrainTuicConnection(Conn);
            co_return false;
        }
        const auto Result = co_await Prism::Network::Relay::Run(
            Prism::Network::Relay::Request{
                std::static_pointer_cast<Prism::Transmission>(Conn),
                std::move(*Dialed),
                4096,
                std::chrono::seconds(15),
                {},
                MakeRelayBytePool(),
                {}});
        if (Result.Failure.Failed() || Result.Total[0] == 0)
        {
            auto Message = Prism::Fault::Describe(Result.Failure.Code);
            std::fprintf(stderr,
                "FAIL: TUIC server target relay: %s native=%d upload=%zu download=%zu\n",
                Message.data(), Result.Failure.Native.value(),
                Result.Total[0], Result.Total[1]);
            co_return false;
        }
        std::printf("DETAIL: tuic_target_upload=%zu tuic_target_download=%zu\n",
            Result.Total[0], Result.Total[1]);
        co_return true;
    }

    auto RunTcpServer(Net::any_io_executor Executor,
                      std::shared_ptr<Prism::Quic::Server> Server,
                      Prism::Tuic::ServerConfig Config) -> Net::awaitable<bool>
    {
        auto DataProviderResult = co_await Server->AcceptBidirectionalStream();
        if (!DataProviderResult)
        {
            co_return false;
        }
        auto DataProvider = std::move(*DataProviderResult);
        auto DataStream = std::make_shared<Prism::Quic::StreamAdapter>(Executor, DataProvider);
        auto [AuthError, Request, Conn] = co_await Prism::Tuic::Accept(DataStream, Config);
        if (AuthError != Prism::Error::None || !Conn)
        {
            const auto Drained = co_await Detail::CloseAndDrainStreamChain(
                DataStream, Prism::SharedTransmission{});
            if (!Drained)
            {
                std::fprintf(stderr, "FAIL: TUIC server data stream drain after auth failure\n");
            }
            co_return false;
        }
        co_return co_await RelayTarget(Executor, std::move(Conn), Request.dst);
    }

    /// 关闭并等待 TUIC server 的 QUIC native pump 完成。
    auto DrainTuicServer(const std::shared_ptr<Prism::Quic::Server> &Server)
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
        std::shared_ptr<Prism::Quic::Server> Server;
        Prism::Tuic::ServerConfig Config;
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
        std::printf("PASS: Prism TUIC server authenticated %s echo\n",
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
        auto Server = std::make_shared<Prism::Quic::Server>(
            Prism::Quic::ServerOptions{
                Executor, Socket, Tls, Prism::Testing::Quic::MakeSender(Socket)});
        Server->Start();
        std::printf("READY: Prism TUIC server on %s\n", OptionsValue.Address.c_str());
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
        std::expected<Prism::Quic::SharedStreamProvider, Prism::Fault::Failure>
            AuthProviderResult;
        std::exception_ptr AuthError;
        try
        {
            AuthProviderResult = co_await Server->AcceptUnidirectionalStream();
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
        if (!AuthProviderResult)
        {
            co_await DrainTuicServer(Server);
            co_return 1;
        }
        auto AuthProvider = std::move(*AuthProviderResult);
        auto AuthStream = std::make_shared<Prism::Quic::StreamAdapter>(Executor, AuthProvider);
        const auto Exporter = [Server](std::span<std::uint8_t> Output,
                                       std::span<const std::uint8_t> Label,
                                       std::string_view Context)
        {
            return Server->ExportKeyingMaterial(Output, Label, Context);
        };
        Prism::Tuic::ServerConfig Config;
        Config.uuid = OptionsValue.Uuid;
        Config.password = OptionsValue.Password;
        Config.AuthStream = std::move(AuthStream);
        Config.Exporter = Exporter;
        co_return co_await RunTuicServerData(
            TuicServerDataRequest{OptionsValue, Executor, Server, std::move(Config)});
    }

} // namespace Prism::Testing::TuicInterop

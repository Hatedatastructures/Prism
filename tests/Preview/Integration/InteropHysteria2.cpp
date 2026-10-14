/**
 * @file InteropHysteria2.cpp
 * @brief Preview 原生 QUIC/HTTP3 与独立 sing-quic Hysteria2 客户端互操作
 * @details 覆盖 HTTP/3 认证、Hysteria2 TCP request/response 首帧、裸 TCP
 *          双向数据和对端 FIN 收口。
 */

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/ssl.hpp>

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

#include "Hysteria2/TcpEcho.hpp"
#include <Preview/Protocols/Http3/NativeServer.hpp>
#include <Preview/Account/Account.hpp>
#include <Preview/Account/Authenticator.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Utility/Crypto/Blake3.hpp>
#include <Preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <Preview/Protocols/Quic/Native.hpp>
#include <TestSupport/Preview/ProviderBindings.hpp>
#include "../../TestSupport/Preview/QuicFactory.hpp"

namespace
{

    namespace Echo = Preview::Testing::Integration::Hysteria2;
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
        std::string Address{"127.0.0.1:19088"};
        std::string Password{"hysteria2_password"};
        bool Udp{false};
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

    [[nodiscard]] auto ParseOptions(int Argc, char **Argv) -> std::optional<Options>
    {
        Options Result;
        for (int Index = 1; Index + 1 < Argc; Index += 2)
        {
            const std::string_view Key = Argv[Index];
            const std::string_view Value = Argv[Index + 1];
            if (Key == "-addr")
            {
                Result.Address = Value;
            }
            else if (Key == "-password")
            {
                Result.Password = Value;
            }
            else if (Key == "-udp")
            {
                Result.Udp = Value == "1";
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

    /** @brief 固定 HTTP/3 ALPN；签名遵循 BoringSSL 的选择回调 ABI。 */
    auto SelectH3(SSL *, const unsigned char **Out, unsigned char *OutLength,
                  const unsigned char *In, unsigned int InLength, void *) -> int
    {
        static constexpr unsigned char H3[] = {0x02, 'h', '3'};
        const auto Result = SSL_select_next_proto(
            const_cast<unsigned char **>(Out), OutLength, H3, sizeof(H3), In, InLength);
        return Result == OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /** @brief 自签证书与 H3 ALPN 共用唯一 TLS 配置；返回值拥有整个上下文。 */
    auto MakeServerTls() -> std::shared_ptr<Ssl::context>
    {
        auto Tls = std::make_shared<Ssl::context>(Ssl::context::tlsv13_server);
        if (!LoadSelfSigned(*Tls)) return {};
        SSL_CTX_set_alpn_select_cb(Tls->native_handle(), SelectH3, nullptr);
        return Tls;
    }
    auto WriteAll(
        const Preview::Quic::SharedStreamProvider &Provider,
        std::span<const std::byte> Data) -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            std::error_code Error;
            const auto Written = co_await Provider->Write(Data.subspan(Offset), Error);
            if (Error || Written == 0 || Written > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Written;
        }
        co_return true;
    }

    auto RunRawStream(
        Preview::Quic::SharedStreamProvider Provider,
        std::shared_ptr<Echo::TcpEchoEvidence> Evidence) -> Net::awaitable<void>
    {
        if (!Provider)
        {
            co_return;
        }
        Echo::StreamState State;
        std::array<std::byte, 16384> Buffer{};
        while (!Provider->IsClosed())
        {
            std::error_code Error;
            const auto Count = co_await Provider->Read(Buffer, Error);
            if (Error)
            {
                Provider->Close();
                co_return;
            }
            const auto Action = Echo::HandleTcpData(Echo::TcpDataInput{
                State,
                std::span<const std::byte>(Buffer.data(), Count),
                Count == 0,
                *Evidence});
            if (!Action.Data.empty() && !co_await WriteAll(Provider, Action.Data))
            {
                Provider->Close();
                co_return;
            }
            if (!Action.Data.empty())
            {
                if (!Echo::RecordWritten(*Evidence, Action))
                {
                    Provider->Close();
                    co_return;
                }
            }
            if (Evidence->ResponseWriteCompleted || Action.Stop || Count == 0)
            {
                if (Evidence->ResponseWriteCompleted)
                {
                    const auto Shutdown = co_await Provider->ShutdownWrite();
                    if (!Shutdown) { Evidence->WriteFinFailure = Shutdown.error(); co_return; }
                    Evidence->WriteFinRequested = true;
                }
                else
                {
                    Provider->Close();
                }
                co_return;
            }
        }
    }

    struct AuthFixture
    {
        std::shared_ptr<Preview::Testing::ProviderAccounts> Directory;
        Preview::SharedAuthenticator Authenticator;
    };

    [[nodiscard]] auto MakeAuthenticator(std::string_view Password) -> AuthFixture
    {
        auto Directory = Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Token(Password));
        return AuthFixture{Directory, Directory->Authenticator};
    }

    struct RawStreamOwner final
    {
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Done;
        std::shared_ptr<std::exception_ptr> Failure;
        bool Started{false};
    };

    struct ServerEventRequest final
    {
        std::shared_ptr<Preview::Hysteria2::Http3AuthSession> AuthSession;
        std::shared_ptr<Echo::TcpEchoEvidence> Evidence;
        std::shared_ptr<RawStreamOwner> RawStream;
    };

    auto HandleServerEvent(ServerEventRequest Request, Preview::Http3::ServerEvent Event)
        -> Net::awaitable<Preview::Http3::SessionAction>
    {
        if (auto *HttpRequest = std::get_if<Preview::Http3::RequestEvent>(&Event))
        {
            auto Response = Request.AuthSession->HandleRequest(std::move(*HttpRequest));
            if (Response)
            {
                co_return Preview::Http3::SessionAction(std::move(*Response));
            }
            co_return Preview::Http3::SessionAction{};
        }
        if (auto *Raw = std::get_if<Preview::Http3::RawStreamEvent>(&Event))
        {
            if (!Request.AuthSession->Authenticated())
            {
                co_return Preview::Http3::SessionAction{};
            }
            Request.RawStream->Started = true;
            const auto Executor = Raw->Provider->Executor();
            auto Owner = Request.RawStream;
            Net::co_spawn(
                Executor,
                RunRawStream(Raw->Provider, Request.Evidence),
                [Owner](std::exception_ptr ErrorValue)
                {
                    if (ErrorValue && !*Owner->Failure)
                    {
                        *Owner->Failure = ErrorValue;
                    }
                    (void)Owner->Done->try_send(boost::system::error_code{});
                });
            co_return Preview::Http3::SessionAction{Preview::Http3::StreamMode::Opaque};
        }
        co_return Preview::Http3::SessionAction{};
    }

    struct UdpEventRequest final
    {
        std::shared_ptr<Preview::Hysteria2::Http3AuthSession> AuthSession;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Authenticated;
    };

    auto HandleUdpEvent(UdpEventRequest Request, Preview::Http3::ServerEvent Event)
        -> Net::awaitable<Preview::Http3::SessionAction>
    {
        if (auto *HttpRequest = std::get_if<Preview::Http3::RequestEvent>(&Event))
        {
            auto Response = Request.AuthSession->HandleRequest(std::move(*HttpRequest));
            if (Response)
            {
                (void)Request.Authenticated->try_send(boost::system::error_code{});
                co_return Preview::Http3::SessionAction(std::move(*Response));
            }
        }
        co_return Preview::Http3::SessionAction{};
    }

    struct SessionOwner final
    {
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Done;
        std::shared_ptr<std::exception_ptr> Failure;
        std::shared_ptr<Preview::Fault::Code> Result;
    };

    auto StartSession(Net::any_io_executor Executor,
                      std::shared_ptr<Preview::Http3::NativeServerSession> Session)
        -> SessionOwner
    {
        SessionOwner Owner{
            std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Executor, 1),
            std::make_shared<std::exception_ptr>(),
            std::make_shared<Preview::Fault::Code>(Preview::Fault::Code::Success)};
        Net::co_spawn(
            Executor,
            Session->Run(),
            [Owner](std::exception_ptr ErrorValue, Preview::Fault::Code Result)
            {
                *Owner.Result = Result;
                if (ErrorValue && !*Owner.Failure)
                {
                    *Owner.Failure = ErrorValue;
                }
                (void)Owner.Done->try_send(boost::system::error_code{});
            });
        return Owner;
    }

    auto WaitSession(SessionOwner Owner) -> Net::awaitable<Preview::Fault::Code>
    {
        boost::system::error_code ErrorCode;
        (void)co_await Owner.Done->async_receive(
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode)
        {
            throw std::system_error(ErrorCode);
        }
        if (*Owner.Failure)
        {
            std::rethrow_exception(*Owner.Failure);
        }
        co_return *Owner.Result;
    }

    /// 关闭并等待没有建立 HTTP3 session 的 QUIC server。
    auto DrainQuicServer(const std::shared_ptr<Preview::Quic::Server> &Server)
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

    auto DrainHttp3SessionAndQuicServer(
        const std::shared_ptr<Preview::Http3::NativeServerSession>& Session,
        const std::shared_ptr<Preview::Quic::Server>& Server) -> Net::awaitable<void>
    {
        std::exception_ptr FirstError;
        try
        {
            CaptureDrainFailure(FirstError, co_await Session->Drain());
        }
        catch (...)
        {
            FirstError = std::current_exception();
        }
        try
        {
            CaptureDrainFailure(FirstError, co_await Server->Drain());
        }
        catch (...)
        {
            if (!FirstError) FirstError = std::current_exception();
        }
        if (FirstError) std::rethrow_exception(FirstError);
    }

    struct UdpDrainRequest final
    {
        std::shared_ptr<Preview::Http3::NativeServerSession> Session;
        SessionOwner SessionState;
        std::shared_ptr<Preview::Quic::Server> QuicServer;
        Preview::Hysteria2::SharedDgram Datagram;
    };

    using UdpNotifyChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct UdpServerDataRequest final
    {
        Options OptionsValue;
        std::shared_ptr<Preview::Http3::NativeServerSession> Session;
        SessionOwner SessionState;
        std::shared_ptr<Preview::Quic::Server> QuicServer;
        std::shared_ptr<UdpNotifyChannel> Authenticated;
    };

    /// 先关闭 UDP/session owner，再等待 session 和 QUIC native drain；保留首异常。
    auto DrainUdpSession(UdpDrainRequest Request)
        -> Net::awaitable<Preview::Fault::Code>
    {
        std::exception_ptr FirstError;
        if (Request.Datagram)
        {
            Request.Datagram->Close();
        }
        Request.Session->Close();
        Request.QuicServer->Close();
        Preview::Fault::Code SessionCode{Preview::Fault::Code::Success};
        try
        {
            SessionCode = co_await WaitSession(Request.SessionState);
        }
        catch (...)
        {
            FirstError = std::current_exception();
        }
        try
        {
            co_await DrainHttp3SessionAndQuicServer(Request.Session, Request.QuicServer);
        }
        catch (...)
        {
            if (!FirstError) FirstError = std::current_exception();
        }
        if (FirstError)
        {
            std::rethrow_exception(FirstError);
        }
        co_return SessionCode;
    }

    auto RunUdpServerData(UdpServerDataRequest Request) -> Net::awaitable<int>
    {
        boost::system::error_code AuthError;
        auto AuthOperation = Request.Authenticated->async_receive(
            Net::redirect_error(Net::use_awaitable, AuthError));
        co_await std::move(AuthOperation);
        if (AuthError)
        {
            (void)co_await DrainUdpSession(
                UdpDrainRequest{Request.Session, Request.SessionState, Request.QuicServer, {}});
            co_return 1;
        }

        auto Dgram = Preview::Hysteria2::AcceptPacket(
            Request.QuicServer->Datagram(),
            Preview::Hysteria2::ServerConfig{Request.OptionsValue.Password});
        if (!Dgram)
        {
            (void)co_await DrainUdpSession(
                UdpDrainRequest{Request.Session, Request.SessionState, Request.QuicServer, {}});
            co_return 1;
        }
        Preview::Hysteria2::Address Source;
        std::vector<std::uint8_t> Payload;
        auto ReceiveOperation = Dgram->AsyncReceiveFrom(Source, Payload);
        const auto ReceiveError = co_await std::move(ReceiveOperation);
        auto SendError = Preview::Error::None;
        if (ReceiveError == Preview::Error::None)
        {
            auto SendOperation = Dgram->AsyncSendTo(Source, Payload);
            SendError = co_await std::move(SendOperation);
        }
        if (ReceiveError != Preview::Error::None || SendError != Preview::Error::None)
        {
            (void)co_await DrainUdpSession(
                UdpDrainRequest{Request.Session, Request.SessionState, Request.QuicServer, Dgram});
            co_return 1;
        }
        const auto SessionCode = co_await DrainUdpSession(
            UdpDrainRequest{Request.Session, Request.SessionState, Request.QuicServer, Dgram});
        if (SessionCode != Preview::Fault::Code::Success)
        {
            co_return 1;
        }
        std::printf("PASS: Preview Hysteria2 UDP authenticated echo (%zu bytes)\n", Payload.size());
        co_return 0;
    }

    auto RunServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed Hysteria2 listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 listen address is not an IP literal\n");
            co_return 2;
        }
        auto Tls = MakeServerTls();
        if (!Tls)
        {
            std::fprintf(stderr, "FAIL: cannot create Hysteria2 self-signed certificate\n");
            co_return 1;
        }

        const auto Executor = co_await Net::this_coro::executor;
        auto Socket = std::make_shared<Udp::socket>(Executor, Udp::endpoint(Address, Listen->Port));
        auto QuicServer = std::make_shared<Preview::Quic::Server>(Preview::Quic::ServerOptions{
            Executor, Socket, Tls, Preview::Testing::Quic::MakeSender(Socket)});
        QuicServer->Start();
        std::printf("READY: Preview Hysteria2 server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto HandshakeOperation = QuicServer->WaitHandshake();
        const auto HandshakeOk = co_await std::move(HandshakeOperation);
        if (!HandshakeOk)
        {
            co_await DrainQuicServer(QuicServer);
            co_return 1;
        }

        auto Evidence = std::make_shared<Echo::TcpEchoEvidence>();
        constexpr auto ExpectedPayload = Echo::ExpectedTcpPayload;
        const auto ExpectedHash = Echo::HashPayload(std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(ExpectedPayload.data()), ExpectedPayload.size()));
        const auto Auth = MakeAuthenticator(OptionsValue.Password);
        auto AuthSession = std::make_shared<Preview::Hysteria2::Http3AuthSession>(
            Preview::Hysteria2::Http3AuthSessionOptions{Executor, Auth.Authenticator});
        Preview::Http3::NativeServerSessionOptions SessionOptions;
        SessionOptions.Executor = Executor;
        SessionOptions.OpenUnidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->OpenUnidirectionalStream();
        };
        SessionOptions.AcceptUnidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->AcceptUnidirectionalStream();
        };
        SessionOptions.AcceptBidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->AcceptBidirectionalStream();
        };
        auto RawStream = std::make_shared<RawStreamOwner>(RawStreamOwner{
            std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Executor, 1),
            std::make_shared<std::exception_ptr>()});
        const ServerEventRequest EventRequest{AuthSession, Evidence, RawStream};
        SessionOptions.OnEvent = [EventRequest](Preview::Http3::ServerEvent Event)
        {
            return HandleServerEvent(EventRequest, std::move(Event));
        };
        auto Session = std::make_shared<Preview::Http3::NativeServerSession>(std::move(SessionOptions));
        auto SessionOperation = Session->Run();
        const auto Code = co_await std::move(SessionOperation);
        co_await DrainHttp3SessionAndQuicServer(Session, QuicServer);
        if (RawStream->Started)
        {
            boost::system::error_code RawError;
            (void)co_await RawStream->Done->async_receive(
                Net::redirect_error(Net::use_awaitable, RawError));
            if (*RawStream->Failure)
            {
                std::rethrow_exception(*RawStream->Failure);
            }
        }
        const auto Authenticated = AuthSession->Authenticated();
        const auto PayloadHashMatches = Evidence->ResponseWriteCompleted &&
            Evidence->PayloadBytes == ExpectedPayload.size() &&
            Evidence->PayloadHash == ExpectedHash;
        const auto EchoedValue = Evidence->ResponseWriteCompleted &&
            PayloadHashMatches && Evidence->WriteFinRequested;
        if (Code != Preview::Fault::Code::Success || !Authenticated || !EchoedValue)
        {
            auto AuthenticatedValue = 0;
            if (Authenticated)
            {
                AuthenticatedValue = 1;
            }
            std::fprintf(stderr,
                         "FAIL: Hysteria2 session code=%s authenticated=%d "
                         "request_parsed=%d response_write_completed=%d "
                         "payload_bytes=%zu payload_hash_match=%d write_fin_requested=%d "
                         "write_fin_code=%d write_fin_native=%d write_fin_category=%s "
                         "peer_delivery_not_inferred=1\n",
                         Preview::Fault::Describe(Code).data(),
                         AuthenticatedValue,
                         Evidence->RequestParsed ? 1 : 0,
                         Evidence->ResponseWriteCompleted ? 1 : 0,
                         Evidence->PayloadBytes,
                         PayloadHashMatches ? 1 : 0,
                         Evidence->WriteFinRequested ? 1 : 0,
                         Evidence->WriteFinFailure ? static_cast<int>(Evidence->WriteFinFailure->Code) : 0,
                         Evidence->WriteFinFailure ? Evidence->WriteFinFailure->Native.value() : 0,
                         Evidence->WriteFinFailure ? Evidence->WriteFinFailure->Native.category().name() : "none");
            co_return 1;
        }
        std::printf("PASS: Preview Hysteria2 authenticated echo\n");
        std::printf(
            "DETAIL: server_response_payload_bytes=%zu payload_hash_match=%d "
            "write_fin_requested=%d peer_delivery_not_inferred=1\n",
            Evidence->PayloadBytes,
            PayloadHashMatches ? 1 : 0,
            Evidence->WriteFinRequested ? 1 : 0);
        co_return 0;
    }

    auto RunUdpServer(Options OptionsValue) -> Net::awaitable<int>
    {
        const auto Listen = SplitHostPort(OptionsValue.Address);
        if (!Listen)
        {
            std::fprintf(stderr, "FAIL: malformed Hysteria2 UDP listen address\n");
            co_return 2;
        }
        boost::system::error_code AddressError;
        const auto Address = Net::ip::make_address(Listen->Host, AddressError);
        if (AddressError)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 UDP listen address is not an IP literal\n");
            co_return 2;
        }
        auto Tls = MakeServerTls();
        if (!Tls)
        {
            std::fprintf(stderr, "FAIL: cannot create Hysteria2 self-signed certificate\n");
            co_return 1;
        }

        const auto Executor = co_await Net::this_coro::executor;
        auto Socket = std::make_shared<Udp::socket>(Executor, Udp::endpoint(Address, Listen->Port));
        auto QuicServer = std::make_shared<Preview::Quic::Server>(Preview::Quic::ServerOptions{
            Executor, Socket, Tls, Preview::Testing::Quic::MakeSender(Socket)});
        QuicServer->Start();
        std::printf("READY: Preview Hysteria2 UDP server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        auto HandshakeOperation = QuicServer->WaitHandshake();
        std::exception_ptr HandshakeError;
        bool HandshakeOk = false;
        try
        {
            HandshakeOk = co_await std::move(HandshakeOperation);
        }
        catch (...)
        {
            HandshakeError = std::current_exception();
        }
        if (HandshakeError)
        {
            try
            {
                co_await DrainQuicServer(QuicServer);
            }
            catch (...)
            {
            }
            std::rethrow_exception(HandshakeError);
        }
        if (!HandshakeOk)
        {
            QuicServer->Close();
            co_return 1;
        }

        auto Authenticated = std::make_shared<UdpNotifyChannel>(Executor, 1);
        const auto Auth = MakeAuthenticator(OptionsValue.Password);
        auto AuthSession = std::make_shared<Preview::Hysteria2::Http3AuthSession>(
            Preview::Hysteria2::Http3AuthSessionOptions{Executor, Auth.Authenticator});
        Preview::Http3::NativeServerSessionOptions SessionOptions;
        SessionOptions.Executor = Executor;
        const UdpEventRequest EventRequest{AuthSession, Authenticated};
        SessionOptions.OnEvent = [EventRequest](Preview::Http3::ServerEvent Event)
        {
            return HandleUdpEvent(EventRequest, std::move(Event));
        };
        SessionOptions.OpenUnidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->OpenUnidirectionalStream();
        };
        SessionOptions.AcceptUnidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->AcceptUnidirectionalStream();
        };
        SessionOptions.AcceptBidirectional = [QuicServer]() -> Net::awaitable<Preview::Quic::SharedStreamProvider>
        {
            co_return co_await QuicServer->AcceptBidirectionalStream();
        };
        auto Session = std::make_shared<Preview::Http3::NativeServerSession>(std::move(SessionOptions));
        auto SessionState = StartSession(Executor, Session);

        co_return co_await RunUdpServerData(
            UdpServerDataRequest{OptionsValue, Session, SessionState, QuicServer, Authenticated});
    }

    auto RunInterop(Options OptionsValue, int &ExitCode) -> Net::awaitable<void>
    {
        if (OptionsValue.Udp)
        {
            ExitCode = co_await RunUdpServer(OptionsValue);
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
        std::fprintf(stderr, "FAIL: malformed Hysteria2 options\n");
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
            std::fprintf(stderr, "FAIL: Hysteria2 coroutine exception: %s\n", Error.what());
        }
        catch (...)
        {
            std::fprintf(stderr, "FAIL: Hysteria2 coroutine exception\n");
        }
        return 1;
    }
    return ExitCode;
}

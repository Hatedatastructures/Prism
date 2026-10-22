#pragma once

/**
 * @file TrustTunnelSupport.hpp
 * @brief TrustTunnel HTTP/2 transport 测试共享队列与 ingress fixture。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
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
#include <chrono>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Account/Account.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Account/Authenticator.hpp>
#include <Prism/Protocols/Trusttunnel/Http2.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Transport.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2ClientDriver.hpp>
#include <Prism/Protocols/Trusttunnel/IngressFactory.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Accept.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Client.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2WireWriter.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trusttunnel = Prism::Trusttunnel;
    using Net::experimental::awaitable_operators::operator||;

    template <typename Awaitable>
    auto RunCoro(
        Net::io_context &IoContext,
        Awaitable Operation) -> void
    {
        IoContext.restart();
        std::exception_ptr Failure;
        auto Completion = [&](std::exception_ptr ErrorValue) -> void
        {
            Failure = std::move(ErrorValue);
            IoContext.stop();
        };
        Net::co_spawn(IoContext, std::move(Operation), std::move(Completion));
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    namespace Ssl = Net::ssl;
    using Tcp = Net::ip::tcp;

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
                           X509_NAME_add_entry_by_txt(
                               Name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>("trusttunnel-test"), -1, -1, 0) > 0 &&
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

    auto SelectH2(SSL *, const unsigned char **Output, unsigned char *OutputLength,
                  const unsigned char *Input, unsigned int InputLength, void *) -> int
    {
        static constexpr unsigned char H2[] = {2, 'h', '2'};
        for (unsigned int Offset = 0; Offset + H2[0] < InputLength;
             Offset += Input[Offset] + 1)
        {
            if (Input[Offset] == H2[0] &&
                std::memcmp(Input + Offset + 1, H2 + 1, H2[0]) == 0)
            {
                *Output = Input + Offset + 1;
                *OutputLength = H2[0];
                return SSL_TLSEXT_ERR_OK;
            }
        }
        return SSL_TLSEXT_ERR_NOACK;
    }

    class CountingAuthenticator final : public Prism::Authenticator
    {
    public:
        explicit CountingAuthenticator(Prism::Account::CredentialIndexView View)
            : Delegate_(std::move(View))
        {
        }

        [[nodiscard]] auto InspectCredential(
            const Prism::Account::CredentialView &Credential) const noexcept
            -> std::expected<bool, Prism::Fault::Failure> override
        {
            return Delegate_.InspectCredential(Credential);
        }

        [[nodiscard]] auto Authenticate(const Prism::AuthenticationRequest &Request) const noexcept
            -> Prism::AuthenticationResult override
        {
            ++AuthenticateCalls_;
            return Delegate_.Authenticate(Request);
        }

        [[nodiscard]] auto Calls() const noexcept -> int
        {
            return AuthenticateCalls_;
        }

    private:
        Prism::DirectoryAuthenticator Delegate_;
        mutable int AuthenticateCalls_{0};
    };

    struct AuthFixture final
    {
        std::shared_ptr<Prism::Testing::ProviderAccounts> Directory;
        std::shared_ptr<CountingAuthenticator> Authenticator;
        std::shared_ptr<const Prism::Account::AccountBinding> Record;
    };

    [[nodiscard]] auto MakeAuthFixture(Prism::AccountId AccountId,
                                       std::string Credential) -> AuthFixture
    {
        if (Credential.empty())
        {
            return {};
        }
        // TrustTunnel 的 wire 凭据是完整的 "username:password"，与配置用户名分开匹配。
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Testing::ProviderAccountInput{
                AccountId, Prism::Account::Credential::Password(std::move(Credential)),
                {}, "Provider Fixture", {.MaxConnections = 1}});
        auto Record = Directory->Store->FindById(AccountId);
        if (!Record)
        {
            return {};
        }
        return {Directory, std::make_shared<CountingAuthenticator>(Directory->Credentials),
                std::move(Record)};
    }

    [[nodiscard]] auto ReadExact(const Prism::SharedTransmission &Transport,
                                 std::span<std::byte> Data)
        -> Net::awaitable<std::expected<bool, Prism::Fault::Failure>>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            const auto Part = co_await Transport->ReadSome(Data.subspan(Offset));
            if (Part.Bytes > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Part.Bytes;
            if (Part.Failure.Failed())
            {
                co_return std::unexpected(Part.Failure);
            }
            if (Part.Bytes == 0) co_return false;
        }
        co_return true;
    }

    [[nodiscard]] auto WriteAll(const Prism::SharedTransmission &Transport,
                                std::span<const std::byte> Data)
        -> Net::awaitable<std::expected<bool, Prism::Fault::Failure>>
    {
        std::size_t Offset = 0;
        while (Offset < Data.size())
        {
            const auto Part = co_await Transport->WriteSome(Data.subspan(Offset));
            if (Part.Bytes > Data.size() - Offset)
            {
                co_return false;
            }
            Offset += Part.Bytes;
            if (Part.Failure.Failed())
            {
                co_return std::unexpected(Part.Failure);
            }
            if (Part.Bytes == 0) co_return false;
        }
        co_return true;
    }

    [[nodiscard]] auto WaitForDriverClosed(
        const std::shared_ptr<Trusttunnel::AuthenticatedTransport> &Proof)
        -> Net::awaitable<bool>
    {
        std::shared_ptr<Trusttunnel::Detail::CarrierLifecycle> Lifecycle;
        if (Proof)
        {
            Lifecycle = Trusttunnel::Detail::Http2Accept::GetLifecycleForTest(*Proof);
        }
        if (!Lifecycle || !Lifecycle->Closed)
        {
            co_return false;
        }
        const auto Driver = co_await Lifecycle->WaitDriver();
        co_return Driver && Lifecycle->DriverCompleted.load(std::memory_order_acquire) &&
            Lifecycle->DriverState.expired();
    }

    struct CarrierRetirementObservation final
    {
        bool DrainSucceeded{false};
        bool Retired{false};
        Prism::Fault::Failure Failure{};
    };

    [[nodiscard]] auto DrainAuthenticatedCarrier(
        const std::shared_ptr<Trusttunnel::AuthenticatedTransport> &Proof)
        -> Net::awaitable<CarrierRetirementObservation>
    {
        if (!Proof) co_return CarrierRetirementObservation{};
        const auto Drained = co_await Proof->Activity()->Drain();
        auto Failure = Prism::Fault::Failure{};
        if (!Drained) Failure = Drained.error();
        co_return CarrierRetirementObservation{
            static_cast<bool>(Drained), Proof->Activity()->IsRetired(), Failure};
    }

    struct WireAdmissionObservation final
    {
        Prism::Fault::Failure SameHandshake{Prism::Fault::Code::IoError};
        Prism::Fault::Failure SameAdmission{Prism::Fault::Code::IoError};
        Prism::Fault::Failure CrossHandshake{Prism::Fault::Code::IoError};
        Prism::Fault::Failure CrossAdmission{Prism::Fault::Code::IoError};
        Prism::Fault::Failure WrongHandshake;
        Prism::Fault::Failure ClientSame{Prism::Fault::Code::IoError};
        Prism::Fault::Failure ClientCross{Prism::Fault::Code::IoError};
        Prism::Fault::Failure ClientWrong;
        std::string SameTarget;
        Prism::AccountId SameAccountId{};
        bool SameAccepted{false};
        bool SameStream{false};
        bool SameAuthenticated{false};
        bool ServerPayloadRead{false};
        bool ServerPayloadEqual{false};
        bool ClientPayloadWritten{false};
        bool ServerResponseWritten{false};
        Prism::Fault::Failure ServerDataFailure;
        Prism::Fault::Failure ClientDataFailure;
        bool ClientResponseRead{false};
        bool ClientResponseEqual{false};
        bool ClientResponseEndStream{false};
        bool ClientHalfClose{false};
        bool ServerHalfClose{false};
        bool DriverClosed{false};
        bool DriverStateExpired{false};
        bool SameDrainSucceeded{false};
        bool SameRetired{false};
        bool CrossDriverClosed{false};
        bool CrossDrainSucceeded{false};
        bool CrossRetired{false};
        bool WrongTransport{false};
        int ServerAcceptErrors{0};
        int ClientConnectErrors{0};
        std::size_t SameActiveDuring{0};
        std::size_t SameActiveAfter{0};
        std::size_t CrossActiveAfter{0};
        bool TimedOut{false};
    };

    inline constexpr std::string_view WirePayload{"trusttunnel-wire-proof-payload"};
    inline constexpr std::string_view WireResponse{"trusttunnel-wire-proof-response"};

    struct WireAdmissionFixture final
    {
        struct ClientConnection final
        {
            Prism::Fault::Failure Failure{Prism::Fault::Code::IoError};
            std::shared_ptr<Ssl::context> Tls;
            std::shared_ptr<Trusttunnel::Detail::Http2ClientState> State;
            Prism::SharedTransmission Transport;
        };

        WireAdmissionFixture()
            : Acceptor(IoContext, Tcp::endpoint(Tcp::v4(), 0)),
              ServerTls(Ssl::context::tlsv13_server),
              AuthA(MakeAuthFixture(Prism::AccountId{4101}, "wire-user:wire-password")),
              AuthB(MakeAuthFixture(Prism::AccountId{4102}, "other-user:other-password")),
              BindingA(Trusttunnel::MakeWireAuthBinding(
                  Trusttunnel::ServerConfig{"wire-user", "wire-password"}, AuthA.Authenticator)),
              BindingB(Trusttunnel::MakeWireAuthBinding(
                  Trusttunnel::ServerConfig{"other-user", "other-password"}, AuthB.Authenticator)),
              FactoryA(Trusttunnel::IngressOptions{BindingA}),
              FactoryB(Trusttunnel::IngressOptions{BindingB}),
              Done(std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
                  IoContext.get_executor(), 1)),
              TlsReady(LoadSelfSigned(ServerTls))
        {
            if (TlsReady)
            {
                SSL_CTX_set_alpn_select_cb(ServerTls.native_handle(), SelectH2, nullptr);
            }
        }

        [[nodiscard]] auto Port() const -> std::uint16_t
        {
            return Acceptor.local_endpoint().port();
        }

        [[nodiscard]] auto ConfigFor(const int Index) const -> Trusttunnel::ClientConfig
        {
            if (Index == 2)
                return Trusttunnel::ClientConfig{"wire-user", "wrong-password"};
            return Trusttunnel::ClientConfig{"wire-user", "wire-password"};
        }

        auto AcceptRaw() -> Net::awaitable<Prism::SharedTransmission>
        {
            boost::system::error_code AcceptError;
            auto Socket = co_await Acceptor.async_accept(
                Net::redirect_error(Net::use_awaitable, AcceptError));
            if (AcceptError)
            {
                ++Observation.ServerAcceptErrors;
                co_return Prism::SharedTransmission{};
            }
            co_return std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
        }

        auto RunServer() -> Net::awaitable<void>
        {
            for (int Index = 0; Index < 3; ++Index)
            {
                auto Raw = co_await AcceptRaw();
                if (!Raw)
                {
                    co_return;
                }
                co_await ServeConnection(Index, std::move(Raw));
            }
        }

        auto ServeConnection(const int Index, Prism::SharedTransmission Raw)
            -> Net::awaitable<void>
        {
            if (Index == 0)
            {
                co_await ServeWinner(std::move(Raw));
            }
            else if (Index == 1)
            {
                co_await ServeMismatched(std::move(Raw));
            }
            else
            {
                co_await ServeWrongBasic(std::move(Raw));
            }
        }

        auto ServeWinner(Prism::SharedTransmission Raw) -> Net::awaitable<void>
        {
            auto Accepted = co_await Trusttunnel::AcceptHttp2(
                Trusttunnel::Http2AcceptRequest{
                    std::move(Raw), ServerTls, BindingA,
                    std::make_shared<Prism::Memory::BytePool>()});
            if (!Accepted)
            {
                Observation.SameHandshake = Accepted.error();
                co_return;
            }
            Observation.SameHandshake = {};
            Observation.SameTarget = Accepted->Target;
            auto Carrier = std::move(Accepted->Transport);
            auto Proof = std::dynamic_pointer_cast<Trusttunnel::AuthenticatedTransport>(Carrier);
            std::shared_ptr<Trusttunnel::Detail::CarrierLifecycle> Lifecycle;
            if (Proof)
            {
                Lifecycle = Trusttunnel::Detail::Http2Accept::GetLifecycleForTest(*Proof);
            }
            std::weak_ptr<const Trusttunnel::Detail::Http2DriverParameters> WeakDriverState;
            if (Lifecycle) WeakDriverState = Lifecycle->DriverState;
            auto Outcome = co_await FactoryA.Accept(Prism::Contract::StreamAcceptInput{
                .Inbound = std::move(Carrier),
                .Metadata = {},
                .Bytes = std::make_shared<Prism::Memory::BytePool>()});
            if (!Outcome)
            {
                Observation.SameAdmission = Outcome.error();
                co_return;
            }
            Observation.SameAdmission = {};
            {
                auto Plane = std::move(*Outcome);
                Observation.SameAccepted = true;
                Observation.SameStream = Plane.IsStream();
                Observation.SameAuthenticated = Plane.ProtocolAuthenticated;
                Observation.SameAccountId = Plane.AccountId;
                Observation.SameActiveDuring = AuthA.Record->Runtime()->ActiveConnections();
                auto *Stream = Plane.Stream();
                if (Stream && Stream->Transport)
                {
                    std::array<std::byte, WirePayload.size()> Request{};
                    const auto RequestBytes = std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(WirePayload.data()), WirePayload.size());
                    const auto PayloadRead = co_await ReadExact(Stream->Transport, Request);
                    Observation.ServerPayloadRead = PayloadRead && *PayloadRead;
                    if (!PayloadRead && Observation.ServerDataFailure.Succeeded())
                        Observation.ServerDataFailure = PayloadRead.error();
                    Observation.ServerPayloadEqual = Observation.ServerPayloadRead &&
                        std::memcmp(Request.data(), RequestBytes.data(), RequestBytes.size()) == 0;
                    const auto ResponseBytes = std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(WireResponse.data()), WireResponse.size());
                    const auto ResponseWritten = co_await WriteAll(Stream->Transport, ResponseBytes);
                    Observation.ServerResponseWritten = ResponseWritten && *ResponseWritten;
                    if (!ResponseWritten && Observation.ServerDataFailure.Succeeded())
                        Observation.ServerDataFailure = ResponseWritten.error();
                    if (Proof)
                    {
                        const auto HalfClose = co_await Proof->WriteShutdown();
                        Observation.ServerHalfClose = static_cast<bool>(HalfClose);
                        if (!HalfClose && Observation.ServerDataFailure.Succeeded())
                            Observation.ServerDataFailure = HalfClose.error();
                    }
                }
            }
            Observation.SameActiveAfter = AuthA.Record->Runtime()->ActiveConnections();
            Observation.DriverClosed = co_await WaitForDriverClosed(Proof);
            Observation.DriverStateExpired = WeakDriverState.expired();
            const auto Retirement = co_await DrainAuthenticatedCarrier(Proof);
            Observation.SameDrainSucceeded = Retirement.DrainSucceeded;
            Observation.SameRetired = Retirement.Retired;
        }

        auto ServeMismatched(Prism::SharedTransmission Raw) -> Net::awaitable<void>
        {
            auto Accepted = co_await Trusttunnel::AcceptHttp2(
                Trusttunnel::Http2AcceptRequest{
                    std::move(Raw), ServerTls, BindingA,
                    std::make_shared<Prism::Memory::BytePool>()});
            if (!Accepted)
            {
                Observation.CrossHandshake = Accepted.error();
                co_return;
            }
            Observation.CrossHandshake = {};
            auto Carrier = std::move(Accepted->Transport);
            auto Proof = std::dynamic_pointer_cast<Trusttunnel::AuthenticatedTransport>(Carrier);
            auto Outcome = co_await FactoryB.Accept(Prism::Contract::StreamAcceptInput{
                .Inbound = std::move(Carrier),
                .Metadata = {},
                .Bytes = std::make_shared<Prism::Memory::BytePool>()});
            Observation.CrossAdmission = {};
            if (!Outcome) Observation.CrossAdmission = Outcome.error();
            Observation.CrossActiveAfter = AuthB.Record->Runtime()->ActiveConnections();
            if (Proof)
            {
                Observation.CrossDriverClosed = co_await WaitForDriverClosed(Proof);
                const auto Retirement = co_await DrainAuthenticatedCarrier(Proof);
                Observation.CrossDrainSucceeded = Retirement.DrainSucceeded;
                Observation.CrossRetired = Retirement.Retired;
            }
        }

        auto ServeWrongBasic(Prism::SharedTransmission Raw) -> Net::awaitable<void>
        {
            auto Accepted = co_await Trusttunnel::AcceptHttp2(
                Trusttunnel::Http2AcceptRequest{
                    std::move(Raw), ServerTls, BindingA,
                    std::make_shared<Prism::Memory::BytePool>()});
            if (!Accepted)
            {
                Observation.WrongHandshake = Accepted.error();
                co_return;
            }
            Observation.WrongHandshake = {};
            auto Carrier = std::move(Accepted->Transport);
            Observation.WrongTransport = static_cast<bool>(Carrier);
            if (Carrier)
            {
                auto Proof =
                    std::dynamic_pointer_cast<Trusttunnel::AuthenticatedTransport>(Carrier);
                if (!Proof)
                {
                    Observation.WrongHandshake =
                        {Prism::Fault::Code::NotSupported};
                    co_return;
                }
                const auto Retirement = co_await DrainAuthenticatedCarrier(Proof);
                if (Retirement.Failure.Failed())
                    Observation.WrongHandshake = Retirement.Failure;
                else if (!Retirement.Retired)
                    Observation.WrongHandshake = {Prism::Fault::Code::Blocked};
            }
        }

        auto OpenClient(const int Index) -> Net::awaitable<ClientConnection>
        {
            ClientConnection Result;
            Tcp::socket Socket(co_await Net::this_coro::executor);
            boost::system::error_code ConnectError;
            co_await Socket.async_connect(
                Tcp::endpoint(Net::ip::address_v4::loopback(), Port()),
                Net::redirect_error(Net::use_awaitable, ConnectError));
            if (ConnectError)
            {
                ++Observation.ClientConnectErrors;
                co_return Result;
            }
            auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
            Result.Tls = std::make_shared<Ssl::context>(Ssl::context::tlsv13_client);
            Result.Tls->set_verify_mode(Ssl::verify_none);
            auto Bytes = std::make_shared<Prism::Memory::BytePool>();
            auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Raw);
            if (!Prepared)
            {
                Result.Failure = Prepared.error();
                co_return Result;
            }
            auto Admission = std::move(*Prepared);
            auto Stream = co_await Trusttunnel::Detail::ConnectHttp2Tls(
                Trusttunnel::Detail::Http2TlsClientRequest{
                    .Raw = std::move(Raw),
                    .SslContext = *Result.Tls,
                    .ServerName = "example.com",
                    .Bytes = Bytes},
                Admission);
            if (!Stream)
            {
                Result.Failure = Stream.error();
                co_return Result;
            }
            auto Encrypted = std::make_shared<Prism::Transport::Encrypted>(
                std::move(*Stream), std::move(Bytes));
            Result.State = Trusttunnel::Detail::MakeHttp2ClientState(Encrypted);
            const auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(Encrypted));
            if (!Tracked)
            {
                Result.Failure = co_await Admission.Retire(Tracked.error());
                co_return Result;
            }
            const auto DriverStart = Trusttunnel::Detail::StartHttp2ClientDriver(Result.State);
            if (DriverStart.Failed())
            {
                Result.Failure = co_await Trusttunnel::Detail::RetireHttp2ClientFactory(
                    Admission, Result.State, DriverStart);
                co_return Result;
            }
            Result.State->Session->SendSettings();
            const auto StreamResult = Result.State->Session->OpenStream(
                {{":method", "CONNECT"}, {":authority", "example.com:443"},
                 {"proxy-authorization", Trusttunnel::BasicAuth(
                     ConfigFor(Index).username, ConfigFor(Index).password)}}, false);
            if (!StreamResult)
            {
                Result.Failure = co_await Admission.Retire(StreamResult.error());
                co_return Result;
            }
            const auto StreamId = *StreamResult;
            if (StreamId < 0)
            {
                Result.Failure = co_await Admission.Retire(
                    Prism::Fault::Failure{Prism::Fault::Code::ProtocolError});
                co_return Result;
            }
            Result.State->Transport->BindStream(StreamId);
            const auto Flushed = co_await Trusttunnel::Detail::FlushHttp2ClientFrames(Result.State);
            if (!Flushed)
            {
                Result.Failure = co_await Admission.Retire(Flushed.error());
                co_return Result;
            }
            boost::system::error_code ResponseError;
            const auto Accepted = co_await Result.State->Response->async_receive(
                Net::redirect_error(Net::use_awaitable, ResponseError));
            if (ResponseError)
            {
                Result.Failure = Prism::Fault::FromNative(
                    static_cast<std::error_code>(ResponseError));
            }
            else if (!Accepted)
            {
                Result.Failure = Accepted.error();
            }
            else
            {
                Result.Failure = {};
            }
            if (Result.Failure.Succeeded() && !ResponseError && Accepted)
            {
                Admission.Release();
                Result.Transport = Result.State->Transport;
            }
            else
            {
                Result.Failure = co_await Admission.Retire(Result.Failure);
            }
            co_return Result;
        }

        auto CloseClient(ClientConnection &Connection) -> Net::awaitable<void>
        {
            if (!Connection.State) co_return;
            const auto Closed = Connection.State->Close();
            if (!Closed && Connection.Failure.Succeeded())
                Connection.Failure = Closed.error();
            const auto Drained = co_await Connection.State->Drain();
            if (!Drained && Connection.Failure.Succeeded())
                Connection.Failure = Drained.error();
            if (!Connection.State->IsRetired() && Connection.Failure.Succeeded())
                Connection.Failure = {Prism::Fault::Code::Blocked};
        }

        auto ConsumeWinner(ClientConnection &Connection) -> Net::awaitable<void>
        {
            Observation.ClientSame = Connection.Failure;
            if (Connection.Failure.Failed() ||
                !Connection.Transport || !Connection.State)
            {
                co_await CloseClient(Connection);
                Observation.ClientSame = Connection.Failure;
                co_return;
            }
            const auto RequestBytes = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(WirePayload.data()), WirePayload.size());
            const auto PayloadWritten = co_await WriteAll(Connection.Transport, RequestBytes);
            Observation.ClientPayloadWritten = PayloadWritten && *PayloadWritten;
            if (!PayloadWritten && Observation.ClientDataFailure.Succeeded())
                Observation.ClientDataFailure = PayloadWritten.error();
            const auto FinishResult = co_await Connection.Transport->WriteShutdown();
            Observation.ClientHalfClose = static_cast<bool>(FinishResult);
            if (!FinishResult && Observation.ClientDataFailure.Succeeded())
                Observation.ClientDataFailure = FinishResult.error();
            std::array<std::byte, WireResponse.size()> ResponseBuffer{};
            const auto ResponseBytes = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(WireResponse.data()), WireResponse.size());
            const auto ResponseRead = co_await ReadExact(Connection.Transport, ResponseBuffer);
            Observation.ClientResponseRead = ResponseRead && *ResponseRead;
            if (!ResponseRead && Observation.ClientDataFailure.Succeeded())
                Observation.ClientDataFailure = ResponseRead.error();
            Observation.ClientResponseEqual = Observation.ClientResponseRead &&
                std::memcmp(ResponseBuffer.data(), ResponseBytes.data(), ResponseBytes.size()) == 0;
            std::array<std::byte, 1> EndStreamBuffer{};
            const auto EndStream = co_await Connection.Transport->ReadSome(EndStreamBuffer);
            Observation.ClientResponseEndStream =
                EndStream.Bytes == 0U && EndStream.Failure.Succeeded();
            co_await CloseClient(Connection);
            Observation.ClientSame = Connection.Failure;
        }

        auto ConsumeMismatched(ClientConnection &Connection) -> Net::awaitable<void>
        {
            co_await CloseClient(Connection);
            Observation.ClientCross = Connection.Failure;
            co_return;
        }

        auto ConsumeWrongBasic(ClientConnection &Connection) -> Net::awaitable<void>
        {
            Observation.WrongTransport = Observation.WrongTransport ||
                static_cast<bool>(Connection.Transport);
            co_await CloseClient(Connection);
            Observation.ClientWrong = Connection.Failure;
            co_return;
        }

        auto RunClientConnection(const int Index) -> Net::awaitable<void>
        {
            auto Connection = co_await OpenClient(Index);
            if (Index == 0)
            {
                co_await ConsumeWinner(Connection);
            }
            else if (Index == 1)
            {
                co_await ConsumeMismatched(Connection);
            }
            else
            {
                co_await ConsumeWrongBasic(Connection);
            }
        }

        auto RunClient() -> Net::awaitable<void>
        {
            for (int Index = 0; Index < 3; ++Index)
            {
                co_await RunClientConnection(Index);
            }
        }

        auto Watchdog() -> Net::awaitable<void>
        {
            Net::steady_timer Timer(co_await Net::this_coro::executor);
            Timer.expires_after(std::chrono::seconds(5));
            boost::system::error_code DoneError;
            boost::system::error_code TimerError;
            auto DoneWait = Done->async_receive(
                Net::redirect_error(Net::use_awaitable, DoneError));
            auto TimerWait = Timer.async_wait(
                Net::redirect_error(Net::use_awaitable, TimerError));
            const auto Result = co_await (std::move(DoneWait) || std::move(TimerWait));
            if (Result.index() == 1 && !TimerError)
            {
                Observation.TimedOut = true;
                Acceptor.close();
                IoContext.stop();
            }
        }

        auto Complete(std::exception_ptr ErrorValue) -> void
        {
            if (ErrorValue && !Failure)
            {
                Failure = std::move(ErrorValue);
            }
            ++Completed;
            if (Completed == 2)
            {
                (void)Done->try_send(boost::system::error_code{});
            }
        }

        Net::io_context IoContext;
        Tcp::acceptor Acceptor;
        Ssl::context ServerTls;
        AuthFixture AuthA;
        AuthFixture AuthB;
        Trusttunnel::SharedWireAuthBinding BindingA;
        Trusttunnel::SharedWireAuthBinding BindingB;
        Trusttunnel::IngressFactory FactoryA;
        Trusttunnel::IngressFactory FactoryB;
        WireAdmissionObservation Observation;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> Done;
        bool TlsReady{false};
        std::exception_ptr Failure;
        int Completed{0};
    };

    struct WireCompletion final
    {
        WireAdmissionFixture *Fixture;

        auto operator()(std::exception_ptr Failure) -> void
        {
            Fixture->Complete(std::move(Failure));
        }
    };

} // namespace


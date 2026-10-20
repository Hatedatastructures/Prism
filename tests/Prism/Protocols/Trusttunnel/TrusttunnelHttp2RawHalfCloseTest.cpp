/**
 * @file TrusttunnelHttp2RawHalfCloseTest.cpp
 * @brief TrustTunnel HTTP/2 原始读半关闭后的反向响应测试。
 */

#include "TrusttunnelHttp2TransportSupport.hpp"

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Accept.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Client.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2ClientDriver.hpp>
#include <Prism/Protocols/Trusttunnel/Detail/Http2Transport.hpp>
#include <Prism/Protocols/Trusttunnel/Http2.hpp>
#include <Prism/Protocols/Trusttunnel/IngressFactory.hpp>
#include <Prism/Protocols/Http2/Session.hpp>
#include <Prism/Transport/Encrypted.hpp>
#include <Prism/Transport/Reliable.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstring>
#include <exception>
#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{
    using Net::experimental::awaitable_operators::operator&&;
    using EndStreamSignal = Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct RawHalfCloseObservation final
    {
        Prism::Fault::Failure ServerFailure{};
        Prism::Fault::Failure ServerReadTerminal{};
        Prism::Fault::Failure ServerReadTerminalAgain{};
        Prism::Fault::Failure ServerCloseFailure{};
        Prism::Fault::Failure ServerDrainFailure{};
        Prism::Fault::Failure ClientFailure{};
        Prism::Fault::Failure ClientReadTerminal{};
        Prism::Fault::Failure ClientDrainFailure{};
        bool TlsReady{false};
        bool PayloadRead{false};
        bool PayloadEqual{false};
        bool PeerWriteShutdown{false};
        bool ServerDriverCompleted{false};
        bool ServerDriverReleased{false};
        bool ServerResponseWriteAllowedAfterReadEof{false};
        bool ServerResponseWritten{false};
        bool ServerWriteShutdown{false};
        bool ClientResponseEndStream{false};
        bool ClientEndStreamObserved{false};
        bool ServerRetired{false};
        bool ResponseRead{false};
        bool ResponseEqual{false};
        bool ClientRetired{false};
    };

    struct PayloadReadResult final
    {
        bool Complete{false};
        bool Matches{false};
        Prism::Fault::Failure Terminal{};
    };

    [[nodiscard]] auto ReadPayloadBeforeTerminal(
        const Prism::SharedTransmission &Transport,
        const std::string_view Expected) -> Net::awaitable<PayloadReadResult>
    {
        std::vector<std::byte> Received;
        PayloadReadResult Result;
        std::array<std::byte, 64> Buffer{};
        while (Received.size() < Expected.size())
        {
            const auto Part = co_await Transport->ReadSome(Buffer);
            if (Part.Bytes > Buffer.size())
            {
                Result.Terminal = {Prism::Fault::Code::ProtocolError};
                co_return Result;
            }
            Received.insert(Received.end(), Buffer.begin(),
                            Buffer.begin() + static_cast<std::ptrdiff_t>(Part.Bytes));
            if (Part.Failure.Failed())
            {
                Result.Terminal = Part.Failure;
                break;
            }
            if (Part.Bytes == 0U)
            {
                co_return Result;
            }
        }
        Result.Complete = Received.size() == Expected.size();
        Result.Matches = Result.Complete &&
            std::memcmp(Received.data(), Expected.data(), Expected.size()) == 0;
        co_return Result;
    }

    struct RawHalfCloseFixture final
    {
        explicit RawHalfCloseFixture()
            : Acceptor(IoContext, Tcp::endpoint(Net::ip::address_v4::loopback(), 0)),
              ServerTls(Ssl::context::tlsv13_server),
              Auth(MakeAuthFixture(Prism::AccountId{7301}, "halfclose-user:halfclose-password")),
              Binding(Trusttunnel::MakeWireAuthBinding(
                  Trusttunnel::ServerConfig{"halfclose-user", "halfclose-password"},
                  Auth.Authenticator)),
              Factory(Trusttunnel::IngressOptions{Binding}),
              ClientEndStreamObserved(IoContext.get_executor(), 1),
              Observation{.TlsReady = LoadSelfSigned(ServerTls)}
        {
            if (Observation.TlsReady)
            {
                SSL_CTX_set_alpn_select_cb(ServerTls.native_handle(), SelectH2, nullptr);
            }
        }

        auto Run() -> Net::awaitable<void>
        {
            co_await (RunServer() && RunClient());
            co_return;
        }

        auto RunServer() -> Net::awaitable<void>
        {
            Prism::SharedTransmission Raw;
            std::shared_ptr<Trusttunnel::AuthenticatedTransport> Proof;
            try
            {
                boost::system::error_code AcceptError;
                auto Socket = co_await Acceptor.async_accept(
                    Net::redirect_error(Net::use_awaitable, AcceptError));
                if (AcceptError)
                {
                    Observation.ServerFailure = Prism::Fault::FromNative(
                        static_cast<std::error_code>(AcceptError));
                }
                else
                {
                    Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
                    ServerRawReceipt = Raw;
                    co_await RunAcceptedServer(Raw, Proof);
                }
            }
            catch (...)
            {
                Observation.ServerFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
            }
            co_await RetireServer(Proof, Raw);
            co_return;
        }

        auto RunAcceptedServer(
            const Prism::SharedTransmission &Raw,
            std::shared_ptr<Trusttunnel::AuthenticatedTransport> &Proof)
            -> Net::awaitable<void>
        {
            auto Accepted = co_await Trusttunnel::AcceptHttp2(
                Trusttunnel::Http2AcceptRequest{
                    Raw, ServerTls, Binding, std::make_shared<Prism::Memory::BytePool>()});
            if (!Accepted)
            {
                Observation.ServerFailure = Accepted.error();
                co_return;
            }
            Proof = std::dynamic_pointer_cast<Trusttunnel::AuthenticatedTransport>(
                Accepted->Transport);
            if (!Proof)
            {
                Observation.ServerFailure = {Prism::Fault::Code::ProtocolError};
                co_return;
            }
            ServerProofReceipt = Proof;
            auto Plane = co_await Factory.Accept(Prism::Contract::StreamAcceptInput{
                .Inbound = Accepted->Transport,
                .Metadata = {},
                .Bytes = std::make_shared<Prism::Memory::BytePool>()});
            if (!Plane)
            {
                Observation.ServerFailure = Plane.error();
                co_return;
            }
            auto *Stream = Plane->Stream();
            if (!Stream || !Stream->Transport)
            {
                Observation.ServerFailure = {Prism::Fault::Code::ProtocolError};
                co_return;
            }
            co_await ExchangeRequestAndResponse(Stream->Transport, Proof);
        }

        auto ExchangeRequestAndResponse(
            const Prism::SharedTransmission &Transport,
            const std::shared_ptr<Trusttunnel::AuthenticatedTransport> &Proof)
            -> Net::awaitable<void>
        {
            std::array<std::byte, WirePayload.size()> Request{};
            const auto RequestRead = co_await ReadExact(Transport, Request);
            Observation.PayloadRead = RequestRead && *RequestRead;
            if (!RequestRead || !*RequestRead)
            {
                Observation.ServerFailure = RequestRead
                    ? Prism::Fault::Failure{Prism::Fault::Code::ProtocolError}
                    : RequestRead.error();
                co_return;
            }
            Observation.PayloadEqual = std::memcmp(
                Request.data(), WirePayload.data(), Request.size()) == 0;

            std::array<std::byte, 1> Tail{};
            const auto ReadEnd = co_await Transport->ReadSome(Tail);
            Observation.ServerReadTerminal = ReadEnd.Failure;
            const auto ReadEndAgain = co_await Transport->ReadSome(Tail);
            Observation.ServerReadTerminalAgain = ReadEndAgain.Failure;
            const auto Lifecycle = Trusttunnel::Detail::Http2Accept::GetLifecycleForTest(*Proof);
            const auto DriverResult = co_await Lifecycle->WaitDriver();
            if (!DriverResult && DriverResult.error().Code != Prism::Fault::Code::Eof)
            {
                Observation.ServerFailure = DriverResult.error();
            }
            Observation.ServerDriverCompleted = Lifecycle->DriverCompleted.load(
                std::memory_order_acquire);
            Observation.ServerDriverReleased = Lifecycle && Lifecycle->DriverState.expired();

            const auto Response = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(WireResponse.data()), WireResponse.size());
            const auto Written = co_await WriteAll(Transport, Response);
            Observation.ServerResponseWritten = Written && *Written;
            Observation.ServerResponseWriteAllowedAfterReadEof =
                Observation.ServerResponseWritten;
            if (!Written || !*Written)
            {
                Observation.ServerFailure = Written
                    ? Prism::Fault::Failure{Prism::Fault::Code::ProtocolError}
                    : Written.error();
                co_return;
            }
            const auto Finished = co_await Proof->WriteShutdown();
            Observation.ServerWriteShutdown = static_cast<bool>(Finished);
            if (!Finished)
            {
                Observation.ServerFailure = Finished.error();
                co_return;
            }
            boost::system::error_code SignalError;
            const auto ClientObservedEndStream = co_await ClientEndStreamObserved.async_receive(
                Net::redirect_error(Net::use_awaitable, SignalError));
            Observation.ClientEndStreamObserved = ClientObservedEndStream && !SignalError;
            if (SignalError)
            {
                Observation.ServerFailure = Prism::Fault::FromNative(
                    static_cast<std::error_code>(SignalError));
            }
            else if (!ClientObservedEndStream)
            {
                Observation.ServerFailure = {Prism::Fault::Code::ProtocolError};
            }
            co_return;
        }

        auto RetireServer(
            const std::shared_ptr<Trusttunnel::AuthenticatedTransport> &Proof,
            const Prism::SharedTransmission &Raw) -> Net::awaitable<void>
        {
            if (Proof)
            {
                const auto Closed = Proof->Close();
                if (!Closed) Observation.ServerCloseFailure = Closed.error();
                const auto Drain = co_await DrainAuthenticatedCarrier(Proof);
                Observation.ServerRetired = Drain.Retired;
                if (!Drain.DrainSucceeded) Observation.ServerDrainFailure = Drain.Failure;
                co_return;
            }
            if (Raw)
            {
                const auto Closed = Raw->Close();
                if (!Closed) Observation.ServerCloseFailure = Closed.error();
                const auto Activity = Raw->Activity();
                if (!Activity)
                {
                    Observation.ServerDrainFailure = {
                        Prism::Fault::Code::InvalidArgument};
                    co_return;
                }
                const auto Drain = co_await Activity->Drain();
                Observation.ServerRetired = Activity->IsRetired();
                if (!Drain) Observation.ServerDrainFailure = Drain.error();
            }
            co_return;
        }

        auto OpenClient() -> Net::awaitable<std::shared_ptr<Trusttunnel::Detail::Http2ClientState>>
        {
            Tcp::socket Socket(IoContext.get_executor());
            boost::system::error_code ConnectError;
            co_await Socket.async_connect(Acceptor.local_endpoint(),
                Net::redirect_error(Net::use_awaitable, ConnectError));
            if (ConnectError)
            {
                Observation.ClientFailure = Prism::Fault::FromNative(
                    static_cast<std::error_code>(ConnectError));
                co_return nullptr;
            }
            auto Raw = std::make_shared<Prism::Transport::Reliable>(std::move(Socket));
            ClientTls = std::make_shared<Ssl::context>(Ssl::context::tlsv13_client);
            ClientTls->set_verify_mode(Ssl::verify_none);
            auto Bytes = std::make_shared<Prism::Memory::BytePool>();
            auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Raw);
            if (!Prepared)
            {
                Observation.ClientFailure = Prepared.error();
                co_return nullptr;
            }
            auto Admission = std::move(*Prepared);
            auto Stream = co_await Trusttunnel::Detail::ConnectHttp2Tls(
                Trusttunnel::Detail::Http2TlsClientRequest{
                    Raw, *ClientTls, "example.com", Bytes}, Admission);
            if (!Stream)
            {
                Observation.ClientFailure = co_await Admission.Retire(Stream.error());
                co_return nullptr;
            }
            ClientEncrypted = std::make_shared<Prism::Transport::Encrypted>(
                std::move(*Stream), Bytes);
            ClientState = Trusttunnel::Detail::MakeHttp2ClientState(ClientEncrypted);
            ClientEncryptedReceipt = ClientEncrypted;
            ClientStateReceipt = ClientState;
            const auto Tracked = Admission.Track(
                std::static_pointer_cast<Prism::Transmission>(ClientEncrypted));
            if (!Tracked)
            {
                Observation.ClientFailure = co_await Trusttunnel::Detail::RetireHttp2ClientFactory(
                    Admission, ClientState, Tracked.error());
                co_return nullptr;
            }
            const auto Started = Trusttunnel::Detail::StartHttp2ClientDriver(ClientState);
            if (Started.Failed())
            {
                Observation.ClientFailure = co_await Trusttunnel::Detail::RetireHttp2ClientFactory(
                    Admission, ClientState, Started);
                co_return nullptr;
            }
            const auto Opened = co_await OpenClientRequest(ClientState);
            if (!Opened)
            {
                Observation.ClientFailure = co_await Trusttunnel::Detail::RetireHttp2ClientFactory(
                    Admission, ClientState, Opened.error());
                co_return nullptr;
            }
            auto Response = co_await WaitClientResponse(ClientState);
            if (!Response)
            {
                Observation.ClientFailure = co_await Trusttunnel::Detail::RetireHttp2ClientFactory(
                    Admission, ClientState, Response.error());
                co_return nullptr;
            }
            Admission.Release();
            co_return ClientState;
        }

        [[nodiscard]] auto OpenClientRequest(
            const std::shared_ptr<Trusttunnel::Detail::Http2ClientState> &State)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            State->Session->SendSettings();
            const auto Stream = State->Session->OpenStream(
                {{":method", "CONNECT"}, {":authority", "example.com:443"},
                 {"proxy-authorization", Trusttunnel::BasicAuth(
                     "halfclose-user", "halfclose-password")}}, false);
            if (!Stream) co_return std::unexpected(Stream.error());
            State->Transport->BindStream(*Stream);
            const auto Sent = co_await FlushHttp2ClientFrames(State);
            if (!Sent)
            {
                co_return std::unexpected(Sent.error());
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        auto WaitClientResponse(
            const std::shared_ptr<Trusttunnel::Detail::Http2ClientState> &State)
            -> Net::awaitable<Trusttunnel::Http2ClientResult>
        {
            boost::system::error_code Error;
            const auto Response = co_await State->Response->async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            }
            co_return Response;
        }

        auto RunClient() -> Net::awaitable<void>
        {
            auto State = co_await OpenClient();
            if (!State) co_return;
            const auto Payload = std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(WirePayload.data()), WirePayload.size());
            const auto Written = co_await WriteAll(State->Transport, Payload);
            if (!Written || !*Written)
            {
                Observation.ClientFailure = Written
                    ? Prism::Fault::Failure{Prism::Fault::Code::ProtocolError}
                    : Written.error();
                SignalClientEndStream(false);
                co_await RetireClient(State);
                co_return;
            }
            const auto HalfClose = co_await ClientEncrypted->WriteShutdown();
            Observation.PeerWriteShutdown = static_cast<bool>(HalfClose);
            if (!HalfClose)
            {
                Observation.ClientFailure = HalfClose.error();
                SignalClientEndStream(false);
                co_await RetireClient(State);
                co_return;
            }
            const auto Response = co_await ReadPayloadBeforeTerminal(
                State->Transport, WireResponse);
            Observation.ResponseRead = Response.Complete;
            Observation.ResponseEqual = Response.Matches;
            Observation.ClientReadTerminal = Response.Terminal;
            std::array<std::byte, 1> EndStreamBuffer{};
            const auto EndStream = co_await State->Transport->ReadSome(EndStreamBuffer);
            Observation.ClientResponseEndStream =
                EndStream.Bytes == 0U && EndStream.Failure.Succeeded();
            SignalClientEndStream(Observation.ClientResponseEndStream);
            co_await RetireClient(State);
            co_return;
        }

        auto SignalClientEndStream(const bool Observed) -> void
        {
            if (!ClientEndStreamObserved.try_send(boost::system::error_code{}, Observed) &&
                Observation.ClientFailure.Succeeded())
            {
                Observation.ClientFailure = {Prism::Fault::Code::ResourceUnavailable};
            }
        }

        auto RetireClient(
            const std::shared_ptr<Trusttunnel::Detail::Http2ClientState> &State)
            -> Net::awaitable<void>
        {
            const auto Closed = State->Close();
            if (!Closed && Observation.ClientFailure.Succeeded())
                Observation.ClientFailure = Closed.error();
            const auto Drain = co_await State->Drain();
            Observation.ClientRetired = State->IsRetired();
            if (!Drain && Observation.ClientDrainFailure.Succeeded())
                Observation.ClientDrainFailure = Drain.error();
            ClientEncrypted.reset();
            ClientState.reset();
            ClientTls.reset();
            co_return;
        }

        Net::io_context IoContext;
        Tcp::acceptor Acceptor;
        Ssl::context ServerTls;
        AuthFixture Auth;
        Trusttunnel::SharedWireAuthBinding Binding;
        Trusttunnel::IngressFactory Factory;
        std::shared_ptr<Ssl::context> ClientTls;
        std::shared_ptr<Prism::Transport::Encrypted> ClientEncrypted;
        std::shared_ptr<Trusttunnel::Detail::Http2ClientState> ClientState;
        EndStreamSignal ClientEndStreamObserved;
        std::weak_ptr<Prism::Transmission> ServerRawReceipt;
        std::weak_ptr<Trusttunnel::AuthenticatedTransport> ServerProofReceipt;
        std::weak_ptr<Prism::Transport::Encrypted> ClientEncryptedReceipt;
        std::weak_ptr<Trusttunnel::Detail::Http2ClientState> ClientStateReceipt;
        RawHalfCloseObservation Observation;
    };
}

TEST(TrusttunnelHttp2RawHalfClose, ServerWritesResponseBeforeFinalClose)
{
    RawHalfCloseFixture Fixture;
    ASSERT_TRUE(Fixture.Observation.TlsReady);
    ASSERT_TRUE(Fixture.Auth.Directory);
    ASSERT_TRUE(Fixture.Auth.Record);

    RunCoro(Fixture.IoContext, Fixture.Run());

    EXPECT_TRUE(Fixture.Observation.ServerFailure.Succeeded());
    EXPECT_TRUE(Fixture.Observation.PayloadRead);
    EXPECT_TRUE(Fixture.Observation.PayloadEqual);
    EXPECT_TRUE(Fixture.Observation.PeerWriteShutdown);
    EXPECT_EQ(Fixture.Observation.ServerReadTerminal.Code, Prism::Fault::Code::Eof);
    EXPECT_EQ(Fixture.Observation.ServerReadTerminalAgain.Code, Prism::Fault::Code::Eof);
    EXPECT_TRUE(Fixture.Observation.ServerDriverCompleted);
    EXPECT_TRUE(Fixture.Observation.ServerDriverReleased);
    EXPECT_TRUE(Fixture.Observation.ServerResponseWritten);
    EXPECT_TRUE(Fixture.Observation.ServerResponseWriteAllowedAfterReadEof);
    EXPECT_TRUE(Fixture.Observation.ServerWriteShutdown);
    EXPECT_TRUE(Fixture.Observation.ClientResponseEndStream);
    EXPECT_TRUE(Fixture.Observation.ClientEndStreamObserved);
    EXPECT_TRUE(Fixture.Observation.ServerCloseFailure.Succeeded());
    EXPECT_TRUE(Fixture.Observation.ServerRetired);
    EXPECT_EQ(Fixture.Observation.ServerDrainFailure.Code, Prism::Fault::Code::Eof);
    EXPECT_TRUE(Fixture.Observation.ResponseRead);
    EXPECT_TRUE(Fixture.Observation.ResponseEqual);
    EXPECT_TRUE(Fixture.Observation.ClientFailure.Succeeded());
    EXPECT_TRUE(Fixture.Observation.ClientReadTerminal.Succeeded());
    EXPECT_TRUE(Fixture.Observation.ClientDrainFailure.Succeeded());
    EXPECT_TRUE(Fixture.Observation.ClientRetired);
    EXPECT_TRUE(Fixture.ServerRawReceipt.expired());
    EXPECT_TRUE(Fixture.ServerProofReceipt.expired());
    EXPECT_TRUE(Fixture.ClientEncryptedReceipt.expired());
    EXPECT_TRUE(Fixture.ClientStateReceipt.expired());
}

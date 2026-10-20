/**
 * @file InteropHysteria2UdpServer.cpp
 * @brief Hysteria2 authenticated UDP datagram echo and activity drain interop.
 */

#include "InteropHysteria2Support.hpp"

#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <algorithm>
#include <exception>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Http3/NativeServer.hpp>
#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <Prism/Protocols/Quic/Native.hpp>
#include "../../TestSupport/Prism/QuicFactory.hpp"

namespace Prism::Testing::Integration::Hysteria2::Interop
{
    using Udp = Net::ip::udp;

    namespace
    {
        using UdpNotifyChannel = Net::experimental::channel<void(boost::system::error_code)>;

        struct UdpEventRequest final
        {
            std::shared_ptr<Prism::Hysteria2::Http3AuthSession> AuthSession;
            std::shared_ptr<UdpNotifyChannel> Authenticated;
        };

        auto HandleUdpEvent(UdpEventRequest Request, Prism::Http3::ServerEvent Event)
            -> Net::awaitable<Prism::Http3::SessionAction>
        {
            if (auto *HttpRequest = std::get_if<Prism::Http3::RequestEvent>(&Event))
            {
                auto Response = Request.AuthSession->HandleRequest(std::move(*HttpRequest));
                if (Response)
                {
                    (void)Request.Authenticated->try_send(boost::system::error_code{});
                    co_return Prism::Http3::SessionAction(std::move(*Response));
                }
            }
            co_return Prism::Http3::SessionAction{};
        }

        struct SessionOwner final
        {
            std::shared_ptr<UdpNotifyChannel> Done;
            std::shared_ptr<std::exception_ptr> Failure;
            std::shared_ptr<SessionRunResult> Result;
        };

        auto StartSession(Net::any_io_executor Executor,
                          std::shared_ptr<Prism::Http3::NativeServerSession> Session)
            -> SessionOwner
        {
            SessionOwner Owner{
                std::make_shared<UdpNotifyChannel>(Executor, 1),
                std::make_shared<std::exception_ptr>(),
                std::make_shared<SessionRunResult>()};
            Net::co_spawn(
                Executor,
                Session->Run(),
                [Owner](std::exception_ptr ErrorValue, SessionRunResult Result)
                {
                    *Owner.Result = std::move(Result);
                    if (ErrorValue && !*Owner.Failure)
                    {
                        *Owner.Failure = ErrorValue;
                    }
                    (void)Owner.Done->try_send(boost::system::error_code{});
                });
            return Owner;
        }

        auto WaitSession(SessionOwner Owner) -> Net::awaitable<SessionRunResult>
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
            co_return std::move(*Owner.Result);
        }

        struct UdpDrainRequest final
        {
            std::shared_ptr<Prism::Http3::NativeServerSession> Session;
            SessionOwner SessionState;
            std::shared_ptr<Prism::Quic::Server> QuicServer;
            Prism::Hysteria2::SharedDgram Datagram;
        };

        struct UdpServerDataRequest final
        {
            Options OptionsValue;
            std::shared_ptr<Prism::Http3::NativeServerSession> Session;
            SessionOwner SessionState;
            std::shared_ptr<Prism::Quic::Server> QuicServer;
            std::shared_ptr<UdpNotifyChannel> Authenticated;
        };

        /// @brief 先关闭 UDP/session owner，再等待 session 和 QUIC native drain；保留首异常。
        auto DrainUdpSession(UdpDrainRequest Request)
            -> Net::awaitable<SessionRunResult>
        {
            Prism::Fault::Failure FirstFailure;
            if (Request.Datagram)
            {
                try
                {
                    const auto Closed = Request.Datagram->Close();
                    if (!Closed && FirstFailure.Succeeded()) FirstFailure = Closed.error();
                }
                catch (...)
                {
                    if (FirstFailure.Succeeded())
                        FirstFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                            std::current_exception());
                }
            }
            try
            {
                const auto Closed = Request.Session->Close();
                if (!Closed && FirstFailure.Succeeded()) FirstFailure = Closed.error();
            }
            catch (...)
            {
                if (FirstFailure.Succeeded())
                    FirstFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
            }
            try
            {
                Request.QuicServer->Close();
            }
            catch (...)
            {
                if (FirstFailure.Succeeded())
                    FirstFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
            }
            SessionRunResult SessionResult;
            try
            {
                SessionResult = co_await WaitSession(Request.SessionState);
            }
            catch (...)
            {
                if (FirstFailure.Succeeded())
                {
                    FirstFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
                }
            }
            std::optional<SessionRunResult> QuicDrain;
            try
            {
                QuicDrain.emplace(co_await Request.QuicServer->Drain());
            }
            catch (...)
            {
                if (FirstFailure.Succeeded())
                {
                    FirstFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
                }
            }
            if (QuicDrain && !*QuicDrain && SessionResult && FirstFailure.Succeeded())
            {
                FirstFailure = QuicDrain->error();
            }
            if (!SessionResult && SessionResult.error().Code != Prism::Fault::Code::Canceled &&
                FirstFailure.Succeeded())
            {
                FirstFailure = SessionResult.error();
            }
            if (Request.Datagram)
            {
                const auto Activity = Request.Datagram->Activity();
                if (!Activity)
                {
                    if (FirstFailure.Succeeded())
                        FirstFailure = {Prism::Fault::Code::ResourceUnavailable};
                }
                else
                {
                    CaptureDrainFailure(FirstFailure,
                        co_await Activity->Drain());
                    if (!Activity->IsRetired() && FirstFailure.Succeeded())
                        FirstFailure = {Prism::Fault::Code::Blocked};
                }
            }
            try
            {
                CaptureDrainFailure(FirstFailure, co_await Request.Session->Drain());
            }
            catch (...)
            {
                if (FirstFailure.Succeeded())
                    FirstFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
            }
            if (FirstFailure.Failed()) co_return std::unexpected(FirstFailure);
            co_return SessionResult;
        }

        auto RunUdpServerData(UdpServerDataRequest Request) -> Net::awaitable<int>
        {
            boost::system::error_code AuthError;
            auto AuthOperation = Request.Authenticated->async_receive(
                Net::redirect_error(Net::use_awaitable, AuthError));
            co_await std::move(AuthOperation);
            if (AuthError)
            {
                const auto DrainResult = co_await DrainUdpSession(
                    UdpDrainRequest{Request.Session, Request.SessionState, Request.QuicServer, {}});
                if (!DrainResult)
                {
                    ReportSessionRunFailure("Hysteria2 UDP session drain", DrainResult.error());
                }
                co_return 1;
            }

            auto DatagramResult = Prism::Hysteria2::AcceptPacket(
                Request.QuicServer->Datagram(),
                Prism::Hysteria2::ServerConfig{Request.OptionsValue.Password});
            if (!DatagramResult)
            {
                const auto DrainResult = co_await DrainUdpSession(
                    UdpDrainRequest{Request.Session, Request.SessionState, Request.QuicServer, {}});
                if (!DrainResult)
                {
                    ReportSessionRunFailure("Hysteria2 UDP session drain", DrainResult.error());
                }
                co_return 1;
            }
            auto Dgram = std::move(*DatagramResult);
            Prism::Hysteria2::Address Source;
            std::vector<std::uint8_t> Payload;
            auto ReceiveOperation = Dgram->AsyncReceiveFrom(Source, Payload);
            const auto ReceiveError = co_await std::move(ReceiveOperation);
            auto SendError = Prism::Error::None;
            if (ReceiveError == Prism::Error::None)
            {
                auto TargetHost = Prism::Network::ParseHost(Source.Host);
                auto TargetAddress = std::optional<Net::ip::address>{};
                if (TargetHost)
                {
                    TargetAddress = Prism::Network::IpAddress(*TargetHost);
                }
                if (!TargetHost || !TargetAddress || Source.Port == 0)
                {
                    SendError = Prism::Error::BadAddress;
                }
                else
                {
                    const auto Executor = co_await Net::this_coro::executor;
                    Udp::socket TargetSocket(Executor);
                    boost::system::error_code TargetError;
                    (void)TargetSocket.open(TargetAddress->is_v4() ? Udp::v4() : Udp::v6(),
                        TargetError);
                    std::array<std::byte, 65536> Buffer{};
                    std::size_t Count = 0;
                    if (!TargetError)
                    {
                        (void)co_await TargetSocket.async_send_to(
                            Net::buffer(Payload),
                            Udp::endpoint(*TargetAddress, Source.Port),
                            Net::redirect_error(Net::use_awaitable, TargetError));
                    }
                    if (!TargetError)
                    {
                        Udp::endpoint ReplySource;
                        Count = co_await TargetSocket.async_receive_from(
                            Net::buffer(Buffer), ReplySource,
                            Net::redirect_error(Net::use_awaitable, TargetError));
                    }
                    if (!TargetError)
                    {
                        std::vector<std::uint8_t> Reply(Count);
                        std::transform(Buffer.begin(),
                            Buffer.begin() + static_cast<std::ptrdiff_t>(Count),
                            Reply.begin(), [](const std::byte Byte)
                            {
                                return std::to_integer<std::uint8_t>(Byte);
                            });
                        SendError = co_await Dgram->AsyncSendTo(
                            Source, std::span<const std::uint8_t>(Reply));
                    }
                    else
                    {
                        SendError = Prism::Error::IoError;
                        (void)TargetSocket.close(TargetError);
                    }
                }
            }
            if (ReceiveError != Prism::Error::None || SendError != Prism::Error::None)
            {
                const auto DrainResult = co_await DrainUdpSession(
                    UdpDrainRequest{Request.Session, Request.SessionState, Request.QuicServer, Dgram});
                if (!DrainResult)
                {
                    ReportSessionRunFailure("Hysteria2 UDP session drain", DrainResult.error());
                }
                co_return 1;
            }
            const auto SessionResult = co_await DrainUdpSession(
                UdpDrainRequest{Request.Session, Request.SessionState, Request.QuicServer, Dgram});
            if (!SessionResult)
            {
                ReportSessionRunFailure("Hysteria2 UDP session", SessionResult.error());
                co_return 1;
            }
            std::printf("PASS: Prism Hysteria2 UDP authenticated echo (%zu bytes)\n", Payload.size());
            co_return 0;
        }
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
        auto QuicServer = std::make_shared<Prism::Quic::Server>(Prism::Quic::ServerOptions{
            Executor, Socket, Tls, Prism::Testing::Quic::MakeSender(Socket)});
        QuicServer->Start();
        std::printf("READY: Prism Hysteria2 UDP server on %s\n", OptionsValue.Address.c_str());
        std::fflush(stdout);
        const auto HandshakeOk = co_await WaitQuicHandshakeOrDrain(QuicServer);
        if (!HandshakeOk)
        {
            co_return 1;
        }

        auto Authenticated = std::make_shared<UdpNotifyChannel>(Executor, 1);
        const auto Auth = MakeAuthenticator(OptionsValue.Password);
        auto AuthSession = std::make_shared<Prism::Hysteria2::Http3AuthSession>(
            Prism::Hysteria2::Http3AuthSessionOptions{Executor, Auth.Authenticator});
        Prism::Http3::NativeServerSessionOptions SessionOptions;
        SessionOptions.Executor = Executor;
        const UdpEventRequest EventRequest{AuthSession, Authenticated};
        SessionOptions.OnEvent = [EventRequest](Prism::Http3::ServerEvent Event)
        {
            return HandleUdpEvent(EventRequest, std::move(Event));
        };
        SessionOptions.OpenUnidirectional = [QuicServer]() -> Net::awaitable<QuicStreamResult>
        {
            co_return co_await QuicServer->OpenUnidirectionalStream();
        };
        SessionOptions.AcceptUnidirectional = [QuicServer]() -> Net::awaitable<QuicStreamResult>
        {
            co_return co_await QuicServer->AcceptUnidirectionalStream();
        };
        SessionOptions.AcceptBidirectional = [QuicServer]() -> Net::awaitable<QuicStreamResult>
        {
            co_return co_await QuicServer->AcceptBidirectionalStream();
        };
        auto Session = std::make_shared<Prism::Http3::NativeServerSession>(std::move(SessionOptions));
        auto SessionState = StartSession(Executor, Session);

        co_return co_await RunUdpServerData(
            UdpServerDataRequest{std::move(OptionsValue), Session, SessionState, QuicServer, Authenticated});
    }
}

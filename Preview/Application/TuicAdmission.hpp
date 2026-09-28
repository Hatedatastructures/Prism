/**
 * @file TuicAdmission.hpp
 * @brief TUIC QUIC admission 后的 TCP/UDP 业务 relay handler。
 */
#pragma once

#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Preview/Ingress/QuicAdmissionContext.hpp>
#include <Preview/Runtime/Middleware/Builtin/Relay.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Preview::Application::TuicAdmission
{

    namespace Net = boost::asio;
    [[nodiscard]] inline auto MakeStreamHandler(
        const std::weak_ptr<const Preview::Ingress::QuicAdmissionContext> &Weak)
        -> std::function<Net::awaitable<void>(Preview::Tuic::Message,
                                               Preview::Tuic::SharedConn,
                                               Preview::Ingress::QuicPeerLogContext)>
    {
        return [Weak](Preview::Tuic::Message Message,
                      Preview::Tuic::SharedConn Connection,
                      Preview::Ingress::QuicPeerLogContext Peer)
            -> Net::awaitable<void>
        {
            const auto Context = Weak.lock();
            if (!Context || !Connection || !Context->Dial || Message.dst.Host.empty() ||
                Message.dst.Port == 0U)
            {
                if (Connection)
                {
                    Connection->Close();
                }
                co_return;
            }
            auto LogContext = Peer.Trace;
            try
            {
                const auto Carrier = std::string_view{"Quic"};
                if (const auto Derived = LogContext.TryWith(
                        Preview::Diagnose::Fields::Carrier, Carrier))
                {
                    LogContext = *Derived;
                }
                const auto Protocol = Preview::Diagnose::PascalCaseToken(Context->Protocol);
                if (const auto Derived = LogContext.TryWith(
                        Preview::Diagnose::Fields::Protocol, Protocol))
                {
                    LogContext = *Derived;
                }
            }
            catch (...)
            {
                LogContext = Peer.Trace;
            }
            Preview::Network::Target Target;
            Target.Host.assign(Message.dst.Host.data(), Message.dst.Host.size());
            Target.Port.assign(std::to_string(Message.dst.Port));
            const auto AccountId = Connection->AccountId();
            const auto Source = Peer.SourceIp.empty() ? std::string_view{"Unknown"}
                                                     : std::string_view{Peer.SourceIp};
            const auto Host = std::string_view{Target.Host.data(), Target.Host.size()};
            const auto Port = std::string_view{Target.Port.data(), Target.Port.size()};
            if (Preview::Diagnose::IsEnabled(Preview::Diagnose::LogLevel::Info))
            {
                const auto User = std::to_string(
                    (AccountId ? AccountId : Context->AccountId).Value());
                (void)Preview::Diagnose::Info(
                    LogContext, "Request SourceIp={} Target={}:{} User={}",
                    Source, Host, Port, User);
            }
            auto Lease = Connection->TakeAuthLease();
            const auto Identity = std::string(Connection->Identity());
            auto [DialError, Outbound] = co_await Context->Dial(Target);
            if (Preview::Fault::Failed(DialError) || !Outbound)
            {
                const auto FailureCode = DialError == Preview::Fault::Code::Success
                                             ? Preview::Fault::Code::BadGateway
                                             : DialError;
                (void)Preview::Diagnose::Warn(
                    LogContext, "QuicDialFailed SourceIp={} Target={}:{} FaultCode={}",
                    Source, Host, Port,
                    Preview::Diagnose::PascalCaseToken(Preview::Fault::Describe(FailureCode)));
                Connection->Close();
                co_return;
            }

            Preview::Middleware::Context SessionContext;
            SessionContext.Inbound = std::move(Connection);
            SessionContext.Outbound = std::move(Outbound);
            SessionContext.Target = std::move(Target);
            SessionContext.SourceIp = Peer.SourceIp;
            SessionContext.AccountId = AccountId ? AccountId : Context->AccountId;
            SessionContext.AccountLease = std::move(Lease);
            SessionContext.Credential = Context->Credential;
            SessionContext.ProtocolAuthenticated = true;
            SessionContext.identity = Identity.empty()
                                           ? std::to_string(SessionContext.AccountId.Value())
                                           : Identity;
            SessionContext.traffic = Context->Metrics.get();
            Preview::Middleware::Builtin::RelayMiddleware Relay(
                nullptr, std::chrono::milliseconds(0));
            const auto RelayError = co_await Relay.Handle(SessionContext.Inbound, SessionContext);
            if (Preview::Fault::Failed(RelayError))
            {
                const auto RelayHost = std::string_view{
                    SessionContext.Target.Host.data(), SessionContext.Target.Host.size()};
                const auto RelayPort = std::string_view{
                    SessionContext.Target.Port.data(), SessionContext.Target.Port.size()};
                (void)Preview::Diagnose::Warn(
                    LogContext, "QuicRelayFailed SourceIp={} Target={}:{} FaultCode={}",
                    Source, RelayHost, RelayPort,
                    Preview::Diagnose::PascalCaseToken(Preview::Fault::Describe(RelayError)));
            }
        };
    }

    [[nodiscard]] inline auto MakeDatagramHandler(
        const std::weak_ptr<const Preview::Ingress::QuicAdmissionContext> &Weak)
        -> std::function<Net::awaitable<void>(Preview::Tuic::SharedDgram,
                                               Preview::Ingress::QuicPeerLogContext)>
    {
        return [Weak](Preview::Tuic::SharedDgram Datagram,
                      Preview::Ingress::QuicPeerLogContext Peer)
            -> Net::awaitable<void>
        {
            const auto Context = Weak.lock();
            if (!Context || !Datagram || !Context->Resolver)
            {
                co_return;
            }
            using Udp = Net::ip::udp;
            Udp::socket Egress(Context->Executor);
            std::vector<std::byte> ReceiveBuffer(65535);
            std::size_t Uploaded = 0;
            std::size_t Downloaded = 0;
            std::size_t DatagramCount = 0;
            bool SummaryLogged = false;
            const auto SourceIp = Peer.SourceIp.empty() ? std::string_view{"Unknown"}
                                                        : std::string_view{Peer.SourceIp};
            while (true)
            {
                Preview::Tuic::Address Target;
                std::vector<std::uint8_t> Payload;
                if (co_await Datagram->AsyncReceiveFrom(Target, Payload) != Preview::Error::None)
                {
                    break;
                }
                ++DatagramCount;
                if (!SummaryLogged && Target.Port != 0U &&
                    Target.Host != "0.0.0.0" && Target.Host != "::")
                {
                    if (Preview::Diagnose::IsEnabled(Preview::Diagnose::LogLevel::Info))
                    {
                        const auto User = std::to_string(Context->AccountId.Value());
                        (void)Preview::Diagnose::Info(
                            Peer.Trace, "Request SourceIp={} Target={}:{} User={}",
                            SourceIp, Target.Host, Target.Port, User);
                    }
                    SummaryLogged = true;
                }
                boost::system::error_code ResolveError;
                Net::ip::udp::endpoint Destination;
                const auto Addresses = co_await Context->Resolver->AsyncResolve(
                    Target.Host, ResolveError);
                if (ResolveError || Addresses.empty())
                {
                    continue;
                }
                Destination = Net::ip::udp::endpoint(Addresses.front(), Target.Port);
                boost::system::error_code Error;
                Egress.close(Error);
                Egress.open(Destination.protocol(), Error);
                if (Error)
                {
                    break;
                }
                co_await Egress.async_send_to(
                    Net::buffer(Payload), Destination,
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    break;
                }
                Uploaded += Payload.size();
                Udp::endpoint Source;
                const auto Size = co_await Egress.async_receive_from(
                    Net::buffer(ReceiveBuffer), Source,
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error || Size == 0U)
                {
                    break;
                }
                const auto SourceType = Source.address().is_v4()
                                            ? Preview::Tuic::AddressType::Ipv4
                                            : Preview::Tuic::AddressType::Ipv6;
                const Preview::Tuic::Address ResponseTarget{
                    SourceType, Source.address().to_string(), Source.port()};
                if (co_await Datagram->AsyncSendTo(
                        ResponseTarget,
                        std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t *>(ReceiveBuffer.data()), Size)) !=
                    Preview::Error::None)
                {
                    break;
                }
                Downloaded += Size;
            }
            boost::system::error_code Error;
            Egress.cancel(Error);
            Egress.close(Error);
            if (Context->Metrics)
            {
                Context->Metrics->Report(
                    std::to_string(Context->AccountId.Value()), Uploaded, Downloaded);
            }
            (void)Preview::Diagnose::Trace(
                Peer.Trace,
                "UdpSessionSummary SourceIp={} Datagrams={} UpBytes={} DownBytes={}",
                SourceIp, DatagramCount, Uploaded, Downloaded);
        };
    }

} // namespace Preview::Application::TuicAdmission

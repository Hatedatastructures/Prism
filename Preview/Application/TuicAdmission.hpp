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
#include <atomic>
#include <string>
#include <utility>
#include <vector>

namespace Preview::Application::TuicAdmission
{

    namespace Net = boost::asio;
    inline std::atomic_uint64_t TuicSessionSequence{1};

    [[nodiscard]] inline auto MakeStreamHandler(
        const std::weak_ptr<const Preview::Ingress::QuicAdmissionContext> &Weak)
        -> std::function<Net::awaitable<void>(Preview::Tuic::Message,
                                               Preview::Tuic::SharedConn)>
    {
        return [Weak](Preview::Tuic::Message Message, Preview::Tuic::SharedConn Connection)
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
            const auto SessionId = TuicSessionSequence.fetch_add(1, std::memory_order_relaxed);
            auto LogContext = Context->Trace;
            try
            {
                const auto Carrier = std::string_view{"quic"};
                if (const auto Derived = LogContext.TryWith(
                        Preview::Diagnose::Fields::Carrier, Carrier))
                {
                    LogContext = *Derived;
                }
                const auto Protocol = std::string_view{Context->Protocol};
                if (const auto Derived = LogContext.TryWith(
                        Preview::Diagnose::Fields::Protocol, Protocol))
                {
                    LogContext = *Derived;
                }
            }
            catch (...)
            {
                LogContext = Context->Trace;
            }
            const auto WriteRelayLog = [Context, SessionId, LogContext](
                                           const std::string_view Outcome,
                                           const std::string_view Fault,
                                           const Preview::Network::Target &Target) noexcept
            {
                (void)Preview::Diagnose::Info(
                    LogContext,
                    "carrier=quic protocol={} session_id=quic-{} stage=relay outcome={} fault={} target={}:{}",
                    Context->Protocol, SessionId, Outcome, Fault,
                    std::string_view{Target.Host.data(), Target.Host.size()},
                    std::string_view{Target.Port.data(), Target.Port.size()});
            };
            Preview::Network::Target Target;
            Target.Host.assign(Message.dst.Host.data(), Message.dst.Host.size());
            Target.Port.assign(std::to_string(Message.dst.Port));
            const auto AccountId = Connection->AccountId();
            auto Lease = Connection->TakeAuthLease();
            const auto Identity = std::string(Connection->Identity());
            auto [DialError, Outbound] = co_await Context->Dial(Target);
            if (Preview::Fault::Failed(DialError) || !Outbound)
            {
                WriteRelayLog("failure", "dial", Target);
                Connection->Close();
                co_return;
            }

            Preview::Middleware::Context SessionContext;
            SessionContext.Inbound = std::move(Connection);
            SessionContext.Outbound = std::move(Outbound);
            SessionContext.Target = std::move(Target);
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
            WriteRelayLog(RelayError == Preview::Fault::Code::Success ? "success" : "failure",
                          Preview::Fault::Describe(RelayError), SessionContext.Target);
        };
    }

    [[nodiscard]] inline auto MakeDatagramHandler(
        const std::weak_ptr<const Preview::Ingress::QuicAdmissionContext> &Weak)
        -> std::function<Net::awaitable<void>(Preview::Tuic::SharedDgram)>
    {
        return [Weak](Preview::Tuic::SharedDgram Datagram) -> Net::awaitable<void>
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
            while (true)
            {
                Preview::Tuic::Address Target;
                std::vector<std::uint8_t> Payload;
                if (co_await Datagram->AsyncReceiveFrom(Target, Payload) != Preview::Error::None)
                {
                    break;
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
        };
    }

} // namespace Preview::Application::TuicAdmission

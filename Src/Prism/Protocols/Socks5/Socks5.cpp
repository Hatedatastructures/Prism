/** @file Socks5.cpp @brief SOCKS5 连接工厂握手实现。 */
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Socks5/Reply.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Fault/Handling.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>

#include <exception>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Socks5
{

    auto ToReplyCode(Prism::Fault::Code Status) -> ReplyCode
    {
        if (!Prism::Fault::Failed(Status))
        {
            return ReplyCode::Success;
        }
        switch (Status)
        {
        case Prism::Fault::Code::ConnectionRefused:
            return ReplyCode::ConnectionRefused;
        case Prism::Fault::Code::Unreachable:
        case Prism::Fault::Code::NetNoreply:
            return ReplyCode::NetworkUnreachable;
        case Prism::Fault::Code::HostNoreply:
            return ReplyCode::HostUnreachable;
        default:
            return ReplyCode::GeneralFailure;
        }
    }

    auto SendConnectDeferredReply(
        std::shared_ptr<Conn<>> Connection,
        Prism::Diagnose::ContextState Trace,
        Prism::Fault::Failure Status) -> Net::awaitable<Prism::Fault::Failure>
    {
        if (!Connection)
        {
            if (Status.Failed())
            {
                co_return Status;
            }
            co_return Prism::Protocol::Common::FailureFromProtocolError(Error::NotOpen);
        }

        const auto Reply = co_await Connection->SendConnectReply(ToReplyCode(Status.Code));
        auto Failure = Prism::Fault::Failure{};
        if (!Reply)
        {
            (void)Prism::Diagnose::Warn(Trace, "Socks5ConnectReplyWriteFailed Action=Close");
            if (Reply.error().Transport.Failed())
            {
                Failure = Reply.error().Transport;
            }
            else if (Reply.error().Protocol != Error::None)
            {
                Failure = Prism::Protocol::Common::FailureFromProtocolError(
                    Reply.error().Protocol);
            }
            else
            {
                Failure = {Prism::Fault::Code::IoError};
            }
        }
        if (Status.Failed() || Failure.Failed())
        {
            const auto Closed = Connection->Close();
            if (!Failure.Failed() && !Closed)
            {
                Failure = Closed.error();
            }
        }
        co_return Failure;
    }

    [[nodiscard]] auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        if (!Params.Upstream)
        {
            co_return std::unexpected(
                Prism::Protocol::Common::FailureFromProtocolError(Error::NotOpen));
        }
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Params.Upstream);
        if (!Prepared) co_return std::unexpected(Prepared.error());
        auto Admission = std::move(*Prepared);
        Request RequestValue;
        RequestValue.Cmd = Params.Cmd;
        RequestValue.Target = Params.Target;
        std::shared_ptr<Conn<>> Connection;
        std::optional<Prism::Fault::Failure> CreationFailure;
        try
        {
            Connection = std::make_shared<Conn<>>(std::move(Params.Upstream));
        }
        catch (...)
        {
            CreationFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (CreationFailure)
        {
            co_return std::unexpected(co_await Admission.Retire(*CreationFailure));
        }
        if (const auto Tracked = Admission.Track(Connection); !Tracked)
        {
            const auto Failure = Tracked.error();
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        auto Handshake = std::expected<void, Prism::Fault::Failure>{};
        try
        {
            Handshake = co_await Connection->WriteHandshake(RequestValue, Params.Config);
        }
        catch (...)
        {
            Handshake = std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(std::current_exception()));
        }
        if (!Handshake)
        {
            const auto Failure = Handshake.error();
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        Admission.Release();
        co_return SharedConn(std::move(Connection));
    }

    [[nodiscard]] auto ConnectPacket(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        auto Connection = co_await Connect(
            ConnectParameters{std::move(Upstream), Config, Target, Command::UdpAssociate});
        if (!Connection)
        {
            co_return std::unexpected(Connection.error());
        }
        co_return std::make_shared<Dgram<>>(std::move(*Connection));
    }

    [[nodiscard]] auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(
                Prism::Protocol::Common::FailureFromProtocolError(Error::NotOpen));
        }
        auto Connection = std::make_shared<Conn<>>(std::move(Upstream));
        auto Handshake = std::expected<Request, Prism::Fault::Failure>{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError})};
        try
        {
            Handshake = co_await Connection->ReadHandshake(Config);
        }
        catch (...)
        {
            Handshake = std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(std::current_exception()));
        }
        if (!Handshake)
        {
            (void)Connection->Close();
            co_return std::unexpected(Handshake.error());
        }
        co_return AcceptedConnection{std::move(*Handshake), SharedConn(std::move(Connection))};
    }

    [[nodiscard]] auto AcceptPacket(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedDatagram, Prism::Fault::Failure>>
    {
        auto Accepted = co_await Accept(std::move(Upstream), Config);
        if (!Accepted)
        {
            co_return std::unexpected(Accepted.error());
        }
        if (Accepted->RequestValue.Cmd != Command::UdpAssociate)
        {
            (void)Accepted->Connection->Close();
            co_return std::unexpected(
                Prism::Protocol::Common::FailureFromProtocolError(Error::BadMessage));
        }
        co_return AcceptedDatagram{
            std::move(Accepted->RequestValue),
            std::make_shared<Dgram<>>(std::move(Accepted->Connection))};
    }

} // namespace Prism::Socks5

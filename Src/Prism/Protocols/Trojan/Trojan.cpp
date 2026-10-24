/** @file Trojan.cpp @brief Trojan 连接工厂握手实现。 */
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <exception>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Trojan
{

    [[nodiscard]] auto Connect(ConnectParameters Params)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        if (!Params.Upstream)
        {
            co_return std::unexpected(Prism::Protocol::Common::FailureFromProtocolError(Error::NotOpen));
        }
        /** @brief 预预约进入协议工厂的 carrier 失败退休，不替代 listener 入口准入。 */
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Params.Upstream);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::shared_ptr<Conn<>> C;
        auto Construction = std::expected<void, Prism::Fault::Failure>{};
        try
        {
            C = std::make_shared<Conn<>>(std::move(Params.Upstream), Params.Config.Password);
        }
        catch (...)
        {
            Construction = std::unexpected(Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception()));
        }
        if (!Construction)
        {
            const auto Failure = Construction.error();
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        if (const auto Tracked = Admission.Track(C); !Tracked)
        {
            const auto Failure = Tracked.error();
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        auto Handshake = std::expected<void, Prism::Fault::Failure>{};
        try
        {
            Handshake = co_await C->WriteHandshake(Params.Target, Params.Cmd);
        }
        catch (...)
        {
            Handshake = std::unexpected(Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception()));
        }
        if (!Handshake)
        {
            const auto Failure = Handshake.error();
            co_return std::unexpected(co_await Admission.Retire(Failure));
        }
        Admission.Release();
        co_return SharedConn(std::move(C));
    }

    [[nodiscard]] auto ConnectPacket(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        auto Result = co_await Connect(
            ConnectParameters{std::move(Upstream), Config, Target, Command::UdpAssociate});
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        co_return std::make_shared<Dgram<>>(std::move(*Result));
    }

    [[nodiscard]] auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(Prism::Protocol::Common::FailureFromProtocolError(Error::NotOpen));
        }
        auto C = std::make_shared<Conn<>>(
            std::move(Upstream),
            Config.Password,
            Config.AuthenticatorOwner);
        auto Handshake = co_await C->ReadHandshake(
            Config.EnableTcp, Config.EnableUdp, Config.EnableMux);
        if (!Handshake)
        {
            co_return std::unexpected(Handshake.error());
        }
        co_return AcceptedConnection{std::move(*Handshake), SharedConn(std::move(C))};
    }

    [[nodiscard]] auto AcceptPacket(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedDatagram, Prism::Fault::Failure>>
    {
        auto Result = co_await Accept(std::move(Upstream), Config);
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        auto Connection = std::make_shared<Dgram<>>(std::move(Result->Connection));
        co_return AcceptedDatagram{std::move(Result->Request), std::move(Connection)};
    }

} // namespace Prism::Trojan

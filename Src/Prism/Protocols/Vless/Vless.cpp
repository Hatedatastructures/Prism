/** @file Vless.cpp @brief VLESS 连接工厂握手实现。 */
#include <Prism/Protocols/Vless/Vless.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <exception>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Vless
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
            C = std::make_shared<Conn<>>(std::move(Params.Upstream), Params.Config.uuid);
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
        const Address &Target) -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        auto Result = co_await Connect(
            ConnectParameters{std::move(Upstream), Config, Target, Command::Udp});
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
            Config.uuid,
            Config.AuthenticatorOwner);
        // 流承载 UDP 的数据面由 UdpTunnel 按传输类型进行能力校验；
        // 握手阶段仍需保留命令信息，避免把不安全的裸流帧当作已建立会话。
        auto Handshake = co_await C->ReadHandshake(true, Config.EnableUdp, true);
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
        auto StreamConnection = std::move(Result->Connection);
        if (Result->Request.Cmd != Command::Udp)
        {
            const auto Rejected =
                Prism::Protocol::Common::FailureFromProtocolError(Error::BadMessage);
            (void)StreamConnection->Close();
            (void)co_await StreamConnection->Activity()->Drain();
            co_return std::unexpected(Rejected);
        }
        auto DatagramConnection = std::make_shared<Dgram<>>(
            std::move(StreamConnection));
        co_return AcceptedDatagram{std::move(Result->Request), std::move(DatagramConnection)};
    }

} // namespace Prism::Vless

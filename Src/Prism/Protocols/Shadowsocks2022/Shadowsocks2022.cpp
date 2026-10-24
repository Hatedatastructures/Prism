/** @file Shadowsocks2022.cpp @brief SS2022 协议工厂实现。 */
#include <Prism/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Utility/Crypto/Base64.hpp>
#include <Prism/Transport/Unreliable.hpp>

#include <cstring>
#include <exception>
#include <memory>
#include <utility>

namespace Prism::Shadowsocks2022
{
    namespace Detail
    {
        namespace
        {
            /** @brief 失败工厂关闭原 socket，并等待载体活动真实退栈。 */
            auto RetireFailedPacketSocket(
                Prism::SharedTransmission Socket) -> Net::awaitable<void>
            {
                if (!Socket)
                {
                    co_return;
                }
                (void)Socket->Close();
                (void)co_await Socket->Activity()->Drain();
            }
        }
    }

    [[nodiscard]] auto DecodePsk(std::string_view Password)
        -> std::optional<std::array<std::uint8_t, 16>>
    {
        const auto Decoded = Prism::Crypto::Base64Decode(Password);
        if (Decoded.size() != 16)
        {
            return std::nullopt;
        }
        std::array<std::uint8_t, 16> Psk{};
        std::memcpy(Psk.data(), Decoded.data(), Psk.size());
        return Psk;
    }

    [[nodiscard]] auto Connect(
        SharedTransmission Upstream,
        const ClientConfig &Config,
        const Address &Target)
        -> Net::awaitable<std::expected<SharedConn, Prism::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Prepared = co_await Prism::Contract::InboundAdmission::Prepare(Upstream);
        if (!Prepared)
        {
            co_return std::unexpected(Prepared.error());
        }
        auto Admission = std::move(*Prepared);
        std::shared_ptr<Conn<>> Connection;
        std::optional<Prism::Fault::Failure> CreationFailure;
        try
        {
            Connection = std::make_shared<Conn<>>(ConnOptions{
                .Executor = Upstream->Executor(), .Psk = Config.Psk});
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
        auto Handshake = Prism::Fault::Failure{};
        try
        {
            Handshake = co_await Connection->WriteHandshake(Upstream, Target);
        }
        catch (...)
        {
            Handshake = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (Handshake.Failed())
        {
            co_return std::unexpected(co_await Admission.Retire(Handshake));
        }
        Admission.Release();
        co_return SharedConn(std::move(Connection));
    }

    [[nodiscard]] auto ConnectPacket(
        Net::any_io_executor Executor,
        std::string Remote,
        ClientConfig Config)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        std::shared_ptr<Prism::Transport::Unreliable> Udp;
        try
        {
            Udp = std::make_shared<Prism::Transport::Unreliable>(Executor);
        }
        catch (...)
        {
            co_return std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(std::current_exception()));
        }
        const auto Connected = Udp->Connect(Remote);
        if (!Connected)
        {
            const auto Failure = Connected.error();
            co_await Detail::RetireFailedPacketSocket(Udp);
            co_return std::unexpected(Failure);
        }
        SharedDgram Datagram;
        std::optional<Prism::Fault::Failure> CreationFailure;
        try
        {
            Datagram = std::make_shared<Dgram<>>(Udp, Config.Psk, UdpRole::Client);
        }
        catch (...)
        {
            CreationFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (CreationFailure)
        {
            co_await Detail::RetireFailedPacketSocket(Udp);
            co_return std::unexpected(*CreationFailure);
        }
        co_return Datagram;
    }

    [[nodiscard]] auto Accept(
        SharedTransmission Upstream,
        const ServerConfig &Config)
        -> Net::awaitable<std::expected<AcceptedConnection, Prism::Fault::Failure>>
    {
        if (!Upstream)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        std::shared_ptr<Conn<>> Connection;
        try
        {
            Connection = std::make_shared<Conn<>>(ConnOptions{
                .Executor = Upstream->Executor(), .Psk = Config.Psk,
                .TimeWindow = Config.TimeWindow,
                .AuthenticatorOwner = Config.Authenticator});
        }
        catch (...)
        {
            co_return std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
        }
        std::expected<Message, Prism::Fault::Failure> Handshake{
            std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError})};
        try
        {
            Handshake = co_await Connection->ReadHandshake(std::move(Upstream));
        }
        catch (...)
        {
            Handshake = std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
        }
        if (!Handshake)
        {
            (void)Connection->Close();
            co_return std::unexpected(Handshake.error());
        }
        co_return AcceptedConnection{std::move(*Handshake), SharedConn(std::move(Connection))};
    }

    [[nodiscard]] auto AcceptPacket(AcceptPacketParameters Params)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        if (!Params.Config.EnableUdp)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
        std::shared_ptr<Prism::Transport::Unreliable> Udp;
        try
        {
            Udp = std::make_shared<Prism::Transport::Unreliable>(Params.Executor);
        }
        catch (...)
        {
            co_return std::unexpected(
                Prism::Contract::InboundAdmission::ExceptionFailure(std::current_exception()));
        }
        const auto Bound = Udp->Bind(Params.Port);
        if (!Bound)
        {
            const auto Failure = Bound.error();
            co_await Detail::RetireFailedPacketSocket(Udp);
            co_return std::unexpected(Failure);
        }
        // 独立 UDP 服务端必须按每个已认证数据报的来源回包，不能把
        // Unreliable 的首次来源捕获为全局共享远端。
        Udp->AllowAnyPeer();
        SharedDgram Datagram;
        std::optional<Prism::Fault::Failure> CreationFailure;
        try
        {
            Datagram = std::make_shared<Dgram<>>(Udp, Params.Config.Psk, UdpRole::Server);
        }
        catch (...)
        {
            CreationFailure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
        }
        if (CreationFailure)
        {
            co_await Detail::RetireFailedPacketSocket(Udp);
            co_return std::unexpected(*CreationFailure);
        }
        if (Params.Bound)
        {
            *Params.Bound = Udp->LocalEndpoint();
        }
        co_return Datagram;
    }

} // namespace Prism::Shadowsocks2022

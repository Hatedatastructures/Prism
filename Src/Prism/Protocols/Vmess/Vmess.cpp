/** @file Vmess.cpp @brief VMess 连接工厂握手实现。 */
#include <Prism/Protocols/Vmess/Vmess.hpp>
#include <Prism/Protocols/Vmess/Datagram/Session.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <exception>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Vmess
{

    auto DatagramWire::Validate() const noexcept -> Prism::Fault::Code
    {
        if (!Carrier_ || !Carrier_->Stream() ||
            FixedTarget_.Host.Empty() || FixedTarget_.Port == 0)
            return Prism::Fault::Code::InvalidArgument;
        return Prism::Fault::Code::Success;
    }

    DatagramWire::DatagramWire(
        std::shared_ptr<Prism::Vmess::Dgram<>> Carrier,
        Prism::Network::Target FixedTarget,
        Net::any_io_executor Executor)
        : Executor_(std::move(Executor)), FixedTarget_(std::move(FixedTarget)),
          Carrier_(std::move(Carrier))
    {
    }

    DatagramWire::DatagramWire(DatagramWire&& Other)
        : Executor_(Other.Executor_), FixedTarget_(std::move(Other.FixedTarget_)),
          Carrier_(std::move(Other.Carrier_))
    {
    }

    auto DatagramWire::Create(
        std::shared_ptr<Prism::Vmess::Dgram<>> Carrier,
        Prism::Network::Target FixedTarget)
        -> std::expected<DatagramWire, Prism::Fault::Failure>
    {
        if (!Carrier || !Carrier->Stream())
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Executor = Carrier->Executor();
        return DatagramWire(
            std::move(Carrier), std::move(FixedTarget), std::move(Executor));
    }

    auto DatagramWire::Executor() const -> Net::any_io_executor
    {
        return Executor_;
    }

    auto DatagramWire::Receive(Prism::Protocols::DatagramPacket& Packet)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Carrier_ || !Carrier_->Stream())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Result = co_await Carrier_->AsyncReceiveDatagram(Packet.Payload);
        if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
        Packet.Target = FixedTarget_;
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto DatagramWire::Send(const Udp::endpoint&,
        std::span<const std::uint8_t> Payload)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Carrier_ || !Carrier_->Stream())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Result = co_await Carrier_->AsyncSendDatagram(Payload);
        if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto DatagramWire::CarrierActivities() const
        -> std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>
    {
        if (!Carrier_) return {};
        return Prism::Protocols::CaptureDatagramCarrierActivities(*Carrier_);
    }

    auto DatagramWire::Cancel() const -> Prism::Transmission::ControlResult
    {
        if (!Carrier_)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        return Carrier_->Cancel();
    }

    auto DatagramWire::Close() const -> Prism::Transmission::ControlResult
    {
        if (!Carrier_)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        return Carrier_->Close();
    }

    DatagramSession::DatagramSession(
        DatagramWire Wire, DatagramSession::Options OptionsValue)
        : Relay(std::move(Wire), std::move(OptionsValue))
    {
    }

    auto DatagramSession::Create(
        std::shared_ptr<Prism::Vmess::Dgram<>> Carrier,
        Prism::Network::Target FixedTarget,
        DatagramSession::Options OptionsValue)
        -> std::expected<std::shared_ptr<DatagramSession>, Prism::Fault::Failure>
    {
        auto Wire = DatagramWire::Create(
            std::move(Carrier), std::move(FixedTarget));
        if (!Wire)
        {
            return std::unexpected(Wire.error());
        }
        return std::shared_ptr<DatagramSession>(
            new DatagramSession(std::move(*Wire), std::move(OptionsValue)));
    }

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
            C = std::make_shared<Conn<>>(ConnOptions{
                .Executor = Params.Upstream->Executor(), .Uuid = Params.Config.uuid});
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
            Handshake = co_await C->WriteHandshake(
                std::move(Params.Upstream), Params.Target, Params.Cmd);
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

    [[nodiscard]] auto ConnectPacket(SharedTransmission upstream, const ClientConfig &cfg,
                                             const Address &Target)
        -> Net::awaitable<std::expected<SharedDgram, Prism::Fault::Failure>>
    {
        auto Result = co_await Connect(ConnectParameters{
            std::move(upstream), cfg, Target, Command::Udp});
        if (!Result)
        {
            co_return std::unexpected(Result.error());
        }
        co_return std::make_shared<Dgram<>>(std::move(*Result));
    }

    [[nodiscard]] auto AcceptSession(SharedTransmission upstream, const ServerConfig &cfg)
        -> Net::awaitable<std::expected<AcceptedSession, Prism::Fault::Failure>>
    {
        if (!upstream)
        {
            co_return std::unexpected(Prism::Protocol::Common::FailureFromProtocolError(Error::NotOpen));
        }
        auto C = std::make_shared<Conn<>>(ConnOptions{
            .Executor = upstream->Executor(), .Uuid = cfg.uuid, .AuthenticatorOwner = cfg.AuthenticatorOwner});
        auto Handshake = co_await C->ReadHandshake(
            std::move(upstream), cfg.EnableUdp, cfg.EnableMux);
        if (!Handshake)
        {
            co_return std::unexpected(Handshake.error());
        }
        if (Handshake->Cmd == CmdUdp)
        {
            auto Datagram = std::make_shared<Dgram<>>(SharedConn(C));
            co_return AcceptedSession{AcceptedDatagram{
                std::move(*Handshake), std::move(Datagram)}};
        }
        co_return AcceptedSession{AcceptedConnection{
            std::move(*Handshake), SharedConn(std::move(C))}};
    }

} // namespace Prism::Vmess

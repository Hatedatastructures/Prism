/** @file Session.cpp @brief Trojan 数据报目标转换实现。 */
#include <Prism/Protocols/Trojan/Datagram/Session.hpp>

#include "../Detail/Target.hpp"

#include <utility>

namespace Prism::Trojan::Detail
{

    auto DatagramWire::Validate() const noexcept -> Prism::Fault::Code
    {
        return Carrier_ ? Prism::Fault::Code::Success
                        : Prism::Fault::Code::InvalidArgument;
    }

    auto DatagramWire::Executor() const -> Net::any_io_executor
    {
        return Carrier_->Executor();
    }

    auto DatagramWire::Receive(Prism::Protocols::DatagramPacket& Packet)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Prism::Trojan::Address Target;
        const auto Result = co_await Carrier_->AsyncReceiveFrom(Target, Packet.Payload);
        if (Result.Failure.Failed())
        {
            co_return std::unexpected(Result.Failure);
        }
        auto Value = ToNetworkTarget(Target);
        if (!Value)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
        Packet.Target = std::move(*Value);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto DatagramWire::Send(const Udp::endpoint& Source,
        std::span<const std::uint8_t> Payload)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Type = Source.address().is_v4()
                              ? Prism::Trojan::AddressType::Ipv4
                              : Prism::Trojan::AddressType::Ipv6;
        Prism::Trojan::Address Address{
            Type, Source.address().to_string(), Source.port()};
        const auto Result = co_await Carrier_->AsyncSendTo(Address, Payload);
        if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto DatagramWire::CarrierActivities() const
        -> std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>
    {
        return Prism::Protocols::CaptureDatagramCarrierActivities(*Carrier_);
    }

    auto DatagramWire::Cancel() const -> Prism::Transmission::ControlResult
    {
        return Carrier_->Cancel();
    }

    auto DatagramWire::Close() const -> Prism::Transmission::ControlResult
    {
        return Carrier_->Close();
    }

    DatagramWire::DatagramWire(std::shared_ptr<Prism::Trojan::Dgram<>> Carrier)
        : Carrier_(std::move(Carrier))
    {
    }

} // namespace Prism::Trojan::Detail

namespace Prism::Trojan
{

    auto DatagramSession::Create(std::shared_ptr<Prism::Trojan::Dgram<>> Carrier,
        Options OptionsValue)
        -> std::expected<std::shared_ptr<DatagramSession>, Prism::Fault::Failure>
    {
        if (!Carrier)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Wire = Detail::DatagramWire(std::move(Carrier));
        return std::shared_ptr<DatagramSession>(
            new DatagramSession(std::move(Wire), std::move(OptionsValue)));
    }

    DatagramSession::DatagramSession(Detail::DatagramWire Wire, Options OptionsValue)
        : Relay(std::move(Wire), std::move(OptionsValue))
    {
    }

} // namespace Prism::Trojan

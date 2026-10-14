/** @file DatagramSession.hpp @brief Trojan 协议拥有的数据报帧与 UDP 交换。 */
#pragma once
#include <Preview/Protocols/Trojan/Detail/Target.hpp>
#include <Preview/Protocols/Trojan/Dgram.hpp>
#include <Preview/Protocols/Common/DatagramRelay.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <expected>
#include <vector>

namespace Preview::Trojan
{
    using Udp = boost::asio::ip::udp;
    struct DatagramWire final
    {
        static constexpr std::string_view ProtocolName{"Trojan"};
        std::shared_ptr<Preview::Trojan::Dgram<>> Carrier;

        /** @brief 在 Run 前验证 carrier 与协议目标。 */
        [[nodiscard]] auto Validate() const noexcept -> Preview::Fault::Code
        {
            return Preview::Fault::Code::Success;
        }

        /** @brief 返回根 carrier 固定的 I/O executor。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Carrier->Executor();
        }

        /** @brief 解码 carrier 数据并写入 Packet；返回协议读取错误。 */
        [[nodiscard]] auto Receive(Preview::Protocols::DatagramPacket &Packet)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            Preview::Trojan::Address Target;
            const auto Result = co_await Carrier->AsyncReceiveFrom(Target, Packet.Payload);
            if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
            auto Value = Preview::Trojan::Detail::ToNetworkTarget(Target);
            if (!Value)
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::BadMessage});
            Packet.Target = std::move(*Value);
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        /** @brief 编码并发送 Source/载荷；载荷借用至 awaitable 返回。 */
        [[nodiscard]] auto Send(const Udp::endpoint &Source,
                                std::span<const std::uint8_t> Payload)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            const auto Type = Source.address().is_v4()
                                  ? Preview::Trojan::AddressType::Ipv4
                                  : Preview::Trojan::AddressType::Ipv6;
            Preview::Trojan::Address Address{
                Type, Source.address().to_string(), Source.port()};
            const auto Result = co_await Carrier->AsyncSendTo(Address, Payload);
            if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        /** @brief 快照根 Wire 与每个 NextLayer 的真实 Activity owner。 */
        [[nodiscard]] auto CarrierActivities() const
            -> std::vector<std::shared_ptr<Preview::Contract::CarrierActivity>>
        {
            return Preview::Protocols::CaptureDatagramCarrierActivities(*Carrier);
        }

        /** @brief 返回 typed 取消请求结果，拒绝不会被丢弃。 */
        [[nodiscard]] auto Cancel() const -> Preview::Transmission::ControlResult
        {
            return Carrier->Cancel();
        }

        /** @brief 返回 typed 关闭请求结果，拒绝不会被丢弃。 */
        [[nodiscard]] auto Close() const -> Preview::Transmission::ControlResult
        {
            return Carrier->Close();
        }
    };

    /** @brief 构造接管已认证载体；取消与最终关闭由本协议会话负责。 */
    class DatagramSession final : public Preview::Protocols::DatagramRelay<DatagramWire>
    {
    public:
        using Relay = Preview::Protocols::DatagramRelay<DatagramWire>;
        DatagramSession(DatagramWire Wire, Relay::Options Options)
            : Relay(std::move(Wire), std::move(Options)) {}
    };
}

/** @file DatagramSession.hpp @brief Vmess 协议拥有的数据报帧与 UDP 交换。 */
#pragma once
#include <Prism/Protocols/Vmess/Dgram.hpp>
#include <Prism/Protocols/Common/DatagramRelay.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <expected>
#include <vector>

namespace Prism::Vmess
{
    using Udp = boost::asio::ip::udp;
    struct DatagramWire final
    {
        static constexpr std::string_view ProtocolName{"Vmess"};
        std::shared_ptr<Prism::Vmess::Dgram<>> Carrier;
        Prism::Network::Target FixedTarget;

        /** @brief 在 Run 前验证 carrier 与协议目标。 */
        [[nodiscard]] auto Validate() const noexcept -> Prism::Fault::Code
        {
            if (FixedTarget.Host.Empty() || FixedTarget.Port == 0) return Prism::Fault::Code::InvalidArgument;
            return Prism::Fault::Code::Success;
        }

        /** @brief 返回根 carrier 固定的 I/O executor。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Carrier->Executor();
        }

        /** @brief 解码 carrier 数据并写入 Packet；返回协议读取错误。 */
        [[nodiscard]] auto Receive(Prism::Protocols::DatagramPacket &Packet)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            const auto Result = co_await Carrier->AsyncReceiveDatagram(Packet.Payload);
            if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
            Packet.Target = FixedTarget;
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 编码并发送载荷；载荷借用至 awaitable 返回。 */
        [[nodiscard]] auto Send(const Udp::endpoint &,
                                std::span<const std::uint8_t> Payload)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            const auto Result = co_await Carrier->AsyncSendDatagram(Payload);
            if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 快照根 Wire 与每个 NextLayer 的真实 Activity owner。 */
        [[nodiscard]] auto CarrierActivities() const
            -> std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>
        {
            return Prism::Protocols::CaptureDatagramCarrierActivities(*Carrier);
        }

        /** @brief 返回 typed 取消请求结果，拒绝不会被丢弃。 */
        [[nodiscard]] auto Cancel() const -> Prism::Transmission::ControlResult
        {
            return Carrier->Cancel();
        }

        /** @brief 返回 typed 关闭请求结果，拒绝不会被丢弃。 */
        [[nodiscard]] auto Close() const -> Prism::Transmission::ControlResult
        {
            return Carrier->Close();
        }
    };

    /** @brief 构造接管已认证载体；取消与最终关闭由本协议会话负责。 */
    class DatagramSession final : public Prism::Protocols::DatagramRelay<DatagramWire>
    {
    public:
        using Relay = Prism::Protocols::DatagramRelay<DatagramWire>;
        DatagramSession(DatagramWire Wire, Relay::Options Options)
            : Relay(std::move(Wire), std::move(Options)) {}
    };
}

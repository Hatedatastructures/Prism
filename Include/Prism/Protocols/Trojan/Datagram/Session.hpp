/** @file Session.hpp @brief Trojan 协议拥有的数据报帧与 UDP 交换。 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>

#include <Prism/Protocols/Trojan/Dgram.hpp>
#include <Prism/Protocols/Common/Datagram/Relay.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <expected>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>
#include <cstdint>

namespace Prism::Trojan
{
    using Udp = boost::asio::ip::udp;

    class DatagramSession;

    namespace Detail
    {
        struct DatagramWire final
        {
            static constexpr std::string_view ProtocolName{"Trojan"};

            DatagramWire(const DatagramWire &) = delete;
            auto operator=(const DatagramWire &) -> DatagramWire & = delete;
            DatagramWire(DatagramWire &&) noexcept = default;
            auto operator=(DatagramWire &&) -> DatagramWire & = delete;

            /** @brief 在创建公共数据面前验证必需的 carrier。 */
            [[nodiscard]] auto Validate() const noexcept -> Prism::Fault::Code;

            /** @brief 返回根 carrier 固定的 I/O executor。 */
            [[nodiscard]] auto Executor() const -> Net::any_io_executor;

            /** @brief 解码 carrier 数据并写入 Packet；返回协议读取错误。 */
            [[nodiscard]] auto Receive(Prism::Protocols::DatagramPacket &Packet)
                -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

            /** @brief 编码并发送 Source/载荷；载荷借用至 awaitable 返回。 */
            [[nodiscard]] auto Send(const Udp::endpoint &Source,
                                    std::span<const std::uint8_t> Payload)
                -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

            /** @brief 快照根 Wire 与每个 NextLayer 的真实 Activity owner。 */
            [[nodiscard]] auto CarrierActivities() const
                -> std::vector<std::shared_ptr<Prism::Contract::CarrierActivity>>;

            /** @brief 返回 typed 取消请求结果，拒绝不会被丢弃。 */
            [[nodiscard]] auto Cancel() const -> Prism::Transmission::ControlResult;

            /** @brief 返回 typed 关闭请求结果，拒绝不会被丢弃。 */
            [[nodiscard]] auto Close() const -> Prism::Transmission::ControlResult;

        private:
            friend class ::Prism::Trojan::DatagramSession;

            explicit DatagramWire(std::shared_ptr<Prism::Trojan::Dgram<>> Carrier);

            std::shared_ptr<Prism::Trojan::Dgram<>> Carrier_;
        };
    } // namespace Detail

    /** @brief 接管 Trojan UDP carrier，并在 pump 构造前验证非空。 */
    class DatagramSession final
        : public Prism::Protocols::DatagramRelay<Detail::DatagramWire>
    {
        using Relay = Prism::Protocols::DatagramRelay<Detail::DatagramWire>;

    public:
        using Options = Prism::Protocols::DatagramRelayOptions;

        /** @brief 创建 Trojan UDP 会话；空 carrier 在创建 pump 前 typed 拒绝。 */
        [[nodiscard]] static auto Create(
            std::shared_ptr<Prism::Trojan::Dgram<>> Carrier,
            Options OptionsValue)
            -> std::expected<std::shared_ptr<DatagramSession>, Prism::Fault::Failure>;

    private:
        DatagramSession(Detail::DatagramWire Wire, Options OptionsValue);
    };
}

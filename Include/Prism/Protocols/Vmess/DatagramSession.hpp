/** @file DatagramSession.hpp @brief Vmess 协议拥有的数据报帧与 UDP 交换。 */
#pragma once
#include <Prism/Net/Target.hpp>
#include <Prism/Protocols/Vmess/Dgram.hpp>
#include <Prism/Protocols/Common/DatagramRelay.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <expected>
#include <vector>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <utility>

namespace Prism::Vmess
{
    using Udp = boost::asio::ip::udp;
    class DatagramWire final
    {
    public:
        static constexpr std::string_view ProtocolName{"Vmess"};

        DatagramWire(const DatagramWire&) = delete;
        auto operator=(const DatagramWire&) -> DatagramWire& = delete;
        /** @brief 移动转移 carrier；executor 快照仍留在源对象供 Pump 安全校验。 */
        DatagramWire(DatagramWire&& Other);
        auto operator=(DatagramWire&&) -> DatagramWire& = delete;

        /**
         * @brief 在进入 Relay/Pump 前拒绝空或已 Release 的 carrier；目标合法性留给 Run。
         * @param Carrier 必须非空且仍持有底层 stream；按值获取一份共享所有权。
         * @note 如需在失败后继续使用 Carrier，请以左值传入；传入 std::move 会消费调用方引用。
         */
        [[nodiscard]] static auto Create(
            std::shared_ptr<Prism::Vmess::Dgram<>> Carrier,
            Prism::Network::Target FixedTarget)
            -> std::expected<DatagramWire, Prism::Fault::Failure>;

        /** @brief 在 Run 前验证 carrier 与协议目标。 */
        [[nodiscard]] auto Validate() const noexcept -> Prism::Fault::Code;

        /** @brief 返回根 carrier 固定的 I/O executor。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor;

        /** @brief 解码 carrier 数据并写入 Packet；返回协议读取错误。 */
        [[nodiscard]] auto Receive(Prism::Protocols::DatagramPacket &Packet)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        /** @brief 编码并发送载荷；载荷借用至 awaitable 返回。 */
        [[nodiscard]] auto Send(const Udp::endpoint &,
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
        DatagramWire(
            std::shared_ptr<Prism::Vmess::Dgram<>> Carrier,
            Prism::Network::Target FixedTarget,
            Net::any_io_executor Executor);

        Net::any_io_executor Executor_;
        Prism::Network::Target FixedTarget_;
        std::shared_ptr<Prism::Vmess::Dgram<>> Carrier_;
    };

    /** @brief 构造接管已认证载体；取消与最终关闭由本协议会话负责。 */
    class DatagramSession final : public Prism::Protocols::DatagramRelay<DatagramWire>
    {
        using Relay = Prism::Protocols::DatagramRelay<DatagramWire>;

    public:
        using Options = Prism::Protocols::DatagramRelayOptions;

        /**
         * @brief 校验 carrier 并创建 Wire，目标检查和退休留在 Run 路径。
         * @param Carrier 必须非空且仍持有底层 stream；按值获取一份共享所有权。
         * @note 如需在失败后继续使用 Carrier，请以左值传入；传入 std::move 会消费调用方引用。
         */
        [[nodiscard]] static auto Create(
            std::shared_ptr<Prism::Vmess::Dgram<>> Carrier,
            Prism::Network::Target FixedTarget,
            Options OptionsValue)
            -> std::expected<std::shared_ptr<DatagramSession>, Prism::Fault::Failure>;

    private:
        DatagramSession(DatagramWire Wire, Options OptionsValue);
    };
}

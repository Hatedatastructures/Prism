/**
 * @file handler.hpp
 * @brief Hysteria2 协议处理器
 * @details 处理单条已认证 QUIC 流：
 *          TCP：解析 0x401 请求帧 → 拨号 → 双向转发
 *          UDP：持续解析 UDP 消息 → 本地 UDP 中继
 */

#pragma once

#include <prism/protocol/handler.hpp>

namespace psm::protocol::hysteria2
{

    /**
     * @class handler
     * @brief Hysteria2 单流处理器
     */
    class handler final : public psm::protocol::protocol_handler
    {
    public:
        explicit handler(psm::protocol::handler_params params);

        auto run() -> net::awaitable<void> override;

    private:
        auto handle_udp(psm::transport::shared_transmission inbound, std::span<const std::byte> head)
            -> net::awaitable<void>;

        psm::resource::session &res_;
        std::span<const std::byte> data_;
    };

} // namespace psm::protocol::hysteria2

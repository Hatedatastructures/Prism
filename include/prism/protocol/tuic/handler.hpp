/**
 * @file handler.hpp
 * @brief TUIC v5 协议处理器
 * @details Connect 流：解析 Connect 帧 → 拨号 → 双向转发
 */

#pragma once

#include <prism/protocol/handler.hpp>

namespace psm::protocol::tuic
{

    /**
     * @class handler
     * @brief TUIC v5 Connect 流处理器
     */
    class handler final : public psm::protocol::protocol_handler
    {
    public:
        explicit handler(psm::protocol::handler_params params);

        auto run() -> net::awaitable<void> override;

    private:
        psm::resource::session &res_;
        std::span<const std::byte> data_;
    };

    /**
     * @class udp_handler
     * @brief TUIC v5 UDP 通道处理器（stream 0）
     * @details 双向 Packet 帧中继：assoc_id → UDP socket
     */
    class udp_handler final : public psm::protocol::protocol_handler
    {
    public:
        explicit udp_handler(psm::protocol::handler_params params);

        auto run() -> net::awaitable<void> override;

    private:
        psm::resource::session &res_;
        std::span<const std::byte> data_;
    };

} // namespace psm::protocol::tuic

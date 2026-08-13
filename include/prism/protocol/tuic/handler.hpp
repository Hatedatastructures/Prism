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
        /**
         * @brief 构造函数
         * @param params 协议处理器参数（会话资源 + 预读数据）
         */
        explicit handler(psm::protocol::handler_params params);

        /**
         * @brief 执行 TUIC v5 Connect 流处理（解析 Connect 帧 → 拨号 → 双向转发）
         * @return 异步操作
         */
        auto run() -> net::awaitable<void> override;

    private:
        psm::resource::session &res_;     ///< 会话资源（含 worker 级 + session 级）
        std::span<const std::byte> data_; ///< 预读数据
    };

    /**
     * @class udp_handler
     * @brief TUIC v5 UDP 通道处理器（stream 0）
     * @details 双向 Packet 帧中继：assoc_id → UDP socket
     */
    class udp_handler final : public psm::protocol::protocol_handler
    {
    public:
        /**
         * @brief 构造函数
         * @param params 协议处理器参数（会话资源 + 预读数据）
         */
        explicit udp_handler(psm::protocol::handler_params params);

        /**
         * @brief 执行 UDP 通道处理（双向 Packet 帧中继：assoc_id → UDP socket）
         * @return 异步操作
         */
        auto run() -> net::awaitable<void> override;

    private:
        psm::resource::session &res_;     ///< 会话资源（含 worker 级 + session 级）
        std::span<const std::byte> data_; ///< 预读数据
    };

} // namespace psm::protocol::tuic

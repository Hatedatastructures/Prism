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
        /**
         * @brief 构造函数
         * @param params 协议处理器参数（会话资源 + 预读数据）
         */
        explicit handler(psm::protocol::handler_params params);

        /**
         * @brief 执行 Hysteria2 协议处理（解析请求帧 → 拨号 → 双向转发）
         * @return 异步操作
         */
        auto run() -> net::awaitable<void> override;

    private:
        /**
         * @brief 处理 UDP 流（持续解析 UDP 消息 → 本地 UDP 中继）
         * @param inbound 入站传输层
         * @param head 预读头部数据
         * @return 异步操作
         */
        auto handle_udp(psm::transport::shared_transmission inbound, std::span<const std::byte> head)
            -> net::awaitable<void>;

        psm::resource::session &res_;     ///< 会话资源（含 worker 级 + session 级）
        std::span<const std::byte> data_; ///< 预读数据
    };

} // namespace psm::protocol::hysteria2

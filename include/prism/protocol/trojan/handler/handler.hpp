/**
 * @file handler.hpp
 * @brief Trojan 协议处理器
 */

#pragma once

#include <prism/protocol/handler.hpp>

namespace psm::protocol::trojan
{
    /**
     * @class handler
     * @brief Trojan 代理协议处理器
     */
    class handler final : public protocol_handler
    {
    public:
        /**
         * @brief 构造函数
         * @param params 协议处理器参数（会话资源 + 预读数据）
         */
        explicit handler(protocol::handler_params params) noexcept;

        /**
         * @brief 执行 Trojan 协议处理（握手 → 解析目标 → 拨号 → 隧道转发）
         * @return 异步操作
         */
        auto run() -> net::awaitable<void> override;

    private:
        psm::resource::session &res_;     ///< 会话资源（含 worker 级 + session 级）
        std::span<const std::byte> data_; ///< 预读数据
    };
} // namespace psm::protocol::trojan

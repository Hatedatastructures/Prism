/**
 * @file scheme.hpp
 * @brief WebSocket 伪装方案
 */

#pragma once

#include <prism/handshake/scheme.hpp>
#include <prism/handshake/ws/config.hpp>

namespace psm::handshake::ws
{

    /**
     * @class scheme
     * @brief WebSocket 传输伪装方案
     * @details TLS + HTTP/1.1 升级（WebSocket）。SNI 路由命中后：
     *          TLS 握手 → 解析 HTTP GET 请求（Upgrade: websocket）→
     *          响应 101 → 建立 WS 帧传输 → executor 二次探测内层协议。
     */
    class scheme final : public psm::handshake::scheme
    {
    public:
        /**
         * @brief 获取方案名称
         * @return 方案名称（"ws"）
         */
        [[nodiscard]] auto name() const noexcept -> std::string_view override;

        /**
         * @brief 判断此方案是否在当前配置下启用
         * @param cfg 服务器配置
         * @return 是否启用
         */
        [[nodiscard]] auto active(const psm::settings &cfg) const noexcept -> bool override;

        /**
         * @brief 获取 SNI 白名单
         * @param cfg 服务器配置
         * @return SNI 名称列表
         */
        [[nodiscard]] auto snis(const psm::settings &cfg) const -> memory::vector<memory::string> override;

        /**
         * @brief 获取检测层级
         * @return 2（Tier 2 模糊检测）
         */
        [[nodiscard]] auto tier() const noexcept -> std::uint8_t override
        {
            return 2;
        }

        /**
         * @brief 模糊检测（Tier 2）
         * @param cfg 服务器配置
         * @return 模糊检测结果（返回权重分）
         */
        [[nodiscard]] auto guess(const psm::settings &cfg) const -> verify_result override;

        /**
         * @brief 执行 WebSocket 握手
         * @param ctx 执行上下文（传输层、预读数据、配置）
         * @return 执行结果
         * @details TLS 握手 → 解析 HTTP GET 请求（Upgrade: websocket）→
         * 响应 101 → 建立 WS 帧传输 → executor 二次探测内层协议。
         */
        [[nodiscard]] auto handshake(handshake::handshake_context ctx)
            -> net::awaitable<handshake::handshake_result> override;
    };

} // namespace psm::handshake::ws

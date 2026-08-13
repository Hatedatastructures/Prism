/**
 * @file scheme.hpp
 * @brief gRPC (gun) 伪装方案
 */

#pragma once

#include <prism/handshake/gun/config.hpp>
#include <prism/handshake/scheme.hpp>

namespace psm::handshake::gun
{

    /**
     * @class scheme
     * @brief gRPC (gun) 传输伪装方案
     * @details TLS + HTTP/2 + gRPC 帧伪装。SNI 路由命中后：
     *          TLS 握手（ALPN h2）→ HTTP/2 会话 → 匹配 POST /GunService/Tun
     *          → 提取双向流（gun 帧编解码）→ 交由 executor 二次探测内层协议。
     */
    class scheme final : public psm::handshake::scheme
    {
    public:
        /**
         * @brief 获取方案名称
         * @return 方案名称（"gun"）
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
         * @brief 执行 gun 握手
         * @param ctx 执行上下文（传输层、预读数据、配置）
         * @return 执行结果
         * @details TLS 握手（ALPN h2）→ HTTP/2 会话 → 匹配 POST /GunService/Tun
         * → 提取双向流（gun 帧编解码）→ 交由 executor 二次探测内层协议。
         */
        [[nodiscard]] auto handshake(handshake::handshake_context ctx)
            -> net::awaitable<handshake::handshake_result> override;
    };

} // namespace psm::handshake::gun

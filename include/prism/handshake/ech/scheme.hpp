/**
 * @file scheme.hpp
 * @brief ECH 伪装方案（TLS 扩展层）
 */

#pragma once

#include <prism/handshake/ech/config.hpp>
#include <prism/handshake/scheme.hpp>

namespace psm::handshake::ech
{

    /**
     * @class scheme
     * @brief ECH 传输伪装方案
     * @details Tier 1：检测 ClientHello 是否携带 ECH 扩展（0xfe0d）。
     *          handshake：使用带 ECH 密钥的独立 SSL_CTX 完成 TLS 握手，
     *          BoringSSL 自动解密 inner ClientHello，返回加密传输层
     *          交由 executor 二次探测内层协议。
     */
    class scheme final : public psm::handshake::scheme
    {
    public:
        /**
         * @brief 获取方案名称
         * @return 方案名称（"ech"）
         */
        [[nodiscard]] auto name() const noexcept -> std::string_view override;

        /**
         * @brief 判断此方案是否在当前配置下启用
         * @param cfg 服务器配置
         * @return 是否启用（配置了 ech_key 时启用）
         */
        [[nodiscard]] auto active(const psm::settings &cfg) const noexcept -> bool override;

        /**
         * @brief 获取检测层级
         * @return 1（Tier 1 详细检测）
         */
        [[nodiscard]] auto tier() const noexcept -> std::uint8_t override
        {
            return 1;
        }

        /**
         * @brief 详细检测（Tier 1）
         * @param features ClientHello 特征结构
         * @param raw 原始 ClientHello 字节
         * @param cfg 服务器配置
         * @return 详细检测结果
         * @details 检测 ClientHello 是否携带 ECH 扩展（0xfe0d）。
         */
        [[nodiscard]] auto verify(const hello_features &features, std::span<const std::byte> raw,
                                  const psm::settings &cfg) const -> verify_result override;

        /**
         * @brief 执行 ECH 握手
         * @param ctx 执行上下文（传输层、预读数据、配置）
         * @return 执行结果
         * @details 使用带 ECH 密钥的独立 SSL_CTX 完成 TLS 握手，
         * BoringSSL 自动解密 inner ClientHello，返回加密传输层交由
         * executor 二次探测内层协议。
         */
        [[nodiscard]] auto handshake(handshake::handshake_context ctx)
            -> net::awaitable<handshake::handshake_result> override;
    };

} // namespace psm::handshake::ech

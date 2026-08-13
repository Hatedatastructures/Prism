/**
 * @file scheme.hpp
 * @brief ShadowTLS v3 伪装方案
 * @details 封装 ShadowTLS 握手和协议检测逻辑，继承 scheme 基类。
 * ShadowTLS 是 Tier 1 方案，需要 HMAC 验证确认身份。
 */
#pragma once

#include <prism/handshake/scheme.hpp>
#include <prism/settings/settings.hpp>

namespace psm::handshake::shadowtls
{

    /**
     * @class scheme
     * @brief ShadowTLS v3 伪装方案
     * @details ShadowTLS 是 Tier 1 方案，需要 HMAC 验证确认身份，
     * 通过 sniff 快速筛查 + verify 有成本验证的流程确认连接。
     */
    class scheme final : public handshake::scheme
    {
    public:
        // === 基本信息 ===
        /**
         * @brief 获取方案名称
         * @return 方案名称（"shadowtls"）
         */
        [[nodiscard]] auto name() const noexcept -> std::string_view override;
        /**
         * @brief 获取检测层级
         * @return 1（Tier 1 详细检测）
         */
        [[nodiscard]] auto tier() const noexcept -> std::uint8_t override
        {
            return 1;
        }
        /**
         * @brief 是否有独占特征
         * @return false（无独占特征）
         */
        [[nodiscard]] auto unique() const noexcept -> bool override
        {
            return false;
        }

        // === 配置检查 ===
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

        // === Tier 0: 快速检测 ===
        /**
         * @brief 快速检测（零成本，Tier 0）
         * @param bitmap 特征位图
         * @param features ClientHello 特征结构
         * @return 快速检测结果
         */
        [[nodiscard]] auto sniff(std::uint32_t bitmap, const hello_features &features) const
            -> sniff_result override;

        // === Tier 1: 详细检测（HMAC 验证）===
        /**
         * @brief 详细检测（有成本，Tier 1）
         * @param features ClientHello 特征结构
         * @param raw 原始 ClientHello 字节
         * @param cfg 服务器配置
         * @return 详细检测结果
         * @details 通过 HMAC 验证确认 ShadowTLS 身份。
         */
        [[nodiscard]] auto verify(const hello_features &features, std::span<const std::byte> raw,
                                  const psm::settings &cfg) const -> verify_result override;

        // === 执行 ===
        /**
         * @brief 执行 ShadowTLS 握手
         * @param ctx 执行上下文（传输层、预读数据、配置）
         * @return 执行结果
         */
        [[nodiscard]] auto handshake(handshake::handshake_context ctx)
            -> net::awaitable<handshake::handshake_result> override;

    protected:
        /**
         * @brief 获取权重分
         * @return 权重值（100）
         */
        [[nodiscard]] auto weight() const noexcept -> std::uint16_t override
        {
            return 100;
        }
    };
} // namespace psm::handshake::shadowtls
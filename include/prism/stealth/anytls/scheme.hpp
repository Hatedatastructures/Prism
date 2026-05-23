/**
 * @file scheme.hpp
 * @brief AnyTLS 伪装方案类
 * @details 实现 stealth_scheme 接口，用于在 TLS 方案管道中处理 AnyTLS 连接。
 * AnyTLS 是 Tier 2 方案，无 ClientHello 独占特征，依赖 SNI 匹配。
 * 可叠加 ECH 加密 ClientHello SNI。
 */
#pragma once

#include <prism/stealth/scheme.hpp>
#include <prism/stealth/anytls/config.hpp>

namespace psm::stealth::anytls
{
    /**
     * @class scheme
     * @brief AnyTLS 伪装方案实现
     * @details AnyTLS 使用标准 TLS 证书，通过应用层认证实现代理功能。
     * 服务端在 TLS 握手完成后，从 TLS 应用数据中读取认证信息。
     *
     * **工作流程**：
     * 1. 执行标准 TLS 握手（使用配置的证书）
     * 2. 读取 TLS 应用数据（客户端首帧）
     * 3. 解析 AnyTLS 认证帧，验证用户身份
     * 4. 认证成功后，检测内层协议
     *
     * **ECH 支持**：
     * - 如果配置了 ech_key，可以叠加 ECH 加密
     * - ECH 解密在 Tier 1 的 verify 中执行
     */
    class scheme final : public stealth_scheme
    {
    public:
        // === 基本信息 ===
        [[nodiscard]] auto name() const noexcept
            -> std::string_view override;
        [[nodiscard]] auto tier() const noexcept
            -> std::uint8_t override { return 2; }
        [[nodiscard]] auto unique() const noexcept
            -> bool override { return false; }

        // === 配置检查 ===
        [[nodiscard]] auto active(const psm::config &cfg) const noexcept
            -> bool override;
        [[nodiscard]] auto snis(const psm::config &cfg) const
            -> memory::vector<memory::string> override;

        // === Tier 1: 详细检测（ECH 解密）===
        [[nodiscard]] auto verify(const hello_features &features, std::span<const std::byte> raw, const psm::config &cfg) const
            -> verify_result override;

        // === Tier 2: 模糊检测 ===
        [[nodiscard]] auto guess(const psm::config &cfg) const
            -> verify_result override;

        // === 执行 ===
        [[nodiscard]] auto handshake(stealth::handshake_context ctx)
            -> net::awaitable<stealth::handshake_result> override;

    protected:
        [[nodiscard]] auto weight() const noexcept
            -> std::uint16_t override { return 100; }
    };
} // namespace psm::stealth::anytls
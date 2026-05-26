/**
 * @file scheme.hpp
 * @brief TrustTunnel 伪装方案类
 * @details 实现 stealth_scheme 接口，用于在 TLS 方案管道中处理 TrustTunnel 连接。
 * TrustTunnel 是 Tier 2 方案，无 ClientHello 独占特征，依赖 SNI 匹配。
 * 支持 TCP（HTTP/2）和 UDP（HTTP/3/QUIC）两种传输模式。
 */
#pragma once

#include <prism/stealth/scheme.hpp>
#include <prism/stealth/trusttunnel/config.hpp>


namespace psm::stealth::trusttunnel
{

    /**
     * @class scheme
     * @brief TrustTunnel 伪装方案实现
     * @details TrustTunnel 使用标准 TLS 证书，支持 TCP 和 UDP 传输。
     *
     * 工作流程：
     * 1. 执行标准 TLS 握手（使用配置的证书）
     * 2. 读取 TLS 应用数据（客户端首帧）
     * 3. 验证用户身份
     * 4. 根据网络配置选择传输模式
     * 5. 认证成功后检测内层协议
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
} // namespace psm::stealth::trusttunnel
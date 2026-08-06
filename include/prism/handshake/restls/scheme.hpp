/**
 * @file scheme.hpp
 * @brief Restls 伪装方案类
 * @details 实现 scheme 接口，用于在 TLS 方案管道中处理 Restls 连接。
 * Restls 是 Tier 2 方案，无 ClientHello 独占特征，依赖 SNI 匹配。
 */
#pragma once

#include <prism/handshake/restls/config.hpp>
#include <prism/handshake/scheme.hpp>


namespace psm::handshake::restls
{

    /**
     * @class scheme
     * @brief Restls 伪装方案实现
     * @details Restls 通过模拟真实 TLS 流量来隐藏代理特征。
     * 服务端与后端 TLS 服务器建立连接，在 TLS 应用数据中嵌入认证信息。
     *
     * 工作流程：
     * 1. 读取客户端 TLS ClientHello
     * 2. 建立到后端 TLS 服务器的连接
     * 3. 在 TLS 应用数据中验证客户端身份
     * 4. 认证成功后，使用 restls-script 控制流量模式
     */
    class scheme final : public handshake::scheme
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
        [[nodiscard]] auto active(const psm::settings &cfg) const noexcept
            -> bool override;
        [[nodiscard]] auto snis(const psm::settings &cfg) const
            -> memory::vector<memory::string> override;

        // === Tier 2: 模糊检测 ===
        [[nodiscard]] auto guess(const psm::settings &cfg) const
            -> verify_result override;

        // === 执行 ===
        [[nodiscard]] auto handshake(handshake::handshake_context ctx)
            -> net::awaitable<handshake::handshake_result> override;

    protected:
        [[nodiscard]] auto weight() const noexcept
            -> std::uint16_t override { return 100; }
    };
} // namespace psm::handshake::restls
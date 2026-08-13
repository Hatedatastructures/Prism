/**
 * @file scheme.hpp
 * @brief TrustTunnel 伪装方案类
 * @details 实现 scheme 接口，用于在 TLS 方案管道中处理 TrustTunnel 连接。
 * TrustTunnel 是 Tier 2 方案，无 ClientHello 独占特征，依赖 SNI 匹配。
 * 支持 TCP（HTTP/2）和 UDP（HTTP/3/QUIC）两种传输模式。
 */
#pragma once

#include <prism/handshake/scheme.hpp>
#include <prism/handshake/trusttunnel/config.hpp>

namespace psm::handshake::trusttunnel
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
    class scheme final : public handshake::scheme
    {
    public:
        // === 基本信息 ===
        /**
         * @brief 获取方案名称
         * @return 方案名称（"trusttunnel"）
         */
        [[nodiscard]] auto name() const noexcept -> std::string_view override;
        /**
         * @brief 获取检测层级
         * @return 2（Tier 2 模糊检测）
         */
        [[nodiscard]] auto tier() const noexcept -> std::uint8_t override
        {
            return 2;
        }
        /**
         * @brief 是否有独占特征
         * @return false（无独占特征，依赖 SNI 匹配）
         */
        [[nodiscard]] auto unique() const noexcept -> bool override
        {
            return false;
        }

        // === 分类 ===
        /**
         * @brief 获取方案执行分类
         * @return scheme_category::stack（内部管理流，executor 收到即终止）
         */
        [[nodiscard]] auto category() const noexcept -> scheme_category override
        {
            return scheme_category::stack;
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

        // === Tier 2: 模糊检测 ===
        /**
         * @brief 模糊检测（Tier 2）
         * @param cfg 服务器配置
         * @return 模糊检测结果（返回权重分）
         */
        [[nodiscard]] auto guess(const psm::settings &cfg) const -> verify_result override;

        // === 执行 ===
        /**
         * @brief 执行 TrustTunnel 握手
         * @param ctx 执行上下文（传输层、预读数据、配置）
         * @return 执行结果
         * @details 完成 TLS 握手后验证用户身份，根据网络配置选择
         * TCP（HTTP/2）或 UDP（HTTP/3/QUIC）传输模式。
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
} // namespace psm::handshake::trusttunnel
/**
 * @file scheme.hpp
 * @brief AnyTLS 伪装方案类
 * @details 实现 scheme 接口，用于在 TLS 方案管道中处理 AnyTLS 连接。
 * AnyTLS 是 Tier 2 方案，无 ClientHello 独占特征，依赖 SNI 匹配。
 * 可叠加 ECH 加密 ClientHello SNI。
 */
#pragma once

#include <prism/handshake/anytls/config.hpp>
#include <prism/handshake/scheme.hpp>

namespace psm::handshake::anytls
{

    /**
     * @class scheme
     * @brief AnyTLS 伪装方案实现
     * @details AnyTLS 使用标准 TLS 证书，通过应用层认证实现代理功能。
     * 服务端在 TLS 握手完成后，从 TLS 应用数据中读取认证信息。
     *
     * 工作流程：
     * 1. 执行标准 TLS 握手（使用配置的证书）
     * 2. 读取 TLS 应用数据（客户端首帧）
     * 3. 解析 AnyTLS 认证帧，验证用户身份
     * 4. 认证成功后，检测内层协议
     *
     * ECH 支持：
     * 如果配置了 ech_key，可以叠加 ECH 加密
     * ECH 解密在 Tier 1 的 verify 中执行
     */
    class scheme final : public handshake::scheme
    {
    public:
        // === 基本信息 ===
        /**
         * @brief 获取方案名称
         * @return 方案名称（"anytls"）
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

        // === Tier 1: 详细检测（ECH 解密）===
        /**
         * @brief 详细检测（Tier 1）
         * @param features ClientHello 特征结构
         * @param raw 原始 ClientHello 字节
         * @param cfg 服务器配置
         * @return 详细检测结果
         * @details 配置了 ech_key 时执行 ECH 解密验证，否则不命中。
         */
        [[nodiscard]] auto verify(const hello_features &features, std::span<const std::byte> raw,
                                  const psm::settings &cfg) const -> verify_result override;

        // === Tier 2: 模糊检测 ===
        /**
         * @brief 模糊检测（Tier 2）
         * @param cfg 服务器配置
         * @return 模糊检测结果（返回权重分）
         */
        [[nodiscard]] auto guess(const psm::settings &cfg) const -> verify_result override;

        // === 执行 ===
        /**
         * @brief 执行 AnyTLS 握手
         * @param ctx 执行上下文（传输层、预读数据、配置）
         * @return 执行结果
         * @details 完成 TLS 握手后读取认证帧验证用户身份，成功后检测内层协议。
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
} // namespace psm::handshake::anytls
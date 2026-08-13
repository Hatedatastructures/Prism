/**
 * @file native.hpp
 * @brief 原生 TLS 伪装方案（兜底）
 * @details 封装标准 TLS 握手和内层协议检测，继承 scheme 基类。
 * Native 是 Tier 2 方案，作为兜底处理无法匹配其他方案的 TLS 连接。
 */
#pragma once

#include <prism/handshake/scheme.hpp>

namespace psm::handshake::native
{

    /**
     * @class native
     * @brief 原生 TLS 伪装方案（兜底）
     * @details 封装标准 TLS 握手和内层协议检测，作为 Tier 2 方案
     * 兜底处理无法匹配其他方案的 TLS 连接。无独占特征，无配置依赖。
     */
    class native final : public handshake::scheme
    {
    public:
        // === 基本信息 ===
        /**
         * @brief 获取方案名称
         * @return 方案名称（"native"）
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
         * @return false（无独占特征，不跳过其他方案）
         */
        [[nodiscard]] auto unique() const noexcept -> bool override
        {
            return false;
        }

        // === 配置检查 ===
        /**
         * @brief 判断此方案是否在当前配置下启用
         * @param cfg 服务器配置
         * @return 是否启用（native 始终启用）
         */
        [[nodiscard]] auto active(const psm::settings &cfg) const noexcept -> bool override;

        // === Tier 2: 模糊检测 ===
        /**
         * @brief 模糊检测（Tier 2）
         * @param cfg 服务器配置
         * @return 检测结果（返回权重分）
         */
        [[nodiscard]] auto guess(const psm::settings &cfg) const -> verify_result override;

        // === 执行 ===
        /**
         * @brief 执行原生 TLS 握手
         * @param ctx 执行上下文（传输层、预读数据、配置）
         * @return 执行结果
         */
        [[nodiscard]] auto handshake(handshake::handshake_context ctx)
            -> net::awaitable<handshake::handshake_result> override;

    protected:
        /**
         * @brief 获取权重分
         * @return 权重值（50）
         */
        [[nodiscard]] auto weight() const noexcept -> std::uint16_t override
        {
            return 50;
        }
    };
} // namespace psm::handshake::native
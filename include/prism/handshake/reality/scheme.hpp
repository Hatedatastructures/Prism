/**
 * @file scheme.hpp
 * @brief Reality 伪装方案类
 * @details 封装 Reality TLS 握手和协议检测逻辑，继承 scheme 基类。
 * Reality 是 Tier 0 方案，有独占特征（session_id 标记）。
 */
#pragma once

#include <prism/handshake/scheme.hpp>
#include <prism/settings/settings.hpp>

namespace psm::handshake::reality
{

    /**
     * @class scheme
     * @brief Reality 伪装方案
     * @details Reality 是 Tier 0 方案，有独占特征（session_id 标记），
     * 通过零成本字节比较即可命中，无需 verify/guess。
     */
    class scheme final : public handshake::scheme
    {
    public:
        // === 基本信息 ===
        /**
         * @brief 获取方案名称
         * @return 方案名称（"reality"）
         */
        [[nodiscard]] auto name() const noexcept -> std::string_view override;
        /**
         * @brief 获取检测层级
         * @return 0（Tier 0 快速检测）
         */
        [[nodiscard]] auto tier() const noexcept -> std::uint8_t override
        {
            return 0;
        }
        /**
         * @brief 是否有独占特征
         * @return true（session_id 标记独占，命中即跳过其他方案）
         */
        [[nodiscard]] auto unique() const noexcept -> bool override
        {
            return true;
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
         * @details 检查 session_id 标记（[0x01, 0x08, 0x02] 前缀）。
         */
        [[nodiscard]] auto sniff(std::uint32_t bitmap, const hello_features &features) const
            -> sniff_result override;

        // === Tier 1/2: 使用默认实现 ===
        // Reality 不需要 verify 和 guess

        // === 执行 ===
        /**
         * @brief 执行 Reality 握手
         * @param ctx 执行上下文（传输层、预读数据、配置）
         * @return 执行结果
         */
        [[nodiscard]] auto handshake(handshake::handshake_context ctx)
            -> net::awaitable<handshake::handshake_result> override;

        /**
         * @brief RFC-065: Reality 挑战-响应(默认实现,后续 GREASE 扩展完善)
         * @param ctx 执行上下文（传输层、预读数据、配置）
         * @return 挑战结果
         */
        [[nodiscard]] auto challenge(handshake::handshake_context ctx)
            -> net::awaitable<challenge_result> override;

    protected:
        /**
         * @brief 获取权重分
         * @return 权重值（450）
         */
        [[nodiscard]] auto weight() const noexcept -> std::uint16_t override
        {
            return 450;
        }
    };
} // namespace psm::handshake::reality
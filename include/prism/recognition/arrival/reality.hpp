/**
 * @file reality.hpp
 * @brief Reality 方案特征分析器
 * @details 检测 Reality 的 ClientHello 特征：SNI 匹配 + 32字节 session_id + X25519 key_share。
 */

#pragma once

#include <prism/recognition/arrival/feature.hpp>

namespace psm::recognition::arrival
{
    /**
     * @class reality
     * @brief Reality 方案特征分析器
     * @details 检测 Reality 的 ClientHello 特征：
     * 1. SNI 匹配 server_names 配置
     * 2. session_id 长度为 32 字节（Reality 使用固定长度）
     * 3. 存在 X25519 key_share 扩展
     *
     * **置信度判定**：
     * - high: SNI 匹配 + 32字节 session_id + X25519 key_share（完整 Reality 特征）
     * - medium: SNI 匹配 + X25519 key_share（session_id 短，可能是 Reality）
     * - low: SNI 匹配（可能是 Reality 客户端配置不完整）
     * - none: SNI 不匹配（不是 Reality）
     *
     * **性能优化**：
     * - 仅检查 SNI 和特征，不做任何 I/O
     * - 可直接复用已解析的 arrival_features
     * - 判断成本约 1-2 次字符串比较
     */
    class reality final : public feature
    {
    public:
        /**
         * @brief 分析器名称
         * @return "reality"
         */
        [[nodiscard]] auto name() const noexcept -> std::string_view override
        {
            return "reality";
        }

        /**
         * @brief 分析 ClientHello 特征判断 Reality 置信度
         * @param features 已提取的 ClientHello 特征
         * @param cfg 全局配置
         * @return 置信度判定
         */
        [[nodiscard]] auto analyze(const arrival_features &features,const config &cfg) const
        -> confidence override;

        /**
         * @brief 检查 Reality 方案是否启用
         * @param cfg 全局配置
         * @return 如果 cfg.stealth.reality.enabled() 返回 true
         */
        [[nodiscard]] auto is_enabled(const config &cfg) const noexcept -> bool override;

    private:
        /**
         * @brief 检查 SNI 是否匹配配置的 server_names
         * @param sni 客户端 SNI
         * @param server_names 配置的服务器名称列表
         * @return 如果匹配返回 true
         */
        [[nodiscard]] static auto check_sni_match(std::string_view sni,const memory::vector<memory::string> &server_names)
            -> bool;
    };
} // namespace psm::recognition::arrival
/**
 * @file anytls.hpp
 * @brief AnyTLS 特征分析器（预留）
 * @details AnyTLS 特征在握手后应用数据，ClientHello 中无明显特征。
 * 当前为预留接口，待后续实现。
 */

#pragma once

#include <prism/recognition/arrival/feature.hpp>

namespace psm::recognition::arrival
{
    /**
     * @class anytls
     * @brief AnyTLS 方案特征分析器（预留）
     * @details AnyTLS 特征：
     * - ClientHello 中无明显特征（与标准 TLS 相似）
     * - 认证信息在握手后应用数据的前 32 字节（password SHA256）
     *
     * **置信度判定**：
     * - none: ClientHello 中无法识别 AnyTLS
     * - AnyTLS 需在 handshake 层执行时检测
     *
     * **实现状态**：预留接口，AnyTLS 需在 stealth 模块实现 scheme，
     * 然后在 handshake::executor 中注册。
     */
    class anytls final : public feature
    {
    public:
        [[nodiscard]] auto name() const noexcept -> std::string_view override
        {
            return "anytls";
        }

        [[nodiscard]] auto analyze(
            [[maybe_unused]] const arrival_features &features,
            [[maybe_unused]] const psm::config &cfg) const -> confidence override
        {
            // AnyTLS 在 ClientHello 中无明显特征
            // 需要在握手后应用数据中检测（32 字节 password SHA256）
            return confidence::none;
        }

        [[nodiscard]] auto is_enabled(const config &cfg) const noexcept -> bool override
        {
            // AnyTLS 方案当前未实现，暂不启用
            // 未来实现后检查 cfg.stealth.anytls.enabled()
            return false;
        }
    };
} // namespace psm::recognition::arrival

// REGISTER_ARRIVAL(anytls)
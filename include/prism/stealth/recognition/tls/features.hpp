/**
 * @file features.hpp
 * @brief TLS ClientHello 特征位图
 * @details 将关键特征压缩为位图，支持快速位运算匹配。
 * 用于分层检测管道的 Layer 0 快速检测阶段。
 */

#pragma once

#include <prism/proto/protocol/tls/types.hpp>

#include <cstdint>


namespace psm::recognition::tls
{

    using hello_features = protocol::tls::hello_features;
    /**
     * @enum feature_bit
     * @brief TLS ClientHello 特征位
     * @details 每个位代表一个特征，支持位运算快速匹配
     */
    enum class feature_bit : std::uint32_t
    {
        has_sni = 1 << 0,
        sni_matched = 1 << 1,
        has_x25519 = 1 << 2,
        full_session = 1 << 3,
        reality_marker = 1 << 4,
        hmac_valid = 1 << 5,
        nonstd_session = 1 << 6,
        has_ech = 1 << 7,
        has_esni = 1 << 8,
        greased_extensions = 1 << 9,
        has_versions = 1 << 10,
        has_alpn = 1 << 11,
        has_psk = 1 << 12,
        has_sigalgs = 1 << 13,
        keyshare_multi = 1 << 14,
        early_data = 1 << 15,
        reserved_16 = 1 << 16,
        reserved_17 = 1 << 17,
        reserved_18 = 1 << 18,
        reserved_19 = 1 << 19,
        reserved_tail = 0xFFF00000
    };

    constexpr std::uint32_t& operator|=(std::uint32_t& lhs, feature_bit rhs) noexcept
    {
        lhs |= static_cast<std::uint32_t>(rhs);
        return lhs;
    }

    constexpr std::uint32_t operator|(feature_bit a, feature_bit b) noexcept
    {
        return static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b);
    }

    constexpr std::uint32_t operator|(std::uint32_t lhs, feature_bit rhs) noexcept
    {
        return lhs | static_cast<std::uint32_t>(rhs);
    }

    constexpr std::uint32_t operator|(feature_bit lhs, std::uint32_t rhs) noexcept
    {
        return static_cast<std::uint32_t>(lhs) | rhs;
    }

    constexpr std::uint32_t operator&(std::uint32_t lhs, feature_bit rhs) noexcept
    {
        return lhs & static_cast<std::uint32_t>(rhs);
    }

    /**
     * @brief 构建特征位图
     * @param features ClientHello 特征结构
     * @return 特征位图（32 位）
     * @note 不检查 SNI 是否匹配配置（sni_matched_config 位需要在路由阶段设置）
     */
    [[nodiscard]] inline auto build_bitmap(const hello_features &features) noexcept
        -> std::uint32_t
    {
        std::uint32_t bitmap = 0;

        if (!features.server_name.empty())
            bitmap |= feature_bit::has_sni;

        if (features.has_x25519)
            bitmap |= feature_bit::has_x25519;

        if (features.session_id_len == 32)
        {
            bitmap |= feature_bit::full_session;
        }
        else if (features.session_id_len > 0 && features.session_id_len != 32)
        {
            bitmap |= feature_bit::nonstd_session;
        }
        else if (!features.session_id.empty() && features.session_id_len != 32)
        {
            bitmap |= feature_bit::nonstd_session;
        }

        if (features.session_id.size() >= 3 &&
            features.session_id[0] == 0x01 &&
            features.session_id[1] == 0x08 &&
            features.session_id[2] == 0x02)
        {
            bitmap |= feature_bit::reality_marker;
        }

        if (!features.versions.empty())
            bitmap |= feature_bit::has_versions;

        if (features.has_ech)
            bitmap |= feature_bit::has_ech;

        return bitmap;
    }

    /**
     * @brief 检查位图中是否有指定特征
     * @param bitmap 特征位图
     * @param bit 要检查的特征位
     * @return 是否存在该特征
     */
    [[nodiscard]] inline auto has_feature(std::uint32_t bitmap, feature_bit bit) noexcept
        -> bool
    {
        return (bitmap & bit) != 0;
    }

    /**
     * @brief 检查位图中是否包含所有指定特征
     * @param bitmap 特征位图
     * @param bits 要检查的特征位组合
     * @return 是否全部存在
     */
    [[nodiscard]] inline auto has_all(std::uint32_t bitmap, std::uint32_t bits) noexcept
        -> bool
    {
        return (bitmap & bits) == bits;
    }

} // namespace psm::recognition::tls

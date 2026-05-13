/**
 * @file feature_bitmap.hpp
 * @brief TLS ClientHello 特征位图
 * @details 将关键特征压缩为位图，支持快速位运算匹配。
 * 用于分层检测管道的 Layer 0 快速检测阶段。
 */

#pragma once

#include <cstdint>
#include <prism/protocol/tls/types.hpp>

namespace psm::protocol::tls
{
    /**
     * @enum feature_bit
     * @brief TLS ClientHello 特征位
     * @details 每个位代表一个特征，支持位运算快速匹配
     */
    enum feature_bit : std::uint32_t
    {
        // ═══════════════════════════════════════════════════════════════════
        // 基础特征
        // ═══════════════════════════════════════════════════════════════════

        /** @brief 有 SNI 扩展 */
        has_sni = 1 << 0,

        /** @brief SNI 匹配配置中的 server_names（需要在路由阶段设置） */
        sni_matched_config = 1 << 1,

        /** @brief 有 X25519 key_share */
        has_x25519 = 1 << 2,

        /** @brief session_id_len == 32 */
        has_full_session_id = 1 << 3,

        // ═══════════════════════════════════════════════════════════════════
        // 确定性标记（独占特征）
        // ═══════════════════════════════════════════════════════════════════

        /** @brief Reality 独占标记: session_id[0:3] == [0x01, 0x08, 0x02] */
        reality_marker_01_08_02 = 1 << 4,

        /** @brief ShadowTLS HMAC 有效（需要 Layer 1 验证） */
        shadowtls_hmac_valid = 1 << 5,

        // ═══════════════════════════════════════════════════════════════════
        // 结构特征
        // ═══════════════════════════════════════════════════════════════════

        /** @brief session_id 长度非标准（!= 32） */
        session_id_non_standard = 1 << 6,

        /** @brief 有 ECH (Encrypted Client Hello) 扩展 */
        has_ech = 1 << 7,

        /** @brief 有 ESNI 扩展（旧版，已废弃） */
        has_esni = 1 << 8,

        /** @brief 有 GREASE 扩展（RFC 8701） */
        greased_extensions = 1 << 9,

        // ═══════════════════════════════════════════════════════════════════
        // 扩展组合
        // ═══════════════════════════════════════════════════════════════════

        /** @brief 有 supported_versions 扩展 */
        has_supported_versions = 1 << 10,

        /** @brief 有 ALPN 扩展 */
        has_alpn = 1 << 11,

        /** @brief 有 PSK 扩展 */
        has_psk = 1 << 12,

        /** @brief 有 signature_algorithms 扩展 */
        has_signature_algorithms = 1 << 13,

        // ═══════════════════════════════════════════════════════════════════
        // 高级特征
        // ═══════════════════════════════════════════════════════════════════

        /** @brief 有多个 key_share */
        key_share_multiple = 1 << 14,

        /** @brief 尝试 0-RTT early data */
        early_data_attempt = 1 << 15,

        // ═══════════════════════════════════════════════════════════════════
        // 保留位（16-31）
        // ═══════════════════════════════════════════════════════════════════

        /** @brief 保留位 16 */
        reserved_16 = 1 << 16,

        /** @brief 保留位 17 */
        reserved_17 = 1 << 17,

        /** @brief 保留位 18 */
        reserved_18 = 1 << 18,

        /** @brief 保留位 19 */
        reserved_19 = 1 << 19,

        /** @brief 保留位 20-31 */
        reserved_20_to_31 = 0xFFF00000
    };

    /**
     * @brief 构建特征位图
     * @param features ClientHello 特征结构
     * @return 特征位图（32 位）
     * @note 不检查 SNI 是否匹配配置（sni_matched_config 位需要在路由阶段设置）
     */
    [[nodiscard]] inline auto build_feature_bitmap(const client_hello_features &features) noexcept
        -> std::uint32_t
    {
        std::uint32_t bitmap = 0;

        // 基础特征
        if (!features.server_name.empty())
            bitmap |= has_sni;

        if (features.has_x25519)
            bitmap |= has_x25519;

        // session_id 相关特征
        // session_id_len == 32 → full session_id
        // session_id_len > 0 && != 32 → non-standard
        if (features.session_id_len == 32)
        {
            bitmap |= has_full_session_id;
        }
        else if (features.session_id_len > 0 && features.session_id_len != 32)
        {
            bitmap |= session_id_non_standard;
        }
        // 也检查 session_id vector（如果 vector 有数据但 len 不匹配）
        else if (!features.session_id.empty() && features.session_id_len != 32)
        {
            bitmap |= session_id_non_standard;
        }

        // Reality 独占标记检查
        // session_id[0] == 0x01, session_id[1] == 0x08, session_id[2] == 0x02
        if (features.session_id.size() >= 3 &&
            features.session_id[0] == 0x01 &&
            features.session_id[1] == 0x08 &&
            features.session_id[2] == 0x02)
        {
            bitmap |= reality_marker_01_08_02;
        }

        // 扩展存在检查（从 versions 判断 supported_versions）
        if (!features.versions.empty())
            bitmap |= has_supported_versions;

        return bitmap;
    }

    /**
     * @brief 检查位图中是否有指定特征
     * @param bitmap 特征位图
     * @param bit 要检查的特征位
     * @return 是否存在该特征
     */
    [[nodiscard]] inline auto has_feature(std::uint32_t bitmap, feature_bit bit) noexcept -> bool
    {
        return (bitmap & bit) != 0;
    }

    /**
     * @brief 检查位图中是否包含所有指定特征
     * @param bitmap 特征位图
     * @param bits 要检查的特征位组合
     * @return 是否全部存在
     */
    [[nodiscard]] inline auto has_all_features(std::uint32_t bitmap, std::uint32_t bits) noexcept -> bool
    {
        return (bitmap & bits) == bits;
    }

} // namespace psm::protocol::tls
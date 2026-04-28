/**
 * @file feature.hpp
 * @brief ClientHello 特征结构定义
 * @details 定义从 TLS ClientHello 提取的关键特征，供各方案分析器使用。
 */

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <prism/memory/container.hpp>

namespace psm::recognition
{
    /**
     * @struct arrival_features
     * @brief 从 ClientHello 提取的关键特征
     * @details 包含 SNI、session_id、key_share、支持的版本、ECH 等特征。
     * 各方案分析器可基于这些特征判断置信度。
     */
    struct arrival_features
    {
        /** @brief SNI 服务器名称 */
        memory::string server_name;

        /** @brief session_id 长度（0-32） */
        std::uint8_t session_id_len{0};

        /** @brief 是否存在 X25519 key_share 扩展 */
        bool has_x25519_key_share{false};

        /** @brief X25519 公钥（如果存在） */
        std::optional<std::array<std::uint8_t, 32>> x25519_public_key;

        /** @brief 支持的 TLS 版本列表 */
        memory::vector<std::uint16_t> supported_versions;

        /** @brief 是否存在 ECH 扩展（扩展类型 0xfe0d） */
        bool has_ech_extension{false};

        /** @brief ECH 配置 ID（如果存在） */
        std::optional<std::array<std::uint8_t, 8>> ech_config_id;

        /** @brief ALPN 协议列表 */
        memory::vector<memory::string> alpn_protocols;

        /** @brief 客户端随机数（32 字节） */
        std::array<std::uint8_t, 32> random{};

        /** @brief session_id 数据 */
        memory::vector<std::uint8_t> session_id;

        /** @brief 原始 ClientHello 记录（含 TLS record header） */
        memory::vector<std::byte> raw_arrival;

        /** @brief 原始握手消息（不含 TLS record header） */
        memory::vector<std::uint8_t> raw_handshake_message;
    };
} // namespace psm::recognition
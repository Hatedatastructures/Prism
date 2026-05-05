/**
 * @file types.hpp
 * @brief TLS 协议共享类型与常量
 * @details 定义 TLS 1.3 记录层和握手协议的通用常量，以及从 ClientHello
 * 提取的特征结构。这些类型是中立的共享层，供 recognition 和 stealth 模块
 * 共同使用，不依赖任何具体实现。
 * @note 遵循 RFC 8446 (TLS 1.3) 和 RFC 5246 (TLS 1.2) 的定义。
 */

#pragma once

#include <array>
#include <cstdint>
#include <prism/memory/container.hpp>

namespace psm::protocol::tls
{
    // ═══════════════════════════════════════════════════════════════════════
    // TLS 记录层常量
    // ═══════════════════════════════════════════════════════════════════════

    /** @brief TLS 记录头长度（字节）：ContentType(1) + Version(2) + Length(2) */
    constexpr std::size_t RECORD_HEADER_LEN = 5;

    /** @brief TLS 记录最大载荷长度 */
    constexpr std::size_t MAX_RECORD_PAYLOAD = 16384;

    // ═══════════════════════════════════════════════════════════════════════
    // Content Type
    // ═══════════════════════════════════════════════════════════════════════

    constexpr std::uint8_t CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14;
    constexpr std::uint8_t CONTENT_TYPE_ALERT = 0x15;
    constexpr std::uint8_t CONTENT_TYPE_HANDSHAKE = 0x16;
    constexpr std::uint8_t CONTENT_TYPE_APPLICATION_DATA = 0x17;

    // ═══════════════════════════════════════════════════════════════════════
    // Handshake Type
    // ═══════════════════════════════════════════════════════════════════════

    constexpr std::uint8_t HANDSHAKE_TYPE_CLIENT_HELLO = 0x01;
    constexpr std::uint8_t HANDSHAKE_TYPE_SERVER_HELLO = 0x02;
    constexpr std::uint8_t HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 0x08;
    constexpr std::uint8_t HANDSHAKE_TYPE_CERTIFICATE = 0x0B;
    constexpr std::uint8_t HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 0x0F;
    constexpr std::uint8_t HANDSHAKE_TYPE_FINISHED = 0x14;

    // ═══════════════════════════════════════════════════════════════════════
    // Extension Type
    // ═══════════════════════════════════════════════════════════════════════

    constexpr std::uint16_t EXT_SERVER_NAME = 0x0000;
    constexpr std::uint16_t EXT_KEY_SHARE = 0x0033;
    constexpr std::uint16_t EXT_SUPPORTED_VERSIONS = 0x002B;

    // ═══════════════════════════════════════════════════════════════════════
    // Named Groups
    // ═══════════════════════════════════════════════════════════════════════

    constexpr std::uint16_t NAMED_GROUP_X25519 = 0x001D;
    constexpr std::uint16_t NAMED_GROUP_X25519_MLKEM768 = 0x11EC;

    // ═══════════════════════════════════════════════════════════════════════
    // TLS Version
    // ═══════════════════════════════════════════════════════════════════════

    constexpr std::uint16_t VERSION_TLS12 = 0x0303;
    constexpr std::uint16_t VERSION_TLS13 = 0x0304;

    // ═══════════════════════════════════════════════════════════════════════
    // Cipher Suite (TLS 1.3)
    // ═══════════════════════════════════════════════════════════════════════

    constexpr std::uint16_t CIPHER_AES_128_GCM_SHA256 = 0x1301;

    // ═══════════════════════════════════════════════════════════════════════
    // Server Name Type
    // ═══════════════════════════════════════════════════════════════════════

    constexpr std::uint8_t SERVER_NAME_TYPE_HOSTNAME = 0x00;

    // ═══════════════════════════════════════════════════════════════════════
    // 密钥与认证常量
    // ═══════════════════════════════════════════════════════════════════════

    /** @brief X25519 密钥/公钥长度 */
    constexpr std::size_t REALITY_KEY_LEN = 32;

    /** @brief TLS session_id 最大长度 */
    constexpr std::size_t SESSION_ID_MAX_LEN = 32;

    /** @brief AEAD tag 长度 */
    constexpr std::size_t AEAD_TAG_LEN = 16;

    /** @brief AEAD nonce 长度 */
    constexpr std::size_t AEAD_NONCE_LEN = 12;

    /** @brief AES-128-GCM 密钥长度 */
    constexpr std::size_t AES_128_KEY_LEN = 16;

    // ═══════════════════════════════════════════════════════════════════════
    // Signature Scheme (TLS 1.3)
    // ═══════════════════════════════════════════════════════════════════════

    /** @brief Ed25519 签名算法 */
    constexpr std::uint16_t SIGNATURE_SCHEME_ED25519 = 0x0807;

    // ═══════════════════════════════════════════════════════════════════════
    // TLS 记录层写入工具
    // ═══════════════════════════════════════════════════════════════════════

    inline auto write_u8(memory::vector<std::uint8_t> &buf, std::uint8_t val) -> void
    {
        buf.push_back(val);
    }

    inline auto write_u16(memory::vector<std::uint8_t> &buf, std::uint16_t val) -> void
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    inline auto write_u24(memory::vector<std::uint8_t> &buf, std::size_t val) -> void
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ClientHello 特征结构
    // ═══════════════════════════════════════════════════════════════════════

    /**
     * @struct client_hello_features
     * @brief 从 TLS ClientHello 提取的关键特征
     * @details 包含 SNI、session_id、key_share、支持的版本等特征。
     * 各方案的 detect() 方法基于这些特征判断置信度。
     * 该结构是中立的共享类型，供 recognition 和 stealth 共同使用。
     */
    struct client_hello_features
    {
        /** @brief SNI 服务器名称 */
        memory::string server_name;

        /** @brief session_id 数据 */
        memory::vector<std::uint8_t> session_id;

        /** @brief session_id 长度（0-32） */
        std::uint8_t session_id_len{0};

        /** @brief 是否存在 X25519 key_share 扩展 */
        bool has_x25519{false};

        /** @brief X25519 公钥（32 字节，存在时有效） */
        std::array<std::uint8_t, 32> x25519_key{};

        /** @brief 支持的 TLS 版本列表 */
        memory::vector<std::uint16_t> versions;

        /** @brief 客户端随机数（32 字节） */
        std::array<std::uint8_t, 32> random{};

        /** @brief 原始握手消息（不含 TLS record header） */
        memory::vector<std::uint8_t> raw_hs_msg;

        /** @brief 原始 ClientHello 记录（含 TLS record header） */
        memory::vector<std::byte> raw_record;
    };

} // namespace psm::protocol::tls

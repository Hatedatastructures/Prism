/**
 * @file keygen.hpp
 * @brief TLS 1.3 密钥调度
 * @details 实现 RFC 8446 Section 7 的 TLS 1.3 密钥派生流程。
 * 从 ECDHE 共享密钥派生握手流量密钥和应用流量密钥。
 * Reality 协议使用自定义的 X25519 共享密钥替代标准 TLS ECDHE 结果，
 * 密钥调度算法与标准 TLS 1.3 完全一致。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <prism/fault/code.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/protocol/reality/constants.hpp>

namespace psm::protocol::reality
{
    using constspan = std::span<const std::uint8_t>;
    /**
     * @struct key_material
     * @brief TLS 1.3 密钥材料
     * @details 包含握手阶段和应用数据阶段的全部加密密钥和 IV。
     * - Handshake keys: 用于加密 ServerHello 之后的握手消息
     * - Application keys: 用于加密后续的应用数据（VLESS）
     */
    struct key_material
    {
        // ================================================================
        // Handshake traffic keys (server → client)
        // ================================================================

        /// 服务端握手加密密钥（16 字节 AES-128-GCM）
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> server_handshake_key{};
        /// 服务端握手 IV（12 字节）
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> server_handshake_iv{};

        // ================================================================
        // Handshake traffic keys (client → server)
        // ================================================================

        /// 客户端握手加密密钥（16 字节）
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> client_handshake_key{};
        /// 客户端握手 IV（12 字节）
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> client_handshake_iv{};

        // ================================================================
        // Application traffic keys (server → client)
        // ================================================================

        /// 服务端应用数据加密密钥（16 字节）
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> server_app_key{};
        /// 服务端应用数据 IV（12 字节）
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> server_app_iv{};

        // ================================================================
        // Application traffic keys (client → server)
        // ================================================================

        /// 客户端应用数据加密密钥（16 字节）
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> client_app_key{};
        /// 客户端应用数据 IV（12 字节）
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> client_app_iv{};

        // ================================================================
        // Handshake traffic secrets（用于 Finished 计算）
        // ================================================================

        /// 服务端 Finished 密钥
        std::array<std::uint8_t, crypto::SHA256_LEN> server_finished_key{};
        /// 主密钥（用于派生 application traffic secrets）
        std::array<std::uint8_t, crypto::SHA256_LEN> master_secret{};
    };

    /**
     * @brief 仅派生握手阶段密钥（不含 application keys）
     * @param shared_secret X25519 共享密钥（32 字节）
     * @param client_hello_msg 原始 ClientHello handshake 消息
     * @param server_hello_msg 生成的 ServerHello handshake 消息
     * @return 错误码和部分密钥材料的配对
     * @details 派生 early_secret 到 handshake keys 阶段的密钥。
     * application keys 需要在发送 Finished 消息后调用
     * derive_application_keys() 单独派生。
     */
    [[nodiscard]] auto derive_handshake_keys(constspan shared_secret, constspan client_hello_msg, constspan server_hello_msg)
        -> std::pair<fault::code, key_material>;

    /**
     * @brief 从 master_secret 派生应用数据密钥
     * @param master_secret 主密钥
     * @param server_finished_hash 服务端 Finished 消息后的 transcript hash
     * @param keys 已包含 handshake keys 的密钥材料（将被填充 app keys）
     * @return 错误码
     */
    [[nodiscard]] auto derive_application_keys(constspan master_secret, constspan server_finished_hash, key_material &keys) -> fault::code;

    /**
     * @brief 计算 Finished verify_data
     * @param finished_key Finished 密钥
     * @param transcript_hash transcript hash
     * @return 32 字节 verify_data
     * @details verify_data = HMAC-SHA256(finished_key, transcript_hash)
     */
    [[nodiscard]] auto compute_finished_verify_data(constspan finished_key, constspan transcript_hash)
        -> std::array<std::uint8_t, crypto::SHA256_LEN>;
} // namespace psm::protocol::reality

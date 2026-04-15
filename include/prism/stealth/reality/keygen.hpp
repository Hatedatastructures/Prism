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
#include <prism/stealth/reality/constants.hpp>

namespace psm::stealth
{
    using constspan = std::span<const std::uint8_t>;

    /**
     * @struct key_material
     * @brief TLS 1.3 密钥材料
     */
    struct key_material
    {
        // Handshake traffic keys (server → client)
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> server_handshake_key{};
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> server_handshake_iv{};

        // Handshake traffic keys (client → server)
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> client_handshake_key{};
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> client_handshake_iv{};

        // Application traffic keys (server → client)
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> server_app_key{};
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> server_app_iv{};

        // Application traffic keys (client → server)
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> client_app_key{};
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> client_app_iv{};

        // Finished keys
        std::array<std::uint8_t, crypto::SHA256_LEN> server_finished_key{};
        std::array<std::uint8_t, crypto::SHA256_LEN> master_secret{};
    };

    /**
     * @brief 派生握手阶段密钥
     */
    [[nodiscard]] auto derive_handshake_keys(constspan shared_secret, constspan client_hello_msg, constspan server_hello_msg)
        -> std::pair<fault::code, key_material>;

    /**
     * @brief 派生应用数据密钥
     */
    [[nodiscard]] auto derive_application_keys(constspan master_secret, constspan server_finished_hash, key_material &keys) -> fault::code;

    /**
     * @brief 计算 Finished verify_data
     */
    [[nodiscard]] auto compute_finished_verify_data(constspan finished_key, constspan transcript_hash)
        -> std::array<std::uint8_t, crypto::SHA256_LEN>;
} // namespace psm::stealth

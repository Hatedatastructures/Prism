/**
 * @file keygen.hpp
 * @brief TLS 1.3 密钥调度
 * @details 实现 RFC 8446 Section 7 的 TLS 1.3 密钥派生流程，
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

namespace psm::stealth::reality
{
    using constspan = std::span<const std::uint8_t>;

    /**
     * @struct key_material
     * @brief TLS 1.3 密钥材料
     * @details 包含握手阶段和应用阶段的全部加密密钥和 IV，
     * 以及 Finished 验证密钥和主密钥
     */
    struct key_material
    {
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> server_handshake_key{}; // 握手阶段服务端加密密钥
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> server_handshake_iv{};   // 握手阶段服务端 IV
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> client_handshake_key{}; // 握手阶段客户端加密密钥
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> client_handshake_iv{};   // 握手阶段客户端 IV
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> server_app_key{};       // 应用阶段服务端加密密钥
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> server_app_iv{};         // 应用阶段服务端 IV
        std::array<std::uint8_t, tls::AES_128_KEY_LEN> client_app_key{};       // 应用阶段客户端加密密钥
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> client_app_iv{};         // 应用阶段客户端 IV
        std::array<std::uint8_t, crypto::SHA256_LEN> server_finished_key{};    // 服务端 Finished 验证密钥
        std::array<std::uint8_t, crypto::SHA256_LEN> master_secret{};          // 主密钥
    };

    /**
     * @brief 派生握手阶段密钥
     * @details 从共享密钥和 ClientHello/ServerHello 消息派生握手流量密钥
     * @param shared_secret ECDHE 共享密钥
     * @param client_hello_msg 完整的 ClientHello 握手消息
     * @param server_hello_msg 完整的 ServerHello 握手消息
     * @return 错误码和派生出的密钥材料
     */
    [[nodiscard]] auto derive_handshake_keys(constspan shared_secret, constspan client_hello_msg, constspan server_hello_msg)
        -> std::pair<fault::code, key_material>;

    /**
     * @brief 派生应用数据密钥
     * @details 从主密钥和服务端 Finished 哈希派生应用流量密钥，
     * 结果写入 keys 参数的应用阶段字段
     * @param master_secret 主密钥
     * @param server_finished_hash 服务端 Finished 消息的哈希
     * @param keys 密钥材料，应用阶段字段将被填充
     * @return fault::code 错误码，成功时为 success
     */
    [[nodiscard]] auto derive_application_keys(constspan master_secret, constspan server_finished_hash, key_material &keys) -> fault::code;

    /**
     * @brief 计算 Finished verify_data
     * @details 使用 finished_key 和 transcript_hash 计算 TLS 1.3 Finished
     * 消息的验证数据，用于握手完整性校验
     * @param finished_key Finished 验证密钥
     * @param transcript_hash 握手消息的 transcript 哈希
     * @return 计算出的 verify_data，长度为 SHA256_LEN
     */
    [[nodiscard]] auto compute_finished_verify_data(constspan finished_key, constspan transcript_hash)
        -> std::array<std::uint8_t, crypto::SHA256_LEN>;
} // namespace psm::stealth::reality

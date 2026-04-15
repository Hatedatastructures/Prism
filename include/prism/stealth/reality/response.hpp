/**
 * @file response.hpp
 * @brief TLS 1.3 ServerHello 生成器
 * @details 生成 Reality 协议所需的 TLS 1.3 服务端握手消息，
 * 包括 ServerHello、ChangeCipherSpec（兼容性）和加密的握手记录。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>
#include <prism/stealth/reality/request.hpp>
#include <prism/stealth/reality/constants.hpp>

namespace psm::stealth
{
    struct key_material;

    /**
     * @struct server_hello_result
     * @brief ServerHello 生成结果
     */
    struct server_hello_result
    {
        memory::vector<std::uint8_t> server_hello_msg;
        memory::vector<std::uint8_t> server_hello_record;
        memory::vector<std::uint8_t> change_cipher_spec_record;
        memory::vector<std::uint8_t> encrypted_handshake_record;
        memory::vector<std::uint8_t> encrypted_handshake_plaintext;
    };

    /**
     * @brief 生成 ServerHello 及完整握手响应
     */
    [[nodiscard]] auto generate_server_hello(
        const client_hello_info &client_hello,
        std::span<const std::uint8_t> server_ephemeral_public,
        const key_material &handshake_keys,
        std::span<const std::uint8_t> dest_certificate,
        std::span<const std::uint8_t> client_hello_msg,
        std::span<const std::uint8_t> auth_key = {})
        -> std::pair<fault::code, server_hello_result>;

    /**
     * @brief 构造 TLS 记录
     */
    [[nodiscard]] auto make_tls_record(std::uint8_t content_type,
                                       std::span<const std::uint8_t> payload)
        -> memory::vector<std::uint8_t>;

    /**
     * @brief 加密 TLS 1.3 记录
     */
    [[nodiscard]] auto encrypt_tls_record(
        std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> iv,
        std::uint64_t sequence,
        std::uint8_t content_type,
        std::span<const std::uint8_t> plaintext)
        -> std::pair<fault::code, memory::vector<std::uint8_t>>;
} // namespace psm::stealth

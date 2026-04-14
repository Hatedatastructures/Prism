/**
 * @file response.hpp
 * @brief TLS 1.3 ServerHello 生成器
 * @details 生成 Reality 协议所需的 TLS 1.3 服务端握手消息，
 * 包括 ServerHello、ChangeCipherSpec（兼容性）和加密的握手记录
 * （EncryptedExtensions + Certificate + CertificateVerify + Finished）。
 * 生成的消息格式严格遵循 RFC 8446。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <prism/fault/code.hpp>
#include <prism/memory/container.hpp>
#include <prism/protocol/reality/request.hpp>
#include <prism/protocol/reality/constants.hpp>

namespace psm::protocol::reality
{
    struct key_material;

    /**
     * @struct server_hello_result
     * @brief ServerHello 生成结果
     */
    struct server_hello_result
    {
        /// ServerHello handshake 消息（HandshakeType + Length + body）
        memory::vector<std::uint8_t> server_hello_msg;

        /// 完整 ServerHello TLS 记录（含 record header）
        memory::vector<std::uint8_t> server_hello_record;

        /// ChangeCipherSpec TLS 记录
        memory::vector<std::uint8_t> change_cipher_spec_record;

        /// 加密握手记录（含 record header）
        memory::vector<std::uint8_t> encrypted_handshake_record;

        /// 完整的加密握手消息明文（用于 transcript hash）
        memory::vector<std::uint8_t> encrypted_handshake_plaintext;
    };

    /**
     * @brief 生成 ServerHello 及完整握手响应
     * @param client_hello 客户端 ClientHello 信息
     * @param server_ephemeral_public 服务端临时 X25519 公钥
     * @param handshake_keys 握手阶段密钥
     * @param dest_certificate dest 服务器的 DER 编码证书链（fallback 使用）
     * @param client_hello_msg 原始 ClientHello handshake 消息（用于 transcript hash）
     * @param auth_key 可选的 Reality 认证密钥（非空时生成 Ed25519 自签名证书）
     * @return 错误码和生成结果
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
     * @brief 构造 TLS 记录头
     * @param content_type 内容类型
     * @param payload 载荷数据
     * @return 完整 TLS 记录
     */
    [[nodiscard]] auto make_tls_record(std::uint8_t content_type,
                                       std::span<const std::uint8_t> payload)
        -> memory::vector<std::uint8_t>;

    /**
     * @brief 加密 TLS 1.3 记录
     * @param key AEAD 密钥（16 字节）
     * @param iv AEAD IV（12 字节）
     * @param sequence 记录序列号
     * @param content_type 记录内容类型
     * @param plaintext 明文数据
     * @return 完整的加密 TLS 记录
     * @details 构造 TLS 1.3 加密记录：
     * plaintext_inner = data + content_type + zeros(padding)
     * nonce = iv XOR sequence (big-endian)
     * additional_data = record_header
     * encrypted = AEAD-seal(key, nonce, ad, plaintext_inner)
     * record = [0x17][0x03][0x03][len(2)][encrypted + tag]
     */
    [[nodiscard]] auto encrypt_tls_record(
        std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> iv,
        std::uint64_t sequence,
        std::uint8_t content_type,
        std::span<const std::uint8_t> plaintext)
        -> std::pair<fault::code, memory::vector<std::uint8_t>>;
} // namespace psm::protocol::reality

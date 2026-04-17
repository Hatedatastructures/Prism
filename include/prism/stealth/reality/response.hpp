/**
 * @file response.hpp
 * @brief TLS 1.3 ServerHello 生成器
 * @details 生成 Reality 协议所需的 TLS 1.3 服务端握手消息，
 * 包括 ServerHello、ChangeCipherSpec（兼容性）和加密的握手记录，
 * 用于构造完整的 TLS 握手响应发送给客户端
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
     * @details 包含 TLS 握手响应的各阶段消息和记录
     */
    struct server_hello_result
    {
        memory::vector<std::uint8_t> server_hello_msg;              // ServerHello 握手消息（含 handshake header）
        memory::vector<std::uint8_t> server_hello_record;           // ServerHello TLS 记录（含 record header）
        memory::vector<std::uint8_t> change_cipher_spec_record;     // ChangeCipherSpec 兼容性记录
        memory::vector<std::uint8_t> encrypted_handshake_record;    // 加密后的握手记录（EncryptedExtensions + Certificate + CertificateVerify + Finished）
        memory::vector<std::uint8_t> encrypted_handshake_plaintext; // 加密前握手记录明文
    };

    /**
     * @brief 生成 ServerHello 及完整握手响应
     * @details 构造 ServerHello 消息、ChangeCipherSpec 兼容性记录和加密的
     * 握手记录（含伪造的 Certificate、CertificateVerify 和 Finished），
     * 使用目标网站的真实证书构造伪造证书用于 Reality 认证
     * @param client_hello 解析后的 ClientHello 信息
     * @param server_ephemeral_public 服务端临时 X25519 公钥
     * @param handshake_keys 握手阶段密钥材料
     * @param dest_certificate 目标网站的 DER 格式证书
     * @param client_hello_msg 完整的 ClientHello 消息字节
     * @param auth_key HKDF 派生的认证密钥，用于签名
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
     * @brief 构造 TLS 记录
     * @details 将载荷数据包装为标准 TLS 记录格式：
     * [ContentType 1B][Version 2B][Length 2B][Payload]
     * @param content_type 内容类型
     * @param payload 记录载荷
     * @return 编码后的 TLS 记录字节
     */
    [[nodiscard]] auto make_tls_record(std::uint8_t content_type,
                                       std::span<const std::uint8_t> payload)
        -> memory::vector<std::uint8_t>;

    /**
     * @brief 加密 TLS 1.3 记录
     * @details 使用 AEAD 加密明文数据，构造加密后的 TLS 记录。
     * nonce 由 IV 和序列号异或生成，加密后追加 content type 和 AEAD tag
     * @param key 加密密钥
     * @param iv 初始化向量
     * @param sequence 序列号，用于生成 nonce
     * @param content_type 内容类型
     * @param plaintext 明文数据
     * @return 错误码和加密后的密文（含 record header）
     */
    [[nodiscard]] auto encrypt_tls_record(
        std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> iv,
        std::uint64_t sequence,
        std::uint8_t content_type,
        std::span<const std::uint8_t> plaintext)
        -> std::pair<fault::code, memory::vector<std::uint8_t>>;
} // namespace psm::stealth

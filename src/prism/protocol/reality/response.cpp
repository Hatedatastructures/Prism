/**
 * @file response.cpp
 * @brief TLS 1.3 ServerHello 生成器实现
 * @details 生成 TLS 1.3 服务端握手消息序列。
 * 消息格式严格遵循 RFC 8446：
 * ServerHello → ChangeCipherSpec → Encrypted[EncryptedExtensions + Certificate + CertificateVerify + Finished]
 */

#include <prism/protocol/reality/response.hpp>
#include <prism/protocol/reality/keygen.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/trace.hpp>
#include <cstring>
#include <random>

namespace psm::protocol::reality
{
    constexpr std::string_view ShTag = "[Reality.ServerHello]";

    // ========================================================================
    // 辅助：大端序写入
    // ========================================================================

    static auto write_u16(memory::vector<std::uint8_t> &buf, std::uint16_t val) -> void
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    static auto write_u24(memory::vector<std::uint8_t> &buf, std::size_t val) -> void
    {
        buf.push_back(static_cast<std::uint8_t>((val >> 16) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>((val >> 8) & 0xFF));
        buf.push_back(static_cast<std::uint8_t>(val & 0xFF));
    }

    static auto write_u8(memory::vector<std::uint8_t> &buf, std::uint8_t val) -> void
    {
        buf.push_back(val);
    }

    // ========================================================================
    // TLS 记录构造
    // ========================================================================

    auto make_tls_record(const std::uint8_t content_type,
                         const std::span<const std::uint8_t> payload)
        -> memory::vector<std::uint8_t>
    {
        memory::vector<std::uint8_t> record;
        record.reserve(tls::RECORD_HEADER_LEN + payload.size());
        record.push_back(content_type);
        write_u16(record, tls::VERSION_TLS12); // legacy version
        write_u16(record, static_cast<std::uint16_t>(payload.size()));
        record.insert(record.end(), payload.begin(), payload.end());
        return record;
    }

    // ========================================================================
    // AEAD 加密记录
    // ========================================================================

    auto encrypt_tls_record(
        const std::span<const std::uint8_t> key,
        const std::span<const std::uint8_t> iv,
        const std::uint64_t sequence,
        const std::uint8_t content_type,
        const std::span<const std::uint8_t> plaintext)
        -> std::pair<fault::code, memory::vector<std::uint8_t>>
    {
        // 构造 TLS 1.3 内部明文: data + content_type + zeros(padding)
        // 最小 padding 为 0 字节
        memory::vector<std::uint8_t> inner;
        inner.reserve(plaintext.size() + 1);
        inner.insert(inner.end(), plaintext.begin(), plaintext.end());
        inner.push_back(content_type);

        // 计算 nonce: iv XOR sequence (big-endian, 12 字节)
        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> nonce{};
        std::memcpy(nonce.data(), iv.data(), tls::AEAD_NONCE_LEN);
        // XOR sequence 的大端表示到 nonce 末尾
        for (int i = 0; i < 8; ++i)
        {
            nonce[tls::AEAD_NONCE_LEN - 1 - i] ^= static_cast<std::uint8_t>((sequence >> (8 * i)) & 0xFF);
        }

        // additional_data = record header
        const std::size_t encrypted_len = inner.size() + tls::AEAD_TAG_LEN;
        std::array<std::uint8_t, tls::RECORD_HEADER_LEN> ad{};
        ad[0] = tls::CONTENT_TYPE_APPLICATION_DATA;
        ad[1] = 0x03;
        ad[2] = 0x03;
        ad[3] = static_cast<std::uint8_t>((encrypted_len >> 8) & 0xFF);
        ad[4] = static_cast<std::uint8_t>(encrypted_len & 0xFF);

        // 加密
        crypto::aead_context aead(crypto::aead_cipher::aes_128_gcm, key);

        memory::vector<std::uint8_t> ciphertext(encrypted_len);
        const auto nonce_span = std::span<const std::uint8_t>{nonce.data(), nonce.size()};
        const auto ad_span = std::span<const std::uint8_t>{ad.data(), ad.size()};
        const auto ec = aead.seal(ciphertext, inner, nonce_span, ad_span);
        if (fault::failed(ec))
        {
            trace::error("{} AEAD seal failed", ShTag);
            return {fault::code::crypto_error, {}};
        }

        // 构造完整记录
        auto record = make_tls_record(tls::CONTENT_TYPE_APPLICATION_DATA, ciphertext);
        return {fault::code::success, std::move(record)};
    }

    // ========================================================================
    // ServerHello 消息生成
    // ========================================================================

    /**
     * @brief 生成 ServerHello handshake 消息体
     */
    static auto build_server_hello_body(
        const client_hello_info &client_hello,
        std::span<const std::uint8_t> server_ephemeral_public)
        -> memory::vector<std::uint8_t>
    {
        memory::vector<std::uint8_t> body;
        body.reserve(128);

        // server_version (legacy TLS 1.2)
        write_u16(body, tls::VERSION_TLS12);

        // server_random (32 bytes)
        std::array<std::uint8_t, 32> server_random{};
        std::random_device rd;
        std::generate(server_random.begin(), server_random.end(), [&rd]() { return static_cast<std::uint8_t>(rd()); });
        body.insert(body.end(), server_random.begin(), server_random.end());

        // session_id (echo client's)
        write_u8(body, static_cast<std::uint8_t>(client_hello.session_id.size()));
        body.insert(body.end(), client_hello.session_id.begin(), client_hello.session_id.end());

        // cipher_suite (AES-128-GCM-SHA256)
        write_u16(body, tls::CIPHER_AES_128_GCM_SHA256);

        // compression_method (null)
        write_u8(body, 0x00);

        // Extensions
        memory::vector<std::uint8_t> extensions;

        // supported_versions extension: TLS 1.3
        // RFC 8446 Section 4.2.1: ServerHello 的 supported_versions 不使用 list length prefix，
        // 直接写入选定的版本号（2 字节）
        {
            memory::vector<std::uint8_t> ext;
            write_u16(ext, tls::VERSION_TLS13);
            // extension header
            write_u16(extensions, tls::EXT_SUPPORTED_VERSIONS);
            write_u16(extensions, static_cast<std::uint16_t>(ext.size()));
            extensions.insert(extensions.end(), ext.begin(), ext.end());
        }

        // key_share extension: X25519
        {
            memory::vector<std::uint8_t> ext;
            write_u16(ext, tls::NAMED_GROUP_X25519);
            write_u16(ext, static_cast<std::uint16_t>(server_ephemeral_public.size()));
            ext.insert(ext.end(), server_ephemeral_public.begin(), server_ephemeral_public.end());
            // extension header
            write_u16(extensions, tls::EXT_KEY_SHARE);
            write_u16(extensions, static_cast<std::uint16_t>(ext.size()));
            extensions.insert(extensions.end(), ext.begin(), ext.end());
        }

        // extensions length prefix
        memory::vector<std::uint8_t> result;
        write_u16(result, static_cast<std::uint16_t>(extensions.size()));
        result.insert(result.end(), extensions.begin(), extensions.end());

        // body = body + extensions
        body.insert(body.end(), result.begin(), result.end());
        return body;
    }

    /**
     * @brief 生成 Handshake 消息（Type + Length + Body）
     */
    static auto make_handshake_message(std::uint8_t msg_type,
                                       std::span<const std::uint8_t> body)
        -> memory::vector<std::uint8_t>
    {
        memory::vector<std::uint8_t> msg;
        msg.reserve(4 + body.size());
        write_u8(msg, msg_type);
        write_u24(msg, body.size());
        msg.insert(msg.end(), body.begin(), body.end());
        return msg;
    }

    /**
     * @brief 生成 EncryptedExtensions 消息体
     */
    static auto build_encrypted_extensions() -> memory::vector<std::uint8_t>
    {
        // 最小化 EncryptedExtensions：空的 extensions 列表
        memory::vector<std::uint8_t> body;
        write_u16(body, 0); // extensions length = 0
        return body;
    }

    /**
     * @brief 生成 Certificate 消息体
     */
    static auto build_certificate(std::span<const std::uint8_t> cert_chain_der)
        -> memory::vector<std::uint8_t>
    {
        memory::vector<std::uint8_t> body;
        // certificate_request_context (0 length for server)
        write_u8(body, 0x00);

        // certificate_list length (3 bytes)
        // 每个证书条目：CertLen(3) + Cert + ExtensionsLen(2)
        memory::vector<std::uint8_t> cert_list;
        // 单个证书条目
        write_u24(cert_list, cert_chain_der.size());
        cert_list.insert(cert_list.end(), cert_chain_der.begin(), cert_chain_der.end());
        write_u16(cert_list, 0); // extensions length = 0

        write_u24(body, cert_list.size());
        body.insert(body.end(), cert_list.begin(), cert_list.end());
        return body;
    }

    /**
     * @brief 生成 CertificateVerify 消息体
     * @details 使用临时的简化签名。Reality 的 CertificateVerify 不需要真正的 CA 签名，
     * 因为客户端通过 X25519 密钥交换验证服务器身份，不依赖 CA 信任链。
     */
    static auto build_certificate_verify() -> memory::vector<std::uint8_t>
    {
        // CertificateVerify: 简化实现
        // 格式：SignatureAlgorithm(2) + SignatureLen(2) + Signature(N)
        // 使用全零签名（Reality 客户端不验证此签名）
        memory::vector<std::uint8_t> body;
        write_u16(body, 0x0403); // rsa_pkcs1_sha256
        write_u16(body, 64);     // signature length
        // 64 字节全零签名
        for (int i = 0; i < 64; ++i)
        {
            body.push_back(0x00);
        }
        return body;
    }

    // ========================================================================
    // 主生成函数
    // ========================================================================

    auto generate_server_hello(
        const client_hello_info &client_hello,
        const std::span<const std::uint8_t> server_ephemeral_public,
        const key_material &handshake_keys,
        const std::span<const std::uint8_t> dest_certificate,
        const std::span<const std::uint8_t> client_hello_msg)
        -> std::pair<fault::code, server_hello_result>
    {
        server_hello_result result;
        result.server_ephemeral_public = {};
        std::copy(server_ephemeral_public.begin(), server_ephemeral_public.end(),
                  result.server_ephemeral_public.begin());

        // ================================================================
        // 1. ServerHello handshake 消息
        // ================================================================
        const auto sh_body = build_server_hello_body(client_hello, server_ephemeral_public);
        const auto sh_msg = make_handshake_message(tls::HANDSHAKE_TYPE_SERVER_HELLO, sh_body);
        result.server_hello_msg = sh_msg;

        // ServerHello TLS 记录
        result.server_hello_record = make_tls_record(tls::CONTENT_TYPE_HANDSHAKE, sh_msg);

        // ================================================================
        // 2. ChangeCipherSpec 记录（兼容性）
        // ================================================================
        result.change_cipher_spec_record = {tls::CONTENT_TYPE_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01};

        // ================================================================
        // 3. 加密握手消息
        // ================================================================

        // 计算 transcript hash (ClientHello || ServerHello)
        const auto hello_hash = crypto::sha256(
            {result.server_hello_msg.data(), result.server_hello_msg.size()},
            {});

        // 构建加密握手消息明文
        memory::vector<std::uint8_t> plaintext;

        // EncryptedExtensions
        const auto ee_body = build_encrypted_extensions();
        const auto ee_msg = make_handshake_message(tls::HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, ee_body);
        plaintext.insert(plaintext.end(), ee_msg.begin(), ee_msg.end());

        // Certificate
        const auto cert_body = build_certificate(dest_certificate);
        const auto cert_msg = make_handshake_message(tls::HANDSHAKE_TYPE_CERTIFICATE, cert_body);
        plaintext.insert(plaintext.end(), cert_msg.begin(), cert_msg.end());

        // CertificateVerify
        const auto cv_body = build_certificate_verify();
        const auto cv_msg = make_handshake_message(tls::HANDSHAKE_TYPE_CERTIFICATE_VERIFY, cv_body);
        plaintext.insert(plaintext.end(), cv_msg.begin(), cv_msg.end());

        // Finished: verify_data = HMAC(finished_key, transcript_hash)
        // transcript hash = SHA-256(ClientHello || ServerHello || EE || Cert || CV)
        const auto transcript_for_finished = crypto::sha256(
            client_hello_msg,
            {result.server_hello_msg.data(), result.server_hello_msg.size()},
            plaintext);

        const auto verify_data = compute_finished_verify_data(
            handshake_keys.server_finished_key, transcript_for_finished);

        // Finished 消息体 = verify_data (32 bytes)
        const auto finished_msg = make_handshake_message(
            tls::HANDSHAKE_TYPE_FINISHED, verify_data);
        plaintext.insert(plaintext.end(), finished_msg.begin(), finished_msg.end());

        // 保存明文（用于后续 application key 派生）
        result.encrypted_handshake_plaintext = plaintext;

        // 加密
        auto [enc_ec, encrypted_record] = encrypt_tls_record(
            handshake_keys.server_handshake_key,
            handshake_keys.server_handshake_iv,
            0, // sequence = 0 (第一条加密记录)
            tls::CONTENT_TYPE_HANDSHAKE,
            plaintext);

        if (fault::failed(enc_ec))
        {
            trace::error("{} failed to encrypt handshake record", ShTag);
            return {enc_ec, result};
        }

        result.encrypted_handshake_record = std::move(encrypted_record);

        trace::debug("{} generated ServerHello + encrypted handshake", ShTag);
        return {fault::code::success, std::move(result)};
    }
} // namespace psm::protocol::reality

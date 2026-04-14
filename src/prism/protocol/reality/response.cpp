#include <prism/protocol/reality/response.hpp>
#include <prism/protocol/reality/keygen.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/crypto/x25519.hpp>
#include <prism/trace.hpp>
#include <cstring>
#include <random>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/curve25519.h>

namespace psm::protocol::reality
{
    constexpr std::string_view ShTag = "[Reality.ServerHello]";

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
     * @brief 生成 Reality Ed25519 自签名证书
     * @details 证书签名 = HMAC-SHA512(auth_key, ed25519_public_key)
     *          手动设置签名算法（绕过 X509_sign，BoringSSL 对 Ed25519 支持有限）
     */
    static auto generate_reality_certificate(std::span<const std::uint8_t> auth_key)
        -> std::pair<memory::vector<std::uint8_t>, crypto::ed25519_keypair>
    {
        memory::vector<std::uint8_t> cert_der;
        crypto::ed25519_keypair ed_keypair;

        if (auth_key.size() != 32)
        {
            trace::error("{} invalid auth_key length for Reality cert: {}", ShTag, auth_key.size());
            return {cert_der, ed_keypair};
        }

        // 用 BoringSSL 底层 API 生成 Ed25519 密钥对
        ED25519_keypair(ed_keypair.public_key.data(), ed_keypair.private_key.data());
        if (std::all_of(ed_keypair.public_key.begin(), ed_keypair.public_key.end(),
                        [](uint8_t b) { return b == 0; }))
        {
            trace::error("{} [CERT] ED25519_keypair returned zero public key", ShTag);
            return {cert_der, ed_keypair};
        }
        ERR_clear_error();

        // 从公钥创建 EVP_PKEY（仅用于 X509_set_pubkey）
        auto *pkey = EVP_PKEY_from_raw_public_key(
            EVP_pkey_ed25519(),
            ed_keypair.public_key.data(), ed_keypair.public_key.size());
        if (!pkey)
        {
            auto err = ERR_get_error();
            trace::error("{} [CERT] EVP_PKEY_from_raw_public_key failed, err=0x{:x}:{}",
                         ShTag, err, ERR_error_string(err, nullptr));
            return {cert_der, ed_keypair};
        }
        ERR_clear_error();

        // 创建 X509
        auto *x509 = X509_new();
        if (!x509)
        {
            EVP_PKEY_free(pkey);
            return {cert_der, ed_keypair};
        }

        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 3600);

        auto *name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    reinterpret_cast<const unsigned char *>("Reality"), -1, -1, 0);
        X509_set_subject_name(x509, name);
        X509_set_issuer_name(x509, name);
        X509_NAME_free(name);

        X509_set_pubkey(x509, pkey);
        EVP_PKEY_free(pkey);

        // 手动设置签名算法为 Ed25519（绕过 X509_sign）
        const auto *ed25519_obj = OBJ_nid2obj(NID_ED25519);

        // 设置 TBS Certificate 的签名算法
        auto *tbs_alg = const_cast<X509_ALGOR *>(X509_get0_tbs_sigalg(x509));
        X509_ALGOR_set0(tbs_alg, const_cast<ASN1_OBJECT *>(ed25519_obj), V_ASN1_UNDEF, nullptr);

        // 设置外层签名算法
        const X509_ALGOR *outer_alg_const = nullptr;
        X509_get0_signature(nullptr, &outer_alg_const, x509);
        auto *outer_alg = const_cast<X509_ALGOR *>(outer_alg_const);
        X509_ALGOR_set0(outer_alg, const_cast<ASN1_OBJECT *>(ed25519_obj), V_ASN1_UNDEF, nullptr);

        // 计算 HMAC-SHA512(auth_key, ed25519_public_key) 作为证书签名
        const auto hmac_sig = crypto::hmac_sha512(
            auth_key,
            std::span<const std::uint8_t>(ed_keypair.public_key.data(), ed_keypair.public_key.size()));
        ERR_clear_error();
        auto sig_rc = X509_set1_signature_value(x509, hmac_sig.data(), hmac_sig.size());
        if (sig_rc != 1)
        {
            auto err = ERR_get_error();
            trace::error("{} [CERT] X509_set1_signature_value failed, rc={} err=0x{:x}",
                         ShTag, sig_rc, err);
        }

        // DER 编码
        auto *bio = BIO_new(BIO_s_mem());
        if (bio)
        {
            i2d_X509_bio(bio, x509);
            char *data = nullptr;
            const auto len = BIO_get_mem_data(bio, &data);
            cert_der.insert(cert_der.end(),
                            reinterpret_cast<std::uint8_t *>(data),
                            reinterpret_cast<std::uint8_t *>(data + len));
            BIO_free(bio);
        }

        X509_free(x509);
        trace::debug("{} generated Reality Ed25519 cert ({} bytes)", ShTag, cert_der.size());
        return {std::move(cert_der), std::move(ed_keypair)};
    }

    /**
     * @brief 生成 Certificate 消息体
     * @param out_ed_keypair 输出 Ed25519 keypair（auth_key 非空时填充）
     */
    static auto build_certificate(std::span<const std::uint8_t> cert_chain_der,
                                  std::span<const std::uint8_t> auth_key,
                                  crypto::ed25519_keypair &out_ed_keypair)
        -> memory::vector<std::uint8_t>
    {
        memory::vector<std::uint8_t> cert_der;
        if (!auth_key.empty())
        {
            auto [der, kp] = generate_reality_certificate(auth_key);
            cert_der = std::move(der);
            out_ed_keypair = std::move(kp);
        }
        if (cert_der.empty())
        {
            cert_der.assign(cert_chain_der.begin(), cert_chain_der.end());
            trace::debug("{} [CERT] using dest certificate: {} bytes", ShTag, cert_der.size());
        }

        memory::vector<std::uint8_t> body;
        // certificate_request_context (0 length for server)
        write_u8(body, 0x00);

        // certificate_list length (3 bytes)
        memory::vector<std::uint8_t> cert_list;
        write_u24(cert_list, cert_der.size());
        cert_list.insert(cert_list.end(), cert_der.begin(), cert_der.end());
        write_u16(cert_list, 0); // extensions length = 0

        write_u24(body, cert_list.size());
        body.insert(body.end(), cert_list.begin(), cert_list.end());
        return body;
    }

    /**
     * @brief 生成 CertificateVerify 消息体
     * @details RFC 8446 Section 4.4.3:
     *   content = 0x20 * 64 + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
     *   signature = Ed25519_sign(private_key, content)
     */
    static auto build_certificate_verify(
        const crypto::ed25519_keypair &ed_keypair,
        std::span<const std::uint8_t> transcript_hash)
        -> memory::vector<std::uint8_t>
    {
        // 构造签名输入: 64 bytes 0x20 + context string + 0x00 + transcript_hash
        static constexpr std::string_view context = "TLS 1.3, server CertificateVerify";
        static constexpr std::size_t padding_len = 64;

        memory::vector<std::uint8_t> message;
        message.reserve(padding_len + context.size() + 1 + transcript_hash.size());
        for (std::size_t i = 0; i < padding_len; ++i)
        {
            message.push_back(0x20);
        }
        message.insert(message.end(), context.begin(), context.end());
        message.push_back(0x00);
        message.insert(message.end(), transcript_hash.begin(), transcript_hash.end());

        // Ed25519 签名
        std::array<std::uint8_t, 64> signature{};
        ED25519_sign(signature.data(), message.data(), message.size(),
                     ed_keypair.private_key.data());

        // CertificateVerify 消息体: SignatureScheme(2) + SignatureLen(2) + Signature(N)
        memory::vector<std::uint8_t> body;
        write_u16(body, tls::SIGNATURE_SCHEME_ED25519);  // 0x0807
        write_u16(body, static_cast<std::uint16_t>(signature.size()));
        body.insert(body.end(), signature.begin(), signature.end());

        return body;
    }

    auto generate_server_hello(
        const client_hello_info &client_hello,
        const std::span<const std::uint8_t> server_ephemeral_public,
        const key_material &handshake_keys,
        const std::span<const std::uint8_t> dest_certificate,
        const std::span<const std::uint8_t> client_hello_msg,
        const std::span<const std::uint8_t> auth_key)
        -> std::pair<fault::code, server_hello_result>
    {
        server_hello_result result;

        const auto sh_body = build_server_hello_body(client_hello, server_ephemeral_public);
        const auto sh_msg = make_handshake_message(tls::HANDSHAKE_TYPE_SERVER_HELLO, sh_body);
        result.server_hello_msg = sh_msg;

        // ServerHello TLS 记录
        result.server_hello_record = make_tls_record(tls::CONTENT_TYPE_HANDSHAKE, sh_msg);

        result.change_cipher_spec_record = {tls::CONTENT_TYPE_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01};

        memory::vector<std::uint8_t> plaintext;
        crypto::ed25519_keypair ed_keypair{};

        // EncryptedExtensions
        const auto ee_body = build_encrypted_extensions();
        const auto ee_msg = make_handshake_message(tls::HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, ee_body);
        plaintext.insert(plaintext.end(), ee_msg.begin(), ee_msg.end());

        // Certificate（auth_key 非空时生成 Ed25519 自签名证书并填充 ed_keypair）
        const auto cert_body = build_certificate(dest_certificate, auth_key, ed_keypair);
        const auto cert_msg = make_handshake_message(tls::HANDSHAKE_TYPE_CERTIFICATE, cert_body);
        plaintext.insert(plaintext.end(), cert_msg.begin(), cert_msg.end());

        // CertificateVerify: transcript_hash = SHA-256(CH || SH || EE || Cert)
        const auto cv_transcript = crypto::sha256(
            client_hello_msg,
            {result.server_hello_msg.data(), result.server_hello_msg.size()},
            {plaintext.data(), plaintext.size()});

        const auto cv_body = build_certificate_verify(ed_keypair, cv_transcript);
        const auto cv_msg = make_handshake_message(tls::HANDSHAKE_TYPE_CERTIFICATE_VERIFY, cv_body);
        plaintext.insert(plaintext.end(), cv_msg.begin(), cv_msg.end());

        // Finished: verify_data = HMAC(finished_key, SHA-256(CH || SH || EE || Cert || CV))
        const auto transcript_for_finished = crypto::sha256(
            client_hello_msg,
            {result.server_hello_msg.data(), result.server_hello_msg.size()},
            plaintext);
        const auto verify_data = compute_finished_verify_data(
            handshake_keys.server_finished_key, transcript_for_finished);

        const auto finished_msg = make_handshake_message(
            tls::HANDSHAKE_TYPE_FINISHED, verify_data);
        plaintext.insert(plaintext.end(), finished_msg.begin(), finished_msg.end());
        trace::debug("{} [HS] total plaintext len={}", ShTag, plaintext.size());

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

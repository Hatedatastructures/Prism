#include <prism/stealth/reality/response.hpp>
#include <prism/stealth/reality/keygen.hpp>
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

namespace psm::stealth
{
    constexpr std::string_view ShTag = "[Stealth.ServerHello]";

    static auto make_handshake_message(std::uint8_t msg_type,
                                       std::span<const std::uint8_t> body)
        -> memory::vector<std::uint8_t>
    {
        memory::vector<std::uint8_t> msg;
        msg.reserve(4 + body.size());
        tls::write_u8(msg, msg_type);
        tls::write_u24(msg, body.size());
        msg.insert(msg.end(), body.begin(), body.end());
        return msg;
    }

    auto make_tls_record(const std::uint8_t content_type,
                         const std::span<const std::uint8_t> payload)
        -> memory::vector<std::uint8_t>
    {
        memory::vector<std::uint8_t> record;
        record.reserve(tls::RECORD_HEADER_LEN + payload.size());
        record.push_back(content_type);
        tls::write_u16(record, tls::VERSION_TLS12);
        tls::write_u16(record, static_cast<std::uint16_t>(payload.size()));
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
        memory::vector<std::uint8_t> inner;
        inner.reserve(plaintext.size() + 1);
        inner.insert(inner.end(), plaintext.begin(), plaintext.end());
        inner.push_back(content_type);

        std::array<std::uint8_t, tls::AEAD_NONCE_LEN> nonce{};
        std::memcpy(nonce.data(), iv.data(), tls::AEAD_NONCE_LEN);
        for (int i = 0; i < 8; ++i)
        {
            nonce[tls::AEAD_NONCE_LEN - 1 - i] ^= static_cast<std::uint8_t>((sequence >> (8 * i)) & 0xFF);
        }

        const std::size_t encrypted_len = inner.size() + tls::AEAD_TAG_LEN;
        std::array<std::uint8_t, tls::RECORD_HEADER_LEN> ad{};
        ad[0] = tls::CONTENT_TYPE_APPLICATION_DATA;
        ad[1] = 0x03;
        ad[2] = 0x03;
        ad[3] = static_cast<std::uint8_t>((encrypted_len >> 8) & 0xFF);
        ad[4] = static_cast<std::uint8_t>(encrypted_len & 0xFF);

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

        auto record = make_tls_record(tls::CONTENT_TYPE_APPLICATION_DATA, ciphertext);
        return {fault::code::success, std::move(record)};
    }

    static auto build_server_hello_body(
        const client_hello_info &client_hello,
        std::span<const std::uint8_t> server_ephemeral_public)
        -> memory::vector<std::uint8_t>
    {
        memory::vector<std::uint8_t> body;
        body.reserve(128);

        tls::write_u16(body, tls::VERSION_TLS12);

        std::array<std::uint8_t, 32> server_random{};
        std::random_device rd;
        std::generate(server_random.begin(), server_random.end(), [&rd]() { return static_cast<std::uint8_t>(rd()); });
        body.insert(body.end(), server_random.begin(), server_random.end());

        tls::write_u8(body, static_cast<std::uint8_t>(client_hello.session_id.size()));
        body.insert(body.end(), client_hello.session_id.begin(), client_hello.session_id.end());

        tls::write_u16(body, tls::CIPHER_AES_128_GCM_SHA256);
        tls::write_u8(body, 0x00);

        memory::vector<std::uint8_t> extensions;

        // supported_versions: TLS 1.3
        {
            memory::vector<std::uint8_t> ext;
            tls::write_u16(ext, tls::VERSION_TLS13);
            tls::write_u16(extensions, tls::EXT_SUPPORTED_VERSIONS);
            tls::write_u16(extensions, static_cast<std::uint16_t>(ext.size()));
            extensions.insert(extensions.end(), ext.begin(), ext.end());
        }

        // key_share: X25519
        {
            memory::vector<std::uint8_t> ext;
            tls::write_u16(ext, tls::NAMED_GROUP_X25519);
            tls::write_u16(ext, static_cast<std::uint16_t>(server_ephemeral_public.size()));
            ext.insert(ext.end(), server_ephemeral_public.begin(), server_ephemeral_public.end());
            tls::write_u16(extensions, tls::EXT_KEY_SHARE);
            tls::write_u16(extensions, static_cast<std::uint16_t>(ext.size()));
            extensions.insert(extensions.end(), ext.begin(), ext.end());
        }

        tls::write_u16(body, static_cast<std::uint16_t>(extensions.size()));
        body.insert(body.end(), extensions.begin(), extensions.end());
        return body;
    }

    static auto build_encrypted_extensions() -> memory::vector<std::uint8_t>
    {
        memory::vector<std::uint8_t> body;
        tls::write_u16(body, 0);
        return body;
    }

    static auto generate_reality_certificate(std::span<const std::uint8_t> auth_key)
        -> std::pair<memory::vector<std::uint8_t>, crypto::ed25519_keypair>
    {
        memory::vector<std::uint8_t> cert_der;
        crypto::ed25519_keypair ed_keypair;

        if (auth_key.size() != 32)
        {
            trace::error("{} invalid auth_key length: {}", ShTag, auth_key.size());
            return {cert_der, ed_keypair};
        }

        ED25519_keypair(ed_keypair.public_key.data(), ed_keypair.private_key.data());
        if (std::all_of(ed_keypair.public_key.begin(), ed_keypair.public_key.end(),
                        [](uint8_t b) { return b == 0; }))
        {
            trace::error("{} ED25519_keypair returned zero public key", ShTag);
            return {cert_der, ed_keypair};
        }
        ERR_clear_error();

        auto *pkey = EVP_PKEY_from_raw_public_key(
            EVP_pkey_ed25519(),
            ed_keypair.public_key.data(), ed_keypair.public_key.size());
        if (!pkey)
        {
            auto err = ERR_get_error();
            trace::error("{} EVP_PKEY_from_raw_public_key failed, err=0x{:x}:{}",
                         ShTag, err, ERR_error_string(err, nullptr));
            return {cert_der, ed_keypair};
        }
        ERR_clear_error();

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

        const auto *ed25519_obj = OBJ_nid2obj(NID_ED25519);

        auto *tbs_alg = const_cast<X509_ALGOR *>(X509_get0_tbs_sigalg(x509));
        X509_ALGOR_set0(tbs_alg, const_cast<ASN1_OBJECT *>(ed25519_obj), V_ASN1_UNDEF, nullptr);

        const X509_ALGOR *outer_alg_const = nullptr;
        X509_get0_signature(nullptr, &outer_alg_const, x509);
        auto *outer_alg = const_cast<X509_ALGOR *>(outer_alg_const);
        X509_ALGOR_set0(outer_alg, const_cast<ASN1_OBJECT *>(ed25519_obj), V_ASN1_UNDEF, nullptr);

        const auto hmac_sig = crypto::hmac_sha512(
            auth_key,
            std::span<const std::uint8_t>(ed_keypair.public_key.data(), ed_keypair.public_key.size()));
        ERR_clear_error();
        auto sig_rc = X509_set1_signature_value(x509, hmac_sig.data(), hmac_sig.size());
        if (sig_rc != 1)
        {
            auto err = ERR_get_error();
            trace::error("{} X509_set1_signature_value failed, rc={} err=0x{:x}",
                         ShTag, sig_rc, err);
        }

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
            trace::debug("{} using dest certificate: {} bytes", ShTag, cert_der.size());
        }

        memory::vector<std::uint8_t> body;
        tls::write_u8(body, 0x00);

        memory::vector<std::uint8_t> cert_list;
        tls::write_u24(cert_list, cert_der.size());
        cert_list.insert(cert_list.end(), cert_der.begin(), cert_der.end());
        tls::write_u16(cert_list, 0);

        tls::write_u24(body, cert_list.size());
        body.insert(body.end(), cert_list.begin(), cert_list.end());
        return body;
    }

    static auto build_certificate_verify(
        const crypto::ed25519_keypair &ed_keypair,
        std::span<const std::uint8_t> transcript_hash)
        -> memory::vector<std::uint8_t>
    {
        static constexpr std::string_view context = "TLS 1.3, server CertificateVerify";
        static constexpr std::size_t padding_len = 64;

        memory::vector<std::uint8_t> message;
        message.reserve(padding_len + context.size() + 1 + transcript_hash.size());
        for (std::size_t i = 0; i < padding_len; ++i)
            message.push_back(0x20);
        message.insert(message.end(), context.begin(), context.end());
        message.push_back(0x00);
        message.insert(message.end(), transcript_hash.begin(), transcript_hash.end());

        std::array<std::uint8_t, 64> signature{};
        ED25519_sign(signature.data(), message.data(), message.size(),
                     ed_keypair.private_key.data());

        memory::vector<std::uint8_t> body;
        tls::write_u16(body, tls::SIGNATURE_SCHEME_ED25519);
        tls::write_u16(body, static_cast<std::uint16_t>(signature.size()));
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

        result.server_hello_record = make_tls_record(tls::CONTENT_TYPE_HANDSHAKE, sh_msg);
        result.change_cipher_spec_record = {tls::CONTENT_TYPE_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01};

        memory::vector<std::uint8_t> plaintext;
        crypto::ed25519_keypair ed_keypair{};

        const auto ee_body = build_encrypted_extensions();
        const auto ee_msg = make_handshake_message(tls::HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, ee_body);
        plaintext.insert(plaintext.end(), ee_msg.begin(), ee_msg.end());

        const auto cert_body = build_certificate(dest_certificate, auth_key, ed_keypair);
        const auto cert_msg = make_handshake_message(tls::HANDSHAKE_TYPE_CERTIFICATE, cert_body);
        plaintext.insert(plaintext.end(), cert_msg.begin(), cert_msg.end());

        const auto cv_transcript = crypto::sha256(
            client_hello_msg,
            {result.server_hello_msg.data(), result.server_hello_msg.size()},
            {plaintext.data(), plaintext.size()});

        const auto cv_body = build_certificate_verify(ed_keypair, cv_transcript);
        const auto cv_msg = make_handshake_message(tls::HANDSHAKE_TYPE_CERTIFICATE_VERIFY, cv_body);
        plaintext.insert(plaintext.end(), cv_msg.begin(), cv_msg.end());

        const auto transcript_for_finished = crypto::sha256(
            client_hello_msg,
            {result.server_hello_msg.data(), result.server_hello_msg.size()},
            plaintext);
        const auto verify_data = compute_finished_verify_data(
            handshake_keys.server_finished_key, transcript_for_finished);

        const auto finished_msg = make_handshake_message(
            tls::HANDSHAKE_TYPE_FINISHED, verify_data);
        plaintext.insert(plaintext.end(), finished_msg.begin(), finished_msg.end());

        result.encrypted_handshake_plaintext = plaintext;

        auto [enc_ec, encrypted_record] = encrypt_tls_record(
            handshake_keys.server_handshake_key,
            handshake_keys.server_handshake_iv,
            0,
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
} // namespace psm::stealth

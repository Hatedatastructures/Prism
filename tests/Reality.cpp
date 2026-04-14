/**
 * @file Reality.cpp
 * @brief Reality 证书离线验证测试
 * @details 生成一份 Reality ServerHello，提取其中的 Certificate 消息，
 * 使用 OpenSSL 解析叶子证书，验证 DER 是否可被正常解析且公钥类型为 Ed25519。
 */

#include <prism/protocol/reality/response.hpp>
#include <prism/protocol/reality/request.hpp>
#include <prism/protocol/reality/keygen.hpp>
#include <prism/crypto/x25519.hpp>
#include <prism/trace/spdlog.hpp>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <cstring>
#include <string>
#include <span>

namespace
{
    int passed = 0;
    int failed = 0;

    auto log_pass(const std::string &msg) -> void
    {
        ++passed;
        psm::trace::info("[Reality] PASS: {}", msg);
    }

    auto log_fail(const std::string &msg) -> void
    {
        ++failed;
        psm::trace::error("[Reality] FAIL: {}", msg);
    }

    auto read_u24(const std::uint8_t *p) -> std::size_t
    {
        return (static_cast<std::size_t>(p[0]) << 16) |
               (static_cast<std::size_t>(p[1]) << 8) |
               static_cast<std::size_t>(p[2]);
    }

    auto extract_leaf_cert_der(std::span<const std::uint8_t> handshake_plaintext)
        -> psm::memory::vector<std::uint8_t>
    {
        psm::memory::vector<std::uint8_t> cert_der;

        std::size_t offset = 0;
        while (offset + 4 <= handshake_plaintext.size())
        {
            const auto msg_type = handshake_plaintext[offset];
            const auto msg_len = read_u24(handshake_plaintext.data() + offset + 1);
            offset += 4;
            if (offset + msg_len > handshake_plaintext.size())
            {
                return {};
            }

            if (msg_type != psm::protocol::reality::tls::HANDSHAKE_TYPE_CERTIFICATE)
            {
                offset += msg_len;
                continue;
            }

            auto body = handshake_plaintext.subspan(offset, msg_len);
            if (body.size() < 4)
            {
                return {};
            }

            std::size_t pos = 0;
            const auto context_len = body[pos++];
            if (pos + context_len + 3 > body.size())
            {
                return {};
            }
            pos += context_len;

            const auto cert_list_len = read_u24(body.data() + pos);
            pos += 3;
            if (pos + cert_list_len > body.size() || cert_list_len < 5)
            {
                return {};
            }

            const auto cert_len = read_u24(body.data() + pos);
            pos += 3;
            if (pos + cert_len + 2 > body.size())
            {
                return {};
            }

            cert_der.insert(cert_der.end(), body.begin() + static_cast<std::ptrdiff_t>(pos),
                            body.begin() + static_cast<std::ptrdiff_t>(pos + cert_len));
            return cert_der;
        }

        return {};
    }
}

void TestRealityCertificateParsesAsEd25519()
{
    using namespace psm;
    using namespace psm::protocol::reality;

    client_hello_info client_hello;
    client_hello.session_id = {0x01, 0x02, 0x03, 0x04};
    client_hello.raw_message = {
        0x01, 0x00, 0x00, 0x05,
        0x03, 0x03, 0x00, 0x00, 0x00
    };

    auto eph = crypto::generate_x25519_keypair();

    key_material keys{};
    for (std::size_t i = 0; i < keys.server_finished_key.size(); ++i)
    {
        keys.server_finished_key[i] = static_cast<std::uint8_t>(i + 1);
    }
    for (std::size_t i = 0; i < keys.server_handshake_key.size(); ++i)
    {
        keys.server_handshake_key[i] = static_cast<std::uint8_t>(0x10 + i);
    }
    for (std::size_t i = 0; i < keys.server_handshake_iv.size(); ++i)
    {
        keys.server_handshake_iv[i] = static_cast<std::uint8_t>(0x20 + i);
    }

    std::array<std::uint8_t, 32> auth_key{};
    for (std::size_t i = 0; i < auth_key.size(); ++i)
    {
        auth_key[i] = static_cast<std::uint8_t>(0x40 + i);
    }

    const auto [ec, sh] = generate_server_hello(
        client_hello,
        std::span<const std::uint8_t>(eph.public_key.data(), eph.public_key.size()),
        keys,
        {},
        std::span<const std::uint8_t>(client_hello.raw_message.data(), client_hello.raw_message.size()),
        std::span<const std::uint8_t>(auth_key.data(), auth_key.size()));

    if (fault::failed(ec))
    {
        log_fail("generate_server_hello failed");
        return;
    }

    const auto cert_der = extract_leaf_cert_der(sh.encrypted_handshake_plaintext);
    if (cert_der.empty())
    {
        log_fail("failed to extract leaf certificate DER from handshake plaintext");
        return;
    }

    const auto *p = cert_der.data();
    X509 *x509 = d2i_X509(nullptr, &p, static_cast<long>(cert_der.size()));
    if (!x509)
    {
        log_fail("OpenSSL failed to parse generated certificate DER");
        return;
    }

    EVP_PKEY *pkey = X509_get_pubkey(x509);
    if (!pkey)
    {
        X509_free(x509);
        log_fail("X509_get_pubkey returned null");
        return;
    }

    const auto pkey_type = EVP_PKEY_id(pkey);
    if (pkey_type != EVP_PKEY_ED25519)
    {
        EVP_PKEY_free(pkey);
        X509_free(x509);
        log_fail("leaf certificate public key is not Ed25519");
        return;
    }

    if (X509_get_signature_nid(x509) != NID_ED25519)
    {
        EVP_PKEY_free(pkey);
        X509_free(x509);
        log_fail("certificate signature algorithm is not Ed25519");
        return;
    }

    EVP_PKEY_free(pkey);
    X509_free(x509);
    log_pass("RealityCertificateParsesAsEd25519");
}

int main()
{
    psm::trace::init({});

    TestRealityCertificateParsesAsEd25519();

    psm::trace::info("[Reality] =============================");
    psm::trace::info("[Reality] Passed: {}", passed);
    psm::trace::info("[Reality] Failed: {}", failed);
    psm::trace::info("[Reality] =============================");

    return failed == 0 ? 0 : 1;
}

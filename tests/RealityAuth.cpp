/**
 * @file RealityAuth.cpp
 * @brief Reality 认证逻辑单元测试
 * @details 测试 match_sni、match_shortid、hex_decode、hex_digit、verify_client_hello 等公开函数，
 *          以及 authenticate 完整流程中各失败路径（SNI 不匹配、无 X25519、无 TLS 1.3、
 *          session_id 过短）。
 */

#include <prism/memory.hpp>
#include <prism/stealth/facade/reality/util/auth.hpp>
#include <prism/protocol/tls/types.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>
#include <prism/crypto/aead.hpp>
#include <prism/crypto/hkdf.hpp>
#include <prism/crypto/x25519.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestMatchSniExactMatch(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> names;
        names.emplace_back("example.com");
        names.emplace_back("test.local");

        runner.Check(psm::stealth::reality::match_sni("example.com", names) == true,
                     "match_sni exact match");
        runner.Check(psm::stealth::reality::match_sni("test.local", names) == true,
                     "match_sni second entry match");
    }

    void TestMatchSniNoMatch(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> names;
        names.emplace_back("example.com");

        runner.Check(psm::stealth::reality::match_sni("other.com", names) == false,
                     "match_sni no match");
    }

    void TestMatchSniEmpty(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> names;
        names.emplace_back("example.com");

        runner.Check(psm::stealth::reality::match_sni("", names) == false,
                     "match_sni empty SNI returns false");
    }

    void TestMatchSniEmptyList(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> names;

        runner.Check(psm::stealth::reality::match_sni("example.com", names) == false,
                     "match_sni empty list returns false");
    }

    void TestMatchShortidWildcard(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> allowed;
        allowed.emplace_back(""); // empty = wildcard

        std::array<std::uint8_t, 8> short_id = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        runner.Check(psm::stealth::reality::match_shortid(short_id, allowed) == true,
                     "match_shortid wildcard (empty string) matches any");
    }

    void TestMatchShortidExactMatch(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> allowed;
        allowed.emplace_back("0102030405060708");

        std::array<std::uint8_t, 8> short_id = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        runner.Check(psm::stealth::reality::match_shortid(short_id, allowed) == true,
                     "match_shortid exact match");
    }

    void TestMatchShortidNoMatch(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> allowed;
        allowed.emplace_back("AABBCCDD");

        std::array<std::uint8_t, 8> short_id = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        runner.Check(psm::stealth::reality::match_shortid(short_id, allowed) == false,
                     "match_shortid no match");
    }

    void TestMatchShortidOddLength(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> allowed;
        allowed.emplace_back("AABBC"); // odd length hex

        std::array<std::uint8_t, 8> short_id = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        runner.Check(psm::stealth::reality::match_shortid(short_id, allowed) == false,
                     "match_shortid odd length skipped");
    }

    void TestMatchShortidEmptyList(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> allowed;
        std::array<std::uint8_t, 8> short_id = {0x01, 0x02, 0x03, 0x04};
        runner.Check(psm::stealth::reality::match_shortid(short_id, allowed) == false,
                     "match_shortid empty list returns false");
    }

    void TestHexDigit(TestRunner &runner)
    {
        auto &hd = psm::stealth::reality::hex_digit;
        runner.Check(hd('0') == 0, "hex_digit '0' == 0");
        runner.Check(hd('9') == 9, "hex_digit '9' == 9");
        runner.Check(hd('a') == 10, "hex_digit 'a' == 10");
        runner.Check(hd('f') == 15, "hex_digit 'f' == 15");
        runner.Check(hd('A') == 10, "hex_digit 'A' == 10");
        runner.Check(hd('F') == 15, "hex_digit 'F' == 15");
        runner.Check(hd('g') == -1, "hex_digit 'g' == -1");
        runner.Check(hd(' ') == -1, "hex_digit ' ' == -1");
        runner.Check(hd('\0') == -1, "hex_digit NUL == -1");
    }

    void TestHexDecode(TestRunner &runner)
    {
        auto &hxd = psm::stealth::reality::hex_decode;

        auto result = hxd("0102FF");
        runner.Check(result.size() == 3, "hex_decode length 3");
        runner.Check(result[0] == 0x01, "hex_decode byte 0");
        runner.Check(result[1] == 0x02, "hex_decode byte 1");
        runner.Check(result[2] == 0xFF, "hex_decode byte 2");

        auto empty = hxd("");
        runner.Check(empty.empty(), "hex_decode empty input");

        auto invalid = hxd("GG");
        runner.Check(invalid.empty(), "hex_decode invalid chars returns empty");

        auto odd = hxd("ABC");
        runner.Check(odd.size() == 1, "hex_decode odd length decodes first byte");
        runner.Check(odd[0] == 0xAB, "hex_decode odd length byte 0");
    }

    // === authenticate 深度路径测试 ===

    /**
     * @brief 辅助：构造 Reality config
     */
    auto make_config() -> psm::stealth::reality::config
    {
        psm::stealth::reality::config cfg;
        cfg.dest = psm::memory::string("www.example.com:443");
        cfg.server_names.emplace_back("www.example.com");
        cfg.private_key = psm::memory::string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        cfg.short_ids.emplace_back(""); // 通配符
        return cfg;
    }

    /**
     * @brief 辅助：构造最小 hello_features
     */
    auto make_hello_features() -> psm::protocol::tls::hello_features
    {
        psm::protocol::tls::hello_features feat;
        feat.server_name = psm::memory::string("www.example.com");
        feat.has_x25519 = true;
        feat.x25519_key.fill(0x42);
        feat.versions.push_back(psm::protocol::tls::VERSION_TLS13);
        feat.session_id_len = 32;
        feat.session_id.resize(32, 0xAA);
        feat.random.fill(0x00);
        return feat;
    }

    /**
     * @brief 辅助：构造 32 字节伪私钥
     */
    auto make_privkey() -> std::array<std::uint8_t, 32>
    {
        std::array<std::uint8_t, 32> key{};
        key[0] = 0x01;
        return key;
    }

    void TestAuthenticateSniMismatch(TestRunner &runner)
    {
        auto cfg = make_config();
        auto feat = make_hello_features();
        feat.server_name = psm::memory::string("evil.attacker.com");
        feat.raw_msg.resize(128, 0x00);

        auto key = make_privkey();
        auto [ec, result] = psm::stealth::reality::authenticate(
            cfg, feat, std::span<const std::uint8_t>{key.data(), key.size()});

        runner.Check(ec == psm::fault::code::badsni,
                     "authenticate: SNI mismatch → badsni");
        runner.Check(result.authenticated == false,
                     "authenticate: SNI mismatch → not authenticated");
    }

    void TestAuthenticateNoX25519(TestRunner &runner)
    {
        auto cfg = make_config();
        auto feat = make_hello_features();
        feat.has_x25519 = false;
        feat.raw_msg.resize(128, 0x00);

        auto key = make_privkey();
        auto [ec, result] = psm::stealth::reality::authenticate(
            cfg, feat, std::span<const std::uint8_t>{key.data(), key.size()});

        runner.Check(ec == psm::fault::code::unauth,
                     "authenticate: no X25519 → unauth");
        runner.Check(result.authenticated == false,
                     "authenticate: no X25519 → not authenticated");
    }

    void TestAuthenticateNoTls13(TestRunner &runner)
    {
        auto cfg = make_config();
        auto feat = make_hello_features();
        feat.versions.clear();
        feat.versions.push_back(psm::protocol::tls::VERSION_TLS12);
        feat.raw_msg.resize(128, 0x00);

        auto key = make_privkey();
        auto [ec, result] = psm::stealth::reality::authenticate(
            cfg, feat, std::span<const std::uint8_t>{key.data(), key.size()});

        runner.Check(ec == psm::fault::code::unauth,
                     "authenticate: no TLS 1.3 → unauth");
        runner.Check(result.authenticated == false,
                     "authenticate: no TLS 1.3 → not authenticated");
    }

    void TestAuthenticateSessionIdTooShort(TestRunner &runner)
    {
        auto cfg = make_config();
        auto feat = make_hello_features();
        feat.session_id_len = 16;
        feat.session_id.resize(16, 0xAA);
        feat.raw_msg.resize(128, 0x00);

        auto key = make_privkey();
        auto [ec, result] = psm::stealth::reality::authenticate(
            cfg, feat, std::span<const std::uint8_t>{key.data(), key.size()});

        runner.Check(ec == psm::fault::code::unauth,
                     "authenticate: short session_id → unauth");
        runner.Check(result.authenticated == false,
                     "authenticate: short session_id → not authenticated");
    }

    void TestAuthenticateEmptySniAllowed(TestRunner &runner)
    {
        // 空 SNI 不触发 badsni（verify_client_hello 仅在非空 SNI 时检查）
        auto cfg = make_config();
        auto feat = make_hello_features();
        feat.server_name.clear();
        feat.raw_msg.resize(128, 0x00);

        auto key = make_privkey();
        auto [ec, result] = psm::stealth::reality::authenticate(
            cfg, feat, std::span<const std::uint8_t>{key.data(), key.size()});

        // 空 SNI 跳过 SNI 检查，但后续 X25519/AEAD 会失败
        runner.Check(ec != psm::fault::code::badsni,
                     "authenticate: empty SNI → not badsni");
        runner.Check(result.authenticated == false,
                     "authenticate: empty SNI → not authenticated (crypto fails)");
    }

    // === match_shortid 边界条件 ===

    void TestMatchShortidInvalidHex(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> allowed;
        allowed.emplace_back("ZZZZ"); // 无效 hex 字符

        std::array<std::uint8_t, 8> short_id = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        runner.Check(psm::stealth::reality::match_shortid(short_id, allowed) == false,
                     "match_shortid invalid hex → false");
    }

    void TestMatchShortidPrefixMatch(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> allowed;
        allowed.emplace_back("0102"); // 仅匹配前 2 字节

        std::array<std::uint8_t, 8> short_id = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        runner.Check(psm::stealth::reality::match_shortid(short_id, allowed) == true,
                     "match_shortid prefix match");
    }

    void TestMatchShortidLongerAllowed(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> allowed;
        allowed.emplace_back("010203040506070809"); // 9 字节 > short_id 的 8 字节

        std::array<std::uint8_t, 8> short_id = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        runner.Check(psm::stealth::reality::match_shortid(short_id, allowed) == false,
                     "match_shortid longer allowed → false");
    }

    // === authenticate 成功路径 ===

    void TestAuthenticateFullSuccess(TestRunner &runner)
    {
        // 1. 生成服务端 X25519 密钥对
        auto server_kp = psm::crypto::generate_keypair();

        // 2. 客户端使用服务端公钥 + 自己的临时私钥执行 X25519
        auto client_kp = psm::crypto::generate_keypair();
        auto [kex_ec, shared_secret] = psm::crypto::x25519(
            client_kp.private_key, server_kp.public_key);
        runner.Check(psm::fault::succeeded(kex_ec), "authenticate success: X25519 kex ok");

        // 3. HKDF 派生 auth_key（与 auth.cpp 中 authenticate() 相同的流程）
        psm::protocol::tls::hello_features feat;
        feat.server_name = psm::memory::string("www.example.com");
        feat.has_x25519 = true;
        feat.x25519_key = client_kp.public_key;
        feat.versions.push_back(psm::protocol::tls::VERSION_TLS13);
        feat.random.fill(0x00);
        feat.session_id_len = 32;

        // 4. 派生 auth_key
        const auto prk = psm::crypto::hkdf_extract(
            std::span<const std::uint8_t>(feat.random.data(), 20),
            std::span<const std::uint8_t>(shared_secret.data(), shared_secret.size()));

        constexpr std::array<std::uint8_t, 7> reality_info{'R', 'E', 'A', 'L', 'I', 'T', 'Y'};
        const auto [expand_ec, auth_key_vec] = psm::crypto::hkdf_expand(
            std::span<const std::uint8_t>(prk.data(), prk.size()),
            std::span<const std::uint8_t>(reality_info.data(), reality_info.size()),
            32);
        runner.Check(psm::fault::succeeded(expand_ec), "authenticate success: HKDF-Expand ok");

        // 5. 构造明文 session_id：version(1) + random(7) + short_id(8) + padding(16) = 32 字节
        //    但 authenticate() 内部 open() 解密出 16 字节，所以明文实际只有 16 字节
        std::array<std::uint8_t, 16> plaintext_sid{};
        plaintext_sid[0] = 0x01; // version marker
        // bytes 8-15 = short_id（全 0x42）
        for (std::size_t i = 8; i < 16; ++i)
            plaintext_sid[i] = 0x42;

        // 6. AEAD 加密 → 密文(16) + tag(16) = 32 字节 = SESSION_ID_MAX_LEN
        psm::crypto::aead_context aead(psm::crypto::aead_cipher::aes_256_gcm,
                                        std::span<const std::uint8_t>(auth_key_vec.data(), auth_key_vec.size()));

        feat.raw_msg.resize(128, 0x00);

        std::array<std::uint8_t, psm::protocol::tls::AEAD_NONCE_LEN> nonce{};
        std::memcpy(nonce.data(), feat.random.data() + 20, psm::protocol::tls::AEAD_NONCE_LEN);

        std::array<std::uint8_t, 32> encrypted_sid{};
        const auto seal_ec = aead.seal(psm::crypto::seal_input{
            std::span<std::uint8_t>(encrypted_sid.data(), encrypted_sid.size()),
            std::span<const std::uint8_t>(plaintext_sid.data(), plaintext_sid.size()),
            std::span<const std::uint8_t>(nonce.data(), nonce.size()),
            std::span<const std::uint8_t>(feat.raw_msg.data(), feat.raw_msg.size())});
        runner.Check(psm::fault::succeeded(seal_ec), "authenticate success: AEAD seal ok");

        // 7. 设置 session_id（32 字节密文+tag）
        feat.session_id.assign(encrypted_sid.begin(), encrypted_sid.end());

        // 8. 配置 short_ids 匹配
        psm::stealth::reality::config cfg;
        cfg.dest = psm::memory::string("www.example.com:443");
        cfg.server_names.emplace_back("www.example.com");
        cfg.private_key = psm::memory::string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        cfg.short_ids.emplace_back(""); // 通配符，接受任意 short_id

        // 9. 调用 authenticate
        auto [auth_ec, auth_result] = psm::stealth::reality::authenticate(
            cfg, feat, std::span<const std::uint8_t>{server_kp.private_key.data(), 32});

        runner.Check(psm::fault::succeeded(auth_ec), "authenticate success: success");
        runner.Check(auth_result.authenticated == true, "authenticate success: authenticated=true");
        runner.Check(auth_result.shared_secret == shared_secret, "authenticate success: shared_secret matches");
    }

    void TestAuthenticateKexFail(TestRunner &runner)
    {
        // 使用全零公钥（低阶点）→ shared_secret 全零 → kexfail
        auto cfg = make_config();
        auto feat = make_hello_features();
        feat.x25519_key.fill(0x00); // 全零公钥
        feat.raw_msg.resize(128, 0x00);

        auto key = make_privkey();
        auto [ec, result] = psm::stealth::reality::authenticate(
            cfg, feat, std::span<const std::uint8_t>{key.data(), key.size()});

        runner.Check(ec == psm::fault::code::kexfail,
                     "authenticate: zero pubkey → kexfail");
        runner.Check(result.authenticated == false,
                     "authenticate: zero pubkey → not authenticated");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RealityAuth");

    TestMatchSniExactMatch(runner);
    TestMatchSniNoMatch(runner);
    TestMatchSniEmpty(runner);
    TestMatchSniEmptyList(runner);
    TestMatchShortidWildcard(runner);
    TestMatchShortidExactMatch(runner);
    TestMatchShortidNoMatch(runner);
    TestMatchShortidOddLength(runner);
    TestMatchShortidEmptyList(runner);
    TestHexDigit(runner);
    TestHexDecode(runner);

    // === authenticate 深度路径测试 ===
    TestAuthenticateSniMismatch(runner);
    TestAuthenticateNoX25519(runner);
    TestAuthenticateNoTls13(runner);
    TestAuthenticateSessionIdTooShort(runner);
    TestAuthenticateEmptySniAllowed(runner);

    // === match_shortid 边界条件 ===
    TestMatchShortidInvalidHex(runner);
    TestMatchShortidPrefixMatch(runner);
    TestMatchShortidLongerAllowed(runner);

    // === authenticate 成功/失败路径 ===
    TestAuthenticateFullSuccess(runner);
    TestAuthenticateKexFail(runner);

    return runner.Summary();
}

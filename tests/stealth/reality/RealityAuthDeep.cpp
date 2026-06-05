/**
 * @file RealityAuthDeep.cpp
 * @brief Reality auth 深度测试
 * @details 测试 auth.cpp 中所有可测试的同步纯函数：
 *          hex_digit、hex_decode、match_sni、match_shortid、verify_client_hello。
 *          通过 #include 源文件覆盖编译行。
 */

#include <gtest/gtest.h>

#include <prism/memory.hpp>

// #include 源文件增加覆盖率计数
#include "../../src/prism/stealth/facade/reality/util/auth.cpp"

namespace
{
    using namespace psm::stealth::reality;
    namespace tls = psm::protocol::tls;
    using reality_config = psm::stealth::reality::config;

    // ─── hex_digit ─────────────────────────────────

    TEST(RealityAuthDeep, HexDigitDigits)
    {
        EXPECT_TRUE(hex_digit('0') == 0) << "hex_digit: '0' -> 0";
        EXPECT_TRUE(hex_digit('9') == 9) << "hex_digit: '9' -> 9";
        EXPECT_TRUE(hex_digit('5') == 5) << "hex_digit: '5' -> 5";
    }

    TEST(RealityAuthDeep, HexDigitLowerHex)
    {
        EXPECT_TRUE(hex_digit('a') == 10) << "hex_digit: 'a' -> 10";
        EXPECT_TRUE(hex_digit('f') == 15) << "hex_digit: 'f' -> 15";
    }

    TEST(RealityAuthDeep, HexDigitUpperHex)
    {
        EXPECT_TRUE(hex_digit('A') == 10) << "hex_digit: 'A' -> 10";
        EXPECT_TRUE(hex_digit('F') == 15) << "hex_digit: 'F' -> 15";
    }

    TEST(RealityAuthDeep, HexDigitInvalid)
    {
        EXPECT_TRUE(hex_digit('g') == -1) << "hex_digit: 'g' -> -1";
        EXPECT_TRUE(hex_digit('G') == -1) << "hex_digit: 'G' -> -1";
        EXPECT_TRUE(hex_digit('z') == -1) << "hex_digit: 'z' -> -1";
        EXPECT_TRUE(hex_digit('/') == -1) << "hex_digit: '/' -> -1";
        EXPECT_TRUE(hex_digit(':') == -1) << "hex_digit: ':' -> -1";
        EXPECT_TRUE(hex_digit(' ') == -1) << "hex_digit: ' ' -> -1";
        EXPECT_TRUE(hex_digit('\0') == -1) << "hex_digit: NUL -> -1";
    }

    // ─── hex_decode ────────────────────────────────

    TEST(RealityAuthDeep, HexDecodeEmpty)
    {
        auto result = hex_decode("");
        EXPECT_TRUE(result.empty()) << "hex_decode: empty -> empty";
    }

    TEST(RealityAuthDeep, HexDecodeValid)
    {
        auto result = hex_decode("0123456789abcdef");
        EXPECT_TRUE(result.size() == 8) << "hex_decode: 16 chars -> 8 bytes";
        EXPECT_TRUE(result[0] == 0x01) << "hex_decode: byte 0 = 0x01";
        EXPECT_TRUE(result[1] == 0x23) << "hex_decode: byte 1 = 0x23";
        EXPECT_TRUE(result[7] == 0xEF) << "hex_decode: byte 7 = 0xEF";
    }

    TEST(RealityAuthDeep, HexDecodeUpperCase)
    {
        auto result = hex_decode("AABBCCDD");
        EXPECT_TRUE(result.size() == 4) << "hex_decode: uppercase -> 4 bytes";
        EXPECT_TRUE(result[0] == 0xAA) << "hex_decode: AA";
        EXPECT_TRUE(result[1] == 0xBB) << "hex_decode: BB";
    }

    TEST(RealityAuthDeep, HexDecodeMixedCase)
    {
        auto result = hex_decode("aAbBcCdD");
        EXPECT_TRUE(result.size() == 4) << "hex_decode: mixed case -> 4 bytes";
        EXPECT_TRUE(result[0] == 0xAA) << "hex_decode: aA -> 0xAA";
    }

    TEST(RealityAuthDeep, HexDecodeInvalidChars)
    {
        auto result = hex_decode("ZZ");
        EXPECT_TRUE(result.empty()) << "hex_decode: invalid chars -> empty";
    }

    TEST(RealityAuthDeep, HexDecodeOddLength)
    {
        // 奇数长度，只处理前偶数个字符
        auto result = hex_decode("ABC");
        EXPECT_TRUE(result.size() == 1) << "hex_decode: odd length -> 1 byte";
        EXPECT_TRUE(result[0] == 0xAB) << "hex_decode: odd -> first byte only";
    }

    TEST(RealityAuthDeep, HexDecodeSinglePair)
    {
        auto result = hex_decode("FF");
        EXPECT_TRUE(result.size() == 1) << "hex_decode: single pair -> 1 byte";
        EXPECT_TRUE(result[0] == 0xFF) << "hex_decode: FF -> 0xFF";
    }

    // ─── match_sni ─────────────────────────────────

    TEST(RealityAuthDeep, MatchSniEmpty)
    {
        psm::memory::vector<psm::memory::string> names(psm::memory::current_resource());
        EXPECT_TRUE(!match_sni("", names)) << "match_sni: empty sni -> false";
    }

    TEST(RealityAuthDeep, MatchSniEmptyList)
    {
        psm::memory::vector<psm::memory::string> names(psm::memory::current_resource());
        EXPECT_TRUE(!match_sni("example.com", names)) << "match_sni: empty list -> false";
    }

    TEST(RealityAuthDeep, MatchSniMatch)
    {
        psm::memory::vector<psm::memory::string> names(psm::memory::current_resource());
        names.emplace_back("example.com");
        names.emplace_back("test.org");
        EXPECT_TRUE(match_sni("example.com", names)) << "match_sni: match first";
        EXPECT_TRUE(match_sni("test.org", names)) << "match_sni: match second";
    }

    TEST(RealityAuthDeep, MatchSniNoMatch)
    {
        psm::memory::vector<psm::memory::string> names(psm::memory::current_resource());
        names.emplace_back("example.com");
        EXPECT_TRUE(!match_sni("other.com", names)) << "match_sni: no match";
    }

    // ─── match_shortid ─────────────────────────────

    TEST(RealityAuthDeep, MatchShortIdEmptyAllowed)
    {
        // 空字符串表示接受任意 short_id
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("");
        std::array<std::uint8_t, 8> sid{};
        EXPECT_TRUE(match_shortid(sid, ids)) << "match_shortid: empty allowed -> true";
    }

    TEST(RealityAuthDeep, MatchShortIdExactMatch)
    {
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("0102030405060708");
        std::array<std::uint8_t, 8> sid{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        EXPECT_TRUE(match_shortid(sid, ids)) << "match_shortid: exact match";
    }

    TEST(RealityAuthDeep, MatchShortIdNoMatch)
    {
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("AABBCCDD");
        std::array<std::uint8_t, 8> sid{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        EXPECT_TRUE(!match_shortid(sid, ids)) << "match_shortid: no match";
    }

    TEST(RealityAuthDeep, MatchShortIdOddLengthHex)
    {
        // 奇数长度的 hex 字符串应被跳过
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("AAB"); // 奇数
        std::array<std::uint8_t, 8> sid{0xAA, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        EXPECT_TRUE(!match_shortid(sid, ids)) << "match_shortid: odd hex -> skip";
    }

    TEST(RealityAuthDeep, MatchShortIdInvalidHex)
    {
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("ZZZZ"); // 无效 hex
        std::array<std::uint8_t, 8> sid{};
        EXPECT_TRUE(!match_shortid(sid, ids)) << "match_shortid: invalid hex -> skip";
    }

    TEST(RealityAuthDeep, MatchShortIdEmptyList)
    {
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        std::array<std::uint8_t, 8> sid{};
        EXPECT_TRUE(!match_shortid(sid, ids)) << "match_shortid: empty list -> false";
    }

    TEST(RealityAuthDeep, MatchShortIdPrefixMatch)
    {
        // short_id 比 allowed 长，但前缀匹配
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("0102");
        std::array<std::uint8_t, 8> sid{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        EXPECT_TRUE(match_shortid(sid, ids)) << "match_shortid: prefix match";
    }

    TEST(RealityAuthDeep, MatchShortIdEmptyAllowedFirst)
    {
        // 第一个为空（通配），直接返回 true
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("");
        ids.emplace_back("AABBCCDD");
        std::array<std::uint8_t, 8> sid{};
        EXPECT_TRUE(match_shortid(sid, ids)) << "match_shortid: wildcard first -> true";
    }

    // ─── verify_client_hello ───────────────────────

    TEST(RealityAuthDeep, VerifyClientHelloSuccess)
    {
        reality_config cfg;
        tls::hello_features hello;
        hello.server_name = "example.com";
        cfg.server_names.emplace_back("example.com");
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        EXPECT_TRUE(ec == psm::fault::code::success) << "verify: success";
    }

    TEST(RealityAuthDeep, VerifyClientHelloSniMismatch)
    {
        reality_config cfg;
        tls::hello_features hello;
        hello.server_name = "bad.com";
        cfg.server_names.emplace_back("example.com");
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        EXPECT_TRUE(ec == psm::fault::code::badsni) << "verify: SNI mismatch -> badsni";
    }

    TEST(RealityAuthDeep, VerifyClientHelloEmptySni)
    {
        // 空 SNI 不触发 mismatch 检查
        reality_config cfg;
        tls::hello_features hello;
        // server_name 默认为空
        cfg.server_names.emplace_back("example.com");
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        EXPECT_TRUE(ec == psm::fault::code::success) << "verify: empty SNI -> success (skip check)";
    }

    TEST(RealityAuthDeep, VerifyClientHelloNoX25519)
    {
        reality_config cfg;
        tls::hello_features hello;
        hello.has_x25519 = false;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        EXPECT_TRUE(ec == psm::fault::code::unauth) << "verify: no x25519 -> unauth";
    }

    TEST(RealityAuthDeep, VerifyClientHelloNoTls13)
    {
        reality_config cfg;
        tls::hello_features hello;
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS12); // 只有 TLS 1.2
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        EXPECT_TRUE(ec == psm::fault::code::unauth) << "verify: no TLS 1.3 -> unauth";
    }

    TEST(RealityAuthDeep, VerifyClientHelloSessionIdTooShort)
    {
        reality_config cfg;
        tls::hello_features hello;
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(16, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        EXPECT_TRUE(ec == psm::fault::code::unauth) << "verify: short session_id -> unauth";
    }

    TEST(RealityAuthDeep, VerifyClientHelloNoVersions)
    {
        reality_config cfg;
        tls::hello_features hello;
        hello.has_x25519 = true;
        // versions 为空
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        EXPECT_TRUE(ec == psm::fault::code::unauth) << "verify: no versions -> unauth";
    }

    TEST(RealityAuthDeep, VerifyClientHelloEmptyServerNames)
    {
        // server_names 为空列表，任何 SNI 都不匹配
        reality_config cfg;
        tls::hello_features hello;
        hello.server_name = "example.com";
        // cfg.server_names 为空
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        EXPECT_TRUE(ec == psm::fault::code::badsni) << "verify: empty server_names + SNI -> badsni";
    }

} // namespace

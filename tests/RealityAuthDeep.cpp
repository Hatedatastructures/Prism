/**
 * @file RealityAuthDeep.cpp
 * @brief Reality auth 深度测试
 * @details 测试 auth.cpp 中所有可测试的同步纯函数：
 *          hex_digit、hex_decode、match_sni、match_shortid、verify_client_hello。
 *          通过 #include 源文件覆盖编译行。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件增加覆盖率计数
#include "../src/prism/stealth/facade/reality/util/auth.cpp"

using psm::testing::TestRunner;

namespace
{
    using namespace psm::stealth::reality;
    namespace tls = psm::protocol::tls;

    // ─── hex_digit ─────────────────────────────────

    void TestHexDigitDigits(TestRunner &runner)
    {
        runner.Check(hex_digit('0') == 0, "hex_digit: '0' -> 0");
        runner.Check(hex_digit('9') == 9, "hex_digit: '9' -> 9");
        runner.Check(hex_digit('5') == 5, "hex_digit: '5' -> 5");
    }

    void TestHexDigitLowerHex(TestRunner &runner)
    {
        runner.Check(hex_digit('a') == 10, "hex_digit: 'a' -> 10");
        runner.Check(hex_digit('f') == 15, "hex_digit: 'f' -> 15");
    }

    void TestHexDigitUpperHex(TestRunner &runner)
    {
        runner.Check(hex_digit('A') == 10, "hex_digit: 'A' -> 10");
        runner.Check(hex_digit('F') == 15, "hex_digit: 'F' -> 15");
    }

    void TestHexDigitInvalid(TestRunner &runner)
    {
        runner.Check(hex_digit('g') == -1, "hex_digit: 'g' -> -1");
        runner.Check(hex_digit('G') == -1, "hex_digit: 'G' -> -1");
        runner.Check(hex_digit('z') == -1, "hex_digit: 'z' -> -1");
        runner.Check(hex_digit('/') == -1, "hex_digit: '/' -> -1");
        runner.Check(hex_digit(':') == -1, "hex_digit: ':' -> -1");
        runner.Check(hex_digit(' ') == -1, "hex_digit: ' ' -> -1");
        runner.Check(hex_digit('\0') == -1, "hex_digit: NUL -> -1");
    }

    // ─── hex_decode ────────────────────────────────

    void TestHexDecodeEmpty(TestRunner &runner)
    {
        auto result = hex_decode("");
        runner.Check(result.empty(), "hex_decode: empty -> empty");
    }

    void TestHexDecodeValid(TestRunner &runner)
    {
        auto result = hex_decode("0123456789abcdef");
        runner.Check(result.size() == 8, "hex_decode: 16 chars -> 8 bytes");
        runner.Check(result[0] == 0x01, "hex_decode: byte 0 = 0x01");
        runner.Check(result[1] == 0x23, "hex_decode: byte 1 = 0x23");
        runner.Check(result[7] == 0xEF, "hex_decode: byte 7 = 0xEF");
    }

    void TestHexDecodeUpperCase(TestRunner &runner)
    {
        auto result = hex_decode("AABBCCDD");
        runner.Check(result.size() == 4, "hex_decode: uppercase -> 4 bytes");
        runner.Check(result[0] == 0xAA, "hex_decode: AA");
        runner.Check(result[1] == 0xBB, "hex_decode: BB");
    }

    void TestHexDecodeMixedCase(TestRunner &runner)
    {
        auto result = hex_decode("aAbBcCdD");
        runner.Check(result.size() == 4, "hex_decode: mixed case -> 4 bytes");
        runner.Check(result[0] == 0xAA, "hex_decode: aA -> 0xAA");
    }

    void TestHexDecodeInvalidChars(TestRunner &runner)
    {
        auto result = hex_decode("ZZ");
        runner.Check(result.empty(), "hex_decode: invalid chars -> empty");
    }

    void TestHexDecodeOddLength(TestRunner &runner)
    {
        // 奇数长度，只处理前偶数个字符
        auto result = hex_decode("ABC");
        runner.Check(result.size() == 1, "hex_decode: odd length -> 1 byte");
        runner.Check(result[0] == 0xAB, "hex_decode: odd -> first byte only");
    }

    void TestHexDecodeSinglePair(TestRunner &runner)
    {
        auto result = hex_decode("FF");
        runner.Check(result.size() == 1, "hex_decode: single pair -> 1 byte");
        runner.Check(result[0] == 0xFF, "hex_decode: FF -> 0xFF");
    }

    // ─── match_sni ─────────────────────────────────

    void TestMatchSniEmpty(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> names(psm::memory::current_resource());
        runner.Check(!match_sni("", names), "match_sni: empty sni -> false");
    }

    void TestMatchSniEmptyList(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> names(psm::memory::current_resource());
        runner.Check(!match_sni("example.com", names), "match_sni: empty list -> false");
    }

    void TestMatchSniMatch(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> names(psm::memory::current_resource());
        names.emplace_back("example.com");
        names.emplace_back("test.org");
        runner.Check(match_sni("example.com", names), "match_sni: match first");
        runner.Check(match_sni("test.org", names), "match_sni: match second");
    }

    void TestMatchSniNoMatch(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> names(psm::memory::current_resource());
        names.emplace_back("example.com");
        runner.Check(!match_sni("other.com", names), "match_sni: no match");
    }

    // ─── match_shortid ─────────────────────────────

    void TestMatchShortIdEmptyAllowed(TestRunner &runner)
    {
        // 空字符串表示接受任意 short_id
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("");
        std::array<std::uint8_t, 8> sid{};
        runner.Check(match_shortid(sid, ids), "match_shortid: empty allowed -> true");
    }

    void TestMatchShortIdExactMatch(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("0102030405060708");
        std::array<std::uint8_t, 8> sid{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        runner.Check(match_shortid(sid, ids), "match_shortid: exact match");
    }

    void TestMatchShortIdNoMatch(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("AABBCCDD");
        std::array<std::uint8_t, 8> sid{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        runner.Check(!match_shortid(sid, ids), "match_shortid: no match");
    }

    void TestMatchShortIdOddLengthHex(TestRunner &runner)
    {
        // 奇数长度的 hex 字符串应被跳过
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("AAB"); // 奇数
        std::array<std::uint8_t, 8> sid{0xAA, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        runner.Check(!match_shortid(sid, ids), "match_shortid: odd hex -> skip");
    }

    void TestMatchShortIdInvalidHex(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("ZZZZ"); // 无效 hex
        std::array<std::uint8_t, 8> sid{};
        runner.Check(!match_shortid(sid, ids), "match_shortid: invalid hex -> skip");
    }

    void TestMatchShortIdEmptyList(TestRunner &runner)
    {
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        std::array<std::uint8_t, 8> sid{};
        runner.Check(!match_shortid(sid, ids), "match_shortid: empty list -> false");
    }

    void TestMatchShortIdPrefixMatch(TestRunner &runner)
    {
        // short_id 比 allowed 长，但前缀匹配
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("0102");
        std::array<std::uint8_t, 8> sid{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        runner.Check(match_shortid(sid, ids), "match_shortid: prefix match");
    }

    void TestMatchShortIdEmptyAllowedFirst(TestRunner &runner)
    {
        // 第一个为空（通配），直接返回 true
        psm::memory::vector<psm::memory::string> ids(psm::memory::current_resource());
        ids.emplace_back("");
        ids.emplace_back("AABBCCDD");
        std::array<std::uint8_t, 8> sid{};
        runner.Check(match_shortid(sid, ids), "match_shortid: wildcard first -> true");
    }

    // ─── verify_client_hello ───────────────────────

    void TestVerifyClientHelloSuccess(TestRunner &runner)
    {
        config cfg;
        tls::hello_features hello;
        hello.server_name = "example.com";
        cfg.server_names.emplace_back("example.com");
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        runner.Check(ec == psm::fault::code::success, "verify: success");
    }

    void TestVerifyClientHelloSniMismatch(TestRunner &runner)
    {
        config cfg;
        tls::hello_features hello;
        hello.server_name = "bad.com";
        cfg.server_names.emplace_back("example.com");
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        runner.Check(ec == psm::fault::code::badsni, "verify: SNI mismatch -> badsni");
    }

    void TestVerifyClientHelloEmptySni(TestRunner &runner)
    {
        // 空 SNI 不触发 mismatch 检查
        config cfg;
        tls::hello_features hello;
        // server_name 默认为空
        cfg.server_names.emplace_back("example.com");
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        runner.Check(ec == psm::fault::code::success, "verify: empty SNI -> success (skip check)");
    }

    void TestVerifyClientHelloNoX25519(TestRunner &runner)
    {
        config cfg;
        tls::hello_features hello;
        hello.has_x25519 = false;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        runner.Check(ec == psm::fault::code::unauth, "verify: no x25519 -> unauth");
    }

    void TestVerifyClientHelloNoTls13(TestRunner &runner)
    {
        config cfg;
        tls::hello_features hello;
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS12); // 只有 TLS 1.2
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        runner.Check(ec == psm::fault::code::unauth, "verify: no TLS 1.3 -> unauth");
    }

    void TestVerifyClientHelloSessionIdTooShort(TestRunner &runner)
    {
        config cfg;
        tls::hello_features hello;
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(16, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        runner.Check(ec == psm::fault::code::unauth, "verify: short session_id -> unauth");
    }

    void TestVerifyClientHelloNoVersions(TestRunner &runner)
    {
        config cfg;
        tls::hello_features hello;
        hello.has_x25519 = true;
        // versions 为空
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        runner.Check(ec == psm::fault::code::unauth, "verify: no versions -> unauth");
    }

    void TestVerifyClientHelloEmptyServerNames(TestRunner &runner)
    {
        // server_names 为空列表，任何 SNI 都不匹配
        config cfg;
        tls::hello_features hello;
        hello.server_name = "example.com";
        // cfg.server_names 为空
        hello.has_x25519 = true;
        hello.versions.push_back(tls::VERSION_TLS13);
        hello.session_id.assign(32, 0x42);

        auto ec = verify_client_hello(cfg, hello);
        runner.Check(ec == psm::fault::code::badsni, "verify: empty server_names + SNI -> badsni");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RealityAuthDeep");

    // hex_digit
    TestHexDigitDigits(runner);
    TestHexDigitLowerHex(runner);
    TestHexDigitUpperHex(runner);
    TestHexDigitInvalid(runner);

    // hex_decode
    TestHexDecodeEmpty(runner);
    TestHexDecodeValid(runner);
    TestHexDecodeUpperCase(runner);
    TestHexDecodeMixedCase(runner);
    TestHexDecodeInvalidChars(runner);
    TestHexDecodeOddLength(runner);
    TestHexDecodeSinglePair(runner);

    // match_sni
    TestMatchSniEmpty(runner);
    TestMatchSniEmptyList(runner);
    TestMatchSniMatch(runner);
    TestMatchSniNoMatch(runner);

    // match_shortid
    TestMatchShortIdEmptyAllowed(runner);
    TestMatchShortIdExactMatch(runner);
    TestMatchShortIdNoMatch(runner);
    TestMatchShortIdOddLengthHex(runner);
    TestMatchShortIdInvalidHex(runner);
    TestMatchShortIdEmptyList(runner);
    TestMatchShortIdPrefixMatch(runner);
    TestMatchShortIdEmptyAllowedFirst(runner);

    // verify_client_hello
    TestVerifyClientHelloSuccess(runner);
    TestVerifyClientHelloSniMismatch(runner);
    TestVerifyClientHelloEmptySni(runner);
    TestVerifyClientHelloNoX25519(runner);
    TestVerifyClientHelloNoTls13(runner);
    TestVerifyClientHelloSessionIdTooShort(runner);
    TestVerifyClientHelloNoVersions(runner);
    TestVerifyClientHelloEmptyServerNames(runner);

    return runner.Summary();
}

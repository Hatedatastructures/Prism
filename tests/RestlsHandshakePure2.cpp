/**
 * @file RestlsHandshakePure2.cpp
 * @brief Restls 握手纯函数深度测试
 * @details 测试 restls::handshake 匿名命名空间中的纯解析函数：
 *          extract_server_random、is_tls13_server_hello、parse_host_port、
 *          extract_server_info。
 *          通过 #include 源文件获取匿名命名空间函数，确保 gcov 源行覆盖。
 */

#include <prism/memory.hpp>
#include <prism/stealth/facade/restls/handshake.hpp>
#include <prism/stealth/common.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件获取匿名命名空间中的纯函数
#include "../src/prism/stealth/facade/restls/handshake.cpp"

using psm::testing::TestRunner;

namespace
{
    using namespace psm::stealth::restls;

    // ─── 辅助：构造 TLS ServerHello 帧缓冲 ────────────

    auto build_server_hello(bool with_tls13_ext, std::uint8_t session_id_len = 0)
        -> std::vector<std::byte>
    {
        // Extensions: supported_versions = type(2)+len(2)+value(2) = 6
        std::size_t ext_size = with_tls13_ext ? 6 : 0;
        std::size_t body_size = 2 + 32 + 1 + session_id_len + 2 + 1 + 2 + ext_size;
        std::size_t total = 5 + 1 + 3 + body_size;

        std::vector<std::byte> buf(total, std::byte{0});
        auto *raw = reinterpret_cast<std::uint8_t *>(buf.data());

        // TLS record header
        raw[0] = 0x16;
        raw[1] = 0x03; raw[2] = 0x01;
        raw[3] = static_cast<std::uint8_t>(((body_size + 4) >> 8) & 0xFF);
        raw[4] = static_cast<std::uint8_t>((body_size + 4) & 0xFF);

        // Handshake header
        raw[5] = 0x02;
        raw[6] = static_cast<std::uint8_t>((body_size >> 16) & 0xFF);
        raw[7] = static_cast<std::uint8_t>((body_size >> 8) & 0xFF);
        raw[8] = static_cast<std::uint8_t>(body_size & 0xFF);

        // Server version (legacy TLS 1.2)
        raw[9] = 0x03; raw[10] = 0x03;

        // Random (32 bytes)
        for (int i = 0; i < 32; ++i)
            raw[11 + i] = static_cast<std::uint8_t>(i);

        // Session ID length + session ID
        std::size_t offset = 43;
        raw[offset] = session_id_len;
        for (int i = 0; i < session_id_len; ++i)
            raw[offset + 1 + i] = static_cast<std::uint8_t>(i + 0xA0);
        offset += 1 + session_id_len;

        // Cipher suite
        raw[offset] = 0x13; raw[offset + 1] = 0x01;
        offset += 2;

        // Compression
        raw[offset] = 0x00;
        offset += 1;

        // Extensions length
        raw[offset] = static_cast<std::uint8_t>((ext_size >> 8) & 0xFF);
        raw[offset + 1] = static_cast<std::uint8_t>(ext_size & 0xFF);
        offset += 2;

        if (with_tls13_ext)
        {
            // supported_versions extension (type=43, len=2, value=0x0304)
            raw[offset] = 0x00; raw[offset + 1] = 43;
            raw[offset + 2] = 0x00; raw[offset + 3] = 0x02;
            raw[offset + 4] = 0x03; raw[offset + 5] = 0x04;
        }

        return buf;
    }

    // ─── extract_server_random ─────────────────────

    void TestExtractServerRandomValid(TestRunner &runner)
    {
        auto hello = build_server_hello(false);
        auto result = extract_server_random(hello);
        runner.Check(result.has_value(), "extract_sr: valid has value");
        runner.Check((*result)[0] == 0, "extract_sr: first byte=0");
        runner.Check((*result)[31] == 31, "extract_sr: last byte=31");
    }

    void TestExtractServerRandomTooShort(TestRunner &runner)
    {
        std::vector<std::byte> short_hello(10, std::byte{0});
        auto result = extract_server_random(short_hello);
        runner.Check(!result.has_value(), "extract_sr: too short -> nullopt");
    }

    void TestExtractServerRandomExactSize(TestRunner &runner)
    {
        // 刚好够: tls_hdrsize(5)+hs_type(1)+hs_len(3)+version(2)+random(32) = 43
        std::vector<std::byte> hello(43, std::byte{0xFF});
        auto result = extract_server_random(hello);
        runner.Check(result.has_value(), "extract_sr: exact size works");
        runner.Check((*result)[0] == 0xFF, "extract_sr: first byte correct");
        runner.Check((*result)[31] == 0xFF, "extract_sr: last byte correct");
    }

    void TestExtractServerRandomOneBelowMinimum(TestRunner &runner)
    {
        std::vector<std::byte> hello(42, std::byte{0});
        auto result = extract_server_random(hello);
        runner.Check(!result.has_value(), "extract_sr: 42 bytes -> nullopt");
    }

    // ─── is_tls13_server_hello ─────────────────────

    void TestIsTls13ServerHelloTrue(TestRunner &runner)
    {
        auto hello = build_server_hello(true);
        auto result = is_tls13_server_hello(hello);
        runner.Check(result == true, "is_tls13: with ext43 -> true");
    }

    void TestIsTls13ServerHelloFalse(TestRunner &runner)
    {
        auto hello = build_server_hello(false);
        auto result = is_tls13_server_hello(hello);
        runner.Check(result == false, "is_tls13: no ext43 -> false");
    }

    void TestIsTls13ServerHelloTooShort(TestRunner &runner)
    {
        std::vector<std::byte> short_hello(10, std::byte{0});
        auto result = is_tls13_server_hello(short_hello);
        runner.Check(result == false, "is_tls13: too short -> false");
    }

    void TestIsTls13ServerHelloWithSessionId(TestRunner &runner)
    {
        auto hello = build_server_hello(true, 32);
        auto result = is_tls13_server_hello(hello);
        runner.Check(result == true, "is_tls13: with session_id + ext43 -> true");
    }

    void TestIsTls13ServerHelloTruncatedBeforeSessionId(TestRunner &runner)
    {
        auto hello = build_server_hello(true);
        // 截断到 random 结束位置，缺少 session_id_len 字段
        std::vector<std::byte> truncated(hello.begin(), hello.begin() + 43);
        auto result = is_tls13_server_hello(truncated);
        runner.Check(result == false, "is_tls13: truncated before session_id -> false");
    }

    void TestIsTls13ServerHelloWrongExtValue(TestRunner &runner)
    {
        auto hello = build_server_hello(true);
        // 修改 extension value 为 TLS 1.2 (0x0303)
        auto *raw = reinterpret_cast<std::uint8_t *>(hello.data());
        raw[hello.size() - 1] = 0x03;
        auto result = is_tls13_server_hello(hello);
        runner.Check(result == false, "is_tls13: ext43 with TLS 1.2 value -> false");
    }

    void TestIsTls13ServerHelloTruncatedInExtensions(TestRunner &runner)
    {
        auto hello = build_server_hello(true);
        // 截断到 extensions 区域中间
        std::vector<std::byte> truncated(hello.begin(), hello.begin() + hello.size() - 2);
        auto result = is_tls13_server_hello(truncated);
        runner.Check(result == false, "is_tls13: truncated in extensions -> false");
    }

    // ─── parse_host_port ───────────────────────────

    void TestParseHostPortDefault(TestRunner &runner)
    {
        auto [host, port] = parse_host_port("example.com");
        runner.Check(host == "example.com", "parse_hp: host without port");
        runner.Check(port == 443, "parse_hp: default port 443");
    }

    void TestParseHostPortCustom(TestRunner &runner)
    {
        auto [host, port] = parse_host_port("example.com:8443");
        runner.Check(host == "example.com", "parse_hp: host with port");
        runner.Check(port == 8443, "parse_hp: custom port 8443");
    }

    void TestParseHostPortIP(TestRunner &runner)
    {
        auto [host, port] = parse_host_port("1.2.3.4:853");
        runner.Check(host == "1.2.3.4", "parse_hp: IP host");
        runner.Check(port == 853, "parse_hp: IP port 853");
    }

    void TestParseHostPortIPv6NoPort(TestRunner &runner)
    {
        auto [host, port] = parse_host_port("::1");
        runner.Check(port == 443, "parse_hp: IPv6 fallback to 443");
    }

    void TestParseHostPortInvalidPort(TestRunner &runner)
    {
        auto [host, port] = parse_host_port("example.com:abc");
        runner.Check(host == "example.com", "parse_hp: invalid port -> host ok");
        runner.Check(port == 443, "parse_hp: invalid port -> default 443");
    }

    void TestParseHostPortEmpty(TestRunner &runner)
    {
        auto [host, port] = parse_host_port("");
        runner.Check(host.empty(), "parse_hp: empty input -> empty host");
        runner.Check(port == 443, "parse_hp: empty input -> default 443");
    }

    // ─── extract_server_info ───────────────────────

    void TestExtractServerInfoTls13(TestRunner &runner)
    {
        auto hello = build_server_hello(true);
        std::array<std::uint8_t, 32> secret{};
        for (int i = 0; i < 32; ++i)
            secret[i] = static_cast<std::uint8_t>(i);

        auto span = std::span<const std::uint8_t, 32>(secret);
        auto result = extract_server_info(hello, span);
        runner.Check(result.has_value(), "extract_si: tls13 -> has value");
        runner.Check(result->version == tls_version::v13, "extract_si: tls13 version");
        runner.Check(result->server_random[0] == 0, "extract_si: sr[0]=0");
        runner.Check(result->server_random[31] == 31, "extract_si: sr[31]=31");
        runner.Check(result->auth_mask.size() > 0, "extract_si: auth_mask not empty");
    }

    void TestExtractServerInfoTls12(TestRunner &runner)
    {
        auto hello = build_server_hello(false);
        std::array<std::uint8_t, 32> secret{};
        for (int i = 0; i < 32; ++i)
            secret[i] = static_cast<std::uint8_t>(i + 0x80);

        auto span = std::span<const std::uint8_t, 32>(secret);
        auto result = extract_server_info(hello, span);
        runner.Check(result.has_value(), "extract_si: tls12 -> has value");
        runner.Check(result->version == tls_version::v12, "extract_si: tls12 version");
    }

    void TestExtractServerInfoTooShort(TestRunner &runner)
    {
        std::vector<std::byte> short_hello(10, std::byte{0});
        std::array<std::uint8_t, 32> secret{};
        auto span = std::span<const std::uint8_t, 32>(secret);
        auto result = extract_server_info(short_hello, span);
        runner.Check(!result.has_value(), "extract_si: too short -> nullopt");
    }

    void TestExtractServerInfoWithSessionId(TestRunner &runner)
    {
        auto hello = build_server_hello(true, 16);
        std::array<std::uint8_t, 32> secret{};
        for (int i = 0; i < 32; ++i)
            secret[i] = static_cast<std::uint8_t>(i);

        auto span = std::span<const std::uint8_t, 32>(secret);
        auto result = extract_server_info(hello, span);
        runner.Check(result.has_value(), "extract_si: with session_id -> has value");
        runner.Check(result->version == tls_version::v13, "extract_si: session_id tls13");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RestlsHandshakePure2");

    // extract_server_random
    TestExtractServerRandomValid(runner);
    TestExtractServerRandomTooShort(runner);
    TestExtractServerRandomExactSize(runner);
    TestExtractServerRandomOneBelowMinimum(runner);

    // is_tls13_server_hello
    TestIsTls13ServerHelloTrue(runner);
    TestIsTls13ServerHelloFalse(runner);
    TestIsTls13ServerHelloTooShort(runner);
    TestIsTls13ServerHelloWithSessionId(runner);
    TestIsTls13ServerHelloTruncatedBeforeSessionId(runner);
    TestIsTls13ServerHelloWrongExtValue(runner);
    TestIsTls13ServerHelloTruncatedInExtensions(runner);

    // parse_host_port
    TestParseHostPortDefault(runner);
    TestParseHostPortCustom(runner);
    TestParseHostPortIP(runner);
    TestParseHostPortIPv6NoPort(runner);
    TestParseHostPortInvalidPort(runner);
    TestParseHostPortEmpty(runner);

    // extract_server_info
    TestExtractServerInfoTls13(runner);
    TestExtractServerInfoTls12(runner);
    TestExtractServerInfoTooShort(runner);
    TestExtractServerInfoWithSessionId(runner);

    return runner.Summary();
}

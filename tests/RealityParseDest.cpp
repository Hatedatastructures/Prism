/**
 * @file RealityParseDest.cpp
 * @brief Reality parse_dest 纯函数测试
 * @details 测试 parse_dest 的全分支：空输入、无端口默认443、
 *          IPv6 [::1]:443 格式、普通 host:port、无效端口。
 */

#include <prism/memory.hpp>
#include <prism/stealth/facade/reality/handshake.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestParseDestEmpty(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("", host, port);
        runner.Check(!ok, "parse_dest: empty returns false");
    }

    void TestParseDestNoPort(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("www.example.com", host, port);
        runner.Check(ok, "parse_dest: no port → success");
        runner.Check(host == "www.example.com", "parse_dest: host without port");
        runner.Check(port == 443, "parse_dest: default port=443");
    }

    void TestParseDestWithPort(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("www.example.com:8443", host, port);
        runner.Check(ok, "parse_dest: with port → success");
        runner.Check(host == "www.example.com", "parse_dest: host extracted");
        runner.Check(port == 8443, "parse_dest: port=8443");
    }

    void TestParseDestIpv6(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("[::1]:443", host, port);
        runner.Check(ok, "parse_dest: ipv6 → success");
        runner.Check(host == "::1", "parse_dest: ipv6 host=::1");
        runner.Check(port == 443, "parse_dest: ipv6 port=443");
    }

    void TestParseDestIpv6NoPort(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("[2001:db8::1]", host, port);
        runner.Check(ok, "parse_dest: ipv6 no port → success");
        runner.Check(host == "2001:db8::1", "parse_dest: ipv6 host extracted");
        runner.Check(port == 443, "parse_dest: ipv6 default port=443");
    }

    void TestParseDestInvalidPort(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("host:abc", host, port);
        runner.Check(!ok, "parse_dest: invalid port → false");
    }

    void TestParseDestOnlyColon(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;
        // 单冒号 → host="" port 取决于 from_chars 对空字符串的行为
        auto ok = psm::stealth::reality::parse_dest(":", host, port);
        // 这里 host="" 且 port 尝试解析空字符串 → 应该失败
        runner.Check(!ok, "parse_dest: single colon → false (empty port)");
    }

    void TestParseDestPortZero(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 99;
        auto ok = psm::stealth::reality::parse_dest("host:0", host, port);
        runner.Check(ok, "parse_dest: port 0 → success");
        runner.Check(host == "host", "parse_dest: host for port 0");
        runner.Check(port == 0, "parse_dest: port=0");
    }

    void TestParseDestPortMax(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("host:65535", host, port);
        runner.Check(ok, "parse_dest: port 65535 → success");
        runner.Check(port == 65535, "parse_dest: port=65535");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RealityParseDest");

    TestParseDestEmpty(runner);
    TestParseDestNoPort(runner);
    TestParseDestWithPort(runner);
    TestParseDestIpv6(runner);
    TestParseDestIpv6NoPort(runner);
    TestParseDestInvalidPort(runner);
    TestParseDestOnlyColon(runner);
    TestParseDestPortZero(runner);
    TestParseDestPortMax(runner);

    return runner.Summary();
}

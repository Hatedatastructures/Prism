/**
 * @file RealityHandshakePure.cpp
 * @brief Reality 握手纯函数单元测试
 * @details 测试 parse_dest 函数对各种 dest 配置字符串的解析能力，
 *          包括标准 host:port、IPv6、默认端口、空字符串及无效端口等边界情况。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include <cstdint>
#include <string>
#include <string_view>

// parse_dest 在命名命名空间中声明，链接时由 prism 静态库提供定义
namespace psm::stealth::reality
{
    [[nodiscard]] auto parse_dest(std::string_view dest, std::string &host, std::uint16_t &port)
        -> bool;
} // namespace psm::stealth::reality

using psm::testing::TestRunner;

namespace
{
    /**
     * @brief 测试标准 host:port 格式解析
     */
    void test_host_port(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;

        const auto ok = psm::stealth::reality::parse_dest("www.example.com:443", host, port);
        runner.Check(ok, "parse_dest: host:port → true");
        runner.Check(host == "www.example.com", "parse_dest: host 提取正确");
        runner.Check(port == 443, "parse_dest: port=443");
    }

    /**
     * @brief 测试无冒号时默认端口 443
     */
    void test_default_port(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;

        const auto ok = psm::stealth::reality::parse_dest("example.com", host, port);
        runner.Check(ok, "parse_dest: 无冒号 → true");
        runner.Check(host == "example.com", "parse_dest: 仅 host 时 host 正确");
        runner.Check(port == 443, "parse_dest: 无冒号默认 port=443");
    }

    /**
     * @brief 测试 IPv6 地址带端口
     */
    void test_ipv6_with_port(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;

        const auto ok = psm::stealth::reality::parse_dest("[::1]:8443", host, port);
        runner.Check(ok, "parse_dest: [::1]:8443 → true");
        runner.Check(host == "::1", "parse_dest: IPv6 host=::1");
        runner.Check(port == 8443, "parse_dest: IPv6 port=8443");
    }

    /**
     * @brief 测试 IPv6 地址无端口（默认 443）
     */
    void test_ipv6_no_port(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;

        const auto ok = psm::stealth::reality::parse_dest("[::1]", host, port);
        runner.Check(ok, "parse_dest: [::1] → true");
        runner.Check(host == "::1", "parse_dest: IPv6 无端口 host=::1");
        runner.Check(port == 443, "parse_dest: IPv6 无端口默认 port=443");
    }

    /**
     * @brief 测试 IPv6 完整地址带端口
     */
    void test_ipv6_full_addr(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;

        const auto ok = psm::stealth::reality::parse_dest("[2001:db8::1]:12345", host, port);
        runner.Check(ok, "parse_dest: [2001:db8::1]:12345 → true");
        runner.Check(host == "2001:db8::1", "parse_dest: IPv6 host=2001:db8::1");
        runner.Check(port == 12345, "parse_dest: IPv6 port=12345");
    }

    /**
     * @brief 测试空字符串应返回 false
     */
    void test_empty(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;

        const auto ok = psm::stealth::reality::parse_dest("", host, port);
        runner.Check(!ok, "parse_dest: 空字符串 → false");
    }

    /**
     * @brief 测试无效端口号（非数字）应返回 false
     */
    void test_invalid_port(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;

        const auto ok = psm::stealth::reality::parse_dest("host:abc", host, port);
        runner.Check(!ok, "parse_dest: host:abc → false");
    }

    /**
     * @brief 测试无冒号的纯主机名（默认端口场景补充）
     */
    void test_no_colon(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;

        const auto ok = psm::stealth::reality::parse_dest("justahost", host, port);
        runner.Check(ok, "parse_dest: justahost → true");
        runner.Check(host == "justahost", "parse_dest: 无冒号 host 正确");
        runner.Check(port == 443, "parse_dest: 无冒号 port=443");
    }

    /**
     * @brief 测试自定义端口
     */
    void test_custom_port(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;

        const auto ok = psm::stealth::reality::parse_dest("my.server:8080", host, port);
        runner.Check(ok, "parse_dest: my.server:8080 → true");
        runner.Check(host == "my.server", "parse_dest: host=my.server");
        runner.Check(port == 8080, "parse_dest: port=8080");
    }

    /**
     * @brief 测试仅冒号（边界情况）
     */
    void test_colon_only(TestRunner &runner)
    {
        std::string host;
        std::uint16_t port = 0;

        const auto ok = psm::stealth::reality::parse_dest(":", host, port);
        runner.Check(!ok, "parse_dest: 仅冒号 → false");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RealityHandshakePure");

    test_host_port(runner);
    test_default_port(runner);
    test_ipv6_with_port(runner);
    test_ipv6_no_port(runner);
    test_ipv6_full_addr(runner);
    test_empty(runner);
    test_invalid_port(runner);
    test_no_colon(runner);
    test_custom_port(runner);
    test_colon_only(runner);

    return runner.Summary();
}

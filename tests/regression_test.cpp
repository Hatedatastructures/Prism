/**
 * @file regression_test.cpp
 * @brief 回归测试：验证关键修复点
 * @details 测试以下关键修复：
 * 1. IPv6 host:port 解析
 * 2. TLS 内层协议探测
 * 3. trojan lease 持有和释放
 */

#include <prism/protocol/analysis.hpp>
#include <prism/agent/account/directory.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <string>
#include <string_view>

namespace
{
    int passed = 0;
    int failed = 0;

    void log_info(const std::string_view msg)
    {
        psm::trace::info("[RegressionTest] {}", msg);
    }

    void log_pass(const std::string_view msg)
    {
        ++passed;
        psm::trace::info("[RegressionTest] PASS: {}", msg);
    }

    void log_fail(const std::string_view msg)
    {
        ++failed;
        psm::trace::error("[RegressionTest] FAIL: {}", msg);
    }
}

/**
 * @brief 测试 IPv6 host:port 解析
 */
void test_ipv6_parsing()
{
    log_info("=== Testing IPv6 host:port parsing ===");

    psm::memory::resource_pointer mr = psm::memory::current_resource();

    auto parse = [&](const std::string_view input) -> std::pair<psm::memory::string, psm::memory::string>
    {
        psm::protocol::analysis::target t = psm::protocol::analysis::resolve(input, mr);
        return {t.host, t.port};
    };

    {
        auto [h, p] = parse("[::1]:443");
        if (h != "::1" || p != "443")
        {
            log_fail("IPv6 loopback parsing failed");
            return;
        }
    }

    {
        auto [h, p] = parse("[2001:db8::1]:8080");
        if (h != "2001:db8::1" || p != "8080")
        {
            log_fail("IPv6 full address parsing failed");
            return;
        }
    }

    {
        auto [h, p] = parse("[fe80::1]:443");
        if (h != "fe80::1" || p != "443")
        {
            log_fail("IPv6 link-local parsing failed");
            return;
        }
    }

    {
        auto [h, p] = parse("example.com:8080");
        if (h != "example.com" || p != "8080")
        {
            log_fail("IPv4 host:port parsing failed");
            return;
        }
    }

    {
        auto [h, p] = parse("192.168.1.1:443");
        if (h != "192.168.1.1" || p != "443")
        {
            log_fail("IPv4 address parsing failed");
            return;
        }
    }

    log_pass("IPv6 host:port parsing");
}

/**
 * @brief 测试 TLS 内层协议探测
 */
void test_inner_protocol_detection()
{
    log_info("=== Testing TLS inner protocol detection ===");

    {
        std::string http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        auto result = psm::protocol::analysis::detect_inner(http_request);
        if (result != psm::protocol::inner_protocol::http)
        {
            log_fail("HTTP detection failed");
            return;
        }
    }

    {
        std::string partial_data = "GET ";
        auto result = psm::protocol::analysis::detect_inner(partial_data);
        if (result != psm::protocol::inner_protocol::http)
        {
            log_fail("Partial HTTP detection failed");
            return;
        }
    }

    {
        std::string short_data(30, 'a');
        auto result = psm::protocol::analysis::detect_inner(short_data);
        if (result != psm::protocol::inner_protocol::undetermined)
        {
            log_fail("Short data should be undetermined");
            return;
        }
    }

    {
        std::string trojan_like(60, 'a');
        trojan_like[56] = '\r';
        trojan_like[57] = '\n';
        trojan_like[58] = 0x01;
        trojan_like[59] = 0x01;
        auto result = psm::protocol::analysis::detect_inner(trojan_like);
        if (result != psm::protocol::inner_protocol::trojan)
        {
            log_fail("Trojan detection failed");
            return;
        }
    }

    {
        std::string invalid_trojan(60, 'a');
        invalid_trojan[56] = 'x';
        auto result = psm::protocol::analysis::detect_inner(invalid_trojan);
        if (result != psm::protocol::inner_protocol::http)
        {
            log_fail("Invalid Trojan should be HTTP");
            return;
        }
    }

    log_pass("TLS inner protocol detection");
}

/**
 * @brief 测试 Trojan lease 持有和释放
 */
void test_trojan_lease()
{
    log_info("=== Testing Trojan lease hold and release ===");

    psm::agent::account::directory dir;
    dir.upsert("test_credential", 2);

    {
        auto lease1 = psm::agent::account::try_acquire(dir, "test_credential");
        if (!lease1)
        {
            log_fail("First lease acquire failed");
            return;
        }

        auto entry = dir.find("test_credential");
        if (!entry || entry->active_connections.load() != 1)
        {
            log_fail("Active connections count incorrect after first lease");
            return;
        }

        auto lease2 = psm::agent::account::try_acquire(dir, "test_credential");
        if (!lease2)
        {
            log_fail("Second lease acquire failed");
            return;
        }

        if (entry->active_connections.load() != 2)
        {
            log_fail("Active connections count incorrect after second lease");
            return;
        }

        auto lease3 = psm::agent::account::try_acquire(dir, "test_credential");
        if (lease3)
        {
            log_fail("Third lease should fail due to limit");
            return;
        }
    }

    auto entry = dir.find("test_credential");
    if (!entry || entry->active_connections.load() != 0)
    {
        log_fail("Active connections should be 0 after leases released");
        return;
    }

    log_pass("Trojan lease hold and release");
}

int main()
{
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    log_info("Starting regression tests...");

    test_ipv6_parsing();
    test_inner_protocol_detection();
    test_trojan_lease();

    log_info("Regression tests completed.");

    psm::trace::info("[RegressionTest] Results: {} passed, {} failed", passed, failed);

    return failed > 0 ? 1 : 0;
}

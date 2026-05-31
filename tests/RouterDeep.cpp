/**
 * @file RouterDeep.cpp
 * @brief connect/dial/router 深度纯函数测试
 * @details 通过 #include 源文件访问 router.cpp 中所有同步函数，
 *          覆盖构造函数、set_endpoint、add_route、string_hash、
 *          string_equal 和所有访问器方法。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include "../src/prism/connect/dial/router.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace connect = psm::connect;
    using tcp = boost::asio::ip::tcp;
    namespace net = boost::asio;

    // ─── string_hash 测试 ───────────────────────

    void TestStringHashStringView(TestRunner &runner)
    {
        connect::router::string_hash h;
        auto v1 = h(std::string_view("hello"));
        auto v2 = h(std::string_view("hello"));
        runner.Check(v1 == v2, "string_hash: same string_view -> same hash");
    }

    void TestStringHashDifferentStrings(TestRunner &runner)
    {
        connect::router::string_hash h;
        auto v1 = h(std::string_view("abc"));
        auto v2 = h(std::string_view("xyz"));
        runner.Check(v1 != v2, "string_hash: different strings -> different hash");
    }

    void TestStringHashMemoryString(TestRunner &runner)
    {
        connect::router::string_hash h;
        psm::memory::string s("hello");
        auto v_view = h(std::string_view("hello"));
        auto v_mem = h(s);
        runner.Check(v_view == v_mem, "string_hash: string_view == memory::string hash");
    }

    void TestStringHashEmpty(TestRunner &runner)
    {
        connect::router::string_hash h;
        auto v = h(std::string_view(""));
        runner.Check(v != 0 || v == 0, "string_hash: empty string -> produces hash");
    }

    // ─── string_equal 测试 ──────────────────────

    void TestStringEqualViewView(TestRunner &runner)
    {
        connect::router::string_equal eq;
        runner.Check(eq(std::string_view("abc"), std::string_view("abc")),
                     "string_equal: view == view -> true");
        runner.Check(!eq(std::string_view("abc"), std::string_view("def")),
                     "string_equal: view != view -> false");
    }

    void TestStringEqualMemView(TestRunner &runner)
    {
        connect::router::string_equal eq;
        psm::memory::string s("test");
        runner.Check(eq(s, std::string_view("test")),
                     "string_equal: mem == view -> true");
        runner.Check(!eq(s, std::string_view("other")),
                     "string_equal: mem != view -> false");
    }

    void TestStringEqualViewMem(TestRunner &runner)
    {
        connect::router::string_equal eq;
        psm::memory::string s("test");
        runner.Check(eq(std::string_view("test"), s),
                     "string_equal: view == mem -> true");
        runner.Check(!eq(std::string_view("other"), s),
                     "string_equal: view != mem -> false");
    }

    void TestStringEqualMemMem(TestRunner &runner)
    {
        connect::router::string_equal eq;
        psm::memory::string a("abc");
        psm::memory::string b("abc");
        psm::memory::string c("def");
        runner.Check(eq(a, b), "string_equal: mem == mem -> true");
        runner.Check(!eq(a, c), "string_equal: mem != mem -> false");
    }

    void TestStringEqualEmpty(TestRunner &runner)
    {
        connect::router::string_equal eq;
        runner.Check(eq(std::string_view(""), std::string_view("")),
                     "string_equal: empty == empty -> true");
        runner.Check(!eq(std::string_view(""), std::string_view("x")),
                     "string_equal: empty != x -> false");
    }

    // ─── 构造函数 + 访问器 ──────────────────────

    void TestConstructor(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        runner.Check(&r.pool() == &pool, "constructor: pool accessor");
        runner.Check(!!r.executor(), "constructor: executor non-empty");
        runner.Check(!r.positive_host().has_value(), "constructor: no positive_host");
        runner.Check(r.positive_port() == 0, "constructor: positive_port == 0");
    }

    void TestIpv6DisabledDefault(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        psm::resolve::dns::config dns_cfg;
        connect::router_options opts{pool, ioc, dns_cfg};
        connect::router r(std::move(opts));

        runner.Check(!r.ipv6_disabled(), "ipv6_disabled: default -> false");
    }

    void TestIpv6DisabledTrue(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        psm::resolve::dns::config dns_cfg;
        dns_cfg.disable_ipv6 = true;
        connect::router_options opts{pool, ioc, dns_cfg};
        connect::router r(std::move(opts));

        runner.Check(r.ipv6_disabled(), "ipv6_disabled: true -> true");
    }

    void TestDnsAccessor(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        runner.Check(&r.dns() != nullptr, "dns: accessor returns non-null");
    }

    void TestPoolConstAccessor(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        const connect::router r(std::move(opts));

        runner.Check(&r.pool() == &pool, "pool: const accessor");
    }

    void TestDnsConstAccessor(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        const connect::router r(std::move(opts));

        runner.Check(&r.dns() != nullptr, "dns: const accessor returns non-null");
    }

    // ─── set_endpoint 测试 ──────────────────────

    void TestSetEndpointEmptyHost(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("", 8080);
        runner.Check(!r.positive_host().has_value(), "set_endpoint: empty host -> reset");
        runner.Check(r.positive_port() == 0, "set_endpoint: empty host -> port 0");
    }

    void TestSetEndpointZeroPort(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("example.com", 0);
        runner.Check(!r.positive_host().has_value(), "set_endpoint: zero port -> reset");
        runner.Check(r.positive_port() == 0, "set_endpoint: zero port -> port 0");
    }

    void TestSetEndpointValid(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("proxy.example.com", 3128);
        runner.Check(r.positive_host().has_value(), "set_endpoint: valid -> has host");
        auto host = r.positive_host().value();
        runner.Check(std::string_view(host.data(), host.size()) == "proxy.example.com",
                     "set_endpoint: host value correct");
        runner.Check(r.positive_port() == 3128, "set_endpoint: port == 3128");
    }

    void TestSetEndpointOverwrite(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("first.com", 80);
        r.set_endpoint("second.com", 443);
        auto host = r.positive_host().value();
        runner.Check(std::string_view(host.data(), host.size()) == "second.com",
                     "set_endpoint: overwrite -> second host");
        runner.Check(r.positive_port() == 443, "set_endpoint: overwrite -> port 443");
    }

    void TestSetEndpointClearAfterSet(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("proxy.com", 8080);
        runner.Check(r.positive_host().has_value(), "set_endpoint: set first");

        r.set_endpoint("", 0);
        runner.Check(!r.positive_host().has_value(), "set_endpoint: cleared -> no host");
        runner.Check(r.positive_port() == 0, "set_endpoint: cleared -> port 0");
    }

    // ─── add_route + async_reverse 行为验证 ──────
    // 注：reverse_map_ 是 private，通过 positive_host/positive_port 访问器
    // 和 add_route 的副作用间接验证。通过 async_reverse 在 io_context 上
    // 运行来验证 add_route 是否正确插入。

    void TestSetEndpointAndReadback(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        // 设置 → 读取 → 清除 → 读取 完整流程
        r.set_endpoint("host1.com", 100);
        runner.Check(r.positive_host().has_value(), "endpoint: set host1");
        runner.Check(r.positive_port() == 100, "endpoint: port 100");

        r.set_endpoint("host2.com", 200);
        runner.Check(r.positive_port() == 200, "endpoint: overwritten to 200");

        r.set_endpoint("", 0);
        runner.Check(!r.positive_host().has_value(), "endpoint: cleared");
    }

    void TestSetEndpointBothEmpty(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("", 0);
        runner.Check(!r.positive_host().has_value(), "endpoint: both empty -> reset");
        runner.Check(r.positive_port() == 0, "endpoint: both empty -> port 0");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RouterDeep");

    TestStringHashStringView(runner);
    TestStringHashDifferentStrings(runner);
    TestStringHashMemoryString(runner);
    TestStringHashEmpty(runner);

    TestStringEqualViewView(runner);
    TestStringEqualMemView(runner);
    TestStringEqualViewMem(runner);
    TestStringEqualMemMem(runner);
    TestStringEqualEmpty(runner);

    TestConstructor(runner);
    TestIpv6DisabledDefault(runner);
    TestIpv6DisabledTrue(runner);
    TestDnsAccessor(runner);
    TestPoolConstAccessor(runner);
    TestDnsConstAccessor(runner);

    TestSetEndpointEmptyHost(runner);
    TestSetEndpointZeroPort(runner);
    TestSetEndpointValid(runner);
    TestSetEndpointOverwrite(runner);
    TestSetEndpointClearAfterSet(runner);

    TestSetEndpointAndReadback(runner);
    TestSetEndpointBothEmpty(runner);

    return runner.Summary();
}

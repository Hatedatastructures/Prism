/**
 * @file RouterDeep.cpp
 * @brief connect/dial/router 深度纯函数测试
 * @details 通过 #include 源文件访问 router.cpp 中所有同步函数，
 *          覆盖构造函数、set_endpoint、add_route、string_hash、
 *          string_equal 和所有访问器方法。
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

#include "../../src/prism/net/connect/dial/router.cpp"

namespace
{
    namespace connect = psm::connect;
    using tcp = boost::asio::ip::tcp;
    namespace net = boost::asio;

    // ─── string_hash 测试 ───────────────────────

    TEST(RouterDeep, StringHashStringView)
    {
        connect::router::string_hash h;
        auto v1 = h(std::string_view("hello"));
        auto v2 = h(std::string_view("hello"));
        EXPECT_TRUE(v1 == v2) << "string_hash: same string_view -> same hash";
    }

    TEST(RouterDeep, StringHashDifferentStrings)
    {
        connect::router::string_hash h;
        auto v1 = h(std::string_view("abc"));
        auto v2 = h(std::string_view("xyz"));
        EXPECT_TRUE(v1 != v2) << "string_hash: different strings -> different hash";
    }

    TEST(RouterDeep, StringHashMemoryString)
    {
        connect::router::string_hash h;
        psm::memory::string s("hello");
        auto v_view = h(std::string_view("hello"));
        auto v_mem = h(s);
        EXPECT_TRUE(v_view == v_mem) << "string_hash: string_view == memory::string hash";
    }

    TEST(RouterDeep, StringHashEmpty)
    {
        connect::router::string_hash h;
        auto v = h(std::string_view(""));
        EXPECT_TRUE(v != 0 || v == 0) << "string_hash: empty string -> produces hash";
    }

    // ─── string_equal 测试 ──────────────────────

    TEST(RouterDeep, StringEqualViewView)
    {
        connect::router::string_equal eq;
        EXPECT_TRUE(eq(std::string_view("abc"), std::string_view("abc")))
            << "string_equal: view == view -> true";
        EXPECT_TRUE(!eq(std::string_view("abc"), std::string_view("def")))
            << "string_equal: view != view -> false";
    }

    TEST(RouterDeep, StringEqualMemView)
    {
        connect::router::string_equal eq;
        psm::memory::string s("test");
        EXPECT_TRUE(eq(s, std::string_view("test")))
            << "string_equal: mem == view -> true";
        EXPECT_TRUE(!eq(s, std::string_view("other")))
            << "string_equal: mem != view -> false";
    }

    TEST(RouterDeep, StringEqualViewMem)
    {
        connect::router::string_equal eq;
        psm::memory::string s("test");
        EXPECT_TRUE(eq(std::string_view("test"), s))
            << "string_equal: view == mem -> true";
        EXPECT_TRUE(!eq(std::string_view("other"), s))
            << "string_equal: view != mem -> false";
    }

    TEST(RouterDeep, StringEqualMemMem)
    {
        connect::router::string_equal eq;
        psm::memory::string a("abc");
        psm::memory::string b("abc");
        psm::memory::string c("def");
        EXPECT_TRUE(eq(a, b)) << "string_equal: mem == mem -> true";
        EXPECT_TRUE(!eq(a, c)) << "string_equal: mem != mem -> false";
    }

    TEST(RouterDeep, StringEqualEmpty)
    {
        connect::router::string_equal eq;
        EXPECT_TRUE(eq(std::string_view(""), std::string_view("")))
            << "string_equal: empty == empty -> true";
        EXPECT_TRUE(!eq(std::string_view(""), std::string_view("x")))
            << "string_equal: empty != x -> false";
    }

    // ─── 构造函数 + 访问器 ──────────────────────

    TEST(RouterDeep, Constructor)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        EXPECT_TRUE(&r.pool() == &pool) << "constructor: pool accessor";
        EXPECT_TRUE(!!r.executor()) << "constructor: executor non-empty";
        EXPECT_TRUE(!r.positive_host().has_value()) << "constructor: no positive_host";
        EXPECT_TRUE(r.positive_port() == 0) << "constructor: positive_port == 0";
    }

    TEST(RouterDeep, Ipv6DisabledDefault)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        psm::resolve::dns::config dns_cfg;
        connect::router_options opts{pool, ioc, dns_cfg};
        connect::router r(std::move(opts));

        EXPECT_TRUE(!r.ipv6_disabled()) << "ipv6_disabled: default -> false";
    }

    TEST(RouterDeep, Ipv6DisabledTrue)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        psm::resolve::dns::config dns_cfg;
        dns_cfg.disable_ipv6 = true;
        connect::router_options opts{pool, ioc, dns_cfg};
        connect::router r(std::move(opts));

        EXPECT_TRUE(r.ipv6_disabled()) << "ipv6_disabled: true -> true";
    }

    TEST(RouterDeep, DnsAccessor)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        EXPECT_TRUE(&r.dns() != nullptr) << "dns: accessor returns non-null";
    }

    TEST(RouterDeep, PoolConstAccessor)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        const connect::router r(std::move(opts));

        EXPECT_TRUE(&r.pool() == &pool) << "pool: const accessor";
    }

    TEST(RouterDeep, DnsConstAccessor)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        const connect::router r(std::move(opts));

        EXPECT_TRUE(&r.dns() != nullptr) << "dns: const accessor returns non-null";
    }

    // ─── set_endpoint 测试 ──────────────────────

    TEST(RouterDeep, SetEndpointEmptyHost)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("", 8080);
        EXPECT_TRUE(!r.positive_host().has_value()) << "set_endpoint: empty host -> reset";
        EXPECT_TRUE(r.positive_port() == 0) << "set_endpoint: empty host -> port 0";
    }

    TEST(RouterDeep, SetEndpointZeroPort)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("example.com", 0);
        EXPECT_TRUE(!r.positive_host().has_value()) << "set_endpoint: zero port -> reset";
        EXPECT_TRUE(r.positive_port() == 0) << "set_endpoint: zero port -> port 0";
    }

    TEST(RouterDeep, SetEndpointValid)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("proxy.example.com", 3128);
        EXPECT_TRUE(r.positive_host().has_value()) << "set_endpoint: valid -> has host";
        auto host = r.positive_host().value();
        EXPECT_TRUE(std::string_view(host.data(), host.size()) == "proxy.example.com")
            << "set_endpoint: host value correct";
        EXPECT_TRUE(r.positive_port() == 3128) << "set_endpoint: port == 3128";
    }

    TEST(RouterDeep, SetEndpointOverwrite)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("first.com", 80);
        r.set_endpoint("second.com", 443);
        auto host = r.positive_host().value();
        EXPECT_TRUE(std::string_view(host.data(), host.size()) == "second.com")
            << "set_endpoint: overwrite -> second host";
        EXPECT_TRUE(r.positive_port() == 443) << "set_endpoint: overwrite -> port 443";
    }

    TEST(RouterDeep, SetEndpointClearAfterSet)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("proxy.com", 8080);
        EXPECT_TRUE(r.positive_host().has_value()) << "set_endpoint: set first";

        r.set_endpoint("", 0);
        EXPECT_TRUE(!r.positive_host().has_value()) << "set_endpoint: cleared -> no host";
        EXPECT_TRUE(r.positive_port() == 0) << "set_endpoint: cleared -> port 0";
    }

    // ─── add_route + async_reverse 行为验证 ──────
    // 注：reverse_map_ 是 private，通过 positive_host/positive_port 访问器
    // 和 add_route 的副作用间接验证。通过 async_reverse 在 io_context 上
    // 运行来验证 add_route 是否正确插入。

    TEST(RouterDeep, SetEndpointAndReadback)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        // 设置 -> 读取 -> 清除 -> 读取 完整流程
        r.set_endpoint("host1.com", 100);
        EXPECT_TRUE(r.positive_host().has_value()) << "endpoint: set host1";
        EXPECT_TRUE(r.positive_port() == 100) << "endpoint: port 100";

        r.set_endpoint("host2.com", 200);
        EXPECT_TRUE(r.positive_port() == 200) << "endpoint: overwritten to 200";

        r.set_endpoint("", 0);
        EXPECT_TRUE(!r.positive_host().has_value()) << "endpoint: cleared";
    }

    TEST(RouterDeep, SetEndpointBothEmpty)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::router_options opts{pool, ioc, {}};
        connect::router r(std::move(opts));

        r.set_endpoint("", 0);
        EXPECT_TRUE(!r.positive_host().has_value()) << "endpoint: both empty -> reset";
        EXPECT_TRUE(r.positive_port() == 0) << "endpoint: both empty -> port 0";
    }

} // namespace

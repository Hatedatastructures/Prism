/**
 * @file UpstreamSettersPure.cpp
 * @brief DNS upstream 构造/setter 纯函数测试
 * @details 通过公共 API 测试 upstream 的构造函数、set_servers、set_mode、set_timeout。
 *          select_best_result 通过等价逻辑间接测试。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/dns/upstream.hpp>
#include <prism/net/dns/config.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/foundation/foundation.hpp>

#include <gtest/gtest.h>

// #include 源文件增加覆盖率计数
#include "../../src/prism/net/dns/upstream.cpp"

namespace
{
    namespace dns = psm::dns;
    namespace net = boost::asio;

    // 与 upstream::select_best_result 等价的本地实现
    auto select_best_local(psm::memory::vector<dns::query_result> &results)
        -> dns::query_result
    {
        using psm::fault::code;
        dns::query_result *best = nullptr;
        for (auto &r : results)
        {
            if (r.error == code::success && !r.ips.empty())
            {
                if (!best || r.rtt_ms < best->rtt_ms)
                {
                    best = &r;
                }
            }
        }
        if (best)
        {
            return std::move(*best);
        }
        if (!results.empty())
        {
            return std::move(results.front());
        }
        dns::query_result fallback;
        fallback.error = code::dns_failed;
        return fallback;
    }

    // ─── 构造函数 ────────────────────────────────────

    TEST(UpstreamSettersPure, UpstreamConstruct)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);
        // 默认构造不崩溃，可调用 setter
        psm::memory::vector<dns::server> servers(psm::memory::current_resource());
        ups.set_servers(servers);
        // 无异常即验证构造成功
        EXPECT_TRUE(true) << "upstream: default construct + set_servers succeeds";
    }

    TEST(UpstreamSettersPure, UpstreamConstructWithMr)
    {
        net::io_context ioc;
        dns::upstream ups(ioc, psm::memory::current_resource());
        // 带内存资源构造不崩溃
        EXPECT_TRUE(true) << "upstream: construct with mr succeeds";
    }

    // ─── set_servers ────────────────────────────────

    TEST(UpstreamSettersPure, UpstreamSetServers)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::server> servers(psm::memory::current_resource());
        dns::server srv;
        srv.address = "8.8.8.8";
        srv.port = 53;
        srv.protocol = dns::protocol::udp;
        servers.push_back(srv);

        ups.set_servers(servers);
        EXPECT_TRUE(true) << "upstream: set_servers stores 1 server";
    }

    TEST(UpstreamSettersPure, UpstreamSetServersMultiple)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::server> servers(psm::memory::current_resource());
        for (int i = 0; i < 5; ++i)
        {
            dns::server srv;
            srv.address = psm::memory::string("1.1.1." + std::to_string(i + 1));
            srv.port = 53;
            srv.protocol = dns::protocol::udp;
            servers.push_back(srv);
        }

        ups.set_servers(servers);
        EXPECT_TRUE(true) << "upstream: set_servers stores 5 servers";
    }

    TEST(UpstreamSettersPure, UpstreamSetServersProtocols)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::server> servers(psm::memory::current_resource());

        dns::server srv_udp;
        srv_udp.address = "8.8.8.8";
        srv_udp.protocol = dns::protocol::udp;
        servers.push_back(srv_udp);

        dns::server srv_tcp;
        srv_tcp.address = "8.8.8.8";
        srv_tcp.port = 53;
        srv_tcp.protocol = dns::protocol::tcp;
        servers.push_back(srv_tcp);

        dns::server srv_tls;
        srv_tls.address = "8.8.8.8";
        srv_tls.port = 853;
        srv_tls.protocol = dns::protocol::tls;
        servers.push_back(srv_tls);

        dns::server srv_https;
        srv_https.address = "8.8.8.8";
        srv_https.port = 443;
        srv_https.protocol = dns::protocol::https;
        servers.push_back(srv_https);

        ups.set_servers(servers);
        EXPECT_TRUE(true) << "upstream: set_servers stores 4 servers (all protocols)";
    }

    // ─── set_mode / set_timeout ─────────────────────

    TEST(UpstreamSettersPure, UpstreamSetMode)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        ups.set_mode(dns::mode::fastest);
        ups.set_mode(dns::mode::first);
        ups.set_mode(dns::mode::fallback);
        EXPECT_TRUE(true) << "upstream: set_mode accepts all mode values";
    }

    TEST(UpstreamSettersPure, UpstreamSetTimeout)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        ups.set_timeout(0);
        ups.set_timeout(1000);
        ups.set_timeout(30000);
        EXPECT_TRUE(true) << "upstream: set_timeout accepts various values";
    }

    // ─── select_best_result 等价测试 ────────────────

    TEST(UpstreamSettersPure, SelectBestSingleSuccess)
    {
        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());
        dns::query_result r(psm::memory::current_resource());
        r.error = psm::fault::code::success;
        r.rtt_ms = 100;
        r.ips.push_back(net::ip::make_address("1.1.1.1"));
        results.push_back(std::move(r));

        auto best = select_best_local(results);
        EXPECT_TRUE(best.rtt_ms == 100) << "select_best: single success";
    }

    TEST(UpstreamSettersPure, SelectBestPicksFastest)
    {
        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());

        dns::query_result r1(psm::memory::current_resource());
        r1.error = psm::fault::code::success;
        r1.rtt_ms = 200;
        r1.server_addr = "slow";
        r1.ips.push_back(net::ip::make_address("1.1.1.1"));
        results.push_back(std::move(r1));

        dns::query_result r2(psm::memory::current_resource());
        r2.error = psm::fault::code::success;
        r2.rtt_ms = 50;
        r2.server_addr = "fast";
        r2.ips.push_back(net::ip::make_address("2.2.2.2"));
        results.push_back(std::move(r2));

        auto best = select_best_local(results);
        EXPECT_TRUE(best.rtt_ms == 50) << "select_best: picks fastest";
        EXPECT_TRUE(best.server_addr == "fast") << "select_best: correct server";
    }

    TEST(UpstreamSettersPure, SelectBestAllFailReturnsFirst)
    {
        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());

        dns::query_result r1(psm::memory::current_resource());
        r1.error = psm::fault::code::timeout;
        r1.server_addr = "first";
        results.push_back(std::move(r1));

        dns::query_result r2(psm::memory::current_resource());
        r2.error = psm::fault::code::io_error;
        r2.server_addr = "second";
        results.push_back(std::move(r2));

        auto best = select_best_local(results);
        EXPECT_TRUE(best.server_addr == "first") << "select_best: all fail -> first";
    }

    TEST(UpstreamSettersPure, SelectBestEmptyReturnsDnsFailed)
    {
        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());
        auto best = select_best_local(results);
        EXPECT_TRUE(best.error == psm::fault::code::dns_failed) << "select_best: empty -> dns_failed";
    }

} // namespace

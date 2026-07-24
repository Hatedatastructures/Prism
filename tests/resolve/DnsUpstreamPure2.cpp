/**
 * @file DnsUpstreamPure2.cpp
 * @brief DNS upstream 纯函数深度测试
 * @details 通过 #define private public 访问 upstream 的 private 方法，
 *          直接调用真实的 select_best_result 和 get_ssl_ctx。
 *          覆盖：构造函数、set_servers/set_mode/set_timeout、
 *          select_best_result 全分支、get_ssl_ctx 缓存命中/未命中。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/dns/config.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/foundation/foundation.hpp>


#include <gtest/gtest.h>

// 通过预处理器 hack 访问 private 成员（仅限测试翻译单元）
#define private public
#include <prism/net/dns/upstream.hpp>
#include "../../src/prism/net/dns/upstream.cpp"
#undef private

namespace
{
    namespace dns = psm::dns;
    namespace net = boost::asio;

    // ─── select_best_result ───────────────────────────

    TEST(DnsUpstreamPure2, SelectBestFastest)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::query_result r1(psm::memory::current_resource());
        r1.error = psm::fault::code::success;
        r1.rtt_ms = 100;
        r1.ips.push_back(net::ip::make_address("1.1.1.1"));

        dns::query_result r2(psm::memory::current_resource());
        r2.error = psm::fault::code::success;
        r2.rtt_ms = 50;
        r2.ips.push_back(net::ip::make_address("2.2.2.2"));

        dns::query_result r3(psm::memory::current_resource());
        r3.error = psm::fault::code::success;
        r3.rtt_ms = 200;
        r3.ips.push_back(net::ip::make_address("3.3.3.3"));

        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());
        results.push_back(std::move(r1));
        results.push_back(std::move(r2));
        results.push_back(std::move(r3));

        auto best = ups.select_best_result(results);
        EXPECT_TRUE(best.rtt_ms == 50) << "select_best: fastest rtt=50";
        EXPECT_TRUE(!best.ips.empty()) << "select_best: has IPs";
    }

    TEST(DnsUpstreamPure2, SelectBestAllFailed)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::query_result r1(psm::memory::current_resource());
        r1.error = psm::fault::code::io_error;
        r1.rtt_ms = 100;

        dns::query_result r2(psm::memory::current_resource());
        r2.error = psm::fault::code::timeout;
        r2.rtt_ms = 50;

        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());
        results.push_back(std::move(r1));
        results.push_back(std::move(r2));

        auto best = ups.select_best_result(results);
        EXPECT_TRUE(best.error == psm::fault::code::io_error) << "select_best: all failed -> first";
    }

    TEST(DnsUpstreamPure2, SelectBestEmpty)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());
        auto best = ups.select_best_result(results);
        EXPECT_TRUE(best.error == psm::fault::code::dns_failed) << "select_best: empty -> dns_failed";
    }

    TEST(DnsUpstreamPure2, SelectBestSuccessNoIps)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::query_result r1(psm::memory::current_resource());
        r1.error = psm::fault::code::success;
        r1.rtt_ms = 10;

        dns::query_result r2(psm::memory::current_resource());
        r2.error = psm::fault::code::io_error;

        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());
        results.push_back(std::move(r1));
        results.push_back(std::move(r2));

        auto best = ups.select_best_result(results);
        EXPECT_TRUE(best.error == psm::fault::code::success) << "select_best: success no ips -> fallback first";
    }

    TEST(DnsUpstreamPure2, SelectBestSingleSuccess)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::query_result r1(psm::memory::current_resource());
        r1.error = psm::fault::code::success;
        r1.rtt_ms = 42;
        r1.ips.push_back(net::ip::make_address("8.8.8.8"));

        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());
        results.push_back(std::move(r1));

        auto best = ups.select_best_result(results);
        EXPECT_TRUE(best.rtt_ms == 42) << "select_best: single success";
        EXPECT_TRUE(best.ips.size() == 1) << "select_best: single IP";
    }

    TEST(DnsUpstreamPure2, SelectBestMixedSuccessFailure)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::query_result r1(psm::memory::current_resource());
        r1.error = psm::fault::code::timeout;
        r1.rtt_ms = 5000;

        dns::query_result r2(psm::memory::current_resource());
        r2.error = psm::fault::code::success;
        r2.rtt_ms = 30;
        r2.ips.push_back(net::ip::make_address("1.1.1.1"));

        dns::query_result r3(psm::memory::current_resource());
        r3.error = psm::fault::code::io_error;
        r3.rtt_ms = 100;

        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());
        results.push_back(std::move(r1));
        results.push_back(std::move(r2));
        results.push_back(std::move(r3));

        auto best = ups.select_best_result(results);
        EXPECT_TRUE(best.rtt_ms == 30) << "select_best: mixed -> success with lowest rtt";
    }

    // ─── get_ssl_ctx ──────────────────────────────────

    TEST(DnsUpstreamPure2, GetSslCtxWithHostname)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::server server(psm::memory::current_resource());
        server.address = "1.1.1.1";
        server.hostname = "dns.example.com";
        server.protocol = dns::protocol::tls;
        server.port = 853;

        auto ctx1 = ups.get_ssl_ctx(server);
        EXPECT_TRUE(ctx1 != nullptr) << "ssl_ctx: first call returns context";

        auto ctx2 = ups.get_ssl_ctx(server);
        EXPECT_TRUE(ctx2 == ctx1) << "ssl_ctx: cache hit returns same context";
    }

    TEST(DnsUpstreamPure2, GetSslCtxEmptyHostname)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::server server(psm::memory::current_resource());
        server.address = "8.8.8.8";
        server.hostname = "";
        server.protocol = dns::protocol::tls;
        server.port = 853;

        auto ctx = ups.get_ssl_ctx(server);
        EXPECT_TRUE(ctx != nullptr) << "ssl_ctx: empty hostname uses address";
    }

    TEST(DnsUpstreamPure2, GetSslCtxSkipCertCheck)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::server server1(psm::memory::current_resource());
        server1.address = "1.1.1.1";
        server1.hostname = "dns.example.com";
        server1.skip_cert_check = false;

        dns::server server2(psm::memory::current_resource());
        server2.address = "1.1.1.1";
        server2.hostname = "dns.example.com";
        server2.skip_cert_check = true;

        auto ctx1 = ups.get_ssl_ctx(server1);
        auto ctx2 = ups.get_ssl_ctx(server2);
        EXPECT_TRUE(ctx1 != nullptr) << "ssl_ctx: verify_peer context ok";
        EXPECT_TRUE(ctx2 != nullptr) << "ssl_ctx: no verify context ok";
        EXPECT_TRUE(ctx1 != ctx2) << "ssl_ctx: different verify -> different cache entries";
    }

    TEST(DnsUpstreamPure2, GetSslCtxMultipleHosts)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::server server1(psm::memory::current_resource());
        server1.address = "1.1.1.1";
        server1.hostname = "dns1.example.com";

        dns::server server2(psm::memory::current_resource());
        server2.address = "8.8.8.8";
        server2.hostname = "dns2.example.com";

        auto ctx1 = ups.get_ssl_ctx(server1);
        auto ctx2 = ups.get_ssl_ctx(server2);
        EXPECT_TRUE(ctx1 != nullptr) << "ssl_ctx: host1 context ok";
        EXPECT_TRUE(ctx2 != nullptr) << "ssl_ctx: host2 context ok";
        EXPECT_TRUE(ctx1 != ctx2) << "ssl_ctx: different hosts -> different contexts";
    }

    // ─── 构造函数 + setters ───────────────────────────

    TEST(DnsUpstreamPure2, ConstructorDefault)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);
        EXPECT_TRUE(ups.servers_.empty()) << "upstream: default constructor, servers empty";
    }

    TEST(DnsUpstreamPure2, ConstructorWithAllocator)
    {
        net::io_context ioc;
        psm::memory::unsynchronized_pool pool;
        dns::upstream ups(ioc, &pool);
        EXPECT_TRUE(ups.servers_.empty()) << "upstream: constructor with allocator, servers empty";
    }

    TEST(DnsUpstreamPure2, SetServers)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::server> servers(psm::memory::current_resource());
        dns::server srv(psm::memory::current_resource());
        srv.address = "8.8.8.8";
        srv.port = 53;
        srv.protocol = dns::protocol::udp;
        servers.push_back(srv);

        ups.set_servers(servers);
        EXPECT_TRUE(ups.servers_.size() == 1) << "upstream: set_servers stores 1 server";
    }

    TEST(DnsUpstreamPure2, SetMode)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);
        ups.set_mode(dns::mode::first);
        ups.set_mode(dns::mode::fallback);
        ups.set_mode(dns::mode::fastest);
        EXPECT_TRUE(ups.mode_ == dns::mode::fastest) << "upstream: set_mode last is fastest";
    }

    TEST(DnsUpstreamPure2, SetTimeout)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);
        ups.set_timeout(1000);
        ups.set_timeout(0);
        ups.set_timeout(4294967295u);
        EXPECT_TRUE(ups.timeout_ms_ == 4294967295u) << "upstream: set_timeout last is max uint32";
    }

} // namespace

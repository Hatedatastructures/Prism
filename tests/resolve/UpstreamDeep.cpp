/**
 * @file UpstreamDeep.cpp
 * @brief DNS upstream 深度测试 — gcov 覆盖
 * @details 通过静态库链接调用 upstream 的同步方法。
 *          覆盖 select_best_result 全分支、构造器、set_servers/set_mode/set_timeout、
 *          get_ssl_ctx 缓存逻辑、ssl_key 相等和哈希。
 *          不 #include 源文件（含大量协程模板，会导致对象文件过大链接失败）。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>


#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <cstdint>
#include <cstring>

#define private public
#include <prism/resolve/dns/upstream.hpp>
#undef private

namespace
{
    namespace net = boost::asio;
    namespace dns = psm::resolve::dns;
    using dns::upstream;
    using dns::query_result;
    using dns::dns_remote;
    using psm::memory::resource_pointer;

    // ─── 构造器 ──────────────────────────────────

    TEST(UpstreamDeep, ConstructDefault)
    {
        net::io_context ioc;
        upstream ups(ioc);
        EXPECT_TRUE(ups.servers_.empty()) << "construct: empty servers";
        EXPECT_TRUE(ups.timeout_ms_ == 4000) << "construct: default timeout=4000";
        EXPECT_TRUE(ups.mode_ == dns::resolve_mode::fastest) << "construct: default mode=fastest";
    }

    TEST(UpstreamDeep, ConstructWithMr)
    {
        net::io_context ioc;
        upstream ups(ioc, psm::memory::current_resource());
        EXPECT_TRUE(ups.mr_ != nullptr) << "construct with mr: mr set";
    }

    // ─── set_servers / set_mode / set_timeout ──────

    TEST(UpstreamDeep, SetServers)
    {
        net::io_context ioc;
        upstream ups(ioc);
        psm::memory::vector<dns_remote> servers(ups.mr_);
        dns_remote srv(ups.mr_);
        srv.address = psm::memory::string("8.8.8.8", ups.mr_);
        servers.push_back(std::move(srv));
        ups.set_servers(servers);
        EXPECT_TRUE(ups.servers_.size() == 1) << "set_servers: size=1";
        EXPECT_TRUE(std::string(ups.servers_[0].address) == "8.8.8.8") << "set_servers: addr=8.8.8.8";
    }

    TEST(UpstreamDeep, SetMode)
    {
        net::io_context ioc;
        upstream ups(ioc);
        ups.set_mode(dns::resolve_mode::first);
        EXPECT_TRUE(ups.mode_ == dns::resolve_mode::first) << "set_mode: first";
        ups.set_mode(dns::resolve_mode::fallback);
        EXPECT_TRUE(ups.mode_ == dns::resolve_mode::fallback) << "set_mode: fallback";
    }

    TEST(UpstreamDeep, SetTimeout)
    {
        net::io_context ioc;
        upstream ups(ioc);
        ups.set_timeout(2000);
        EXPECT_TRUE(ups.timeout_ms_ == 2000) << "set_timeout: 2000";
    }

    // ─── select_best_result: 全成功选最低 RTT ──────

    TEST(UpstreamDeep, SelectBestLowestRtt)
    {
        net::io_context ioc;
        upstream ups(ioc);

        psm::memory::vector<query_result> results(ups.mr_);

        query_result r1(ups.mr_);
        r1.error = psm::fault::code::success;
        r1.rtt_ms = 100;
        r1.ips.push_back(net::ip::make_address("1.1.1.1"));
        r1.server_addr = psm::memory::string("server1", ups.mr_);

        query_result r2(ups.mr_);
        r2.error = psm::fault::code::success;
        r2.rtt_ms = 50;
        r2.ips.push_back(net::ip::make_address("2.2.2.2"));
        r2.server_addr = psm::memory::string("server2", ups.mr_);

        query_result r3(ups.mr_);
        r3.error = psm::fault::code::success;
        r3.rtt_ms = 200;
        r3.ips.push_back(net::ip::make_address("3.3.3.3"));
        r3.server_addr = psm::memory::string("server3", ups.mr_);

        results.push_back(std::move(r1));
        results.push_back(std::move(r2));
        results.push_back(std::move(r3));

        auto best = ups.select_best_result(results);
        EXPECT_TRUE(best.rtt_ms == 50) << "best: lowest rtt=50";
        EXPECT_TRUE(std::string(best.server_addr) == "server2") << "best: server2";
    }

    // ─── select_best_result: 部分成功 ──────────────

    TEST(UpstreamDeep, SelectBestPartialSuccess)
    {
        net::io_context ioc;
        upstream ups(ioc);

        psm::memory::vector<query_result> results(ups.mr_);

        query_result r1(ups.mr_);
        r1.error = psm::fault::code::io_error;
        r1.rtt_ms = 10;
        r1.server_addr = psm::memory::string("fail1", ups.mr_);

        query_result r2(ups.mr_);
        r2.error = psm::fault::code::success;
        r2.rtt_ms = 80;
        r2.ips.push_back(net::ip::make_address("1.2.3.4"));
        r2.server_addr = psm::memory::string("ok1", ups.mr_);

        query_result r3(ups.mr_);
        r3.error = psm::fault::code::timeout;
        r3.rtt_ms = 5000;
        r3.server_addr = psm::memory::string("fail2", ups.mr_);

        results.push_back(std::move(r1));
        results.push_back(std::move(r2));
        results.push_back(std::move(r3));

        auto best = ups.select_best_result(results);
        EXPECT_TRUE(best.rtt_ms == 80) << "partial: selects the only successful rtt=80";
        EXPECT_TRUE(best.error == psm::fault::code::success) << "partial: success error";
    }

    // ─── select_best_result: 成功但无 IP → 跳过 ──

    TEST(UpstreamDeep, SelectBestSuccessNoIps)
    {
        net::io_context ioc;
        upstream ups(ioc);

        psm::memory::vector<query_result> results(ups.mr_);

        query_result r1(ups.mr_);
        r1.error = psm::fault::code::success;
        r1.rtt_ms = 30;

        query_result r2(ups.mr_);
        r2.error = psm::fault::code::success;
        r2.rtt_ms = 100;
        r2.ips.push_back(net::ip::make_address("9.9.9.9"));
        r2.server_addr = psm::memory::string("ok", ups.mr_);

        results.push_back(std::move(r1));
        results.push_back(std::move(r2));

        auto best = ups.select_best_result(results);
        EXPECT_TRUE(best.rtt_ms == 100) << "no-ips: skips empty-ips, picks rtt=100";
        EXPECT_TRUE(!best.ips.empty()) << "no-ips: result has ips";
    }

    // ─── select_best_result: 全失败 → 返回第一个 ──

    TEST(UpstreamDeep, SelectBestAllFailed)
    {
        net::io_context ioc;
        upstream ups(ioc);

        psm::memory::vector<query_result> results(ups.mr_);

        query_result r1(ups.mr_);
        r1.error = psm::fault::code::timeout;
        r1.server_addr = psm::memory::string("first", ups.mr_);

        query_result r2(ups.mr_);
        r2.error = psm::fault::code::io_error;
        r2.server_addr = psm::memory::string("second", ups.mr_);

        results.push_back(std::move(r1));
        results.push_back(std::move(r2));

        auto best = ups.select_best_result(results);
        EXPECT_TRUE(std::string(best.server_addr) == "first") << "all-failed: returns first";
    }

    // ─── select_best_result: 空列表 → dns_failed ──

    TEST(UpstreamDeep, SelectBestEmpty)
    {
        net::io_context ioc;
        upstream ups(ioc);
        psm::memory::vector<query_result> results(ups.mr_);

        auto best = ups.select_best_result(results);
        EXPECT_TRUE(best.error == psm::fault::code::dns_failed) << "empty: dns_failed";
        EXPECT_TRUE(best.ips.empty()) << "empty: no ips";
    }

    // ─── select_best_result: 单个成功 ──────────────

    TEST(UpstreamDeep, SelectBestSingle)
    {
        net::io_context ioc;
        upstream ups(ioc);

        psm::memory::vector<query_result> results(ups.mr_);
        query_result r1(ups.mr_);
        r1.error = psm::fault::code::success;
        r1.rtt_ms = 42;
        r1.ips.push_back(net::ip::make_address("10.0.0.1"));
        r1.server_addr = psm::memory::string("only", ups.mr_);
        results.push_back(std::move(r1));

        auto best = ups.select_best_result(results);
        EXPECT_TRUE(best.rtt_ms == 42) << "single: rtt=42";
        EXPECT_TRUE(best.error == psm::fault::code::success) << "single: success";
    }

    // ─── ssl_key 相等和哈希 ────────────────────────

    TEST(UpstreamDeep, SslKeyEquality)
    {
        net::io_context ioc;
        upstream ups(ioc);
        upstream::ssl_key k1{psm::memory::string("example.com", ups.mr_), true};
        upstream::ssl_key k2{psm::memory::string("example.com", ups.mr_), true};
        upstream::ssl_key k3{psm::memory::string("example.com", ups.mr_), false};
        upstream::ssl_key k4{psm::memory::string("other.com", ups.mr_), true};

        EXPECT_TRUE(k1 == k2) << "ssl_key: same equals";
        EXPECT_TRUE(!(k1 == k3)) << "ssl_key: diff verify_peer not equal";
        EXPECT_TRUE(!(k1 == k4)) << "ssl_key: diff hostname not equal";
    }

    TEST(UpstreamDeep, SslKeyHash)
    {
        net::io_context ioc;
        upstream ups(ioc);
        upstream::ssl_key_hash hasher;
        upstream::ssl_key k1{psm::memory::string("a.com", ups.mr_), true};
        upstream::ssl_key k2{psm::memory::string("a.com", ups.mr_), true};
        upstream::ssl_key k3{psm::memory::string("b.com", ups.mr_), true};

        EXPECT_TRUE(hasher(k1) == hasher(k2)) << "ssl_hash: same key same hash";
        EXPECT_TRUE(hasher(k1) != hasher(k3)) << "ssl_hash: diff key diff hash";
    }

    // ─── get_ssl_ctx: 缓存命中 ────────────────────

    TEST(UpstreamDeep, GetSslCtxCache)
    {
        net::io_context ioc;
        upstream ups(ioc);

        dns_remote srv(ups.mr_);
        srv.address = psm::memory::string("1.1.1.1", ups.mr_);
        srv.hostname = psm::memory::string("dns.example.com", ups.mr_);
        srv.skip_cert_check = false;

        auto ctx1 = ups.get_ssl_ctx(srv);
        EXPECT_TRUE(ctx1 != nullptr) << "ssl_ctx: first call not null";
        auto ctx2 = ups.get_ssl_ctx(srv);
        EXPECT_TRUE(ctx1.get() == ctx2.get()) << "ssl_ctx: cache hit same ptr";
        EXPECT_TRUE(ups.ssl_cache_.size() == 1) << "ssl_ctx: cache size=1";
    }

    // ─── get_ssl_ctx: 空 hostname 用 address ──────

    TEST(UpstreamDeep, GetSslCtxNoHostname)
    {
        net::io_context ioc;
        upstream ups(ioc);

        dns_remote srv(ups.mr_);
        srv.address = psm::memory::string("9.9.9.9", ups.mr_);
        srv.hostname.clear();
        srv.skip_cert_check = false;

        auto ctx = ups.get_ssl_ctx(srv);
        EXPECT_TRUE(ctx != nullptr) << "ssl_ctx no host: not null";
        EXPECT_TRUE(ups.ssl_cache_.size() == 1) << "ssl_ctx no host: cached";
    }

    // ─── get_ssl_ctx: 不同配置不同缓存 ──────────────

    TEST(UpstreamDeep, GetSslCtxDifferentConfigs)
    {
        net::io_context ioc;
        upstream ups(ioc);

        dns_remote srv1(ups.mr_);
        srv1.address = psm::memory::string("1.1.1.1", ups.mr_);
        srv1.hostname = psm::memory::string("a.com", ups.mr_);
        srv1.skip_cert_check = false;

        dns_remote srv2(ups.mr_);
        srv2.address = psm::memory::string("8.8.8.8", ups.mr_);
        srv2.hostname = psm::memory::string("b.com", ups.mr_);
        srv2.skip_cert_check = true;

        auto ctx1 = ups.get_ssl_ctx(srv1);
        auto ctx2 = ups.get_ssl_ctx(srv2);
        EXPECT_TRUE(ctx1.get() != ctx2.get()) << "ssl_ctx: diff config diff ctx";
        EXPECT_TRUE(ups.ssl_cache_.size() == 2) << "ssl_ctx: cache size=2";
    }

    // ─── dns_remote 默认值 ──────────────────────────

    TEST(UpstreamDeep, DnsRemoteDefaults)
    {
        dns_remote srv;
        EXPECT_TRUE(srv.protocol == dns::dns_protocol::udp) << "dns_remote: default udp";
        EXPECT_TRUE(srv.port == 53) << "dns_remote: default port=53";
        EXPECT_TRUE(srv.timeout_ms == 5000) << "dns_remote: default timeout=5000";
        EXPECT_TRUE(srv.skip_cert_check == false) << "dns_remote: default verify";
        EXPECT_TRUE(std::string(srv.http_path) == "/dns-query") << "dns_remote: default path";
    }

    // ─── query_result 默认值 ──────────────────────────

    TEST(UpstreamDeep, QueryResultDefaults)
    {
        query_result qr;
        EXPECT_TRUE(qr.error == psm::fault::code::success) << "qr: default success";
        EXPECT_TRUE(qr.rtt_ms == 0) << "qr: default rtt=0";
        EXPECT_TRUE(qr.ips.empty()) << "qr: default empty ips";
        EXPECT_TRUE(std::string(qr.server_addr).empty()) << "qr: default empty server";
    }

} // namespace

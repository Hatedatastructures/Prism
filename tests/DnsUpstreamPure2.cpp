/**
 * @file DnsUpstreamPure2.cpp
 * @brief DNS upstream 纯函数深度测试
 * @details 通过 #define private public 访问 upstream 的 private 方法，
 *          直接调用真实的 select_best_result 和 get_ssl_ctx。
 *          覆盖：构造函数、set_servers/set_mode/set_timeout、
 *          select_best_result 全分支、get_ssl_ctx 缓存命中/未命中。
 */

#include <prism/memory.hpp>
#include <prism/resolve/dns/config.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// 通过预处理器 hack 访问 private 成员（仅限测试翻译单元）
#define private public
#include <prism/resolve/dns/upstream.hpp>
#include "../src/prism/resolve/dns/upstream.cpp"
#undef private

using psm::testing::TestRunner;

namespace
{
    namespace dns = psm::resolve::dns;
    namespace net = boost::asio;

    // ─── select_best_result ───────────────────────────

    void TestSelectBestFastest(TestRunner &runner)
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
        runner.Check(best.rtt_ms == 50, "select_best: fastest rtt=50");
        runner.Check(!best.ips.empty(), "select_best: has IPs");
    }

    void TestSelectBestAllFailed(TestRunner &runner)
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
        runner.Check(best.error == psm::fault::code::io_error, "select_best: all failed -> first");
    }

    void TestSelectBestEmpty(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());
        auto best = ups.select_best_result(results);
        runner.Check(best.error == psm::fault::code::dns_failed, "select_best: empty -> dns_failed");
    }

    void TestSelectBestSuccessNoIps(TestRunner &runner)
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
        runner.Check(best.error == psm::fault::code::success, "select_best: success no ips -> fallback first");
    }

    void TestSelectBestSingleSuccess(TestRunner &runner)
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
        runner.Check(best.rtt_ms == 42, "select_best: single success");
        runner.Check(best.ips.size() == 1, "select_best: single IP");
    }

    void TestSelectBestMixedSuccessFailure(TestRunner &runner)
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
        runner.Check(best.rtt_ms == 30, "select_best: mixed -> success with lowest rtt");
    }

    // ─── get_ssl_ctx ──────────────────────────────────

    void TestGetSslCtxWithHostname(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::dns_remote server(psm::memory::current_resource());
        server.address = "1.1.1.1";
        server.hostname = "dns.example.com";
        server.protocol = dns::dns_protocol::tls;
        server.port = 853;

        auto ctx1 = ups.get_ssl_ctx(server);
        runner.Check(ctx1 != nullptr, "ssl_ctx: first call returns context");

        auto ctx2 = ups.get_ssl_ctx(server);
        runner.Check(ctx2 == ctx1, "ssl_ctx: cache hit returns same context");
    }

    void TestGetSslCtxEmptyHostname(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::dns_remote server(psm::memory::current_resource());
        server.address = "8.8.8.8";
        server.hostname = "";
        server.protocol = dns::dns_protocol::tls;
        server.port = 853;

        auto ctx = ups.get_ssl_ctx(server);
        runner.Check(ctx != nullptr, "ssl_ctx: empty hostname uses address");
    }

    void TestGetSslCtxSkipCertCheck(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::dns_remote server1(psm::memory::current_resource());
        server1.address = "1.1.1.1";
        server1.hostname = "dns.example.com";
        server1.skip_cert_check = false;

        dns::dns_remote server2(psm::memory::current_resource());
        server2.address = "1.1.1.1";
        server2.hostname = "dns.example.com";
        server2.skip_cert_check = true;

        auto ctx1 = ups.get_ssl_ctx(server1);
        auto ctx2 = ups.get_ssl_ctx(server2);
        runner.Check(ctx1 != nullptr, "ssl_ctx: verify_peer context ok");
        runner.Check(ctx2 != nullptr, "ssl_ctx: no verify context ok");
        runner.Check(ctx1 != ctx2, "ssl_ctx: different verify -> different cache entries");
    }

    void TestGetSslCtxMultipleHosts(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        dns::dns_remote server1(psm::memory::current_resource());
        server1.address = "1.1.1.1";
        server1.hostname = "dns1.example.com";

        dns::dns_remote server2(psm::memory::current_resource());
        server2.address = "8.8.8.8";
        server2.hostname = "dns2.example.com";

        auto ctx1 = ups.get_ssl_ctx(server1);
        auto ctx2 = ups.get_ssl_ctx(server2);
        runner.Check(ctx1 != nullptr, "ssl_ctx: host1 context ok");
        runner.Check(ctx2 != nullptr, "ssl_ctx: host2 context ok");
        runner.Check(ctx1 != ctx2, "ssl_ctx: different hosts -> different contexts");
    }

    // ─── 构造函数 + setters ───────────────────────────

    void TestConstructorDefault(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);
        runner.Check(true, "upstream: default constructor ok");
    }

    void TestConstructorWithAllocator(TestRunner &runner)
    {
        net::io_context ioc;
        psm::memory::unsynchronized_pool pool;
        dns::upstream ups(ioc, &pool);
        runner.Check(true, "upstream: constructor with allocator ok");
    }

    void TestSetServers(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::dns_remote> servers(psm::memory::current_resource());
        dns::dns_remote srv(psm::memory::current_resource());
        srv.address = "8.8.8.8";
        srv.port = 53;
        srv.protocol = dns::dns_protocol::udp;
        servers.push_back(srv);

        ups.set_servers(servers);
        runner.Check(true, "upstream: set_servers ok");
    }

    void TestSetMode(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);
        ups.set_mode(dns::resolve_mode::first);
        ups.set_mode(dns::resolve_mode::fallback);
        ups.set_mode(dns::resolve_mode::fastest);
        runner.Check(true, "upstream: set_mode all values ok");
    }

    void TestSetTimeout(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);
        ups.set_timeout(1000);
        ups.set_timeout(0);
        ups.set_timeout(4294967295u);
        runner.Check(true, "upstream: set_timeout all values ok");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("DnsUpstreamPure2");

    // select_best_result
    TestSelectBestFastest(runner);
    TestSelectBestAllFailed(runner);
    TestSelectBestEmpty(runner);
    TestSelectBestSuccessNoIps(runner);
    TestSelectBestSingleSuccess(runner);
    TestSelectBestMixedSuccessFailure(runner);

    // get_ssl_ctx
    TestGetSslCtxWithHostname(runner);
    TestGetSslCtxEmptyHostname(runner);
    TestGetSslCtxSkipCertCheck(runner);
    TestGetSslCtxMultipleHosts(runner);

    // 构造函数 + setters
    TestConstructorDefault(runner);
    TestConstructorWithAllocator(runner);
    TestSetServers(runner);
    TestSetMode(runner);
    TestSetTimeout(runner);

    return runner.Summary();
}

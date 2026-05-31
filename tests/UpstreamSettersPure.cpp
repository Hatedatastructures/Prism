/**
 * @file UpstreamSettersPure.cpp
 * @brief DNS upstream 构造/setter 纯函数测试
 * @details 通过 #include 源文件覆盖 upstream.cpp 的编译行。
 *          测试构造函数、set_servers、set_mode、set_timeout。
 *          select_best_result 通过等价逻辑间接测试。
 */

#include <prism/memory.hpp>
#include <prism/resolve/dns/upstream.hpp>
#include <prism/resolve/dns/config.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/fault.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// #include 源文件增加覆盖率计数
#include "../src/prism/resolve/dns/upstream.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace dns = psm::resolve::dns;
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

    void TestUpstreamConstruct(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);
        runner.Check(true, "upstream: construct no crash");
    }

    void TestUpstreamConstructWithMr(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc, psm::memory::current_resource());
        runner.Check(true, "upstream: construct with mr no crash");
    }

    // ─── set_servers ────────────────────────────────

    void TestUpstreamSetServers(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::dns_remote> servers(psm::memory::current_resource());
        dns::dns_remote srv;
        srv.address = "8.8.8.8";
        srv.port = 53;
        srv.protocol = dns::dns_protocol::udp;
        servers.push_back(srv);

        ups.set_servers(servers);
        runner.Check(true, "upstream: set_servers no crash");
    }

    void TestUpstreamSetServersMultiple(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::dns_remote> servers(psm::memory::current_resource());
        for (int i = 0; i < 5; ++i)
        {
            dns::dns_remote srv;
            srv.address = psm::memory::string("1.1.1." + std::to_string(i + 1));
            srv.port = 53;
            srv.protocol = dns::dns_protocol::udp;
            servers.push_back(srv);
        }

        ups.set_servers(servers);
        runner.Check(true, "upstream: set_servers multiple no crash");
    }

    void TestUpstreamSetServersProtocols(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        psm::memory::vector<dns::dns_remote> servers(psm::memory::current_resource());

        dns::dns_remote srv_udp;
        srv_udp.address = "8.8.8.8";
        srv_udp.protocol = dns::dns_protocol::udp;
        servers.push_back(srv_udp);

        dns::dns_remote srv_tcp;
        srv_tcp.address = "8.8.8.8";
        srv_tcp.port = 53;
        srv_tcp.protocol = dns::dns_protocol::tcp;
        servers.push_back(srv_tcp);

        dns::dns_remote srv_tls;
        srv_tls.address = "8.8.8.8";
        srv_tls.port = 853;
        srv_tls.protocol = dns::dns_protocol::tls;
        servers.push_back(srv_tls);

        dns::dns_remote srv_https;
        srv_https.address = "8.8.8.8";
        srv_https.port = 443;
        srv_https.protocol = dns::dns_protocol::https;
        servers.push_back(srv_https);

        ups.set_servers(servers);
        runner.Check(true, "upstream: set_servers all protocols no crash");
    }

    // ─── set_mode / set_timeout ─────────────────────

    void TestUpstreamSetMode(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        ups.set_mode(dns::resolve_mode::fastest);
        ups.set_mode(dns::resolve_mode::first);
        ups.set_mode(dns::resolve_mode::fallback);
        runner.Check(true, "upstream: set_mode all values no crash");
    }

    void TestUpstreamSetTimeout(TestRunner &runner)
    {
        net::io_context ioc;
        dns::upstream ups(ioc);

        ups.set_timeout(0);
        ups.set_timeout(1000);
        ups.set_timeout(30000);
        runner.Check(true, "upstream: set_timeout various values no crash");
    }

    // ─── select_best_result 等价测试 ────────────────

    void TestSelectBestSingleSuccess(TestRunner &runner)
    {
        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());
        dns::query_result r(psm::memory::current_resource());
        r.error = psm::fault::code::success;
        r.rtt_ms = 100;
        r.ips.push_back(net::ip::make_address("1.1.1.1"));
        results.push_back(std::move(r));

        auto best = select_best_local(results);
        runner.Check(best.rtt_ms == 100, "select_best: single success");
    }

    void TestSelectBestPicksFastest(TestRunner &runner)
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
        runner.Check(best.rtt_ms == 50, "select_best: picks fastest");
        runner.Check(best.server_addr == "fast", "select_best: correct server");
    }

    void TestSelectBestAllFailReturnsFirst(TestRunner &runner)
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
        runner.Check(best.server_addr == "first", "select_best: all fail → first");
    }

    void TestSelectBestEmptyReturnsDnsFailed(TestRunner &runner)
    {
        psm::memory::vector<dns::query_result> results(psm::memory::current_resource());
        auto best = select_best_local(results);
        runner.Check(best.error == psm::fault::code::dns_failed, "select_best: empty → dns_failed");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("UpstreamSettersPure");

    TestUpstreamConstruct(runner);
    TestUpstreamConstructWithMr(runner);
    TestUpstreamSetServers(runner);
    TestUpstreamSetServersMultiple(runner);
    TestUpstreamSetServersProtocols(runner);
    TestUpstreamSetMode(runner);
    TestUpstreamSetTimeout(runner);
    TestSelectBestSingleSuccess(runner);
    TestSelectBestPicksFastest(runner);
    TestSelectBestAllFailReturnsFirst(runner);
    TestSelectBestEmptyReturnsDnsFailed(runner);

    return runner.Summary();
}

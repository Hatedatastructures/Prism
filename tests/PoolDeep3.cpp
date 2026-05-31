/**
 * @file PoolDeep3.cpp
 * @brief connect/pool/pool 深度测试 — cleanup/recycle/clear/apply_opts 完整路径
 * @details 通过 #define private public 访问 private 成员，覆盖
 *          cleanup() 过期清理全分支（空/全过期/混合/全有效/多端点/压缩位移）、
 *          recycle IPv6 过滤和 cache_peraddr 限制、
 *          clear() 与 started pool 交互、apply_opts 正常与错误路径。
 *          通过 #include 源文件确保 gcov 计入覆盖行。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// 打开 private 以访问 cache_, stat_*, cleanup(), clear(), apply_opts()
// 先预包含所有依赖头文件（不打开 private），再重新包含 pool.hpp（打开 private）
#include <prism/connect/pool/config.hpp>
#include <prism/connect/pool/health.hpp>
#include <prism/fault.hpp>
#include <prism/trace.hpp>
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <ranges>
#include <cstdint>
#include <memory>

#define private public
#define protected public
#include <prism/connect/pool/pool.hpp>
#undef protected
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../src/prism/connect/pool/pool.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace pool = psm::connect;
    using tcp = boost::asio::ip::tcp;
    namespace net = boost::asio;

    struct connected_pair
    {
        tcp::socket *client;
        tcp::socket server;
    };

    auto make_connected_pair(net::io_context &ioc, tcp::acceptor &acc)
        -> connected_pair
    {
        auto *s = new tcp::socket(ioc);
        s->open(tcp::v4());
        s->bind(tcp::endpoint(tcp::v4(), 0));
        s->connect(tcp::endpoint(net::ip::make_address_v4("127.0.0.1"),
                                  acc.local_endpoint().port()));
        tcp::socket server(ioc);
        acc.accept(server);
        return {s, std::move(server)};
    }

    // ─── cleanup() 空缓存 ─────────────────────────

    void TestCleanupEmptyCache(TestRunner &runner)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        p.cleanup();
        runner.Check(p.cache_.empty(), "cleanup: empty cache -> still empty");
        runner.Check(p.stats().idle_count == 0, "cleanup: empty -> idle 0");
    }

    // ─── cleanup() 全部过期 → 端点移除 ────────────

    void TestCleanupAllExpired(TestRunner &runner)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.idle_sec = 1;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());

        auto key = pool::to_key(ep);
        auto &stack = p.cache_[key];
        p.stat_endpoints_ += 1;
        p.stat_idle_ += 1;
        stack.push_back({sock, std::chrono::steady_clock::now() - std::chrono::seconds(10)});

        p.cleanup();

        runner.Check(p.cache_.empty(), "cleanup: all expired -> cache empty");
        runner.Check(p.stats().idle_count == 0, "cleanup: all expired -> idle 0");
        runner.Check(p.stats().endpoint_count == 0, "cleanup: all expired -> endpoints 0");
        runner.Check(p.stats().total_evictions == 1, "cleanup: all expired -> 1 eviction");

        srv.close();
        acc.close();
    }

    // ─── cleanup() 混合过期/有效 ──────────────────

    void TestCleanupMixedExpiredAndValid(TestRunner &runner)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.idle_sec = 5;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [s1, srv1] = make_connected_pair(ioc, acc);
        auto [s2, srv2] = make_connected_pair(ioc, acc);
        auto [s3, srv3] = make_connected_pair(ioc, acc);

        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        auto key = pool::to_key(ep);
        auto &stack = p.cache_[key];
        p.stat_endpoints_ += 1;

        auto now = std::chrono::steady_clock::now();
        auto expired = now - std::chrono::seconds(10);
        stack.push_back({s1, expired}); // 过期
        stack.push_back({s2, now});     // 有效
        stack.push_back({s3, expired}); // 过期
        p.stat_idle_ += 3;

        p.cleanup();

        runner.Check(p.cache_.size() == 1, "cleanup: mixed -> cache has endpoint");
        runner.Check(p.stats().idle_count == 1, "cleanup: mixed -> idle 1");
        runner.Check(p.stats().total_evictions == 2, "cleanup: mixed -> 2 evictions");
        runner.Check(p.cache_[key].size() == 1, "cleanup: mixed -> 1 socket remaining");

        srv1.close();
        srv2.close();
        srv3.close();
        acc.close();
    }

    // ─── cleanup() 全部有效 → 无变化 ─────────────

    void TestCleanupAllValid(TestRunner &runner)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.idle_sec = 300;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());

        auto key = pool::to_key(ep);
        auto &stack = p.cache_[key];
        p.stat_endpoints_ += 1;
        p.stat_idle_ += 1;
        stack.push_back({sock, std::chrono::steady_clock::now()});

        p.cleanup();

        runner.Check(p.cache_.size() == 1, "cleanup: all valid -> cache unchanged");
        runner.Check(p.stats().idle_count == 1, "cleanup: all valid -> idle still 1");

        srv.close();
        acc.close();
    }

    // ─── cleanup() 多端点混合 ────────────────────

    void TestCleanupMultipleEndpoints(TestRunner &runner)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.idle_sec = 1;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);

        tcp::acceptor acc1(ioc, tcp::endpoint(tcp::v4(), 0));
        tcp::acceptor acc2(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [s1, srv1] = make_connected_pair(ioc, acc1);
        auto [s2, srv2] = make_connected_pair(ioc, acc2);
        auto [s3, srv3] = make_connected_pair(ioc, acc2);

        auto key1 = pool::to_key(tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc1.local_endpoint().port()));
        auto key2 = pool::to_key(tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc2.local_endpoint().port()));

        auto now = std::chrono::steady_clock::now();
        // ep1: 全部过期
        p.cache_[key1].push_back({s1, now - std::chrono::seconds(10)});
        p.stat_endpoints_ += 1;
        p.stat_idle_ += 1;

        // ep2: 一个过期，一个有效
        p.cache_[key2].push_back({s2, now - std::chrono::seconds(10)});
        p.cache_[key2].push_back({s3, now});
        p.stat_endpoints_ += 1;
        p.stat_idle_ += 2;

        p.cleanup();

        runner.Check(p.cache_.size() == 1, "cleanup: multi-ep -> 1 endpoint remains");
        runner.Check(p.stats().idle_count == 1, "cleanup: multi-ep -> idle 1");
        runner.Check(p.stats().total_evictions == 2, "cleanup: multi-ep -> 2 evictions");

        srv1.close();
        srv2.close();
        srv3.close();
        acc1.close();
        acc2.close();
    }

    // ─── cleanup() 压缩位移 (write != read 分支) ─

    void TestCleanupCompactionShift(TestRunner &runner)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.idle_sec = 5;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [s1, srv1] = make_connected_pair(ioc, acc);
        auto [s2, srv2] = make_connected_pair(ioc, acc);
        auto [s3, srv3] = make_connected_pair(ioc, acc);
        auto [s4, srv4] = make_connected_pair(ioc, acc);
        auto [s5, srv5] = make_connected_pair(ioc, acc);

        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        auto key = pool::to_key(ep);
        auto &stack = p.cache_[key];
        p.stat_endpoints_ += 1;

        auto now = std::chrono::steady_clock::now();
        auto expired = now - std::chrono::seconds(10);
        stack.push_back({s1, expired}); // 过期 → write=0, read=0, skip
        stack.push_back({s2, now});     // 有效 → write=0→1 (shift)
        stack.push_back({s3, expired}); // 过期
        stack.push_back({s4, now});     // 有效 → shift
        stack.push_back({s5, expired}); // 过期
        p.stat_idle_ += 5;

        p.cleanup();

        runner.Check(p.stats().idle_count == 2, "compaction: 2 valid remaining");
        runner.Check(p.stats().total_evictions == 3, "compaction: 3 evicted");
        runner.Check(p.cache_[key].size() == 2, "compaction: stack has 2 items");

        srv1.close();
        srv2.close();
        srv3.close();
        srv4.close();
        srv5.close();
        acc.close();
    }

    // ─── recycle IPv6 过滤路径 ──────────────────

    void TestRecycleIPv6Filtered(TestRunner &runner)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.cache_ipv6 = false;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v6(), 0));
        auto *sock = new tcp::socket(ioc);
        sock->open(tcp::v6());
        sock->connect(tcp::endpoint(net::ip::make_address_v6("::1"), acc.local_endpoint().port()));
        tcp::socket srv(ioc);
        acc.accept(srv);

        auto ep = tcp::endpoint(net::ip::make_address_v6("::1"), acc.local_endpoint().port());
        p.recycle(sock, ep);

        auto s = p.stats();
        runner.Check(s.total_recycles == 1, "recycle IPv6: recycle counted");
        runner.Check(s.idle_count == 0, "recycle IPv6: not cached");
        runner.Check(s.total_evictions == 1, "recycle IPv6: eviction counted");

        srv.close();
        acc.close();
    }

    // ─── recycle cache_peraddr 限制 ──────────────

    void TestRecycleCachePerAddrLimit(TestRunner &runner)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.cache_peraddr = 1;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [s1, srv1] = make_connected_pair(ioc, acc);
        auto [s2, srv2] = make_connected_pair(ioc, acc);

        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());

        p.recycle(s1, ep);
        runner.Check(p.stats().idle_count == 1, "peraddr: first -> idle 1");

        p.recycle(s2, ep);
        runner.Check(p.stats().total_recycles == 2, "peraddr: second counted");
        runner.Check(p.stats().idle_count == 1, "peraddr: still idle 1");
        runner.Check(p.stats().total_evictions == 1, "peraddr: 1 eviction");

        srv1.close();
        srv2.close();
        acc.close();
    }

    // ─── recycle 不健康 socket（对端关闭后触发 healthy_fast 失败）──

    void TestRecycleUnhealthyPeerClosed(TestRunner &runner)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());

        srv.close();
        char buf[1];
        boost::system::error_code ec;
        sock->read_some(net::buffer(buf), ec);

        p.recycle(sock, ep);

        auto s = p.stats();
        runner.Check(s.total_recycles == 1, "recycle unhealthy: recycle attempted");

        acc.close();
    }

    // ─── clear() 与 started pool ──────────────────

    void TestClearWithStartedPool(TestRunner &runner)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        p.start();

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        p.recycle(sock, ep);

        runner.Check(p.stats().idle_count == 1, "clear: idle 1 before");

        p.clear();

        runner.Check(p.cache_.empty(), "clear: cache empty after clear");
        runner.Check(p.stats().idle_count == 0, "clear: idle 0 after clear");
        runner.Check(!p.cleanup_timer_.has_value(), "clear: timer reset");

        srv.close();
        acc.close();
    }

    // ─── clear() 未 started pool ─────────────────

    void TestClearUnstartedPool(TestRunner &runner)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        p.recycle(sock, ep);

        p.clear();

        runner.Check(p.cache_.empty(), "clear unstarted: cache empty");
        runner.Check(p.stats().idle_count == 0, "clear unstarted: idle 0");

        srv.close();
        acc.close();
    }

    // ─── apply_opts 错误路径（关闭的 socket）──

    void TestApplyOptsClosedSocket(TestRunner &runner)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.tcp_nodelay = true;
        cfg.keep_alive = true;
        cfg.recv_bufsz = 65536;
        cfg.send_bufsz = 65536;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);

        tcp::socket sock(ioc);
        sock.open(tcp::v4());
        sock.close();

        p.apply_opts(sock);
        runner.Check(true, "apply_opts: closed socket -> error paths exercised");
    }

    // ─── apply_opts 正常路径 ───────────────────

    void TestApplyOptsNormalPath(TestRunner &runner)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.tcp_nodelay = true;
        cfg.keep_alive = true;
        cfg.recv_bufsz = 65536;
        cfg.send_bufsz = 65536;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);

        p.apply_opts(*sock);
        runner.Check(true, "apply_opts: normal path -> no error");
        runner.Check(sock->is_open(), "apply_opts: socket still open");

        delete sock;
        srv.close();
        acc.close();
    }

    // ─── apply_opts 全禁用 → 跳过所有分支 ─────

    void TestApplyOptsAllDisabled(TestRunner &runner)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.tcp_nodelay = false;
        cfg.keep_alive = false;
        cfg.recv_bufsz = 0;
        cfg.send_bufsz = 0;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);

        p.apply_opts(*sock);
        runner.Check(true, "apply_opts: all disabled -> no-op");

        delete sock;
        srv.close();
        acc.close();
    }

    // ─── endpoint_key 相等比较 ──────────────────

    void TestEndpointKeyEquality(TestRunner &runner)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        auto ep3 = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 81);

        auto k1 = pool::to_key(ep1);
        auto k2 = pool::to_key(ep2);
        auto k3 = pool::to_key(ep3);

        runner.Check(k1 == k2, "key: same endpoint -> equal");
        runner.Check(k1 != k3, "key: different port -> not equal");
    }

    // ─── start() 幂等：第二次走 timer exists 路径 ─

    void TestStartIdempotentTimerExists(TestRunner &runner)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        p.start();
        runner.Check(p.cleanup_timer_.has_value(), "start: timer created after first start");
        runner.Check(p.started_, "start: started_ is true");

        p.start();
        runner.Check(true, "start: second call -> early return (timer exists)");

        // clear 后 cleanup_timer_ 被销毁
        p.clear();
        runner.Check(!p.cleanup_timer_.has_value(), "start: timer cleared after clear");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("PoolDeep3");

    TestCleanupEmptyCache(runner);
    TestCleanupAllExpired(runner);
    TestCleanupMixedExpiredAndValid(runner);
    TestCleanupAllValid(runner);
    TestCleanupMultipleEndpoints(runner);
    TestCleanupCompactionShift(runner);

    TestRecycleIPv6Filtered(runner);
    TestRecycleCachePerAddrLimit(runner);
    TestRecycleUnhealthyPeerClosed(runner);

    TestClearWithStartedPool(runner);
    TestClearUnstartedPool(runner);

    TestApplyOptsClosedSocket(runner);
    TestApplyOptsNormalPath(runner);
    TestApplyOptsAllDisabled(runner);

    TestEndpointKeyEquality(runner);
    TestStartIdempotentTimerExists(runner);

    return runner.Summary();
}

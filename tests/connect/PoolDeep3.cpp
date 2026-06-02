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


#include <gtest/gtest.h>

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
#include "../../src/prism/connect/pool/pool.cpp"

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

    TEST(PoolDeep3, CleanupEmptyCache)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        p.cleanup();
        EXPECT_TRUE(p.cache_.empty()) << "cleanup: empty cache -> still empty";
        EXPECT_TRUE(p.stats().idle_count == 0) << "cleanup: empty -> idle 0";
    }

    // ─── cleanup() 全部过期 → 端点移除 ────────────

    TEST(PoolDeep3, CleanupAllExpired)
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

        EXPECT_TRUE(p.cache_.empty()) << "cleanup: all expired -> cache empty";
        EXPECT_TRUE(p.stats().idle_count == 0) << "cleanup: all expired -> idle 0";
        EXPECT_TRUE(p.stats().endpoint_count == 0) << "cleanup: all expired -> endpoints 0";
        EXPECT_TRUE(p.stats().total_evictions == 1) << "cleanup: all expired -> 1 eviction";

        srv.close();
        acc.close();
    }

    // ─── cleanup() 混合过期/有效 ──────────────────

    TEST(PoolDeep3, CleanupMixedExpiredAndValid)
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

        EXPECT_TRUE(p.cache_.size() == 1) << "cleanup: mixed -> cache has endpoint";
        EXPECT_TRUE(p.stats().idle_count == 1) << "cleanup: mixed -> idle 1";
        EXPECT_TRUE(p.stats().total_evictions == 2) << "cleanup: mixed -> 2 evictions";
        EXPECT_TRUE(p.cache_[key].size() == 1) << "cleanup: mixed -> 1 socket remaining";

        srv1.close();
        srv2.close();
        srv3.close();
        acc.close();
    }

    // ─── cleanup() 全部有效 → 无变化 ─────────────

    TEST(PoolDeep3, CleanupAllValid)
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

        EXPECT_TRUE(p.cache_.size() == 1) << "cleanup: all valid -> cache unchanged";
        EXPECT_TRUE(p.stats().idle_count == 1) << "cleanup: all valid -> idle still 1";

        srv.close();
        acc.close();
    }

    // ─── cleanup() 多端点混合 ────────────────────

    TEST(PoolDeep3, CleanupMultipleEndpoints)
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

        EXPECT_TRUE(p.cache_.size() == 1) << "cleanup: multi-ep -> 1 endpoint remains";
        EXPECT_TRUE(p.stats().idle_count == 1) << "cleanup: multi-ep -> idle 1";
        EXPECT_TRUE(p.stats().total_evictions == 2) << "cleanup: multi-ep -> 2 evictions";

        srv1.close();
        srv2.close();
        srv3.close();
        acc1.close();
        acc2.close();
    }

    // ─── cleanup() 压缩位移 (write != read 分支) ─

    TEST(PoolDeep3, CleanupCompactionShift)
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

        EXPECT_TRUE(p.stats().idle_count == 2) << "compaction: 2 valid remaining";
        EXPECT_TRUE(p.stats().total_evictions == 3) << "compaction: 3 evicted";
        EXPECT_TRUE(p.cache_[key].size() == 2) << "compaction: stack has 2 items";

        srv1.close();
        srv2.close();
        srv3.close();
        srv4.close();
        srv5.close();
        acc.close();
    }

    // ─── recycle IPv6 过滤路径 ──────────────────

    TEST(PoolDeep3, RecycleIPv6Filtered)
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
        EXPECT_TRUE(s.total_recycles == 1) << "recycle IPv6: recycle counted";
        EXPECT_TRUE(s.idle_count == 0) << "recycle IPv6: not cached";
        EXPECT_TRUE(s.total_evictions == 1) << "recycle IPv6: eviction counted";

        srv.close();
        acc.close();
    }

    // ─── recycle cache_peraddr 限制 ──────────────

    TEST(PoolDeep3, RecycleCachePerAddrLimit)
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
        EXPECT_TRUE(p.stats().idle_count == 1) << "peraddr: first -> idle 1";

        p.recycle(s2, ep);
        EXPECT_TRUE(p.stats().total_recycles == 2) << "peraddr: second counted";
        EXPECT_TRUE(p.stats().idle_count == 1) << "peraddr: still idle 1";
        EXPECT_TRUE(p.stats().total_evictions == 1) << "peraddr: 1 eviction";

        srv1.close();
        srv2.close();
        acc.close();
    }

    // ─── recycle 不健康 socket（对端关闭后触发 healthy_fast 失败）──

    TEST(PoolDeep3, RecycleUnhealthyPeerClosed)
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
        EXPECT_TRUE(s.total_recycles == 1) << "recycle unhealthy: recycle attempted";

        acc.close();
    }

    // ─── clear() 与 started pool ──────────────────

    TEST(PoolDeep3, ClearWithStartedPool)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        p.start();

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        p.recycle(sock, ep);

        EXPECT_TRUE(p.stats().idle_count == 1) << "clear: idle 1 before";

        p.clear();

        EXPECT_TRUE(p.cache_.empty()) << "clear: cache empty after clear";
        EXPECT_TRUE(p.stats().idle_count == 0) << "clear: idle 0 after clear";
        EXPECT_TRUE(!p.cleanup_timer_.has_value()) << "clear: timer reset";

        srv.close();
        acc.close();
    }

    // ─── clear() 未 started pool ─────────────────

    TEST(PoolDeep3, ClearUnstartedPool)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        p.recycle(sock, ep);

        p.clear();

        EXPECT_TRUE(p.cache_.empty()) << "clear unstarted: cache empty";
        EXPECT_TRUE(p.stats().idle_count == 0) << "clear unstarted: idle 0";

        srv.close();
        acc.close();
    }

    // ─── apply_opts 错误路径（关闭的 socket）──

    TEST(PoolDeep3, ApplyOptsClosedSocket)
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
        EXPECT_TRUE(!sock.is_open()) << "apply_opts: closed socket stays closed";
    }

    // ─── apply_opts 正常路径 ───────────────────

    TEST(PoolDeep3, ApplyOptsNormalPath)
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
        EXPECT_TRUE(sock->is_open()) << "apply_opts: normal path -> socket still open";

        delete sock;
        srv.close();
        acc.close();
    }

    // ─── apply_opts 全禁用 → 跳过所有分支 ─────

    TEST(PoolDeep3, ApplyOptsAllDisabled)
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
        EXPECT_TRUE(sock->is_open()) << "apply_opts: all disabled -> socket still open";

        delete sock;
        srv.close();
        acc.close();
    }

    // ─── endpoint_key 相等比较 ──────────────────

    TEST(PoolDeep3, EndpointKeyEquality)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        auto ep3 = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 81);

        auto k1 = pool::to_key(ep1);
        auto k2 = pool::to_key(ep2);
        auto k3 = pool::to_key(ep3);

        EXPECT_TRUE(k1 == k2) << "key: same endpoint -> equal";
        EXPECT_TRUE(k1 != k3) << "key: different port -> not equal";
    }

    // ─── start() 幂等：第二次走 timer exists 路径 ─

    TEST(PoolDeep3, StartIdempotentTimerExists)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        p.start();
        EXPECT_TRUE(p.cleanup_timer_.has_value()) << "start: timer created after first start";
        EXPECT_TRUE(p.started_) << "start: started_ is true";

        p.start();
        EXPECT_TRUE(p.started_) << "start: second call -> started_ still true";

        // clear 后 cleanup_timer_ 被销毁
        p.clear();
        EXPECT_TRUE(!p.cleanup_timer_.has_value()) << "start: timer cleared after clear";
    }

} // namespace

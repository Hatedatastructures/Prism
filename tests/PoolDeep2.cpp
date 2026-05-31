/**
 * @file PoolDeep2.cpp
 * @brief connect/pool/pool 深度纯函数测试（扩展）
 * @details 通过 #include 源文件访问 pool.cpp 中所有同步函数，
 *          覆盖 recycle 边界条件、IPv6 过滤、start 幂等、
 *          pooled_connection RAII 完整路径、stats 累加器。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include <set>

#include "../src/prism/connect/pool/pool.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace pool = psm::connect;
    using tcp = boost::asio::ip::tcp;
    namespace net = boost::asio;

    // 辅助：创建一个已连接的堆分配 socket，同时返回服务端 socket（保持打开以防 FIN）
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

    // ─── to_key 边界值测试 ────────────────────────

    void TestToKeyZeroPort(TestRunner &runner)
    {
        auto addr = net::ip::make_address_v4("0.0.0.0");
        tcp::endpoint ep(addr, 0);
        auto key = pool::to_key(ep);
        runner.Check(key.port == 0, "to_key: port == 0");
        runner.Check(key.family == 4, "to_key: family == 4 (zero port)");
    }

    void TestToKeyMaxPort(TestRunner &runner)
    {
        auto addr = net::ip::make_address_v4("1.1.1.1");
        tcp::endpoint ep(addr, 65535);
        auto key = pool::to_key(ep);
        runner.Check(key.port == 65535, "to_key: port == 65535");
    }

    void TestToKeyIPv6FullAddress(TestRunner &runner)
    {
        auto addr = net::ip::make_address_v6("2001:db8:85a3::8a2e:370:7334");
        tcp::endpoint ep(addr, 443);
        auto key = pool::to_key(ep);
        runner.Check(key.family == 6, "to_key: full IPv6 family == 6");
        runner.Check(key.port == 443, "to_key: full IPv6 port == 443");
        auto bytes = addr.to_bytes();
        runner.Check(std::memcmp(key.address.data(), bytes.data(), 16) == 0,
                     "to_key: full IPv6 address bytes match");
    }

    void TestToKeyIPv4MappedIPv6(TestRunner &runner)
    {
        auto addr = net::ip::make_address_v6("::ffff:192.168.1.1");
        tcp::endpoint ep(addr, 8080);
        auto key = pool::to_key(ep);
        runner.Check(key.family == 6, "to_key: mapped IPv6 family == 6");
    }

    // ─── endpoint_hash 分布测试 ───────────────────

    void TestHashCollisionResistance(TestRunner &runner)
    {
        pool::endpoint_hash hasher;
        std::set<std::size_t> hashes;
        bool all_unique = true;
        for (int i = 0; i < 100; ++i)
        {
            auto addr = net::ip::make_address_v4(
                "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256));
            auto h = hasher(pool::to_key(tcp::endpoint(addr, 80 + i)));
            if (!hashes.insert(h).second)
            {
                all_unique = false;
                break;
            }
        }
        runner.Check(all_unique, "hash: 100 different endpoints -> all unique hashes");
    }

    void TestHashIPv4vsIPv6(TestRunner &runner)
    {
        pool::endpoint_hash hasher;
        auto h4 = hasher(pool::to_key(tcp::endpoint(
            net::ip::make_address_v4("127.0.0.1"), 80)));
        auto h6 = hasher(pool::to_key(tcp::endpoint(
            net::ip::make_address_v6("::1"), 80)));
        runner.Check(h4 != h6, "hash: IPv4 vs IPv6 same port -> different");
    }

    // ─── pooled_connection 析构路径 ─────────────

    void TestPooledConnectionDestructorWithPool(TestRunner &runner)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);

        tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        {
            pool::pooled_connection conn(&p, sock, ep);
            runner.Check(conn.valid(), "pooled: with pool -> valid");
        }
        auto s = p.stats();
        runner.Check(s.total_recycles == 1, "pooled: destructor with pool -> recycle counted");
        runner.Check(s.idle_count == 1, "pooled: destructor with pool -> idle 1");

        srv.close();
        acc.close();
    }

    void TestPooledConnectionResetWithPool(TestRunner &runner)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);

        tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        pool::pooled_connection conn(&p, sock, ep);
        conn.reset();
        runner.Check(!conn.valid(), "pooled: reset with pool -> not valid");
        auto s = p.stats();
        runner.Check(s.total_recycles == 1, "pooled: reset with pool -> recycle counted");
        runner.Check(s.idle_count == 1, "pooled: reset with pool -> idle 1");

        srv.close();
        acc.close();
    }

    void TestPooledConnectionMoveAssignCleansSource(TestRunner &runner)
    {
        net::io_context ioc;
        auto *sock1 = new tcp::socket(ioc);
        auto *sock2 = new tcp::socket(ioc);
        tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), 80);
        pool::pooled_connection conn1(nullptr, sock1, ep);
        pool::pooled_connection conn2(nullptr, sock2, ep);

        conn1 = std::move(conn2);
        runner.Check(!conn2.valid(), "pooled: move assign cleans source");
        runner.Check(conn1.valid(), "pooled: move assign target valid");
        runner.Check(conn1.get() == sock2, "pooled: move assign target has sock2");

        conn1.release();
        delete sock2;
    }

    // ─── recycle 完整路径测试 ────────────────────

    void TestRecycleValidConnectedSocket(TestRunner &runner)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);

        tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        p.recycle(sock, ep);

        auto s = p.stats();
        runner.Check(s.total_recycles == 1, "recycle: valid socket -> recycle counted");
        runner.Check(s.idle_count == 1, "recycle: valid socket -> idle 1 (IPv4 cached)");

        srv.close();
        acc.close();
    }

    void TestRecycleMultipleSockets(TestRunner &runner)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [s1, srv1] = make_connected_pair(ioc, acc);
        auto [s2, srv2] = make_connected_pair(ioc, acc);

        tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        p.recycle(s1, ep);
        p.recycle(s2, ep);

        auto s = p.stats();
        runner.Check(s.total_recycles == 2, "recycle: two sockets -> 2 recycles");
        runner.Check(s.idle_count == 2, "recycle: two sockets -> idle 2");

        srv1.close();
        srv2.close();
        acc.close();
    }

    // ─── stats 累加器测试 ────────────────────────

    void TestStatsAfterRecycleAndDestruct(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));

        {
            pool::connection_pool p(ioc);
            auto [sock, srv] = make_connected_pair(ioc, acc);

            tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
            p.recycle(sock, ep);

            auto s = p.stats();
            runner.Check(s.total_recycles == 1, "stats: after recycle -> 1 recycle");
            runner.Check(s.idle_count == 1, "stats: after recycle -> idle 1");

            srv.close();
        }

        acc.close();
    }

    // ─── start 幂等性测试 ────────────────────────

    void TestStartThenRecycle(TestRunner &runner)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        p.start();
        p.start(); // 幂等

        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);

        tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        p.recycle(sock, ep);

        auto s = p.stats();
        runner.Check(s.idle_count == 1, "start+recycle: idle 1 after start");

        srv.close();
        acc.close();
    }

    // ─── pool config 自定义 ─────────────────────

    void TestPoolCustomConfig(TestRunner &runner)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.cache_peraddr = 4;
        cfg.idle_sec = 30;
        cfg.conn_timeout = 5;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);
        auto &c = p.get_config();
        runner.Check(c.cache_peraddr == 4, "config: custom cache_peraddr == 4");
        runner.Check(c.idle_sec == 30, "config: custom idle_sec == 30");
        runner.Check(c.conn_timeout == 5, "config: custom conn_timeout == 5");
    }

    // ─── pool 析构清理 ──────────────────────────

    void TestPoolDestructorClearsIdle(TestRunner &runner)
    {
        net::io_context ioc;
        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));

        {
            pool::connection_pool p(ioc);
            auto [sock, srv] = make_connected_pair(ioc, acc);

            tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
            p.recycle(sock, ep);

            auto s1 = p.stats();
            runner.Check(s1.idle_count == 1, "destructor: before destruct -> idle 1");

            srv.close();
        }
        runner.Check(true, "destructor: pool destruct with idle -> no crash");

        acc.close();
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("PoolDeep2");

    TestToKeyZeroPort(runner);
    TestToKeyMaxPort(runner);
    TestToKeyIPv6FullAddress(runner);
    TestToKeyIPv4MappedIPv6(runner);

    TestHashCollisionResistance(runner);
    TestHashIPv4vsIPv6(runner);

    TestPooledConnectionDestructorWithPool(runner);
    TestPooledConnectionResetWithPool(runner);
    TestPooledConnectionMoveAssignCleansSource(runner);

    TestRecycleValidConnectedSocket(runner);
    TestRecycleMultipleSockets(runner);

    TestStatsAfterRecycleAndDestruct(runner);

    TestStartThenRecycle(runner);

    TestPoolCustomConfig(runner);

    TestPoolDestructorClearsIdle(runner);

    return runner.Summary();
}

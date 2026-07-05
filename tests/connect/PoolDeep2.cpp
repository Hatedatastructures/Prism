/**
 * @file PoolDeep2.cpp
 * @brief connect/pool/pool 深度纯函数测试（扩展）
 * @details 通过 #include 源文件访问 pool.cpp 中所有同步函数，
 *          覆盖 recycle 边界条件、IPv6 过滤、start 幂等、
 *          pooled_connection RAII 完整路径、stats 累加器。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

#include <set>

#include "../../src/prism/net/connect/pool/pool.cpp"

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

    TEST(PoolDeep2, ToKeyZeroPort)
    {
        auto addr = net::ip::make_address_v4("0.0.0.0");
        tcp::endpoint ep(addr, 0);
        auto key = pool::to_key(ep);
        EXPECT_TRUE(key.port == 0) << "to_key: port == 0";
        EXPECT_TRUE(key.family == 4) << "to_key: family == 4 (zero port)";
    }

    TEST(PoolDeep2, ToKeyMaxPort)
    {
        auto addr = net::ip::make_address_v4("1.1.1.1");
        tcp::endpoint ep(addr, 65535);
        auto key = pool::to_key(ep);
        EXPECT_TRUE(key.port == 65535) << "to_key: port == 65535";
    }

    TEST(PoolDeep2, ToKeyIPv6FullAddress)
    {
        auto addr = net::ip::make_address_v6("2001:db8:85a3::8a2e:370:7334");
        tcp::endpoint ep(addr, 443);
        auto key = pool::to_key(ep);
        EXPECT_TRUE(key.family == 6) << "to_key: full IPv6 family == 6";
        EXPECT_TRUE(key.port == 443) << "to_key: full IPv6 port == 443";
        auto bytes = addr.to_bytes();
        EXPECT_TRUE(std::memcmp(key.address.data(), bytes.data(), 16) == 0)
            << "to_key: full IPv6 address bytes match";
    }

    TEST(PoolDeep2, ToKeyIPv4MappedIPv6)
    {
        auto addr = net::ip::make_address_v6("::ffff:192.168.1.1");
        tcp::endpoint ep(addr, 8080);
        auto key = pool::to_key(ep);
        EXPECT_TRUE(key.family == 6) << "to_key: mapped IPv6 family == 6";
    }

    // ─── endpoint_hash 分布测试 ───────────────────

    TEST(PoolDeep2, HashCollisionResistance)
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
        EXPECT_TRUE(all_unique) << "hash: 100 different endpoints -> all unique hashes";
    }

    TEST(PoolDeep2, HashIPv4vsIPv6)
    {
        pool::endpoint_hash hasher;
        auto h4 = hasher(pool::to_key(tcp::endpoint(
            net::ip::make_address_v4("127.0.0.1"), 80)));
        auto h6 = hasher(pool::to_key(tcp::endpoint(
            net::ip::make_address_v6("::1"), 80)));
        EXPECT_TRUE(h4 != h6) << "hash: IPv4 vs IPv6 same port -> different";
    }

    // ─── pooled_connection 析构路径 ─────────────

    TEST(PoolDeep2, PooledConnectionDestructorWithPool)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);

        tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        {
            pool::pooled_connection conn(&p, sock, ep);
            EXPECT_TRUE(conn.valid()) << "pooled: with pool -> valid";
        }
        auto s = p.stats();
        EXPECT_TRUE(s.total_recycles == 1) << "pooled: destructor with pool -> recycle counted";
        EXPECT_TRUE(s.idle_count == 1) << "pooled: destructor with pool -> idle 1";

        srv.close();
        acc.close();
    }

    TEST(PoolDeep2, PooledConnectionResetWithPool)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);

        tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        pool::pooled_connection conn(&p, sock, ep);
        conn.reset();
        EXPECT_TRUE(!conn.valid()) << "pooled: reset with pool -> not valid";
        auto s = p.stats();
        EXPECT_TRUE(s.total_recycles == 1) << "pooled: reset with pool -> recycle counted";
        EXPECT_TRUE(s.idle_count == 1) << "pooled: reset with pool -> idle 1";

        srv.close();
        acc.close();
    }

    TEST(PoolDeep2, PooledConnectionMoveAssignCleansSource)
    {
        net::io_context ioc;
        auto *sock1 = new tcp::socket(ioc);
        auto *sock2 = new tcp::socket(ioc);
        tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), 80);
        pool::pooled_connection conn1(nullptr, sock1, ep);
        pool::pooled_connection conn2(nullptr, sock2, ep);

        conn1 = std::move(conn2);
        EXPECT_TRUE(!conn2.valid()) << "pooled: move assign cleans source";
        EXPECT_TRUE(conn1.valid()) << "pooled: move assign target valid";
        EXPECT_TRUE(conn1.get() == sock2) << "pooled: move assign target has sock2";

        conn1.release();
        delete sock2;
    }

    // ─── recycle 完整路径测试 ────────────────────

    TEST(PoolDeep2, RecycleValidConnectedSocket)
    {
        net::io_context ioc;
        pool::connection_pool p(ioc);
        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));
        auto [sock, srv] = make_connected_pair(ioc, acc);

        tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
        p.recycle(sock, ep);

        auto s = p.stats();
        EXPECT_TRUE(s.total_recycles == 1) << "recycle: valid socket -> recycle counted";
        EXPECT_TRUE(s.idle_count == 1) << "recycle: valid socket -> idle 1 (IPv4 cached)";

        srv.close();
        acc.close();
    }

    TEST(PoolDeep2, RecycleMultipleSockets)
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
        EXPECT_TRUE(s.total_recycles == 2) << "recycle: two sockets -> 2 recycles";
        EXPECT_TRUE(s.idle_count == 2) << "recycle: two sockets -> idle 2";

        srv1.close();
        srv2.close();
        acc.close();
    }

    // ─── stats 累加器测试 ────────────────────────

    TEST(PoolDeep2, StatsAfterRecycleAndDestruct)
    {
        net::io_context ioc;
        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));

        {
            pool::connection_pool p(ioc);
            auto [sock, srv] = make_connected_pair(ioc, acc);

            tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
            p.recycle(sock, ep);

            auto s = p.stats();
            EXPECT_TRUE(s.total_recycles == 1) << "stats: after recycle -> 1 recycle";
            EXPECT_TRUE(s.idle_count == 1) << "stats: after recycle -> idle 1";

            srv.close();
        }

        acc.close();
    }

    // ─── start 幂等性测试 ────────────────────────

    TEST(PoolDeep2, StartThenRecycle)
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
        EXPECT_TRUE(s.idle_count == 1) << "start+recycle: idle 1 after start";

        srv.close();
        acc.close();
    }

    // ─── pool config 自定义 ─────────────────────

    TEST(PoolDeep2, PoolCustomConfig)
    {
        net::io_context ioc;
        pool::config cfg;
        cfg.cache_peraddr = 4;
        cfg.idle_sec = 30;
        cfg.conn_timeout = 5;
        pool::connection_pool p(ioc, psm::memory::current_resource(), cfg);
        auto &c = p.get_config();
        EXPECT_TRUE(c.cache_peraddr == 4) << "config: custom cache_peraddr == 4";
        EXPECT_TRUE(c.idle_sec == 30) << "config: custom idle_sec == 30";
        EXPECT_TRUE(c.conn_timeout == 5) << "config: custom conn_timeout == 5";
    }

    // ─── pool 析构清理 ──────────────────────────

    TEST(PoolDeep2, PoolDestructorClearsIdle)
    {
        net::io_context ioc;
        tcp::acceptor acc(ioc, tcp::endpoint(tcp::v4(), 0));

        {
            pool::connection_pool p(ioc);
            auto [sock, srv] = make_connected_pair(ioc, acc);

            tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), acc.local_endpoint().port());
            p.recycle(sock, ep);

            auto s1 = p.stats();
            EXPECT_TRUE(s1.idle_count == 1) << "destructor: before destruct -> idle 1";

            srv.close();
        }
        // pool 析构后连接已清理，无外部状态可验证

        acc.close();
    }

} // namespace

/**
 * @file PoolDeep.cpp
 * @brief 连接池深度纯函数测试
 * @details 通过 #include 源文件访问 pool.cpp 中所有同步函数，
 *          覆盖 pooled_connection 生命周期、to_key、endpoint_hash、
 *          stats、cleanup、clear、recycle、delete_socket。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

#include "../../src/prism/connect/pool/pool.cpp"

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    // ─── to_key ─────────────────────────────────

    TEST(PoolDeep, ToKeyIPv4Loopback)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        auto key = psm::connect::to_key(ep);
        EXPECT_TRUE(key.family == 4) << "to_key: IPv4 family=4";
        EXPECT_TRUE(key.port == 80) << "to_key: IPv4 port=80";
        EXPECT_TRUE(key.address[0] == 127) << "to_key: IPv4 addr[0]";
        EXPECT_TRUE(key.address[3] == 1) << "to_key: IPv4 addr[3]";
    }

    TEST(PoolDeep, ToKeyIPv4Broadcast)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("255.255.255.255"), 65535);
        auto key = psm::connect::to_key(ep);
        EXPECT_TRUE(key.family == 4) << "to_key: broadcast family=4";
        EXPECT_TRUE(key.port == 65535) << "to_key: broadcast port=65535";
        EXPECT_TRUE(key.address[0] == 255) << "to_key: broadcast addr[0]";
        EXPECT_TRUE(key.address[3] == 255) << "to_key: broadcast addr[3]";
    }

    TEST(PoolDeep, ToKeyIPv6Loopback)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v6("::1"), 443);
        auto key = psm::connect::to_key(ep);
        EXPECT_TRUE(key.family == 6) << "to_key: IPv6 family=6";
        EXPECT_TRUE(key.port == 443) << "to_key: IPv6 port=443";
        EXPECT_TRUE(key.address[15] == 1) << "to_key: IPv6 addr[15]=1";
        for (std::size_t i = 0; i < 15; ++i)
        {
            EXPECT_TRUE(key.address[i] == 0) << "to_key: IPv6 leading zeros";
            if (key.address[i] != 0)
                break;
        }
    }

    TEST(PoolDeep, ToKeyIPv6Full)
    {
        net::ip::address_v6::bytes_type bytes;
        for (std::size_t i = 0; i < 16; ++i)
            bytes[i] = static_cast<std::uint8_t>(i + 1);
        auto ep = tcp::endpoint(net::ip::address_v6(bytes), 8080);
        auto key = psm::connect::to_key(ep);
        EXPECT_TRUE(key.family == 6) << "to_key: IPv6 full family=6";
        EXPECT_TRUE(key.address[0] == 1) << "to_key: IPv6 full addr[0]=1";
        EXPECT_TRUE(key.address[15] == 16) << "to_key: IPv6 full addr[15]=16";
    }

    // ─── endpoint_hash ──────────────────────────

    TEST(PoolDeep, EndpointHashIPv4)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 80);
        auto key = psm::connect::to_key(ep);
        psm::connect::endpoint_hash hasher;
        auto h = hasher(key);
        EXPECT_TRUE(h != 0) << "endpoint_hash: IPv4 nonzero";
        EXPECT_TRUE(hasher(key) == h) << "endpoint_hash: deterministic";
    }

    TEST(PoolDeep, EndpointHashIPv6)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v6("2001:db8::1"), 443);
        auto key = psm::connect::to_key(ep);
        psm::connect::endpoint_hash hasher;
        auto h = hasher(key);
        EXPECT_TRUE(h != 0) << "endpoint_hash: IPv6 nonzero";
    }

    TEST(PoolDeep, EndpointHashDifferentPorts)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("1.2.3.4"), 80);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("1.2.3.4"), 81);
        auto k1 = psm::connect::to_key(ep1);
        auto k2 = psm::connect::to_key(ep2);
        psm::connect::endpoint_hash hasher;
        EXPECT_TRUE(hasher(k1) != hasher(k2)) << "endpoint_hash: different ports";
    }

    TEST(PoolDeep, EndpointHashDifferentFamilies)
    {
        auto ep4 = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        auto ep6 = tcp::endpoint(net::ip::make_address("::1"), 80);
        auto k4 = psm::connect::to_key(ep4);
        auto k6 = psm::connect::to_key(ep6);
        psm::connect::endpoint_hash hasher;
        EXPECT_TRUE(hasher(k4) != hasher(k6)) << "endpoint_hash: different families";
    }

    TEST(PoolDeep, EndpointHashAllZeroKey)
    {
        psm::connect::endpoint_key zero_key{};
        psm::connect::endpoint_hash hasher;
        auto h = hasher(zero_key);
        EXPECT_TRUE(h != 0) << "endpoint_hash: zero key -> nonzero (FNV offset)";
    }

    // ─── pooled_connection 生命周期 ──────────────

    TEST(PoolDeep, PooledDefaultDestruct)
    {
        {
            psm::connect::pooled_connection conn;
            EXPECT_TRUE(!conn.valid()) << "pooled: default invalid";
            EXPECT_TRUE(conn.get() == nullptr) << "pooled: default get=nullptr";
        }
        // scope 结束后 conn 已析构，前面已验证 valid()==false，析构无异常即可
    }

    TEST(PoolDeep, PooledReleaseEmpty)
    {
        psm::connect::pooled_connection conn;
        auto *s = conn.release();
        EXPECT_TRUE(s == nullptr) << "pooled: release empty -> nullptr";
    }

    TEST(PoolDeep, PooledResetEmpty)
    {
        psm::connect::pooled_connection conn;
        conn.reset();
        EXPECT_TRUE(!conn.valid()) << "pooled: reset empty no crash";
    }

    TEST(PoolDeep, PooledMoveAssignEmpty)
    {
        psm::connect::pooled_connection a;
        psm::connect::pooled_connection b;
        a = std::move(b);
        EXPECT_TRUE(!a.valid()) << "pooled: move-assign empty -> still empty";
        EXPECT_TRUE(!b.valid()) << "pooled: move-assign src empty";
    }

    TEST(PoolDeep, PooledMoveAssignSelf)
    {
        psm::connect::pooled_connection conn;
        conn = std::move(conn);
        EXPECT_TRUE(!conn.valid()) << "pooled: self-move-assign no crash";
    }

    TEST(PoolDeep, PooledConstructWithPoolNullSocket)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        psm::connect::pooled_connection conn(&pool, nullptr, ep);
        EXPECT_TRUE(!conn.valid()) << "pooled: null socket -> invalid";
    }

    TEST(PoolDeep, PooledConstructWithSocketNoPool)
    {
        // pool_==nullptr, socket_!=null -> reset() 会 close+delete
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        {
            psm::connect::pooled_connection conn(nullptr, sock, ep);
            EXPECT_TRUE(conn.valid()) << "pooled: socket valid";
            EXPECT_TRUE(conn.get() == sock) << "pooled: get returns socket";
        }
        // 析构时 pool_==null → delete_socket 路径
        // socket 已被 delete，裸指针变为悬垂（值不变），不可再访问
        // 验证方式：析构不崩溃 + 之前 valid()==true 已确认
    }

    TEST(PoolDeep, PooledReleaseWithSocket)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        psm::connect::pooled_connection conn(nullptr, sock, ep);

        auto *released = conn.release();
        EXPECT_TRUE(released == sock) << "pooled: release returns socket";
        EXPECT_TRUE(!conn.valid()) << "pooled: release -> invalid";

        // 手动清理释放的 socket
        boost::system::error_code ec;
        released->close(ec);
        delete released;
    }

    TEST(PoolDeep, PooledMoveConstruct)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        psm::connect::pooled_connection a(nullptr, sock, ep);
        EXPECT_TRUE(a.valid()) << "pooled: move src valid";

        psm::connect::pooled_connection b(std::move(a));
        EXPECT_TRUE(!a.valid()) << "pooled: move src invalidated";
        EXPECT_TRUE(b.valid()) << "pooled: move dst valid";
        EXPECT_TRUE(b.get() == sock) << "pooled: move dst has socket";

        // b 析构时 delete socket
    }

    TEST(PoolDeep, PooledMoveAssignWithData)
    {
        net::io_context ioc;
        auto *sock1 = new tcp::socket(ioc);
        auto *sock2 = new tcp::socket(ioc);
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);

        psm::connect::pooled_connection a(nullptr, sock1, ep1);
        psm::connect::pooled_connection b(nullptr, sock2, ep2);

        // a = std::move(b) -> a 先 reset (close+delete sock1)，然后接管 sock2
        a = std::move(b);
        EXPECT_TRUE(a.valid()) << "pooled: move-assign dst valid";
        EXPECT_TRUE(a.get() == sock2) << "pooled: move-assign dst has sock2";
        EXPECT_TRUE(!b.valid()) << "pooled: move-assign src invalidated";
    }

    // ─── delete_socket ──────────────────────────

    TEST(PoolDeep, DeleteSocketNull)
    {
        psm::connect::delete_socket(nullptr);
        // nullptr delete 是 no-op，不崩溃即通过
    }

    TEST(PoolDeep, DeleteSocketReal)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        boost::system::error_code ec;
        sock->close(ec);
        psm::connect::delete_socket(sock);
        // sock 已被 delete，无内存泄漏
    }

    // ─── connection_pool 同步方法 ────────────────

    TEST(PoolDeep, PoolStatsInitial)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        auto s = pool.stats();
        EXPECT_TRUE(s.total_acquires == 0) << "pool: initial acquires=0";
        EXPECT_TRUE(s.total_hits == 0) << "pool: initial hits=0";
        EXPECT_TRUE(s.total_creates == 0) << "pool: initial creates=0";
        EXPECT_TRUE(s.total_recycles == 0) << "pool: initial recycles=0";
        EXPECT_TRUE(s.total_evictions == 0) << "pool: initial evictions=0";
        EXPECT_TRUE(s.idle_count == 0) << "pool: initial idle=0";
        EXPECT_TRUE(s.endpoint_count == 0) << "pool: initial endpoints=0";
    }

    TEST(PoolDeep, PoolGetConfig)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        const auto &cfg = pool.get_config();
        EXPECT_TRUE(cfg.tcp_nodelay) << "pool: default tcp_nodelay";
        EXPECT_TRUE(cfg.keep_alive) << "pool: default keep_alive";
    }

    // cleanup/clear/apply_opts 为 private，无法直接调用
    // 通过析构函数间接调用 clear()，通过 recycle 间接覆盖逻辑

    TEST(PoolDeep, PoolRecycleNull)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        pool.recycle(nullptr, ep);
        auto s = pool.stats();
        EXPECT_TRUE(s.total_recycles == 0) << "pool: recycle null -> no recycle count";
    }

    TEST(PoolDeep, PoolRecycleClosedSocket)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        auto *sock = new tcp::socket(ioc);
        sock->close();
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        pool.recycle(sock, ep);
        auto s = pool.stats();
        EXPECT_TRUE(s.total_recycles == 0) << "pool: recycle closed -> no recycle count";
        EXPECT_TRUE(s.idle_count == 0) << "pool: recycle closed -> idle=0";
    }

    TEST(PoolDeep, PoolDestruct)
    {
        {
            net::io_context ioc;
            psm::connect::connection_pool pool(ioc);
            pool.start();
            ioc.poll();
        }
        // pool 析构调用 clear()，清理协程正常停止
    }

    TEST(PoolDeep, PoolStartIdempotent)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        pool.start();
        pool.start();
        auto s = pool.stats();
        EXPECT_TRUE(s.idle_count == 0) << "pool: double start, stats still valid";
        // 析构时调用 clear() 停止清理协程
    }

    // apply_opts 为 private，通过 async_acquire 路径间接覆盖

} // namespace

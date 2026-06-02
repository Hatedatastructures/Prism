/**
 * @file PoolDeep4.cpp
 * @brief 连接池纯函数深度测试 — gcov 覆盖
 * @details 通过 #include 源文件确保 gcov 计入覆盖行。
 *          覆盖 to_key (IPv4/IPv6)、endpoint_hash、pooled_connection RAII、
 *          connection_pool::stats()、pool_stats 默认值。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <array>
#include <cstdint>
#include <cstring>

#define private public
#include <prism/connect/pool/pool.hpp>
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../../src/prism/connect/pool/pool.cpp"

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using psm::connect::to_key;
    using psm::connect::endpoint_key;
    using psm::connect::endpoint_hash;
    using psm::connect::pooled_connection;
    using psm::connect::connection_pool;
    using psm::connect::pool_stats;

    // ─── to_key IPv4 ──────────────────────────────

    TEST(PoolDeep4, ToKeyIPv4)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("192.168.1.1"), 443);
        auto key = to_key(ep);
        EXPECT_TRUE(key.port == 443) << "to_key: ipv4 port=443";
        EXPECT_TRUE(key.family == 4) << "to_key: ipv4 family=4";
        EXPECT_TRUE(key.address[0] == 192) << "to_key: ipv4 addr[0]=192";
        EXPECT_TRUE(key.address[1] == 168) << "to_key: ipv4 addr[1]=168";
        EXPECT_TRUE(key.address[2] == 1) << "to_key: ipv4 addr[2]=1";
        EXPECT_TRUE(key.address[3] == 1) << "to_key: ipv4 addr[3]=1";
    }

    TEST(PoolDeep4, ToKeyIPv4Loopback)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 8080);
        auto key = to_key(ep);
        EXPECT_TRUE(key.port == 8080) << "to_key: loopback port=8080";
        EXPECT_TRUE(key.family == 4) << "to_key: loopback family=4";
        EXPECT_TRUE(key.address[0] == 127) << "to_key: loopback addr[0]=127";
    }

    // ─── to_key IPv6 ──────────────────────────────

    TEST(PoolDeep4, ToKeyIPv6)
    {
        auto addr = net::ip::make_address_v6("::1");
        auto ep = tcp::endpoint(addr, 8443);
        auto key = to_key(ep);
        EXPECT_TRUE(key.port == 8443) << "to_key: ipv6 port=8443";
        EXPECT_TRUE(key.family == 6) << "to_key: ipv6 family=6";
        // ::1 → 最后字节为 1，其余为 0
        EXPECT_TRUE(key.address[15] == 1) << "to_key: ipv6 ::1 last byte=1";
        EXPECT_TRUE(key.address[0] == 0) << "to_key: ipv6 ::1 first byte=0";
    }

    TEST(PoolDeep4, ToKeyIPv6FullAddress)
    {
        net::ip::address_v6::bytes_type bytes{};
        bytes[0] = 0x20;
        bytes[1] = 0x01;
        bytes[15] = 0x01;
        auto addr = net::ip::address_v6(bytes);
        auto ep = tcp::endpoint(addr, 443);
        auto key = to_key(ep);
        EXPECT_TRUE(key.family == 6) << "to_key: ipv6 full family=6";
        EXPECT_TRUE(key.address[0] == 0x20) << "to_key: ipv6 full byte[0]";
        EXPECT_TRUE(key.address[1] == 0x01) << "to_key: ipv6 full byte[1]";
        EXPECT_TRUE(key.address[15] == 0x01) << "to_key: ipv6 full byte[15]";
    }

    // ─── endpoint_key 相等比较 ──────────────────────

    TEST(PoolDeep4, EndpointKeyEquality)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto k1 = to_key(ep1);
        auto k2 = to_key(ep2);
        EXPECT_TRUE(k1 == k2) << "endpoint_key: same endpoint equals";
    }

    TEST(PoolDeep4, EndpointKeyDiffPort)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 8443);
        EXPECT_TRUE(to_key(ep1) != to_key(ep2)) << "endpoint_key: different port not equal";
    }

    TEST(PoolDeep4, EndpointKeyDiffAddr)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.2"), 443);
        EXPECT_TRUE(to_key(ep1) != to_key(ep2)) << "endpoint_key: different addr not equal";
    }

    // ─── endpoint_hash 一致性 ──────────────────────

    TEST(PoolDeep4, HashConsistency)
    {
        endpoint_hash hasher;
        auto ep = tcp::endpoint(net::ip::make_address_v4("1.2.3.4"), 5678);
        auto key = to_key(ep);
        auto h1 = hasher(key);
        auto h2 = hasher(key);
        EXPECT_TRUE(h1 == h2) << "hash: same key same hash";
    }

    TEST(PoolDeep4, HashDifferentEndpoints)
    {
        endpoint_hash hasher;
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("1.2.3.4"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("5.6.7.8"), 443);
        auto h1 = hasher(to_key(ep1));
        auto h2 = hasher(to_key(ep2));
        EXPECT_TRUE(h1 != h2) << "hash: different endpoints different hash";
    }

    TEST(PoolDeep4, HashIPv4AndIPv6Diff)
    {
        endpoint_hash hasher;
        auto ep4 = tcp::endpoint(net::ip::make_address_v4("0.0.0.0"), 443);
        auto ep6 = tcp::endpoint(net::ip::make_address_v6("::"), 443);
        auto h4 = hasher(to_key(ep4));
        auto h6 = hasher(to_key(ep6));
        EXPECT_TRUE(h4 != h6) << "hash: v4 vs v6 different";
    }

    // ─── pooled_connection RAII ──────────────────────

    TEST(PoolDeep4, PooledConnectionDefault)
    {
        pooled_connection conn;
        EXPECT_TRUE(!conn.valid()) << "pooled: default invalid";
        EXPECT_TRUE(!conn) << "pooled: default bool=false";
        EXPECT_TRUE(conn.get() == nullptr) << "pooled: default get()=null";
    }

    TEST(PoolDeep4, PooledConnectionMove)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);

        pooled_connection conn1(nullptr, sock, ep);
        EXPECT_TRUE(conn1.valid()) << "pooled: conn1 valid";

        pooled_connection conn2(std::move(conn1));
        EXPECT_TRUE(!conn1.valid()) << "pooled: after move conn1 invalid";
        EXPECT_TRUE(conn2.valid()) << "pooled: after move conn2 valid";
        EXPECT_TRUE(conn2.get() == sock) << "pooled: conn2 owns socket";

        // conn2 析构时无 pool_，直接 delete socket
        conn2.release();
        delete sock;
    }

    TEST(PoolDeep4, PooledConnectionRelease)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);

        pooled_connection conn(nullptr, sock, ep);
        auto *released = conn.release();
        EXPECT_TRUE(released == sock) << "pooled: release returns socket";
        EXPECT_TRUE(!conn.valid()) << "pooled: after release invalid";
        EXPECT_TRUE(conn.get() == nullptr) << "pooled: after release get=null";

        delete sock;
    }

    TEST(PoolDeep4, PooledConnectionMoveAssign)
    {
        net::io_context ioc;
        auto *sock1 = new tcp::socket(ioc);
        auto *sock2 = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);

        pooled_connection conn1(nullptr, sock1, ep);
        pooled_connection conn2(nullptr, sock2, ep);

        conn2 = std::move(conn1);
        EXPECT_TRUE(!conn1.valid()) << "pooled: move assign src invalid";
        EXPECT_TRUE(conn2.valid()) << "pooled: move assign dst valid";
        EXPECT_TRUE(conn2.get() == sock1) << "pooled: move assign dst owns sock1";

        conn2.release();
        delete sock1;
        // sock2 被 conn1 析构时 delete（无 pool_）
        // 但 conn1 移动后 socket_ 为 nullptr，不会 delete
        // 所以不需要再 delete sock2，它已经在 conn2=move 时的 reset() 中被 delete
    }

    TEST(PoolDeep4, PooledConnectionSelfAssign)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);

        pooled_connection conn(nullptr, sock, ep);
        conn = std::move(conn); // 自赋值
        EXPECT_TRUE(conn.valid()) << "pooled: self assign still valid";
        EXPECT_TRUE(conn.get() == sock) << "pooled: self assign same socket";

        conn.release();
        delete sock;
    }

    // ─── connection_pool stats 默认 ──────────────────

    TEST(PoolDeep4, PoolStatsDefault)
    {
        net::io_context ioc;
        connection_pool pool(ioc);
        auto s = pool.stats();
        EXPECT_TRUE(s.idle_count == 0) << "pool stats: initial idle=0";
        EXPECT_TRUE(s.endpoint_count == 0) << "pool stats: initial endpoints=0";
        EXPECT_TRUE(s.total_acquires == 0) << "pool stats: initial acquires=0";
        EXPECT_TRUE(s.total_hits == 0) << "pool stats: initial hits=0";
        EXPECT_TRUE(s.total_creates == 0) << "pool stats: initial creates=0";
    }

    // ─── delete_socket null 安全 ──────────────────

    TEST(PoolDeep4, DeleteSocketNull)
    {
        // 内部函数，通过 pool 的 clear() 间接调用
        // 直接测试 null 不崩溃
        psm::connect::delete_socket(nullptr);
        // nullptr delete 是 no-op，无内存泄漏
    }

} // namespace

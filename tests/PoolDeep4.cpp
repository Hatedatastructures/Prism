/**
 * @file PoolDeep2.cpp
 * @brief 连接池纯函数深度测试 — gcov 覆盖
 * @details 通过 #include 源文件确保 gcov 计入覆盖行。
 *          覆盖 to_key (IPv4/IPv6)、endpoint_hash、pooled_connection RAII、
 *          connection_pool::stats()、pool_stats 默认值。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include <boost/asio.hpp>
#include <array>
#include <cstdint>
#include <cstring>

#define private public
#include <prism/connect/pool/pool.hpp>
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../src/prism/connect/pool/pool.cpp"

using psm::testing::TestRunner;

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

    void TestToKeyIPv4(TestRunner &runner)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("192.168.1.1"), 443);
        auto key = to_key(ep);
        runner.Check(key.port == 443, "to_key: ipv4 port=443");
        runner.Check(key.family == 4, "to_key: ipv4 family=4");
        runner.Check(key.address[0] == 192, "to_key: ipv4 addr[0]=192");
        runner.Check(key.address[1] == 168, "to_key: ipv4 addr[1]=168");
        runner.Check(key.address[2] == 1, "to_key: ipv4 addr[2]=1");
        runner.Check(key.address[3] == 1, "to_key: ipv4 addr[3]=1");
    }

    void TestToKeyIPv4Loopback(TestRunner &runner)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 8080);
        auto key = to_key(ep);
        runner.Check(key.port == 8080, "to_key: loopback port=8080");
        runner.Check(key.family == 4, "to_key: loopback family=4");
        runner.Check(key.address[0] == 127, "to_key: loopback addr[0]=127");
    }

    // ─── to_key IPv6 ──────────────────────────────

    void TestToKeyIPv6(TestRunner &runner)
    {
        auto addr = net::ip::make_address_v6("::1");
        auto ep = tcp::endpoint(addr, 8443);
        auto key = to_key(ep);
        runner.Check(key.port == 8443, "to_key: ipv6 port=8443");
        runner.Check(key.family == 6, "to_key: ipv6 family=6");
        // ::1 → 最后字节为 1，其余为 0
        runner.Check(key.address[15] == 1, "to_key: ipv6 ::1 last byte=1");
        runner.Check(key.address[0] == 0, "to_key: ipv6 ::1 first byte=0");
    }

    void TestToKeyIPv6FullAddress(TestRunner &runner)
    {
        net::ip::address_v6::bytes_type bytes{};
        bytes[0] = 0x20;
        bytes[1] = 0x01;
        bytes[15] = 0x01;
        auto addr = net::ip::address_v6(bytes);
        auto ep = tcp::endpoint(addr, 443);
        auto key = to_key(ep);
        runner.Check(key.family == 6, "to_key: ipv6 full family=6");
        runner.Check(key.address[0] == 0x20, "to_key: ipv6 full byte[0]");
        runner.Check(key.address[1] == 0x01, "to_key: ipv6 full byte[1]");
        runner.Check(key.address[15] == 0x01, "to_key: ipv6 full byte[15]");
    }

    // ─── endpoint_key 相等比较 ──────────────────────

    void TestEndpointKeyEquality(TestRunner &runner)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto k1 = to_key(ep1);
        auto k2 = to_key(ep2);
        runner.Check(k1 == k2, "endpoint_key: same endpoint equals");
    }

    void TestEndpointKeyDiffPort(TestRunner &runner)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 8443);
        runner.Check(to_key(ep1) != to_key(ep2), "endpoint_key: different port not equal");
    }

    void TestEndpointKeyDiffAddr(TestRunner &runner)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.2"), 443);
        runner.Check(to_key(ep1) != to_key(ep2), "endpoint_key: different addr not equal");
    }

    // ─── endpoint_hash 一致性 ──────────────────────

    void TestHashConsistency(TestRunner &runner)
    {
        endpoint_hash hasher;
        auto ep = tcp::endpoint(net::ip::make_address_v4("1.2.3.4"), 5678);
        auto key = to_key(ep);
        auto h1 = hasher(key);
        auto h2 = hasher(key);
        runner.Check(h1 == h2, "hash: same key same hash");
    }

    void TestHashDifferentEndpoints(TestRunner &runner)
    {
        endpoint_hash hasher;
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("1.2.3.4"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("5.6.7.8"), 443);
        auto h1 = hasher(to_key(ep1));
        auto h2 = hasher(to_key(ep2));
        runner.Check(h1 != h2, "hash: different endpoints different hash");
    }

    void TestHashIPv4AndIPv6Diff(TestRunner &runner)
    {
        endpoint_hash hasher;
        auto ep4 = tcp::endpoint(net::ip::make_address_v4("0.0.0.0"), 443);
        auto ep6 = tcp::endpoint(net::ip::make_address_v6("::"), 443);
        auto h4 = hasher(to_key(ep4));
        auto h6 = hasher(to_key(ep6));
        runner.Check(h4 != h6, "hash: v4 vs v6 different");
    }

    // ─── pooled_connection RAII ──────────────────────

    void TestPooledConnectionDefault(TestRunner &runner)
    {
        pooled_connection conn;
        runner.Check(!conn.valid(), "pooled: default invalid");
        runner.Check(!conn, "pooled: default bool=false");
        runner.Check(conn.get() == nullptr, "pooled: default get()=null");
    }

    void TestPooledConnectionMove(TestRunner &runner)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);

        pooled_connection conn1(nullptr, sock, ep);
        runner.Check(conn1.valid(), "pooled: conn1 valid");

        pooled_connection conn2(std::move(conn1));
        runner.Check(!conn1.valid(), "pooled: after move conn1 invalid");
        runner.Check(conn2.valid(), "pooled: after move conn2 valid");
        runner.Check(conn2.get() == sock, "pooled: conn2 owns socket");

        // conn2 析构时无 pool_，直接 delete socket
        conn2.release();
        delete sock;
    }

    void TestPooledConnectionRelease(TestRunner &runner)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);

        pooled_connection conn(nullptr, sock, ep);
        auto *released = conn.release();
        runner.Check(released == sock, "pooled: release returns socket");
        runner.Check(!conn.valid(), "pooled: after release invalid");
        runner.Check(conn.get() == nullptr, "pooled: after release get=null");

        delete sock;
    }

    void TestPooledConnectionMoveAssign(TestRunner &runner)
    {
        net::io_context ioc;
        auto *sock1 = new tcp::socket(ioc);
        auto *sock2 = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);

        pooled_connection conn1(nullptr, sock1, ep);
        pooled_connection conn2(nullptr, sock2, ep);

        conn2 = std::move(conn1);
        runner.Check(!conn1.valid(), "pooled: move assign src invalid");
        runner.Check(conn2.valid(), "pooled: move assign dst valid");
        runner.Check(conn2.get() == sock1, "pooled: move assign dst owns sock1");

        conn2.release();
        delete sock1;
        // sock2 被 conn1 析构时 delete（无 pool_）
        // 但 conn1 移动后 socket_ 为 nullptr，不会 delete
        // 所以不需要再 delete sock2，它已经在 conn2=move 时的 reset() 中被 delete
    }

    void TestPooledConnectionSelfAssign(TestRunner &runner)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);

        pooled_connection conn(nullptr, sock, ep);
        conn = std::move(conn); // 自赋值
        runner.Check(conn.valid(), "pooled: self assign still valid");
        runner.Check(conn.get() == sock, "pooled: self assign same socket");

        conn.release();
        delete sock;
    }

    // ─── connection_pool stats 默认 ──────────────────

    void TestPoolStatsDefault(TestRunner &runner)
    {
        net::io_context ioc;
        connection_pool pool(ioc);
        auto s = pool.stats();
        runner.Check(s.idle_count == 0, "pool stats: initial idle=0");
        runner.Check(s.endpoint_count == 0, "pool stats: initial endpoints=0");
        runner.Check(s.total_acquires == 0, "pool stats: initial acquires=0");
        runner.Check(s.total_hits == 0, "pool stats: initial hits=0");
        runner.Check(s.total_creates == 0, "pool stats: initial creates=0");
    }

    // ─── delete_socket null 安全 ──────────────────

    void TestDeleteSocketNull(TestRunner &runner)
    {
        // 内部函数，通过 pool 的 clear() 间接调用
        // 直接测试 null 不崩溃
        psm::connect::delete_socket(nullptr);
        runner.Check(true, "delete_socket: null -> no crash");
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

    TestToKeyIPv4(runner);
    TestToKeyIPv4Loopback(runner);
    TestToKeyIPv6(runner);
    TestToKeyIPv6FullAddress(runner);

    TestEndpointKeyEquality(runner);
    TestEndpointKeyDiffPort(runner);
    TestEndpointKeyDiffAddr(runner);

    TestHashConsistency(runner);
    TestHashDifferentEndpoints(runner);
    TestHashIPv4AndIPv6Diff(runner);

    TestPooledConnectionDefault(runner);
    TestPooledConnectionMove(runner);
    TestPooledConnectionRelease(runner);
    TestPooledConnectionMoveAssign(runner);
    TestPooledConnectionSelfAssign(runner);

    TestPoolStatsDefault(runner);
    TestDeleteSocketNull(runner);

    return runner.Summary();
}

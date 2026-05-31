/**
 * @file PoolDeep.cpp
 * @brief 连接池深度纯函数测试
 * @details 通过 #include 源文件访问 pool.cpp 中所有同步函数，
 *          覆盖 pooled_connection 生命周期、to_key、endpoint_hash、
 *          stats、cleanup、clear、recycle、delete_socket。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include "../src/prism/connect/pool/pool.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    // ─── to_key ─────────────────────────────────

    void TestToKeyIPv4Loopback(TestRunner &runner)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        auto key = psm::connect::to_key(ep);
        runner.Check(key.family == 4, "to_key: IPv4 family=4");
        runner.Check(key.port == 80, "to_key: IPv4 port=80");
        runner.Check(key.address[0] == 127, "to_key: IPv4 addr[0]");
        runner.Check(key.address[3] == 1, "to_key: IPv4 addr[3]");
    }

    void TestToKeyIPv4Broadcast(TestRunner &runner)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("255.255.255.255"), 65535);
        auto key = psm::connect::to_key(ep);
        runner.Check(key.family == 4, "to_key: broadcast family=4");
        runner.Check(key.port == 65535, "to_key: broadcast port=65535");
        runner.Check(key.address[0] == 255, "to_key: broadcast addr[0]");
        runner.Check(key.address[3] == 255, "to_key: broadcast addr[3]");
    }

    void TestToKeyIPv6Loopback(TestRunner &runner)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v6("::1"), 443);
        auto key = psm::connect::to_key(ep);
        runner.Check(key.family == 6, "to_key: IPv6 family=6");
        runner.Check(key.port == 443, "to_key: IPv6 port=443");
        runner.Check(key.address[15] == 1, "to_key: IPv6 addr[15]=1");
        for (std::size_t i = 0; i < 15; ++i)
        {
            runner.Check(key.address[i] == 0, "to_key: IPv6 leading zeros");
            if (key.address[i] != 0)
                break;
        }
    }

    void TestToKeyIPv6Full(TestRunner &runner)
    {
        net::ip::address_v6::bytes_type bytes;
        for (std::size_t i = 0; i < 16; ++i)
            bytes[i] = static_cast<std::uint8_t>(i + 1);
        auto ep = tcp::endpoint(net::ip::address_v6(bytes), 8080);
        auto key = psm::connect::to_key(ep);
        runner.Check(key.family == 6, "to_key: IPv6 full family=6");
        runner.Check(key.address[0] == 1, "to_key: IPv6 full addr[0]=1");
        runner.Check(key.address[15] == 16, "to_key: IPv6 full addr[15]=16");
    }

    // ─── endpoint_hash ──────────────────────────

    void TestEndpointHashIPv4(TestRunner &runner)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 80);
        auto key = psm::connect::to_key(ep);
        psm::connect::endpoint_hash hasher;
        auto h = hasher(key);
        runner.Check(h != 0, "endpoint_hash: IPv4 nonzero");
        runner.Check(hasher(key) == h, "endpoint_hash: deterministic");
    }

    void TestEndpointHashIPv6(TestRunner &runner)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v6("2001:db8::1"), 443);
        auto key = psm::connect::to_key(ep);
        psm::connect::endpoint_hash hasher;
        auto h = hasher(key);
        runner.Check(h != 0, "endpoint_hash: IPv6 nonzero");
    }

    void TestEndpointHashDifferentPorts(TestRunner &runner)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("1.2.3.4"), 80);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("1.2.3.4"), 81);
        auto k1 = psm::connect::to_key(ep1);
        auto k2 = psm::connect::to_key(ep2);
        psm::connect::endpoint_hash hasher;
        runner.Check(hasher(k1) != hasher(k2), "endpoint_hash: different ports");
    }

    void TestEndpointHashDifferentFamilies(TestRunner &runner)
    {
        auto ep4 = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        auto ep6 = tcp::endpoint(net::ip::make_address("::1"), 80);
        auto k4 = psm::connect::to_key(ep4);
        auto k6 = psm::connect::to_key(ep6);
        psm::connect::endpoint_hash hasher;
        runner.Check(hasher(k4) != hasher(k6), "endpoint_hash: different families");
    }

    void TestEndpointHashAllZeroKey(TestRunner &runner)
    {
        psm::connect::endpoint_key zero_key{};
        psm::connect::endpoint_hash hasher;
        auto h = hasher(zero_key);
        runner.Check(h != 0, "endpoint_hash: zero key -> nonzero (FNV offset)");
    }

    // ─── pooled_connection 生命周期 ──────────────

    void TestPooledDefaultDestruct(TestRunner &runner)
    {
        {
            psm::connect::pooled_connection conn;
            runner.Check(!conn.valid(), "pooled: default invalid");
            runner.Check(conn.get() == nullptr, "pooled: default get=nullptr");
        }
        runner.Check(true, "pooled: default destruct no crash");
    }

    void TestPooledReleaseEmpty(TestRunner &runner)
    {
        psm::connect::pooled_connection conn;
        auto *s = conn.release();
        runner.Check(s == nullptr, "pooled: release empty -> nullptr");
    }

    void TestPooledResetEmpty(TestRunner &runner)
    {
        psm::connect::pooled_connection conn;
        conn.reset();
        runner.Check(!conn.valid(), "pooled: reset empty no crash");
    }

    void TestPooledMoveAssignEmpty(TestRunner &runner)
    {
        psm::connect::pooled_connection a;
        psm::connect::pooled_connection b;
        a = std::move(b);
        runner.Check(!a.valid(), "pooled: move-assign empty -> still empty");
        runner.Check(!b.valid(), "pooled: move-assign src empty");
    }

    void TestPooledMoveAssignSelf(TestRunner &runner)
    {
        psm::connect::pooled_connection conn;
        conn = std::move(conn);
        runner.Check(!conn.valid(), "pooled: self-move-assign no crash");
    }

    void TestPooledConstructWithPoolNullSocket(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        psm::connect::pooled_connection conn(&pool, nullptr, ep);
        runner.Check(!conn.valid(), "pooled: null socket -> invalid");
    }

    void TestPooledConstructWithSocketNoPool(TestRunner &runner)
    {
        // pool_==nullptr, socket_!=null → reset() 会 close+delete
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        {
            psm::connect::pooled_connection conn(nullptr, sock, ep);
            runner.Check(conn.valid(), "pooled: socket valid");
            runner.Check(conn.get() == sock, "pooled: get returns socket");
        }
        // 析构时 pool_==null → delete_socket 路径
        runner.Check(true, "pooled: destruct with socket no pool -> delete path");
    }

    void TestPooledReleaseWithSocket(TestRunner &runner)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        psm::connect::pooled_connection conn(nullptr, sock, ep);

        auto *released = conn.release();
        runner.Check(released == sock, "pooled: release returns socket");
        runner.Check(!conn.valid(), "pooled: release -> invalid");

        // 手动清理释放的 socket
        boost::system::error_code ec;
        released->close(ec);
        delete released;
    }

    void TestPooledMoveConstruct(TestRunner &runner)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        psm::connect::pooled_connection a(nullptr, sock, ep);
        runner.Check(a.valid(), "pooled: move src valid");

        psm::connect::pooled_connection b(std::move(a));
        runner.Check(!a.valid(), "pooled: move src invalidated");
        runner.Check(b.valid(), "pooled: move dst valid");
        runner.Check(b.get() == sock, "pooled: move dst has socket");

        // b 析构时 delete socket
    }

    void TestPooledMoveAssignWithData(TestRunner &runner)
    {
        net::io_context ioc;
        auto *sock1 = new tcp::socket(ioc);
        auto *sock2 = new tcp::socket(ioc);
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);

        psm::connect::pooled_connection a(nullptr, sock1, ep1);
        psm::connect::pooled_connection b(nullptr, sock2, ep2);

        // a = std::move(b) → a 先 reset (close+delete sock1)，然后接管 sock2
        a = std::move(b);
        runner.Check(a.valid(), "pooled: move-assign dst valid");
        runner.Check(a.get() == sock2, "pooled: move-assign dst has sock2");
        runner.Check(!b.valid(), "pooled: move-assign src invalidated");
    }

    // ─── delete_socket ──────────────────────────

    void TestDeleteSocketNull(TestRunner &runner)
    {
        psm::connect::delete_socket(nullptr);
        runner.Check(true, "delete_socket: nullptr no crash");
    }

    void TestDeleteSocketReal(TestRunner &runner)
    {
        net::io_context ioc;
        auto *sock = new tcp::socket(ioc);
        psm::connect::delete_socket(sock);
        runner.Check(true, "delete_socket: real socket no crash");
    }

    // ─── connection_pool 同步方法 ────────────────

    void TestPoolStatsInitial(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        auto s = pool.stats();
        runner.Check(s.total_acquires == 0, "pool: initial acquires=0");
        runner.Check(s.total_hits == 0, "pool: initial hits=0");
        runner.Check(s.total_creates == 0, "pool: initial creates=0");
        runner.Check(s.total_recycles == 0, "pool: initial recycles=0");
        runner.Check(s.total_evictions == 0, "pool: initial evictions=0");
        runner.Check(s.idle_count == 0, "pool: initial idle=0");
        runner.Check(s.endpoint_count == 0, "pool: initial endpoints=0");
    }

    void TestPoolGetConfig(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        const auto &cfg = pool.get_config();
        runner.Check(cfg.tcp_nodelay, "pool: default tcp_nodelay");
        runner.Check(cfg.keep_alive, "pool: default keep_alive");
    }

    // cleanup/clear/apply_opts 为 private，无法直接调用
    // 通过析构函数间接调用 clear()，通过 recycle 间接覆盖逻辑

    void TestPoolRecycleNull(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        pool.recycle(nullptr, ep);
        auto s = pool.stats();
        runner.Check(s.total_recycles == 0, "pool: recycle null -> no recycle count");
    }

    void TestPoolRecycleClosedSocket(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        auto *sock = new tcp::socket(ioc);
        sock->close();
        auto ep = tcp::endpoint(net::ip::make_address_v4("127.0.0.1"), 80);
        pool.recycle(sock, ep);
        auto s = pool.stats();
        runner.Check(s.total_recycles == 0, "pool: recycle closed -> no recycle count");
        runner.Check(s.idle_count == 0, "pool: recycle closed -> idle=0");
    }

    void TestPoolDestruct(TestRunner &runner)
    {
        {
            net::io_context ioc;
            psm::connect::connection_pool pool(ioc);
        }
        runner.Check(true, "pool: destruct (calls clear) no crash");
    }

    void TestPoolStartIdempotent(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        pool.start();
        pool.start();
        runner.Check(true, "pool: double start no crash");
        // 析构时调用 clear() 停止清理协程
    }

    // apply_opts 为 private，通过 async_acquire 路径间接覆盖

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("PoolDeep");

    TestToKeyIPv4Loopback(runner);
    TestToKeyIPv4Broadcast(runner);
    TestToKeyIPv6Loopback(runner);
    TestToKeyIPv6Full(runner);

    TestEndpointHashIPv4(runner);
    TestEndpointHashIPv6(runner);
    TestEndpointHashDifferentPorts(runner);
    TestEndpointHashDifferentFamilies(runner);
    TestEndpointHashAllZeroKey(runner);

    TestPooledDefaultDestruct(runner);
    TestPooledReleaseEmpty(runner);
    TestPooledResetEmpty(runner);
    TestPooledMoveAssignEmpty(runner);
    TestPooledMoveAssignSelf(runner);
    TestPooledConstructWithPoolNullSocket(runner);
    TestPooledConstructWithSocketNoPool(runner);
    TestPooledReleaseWithSocket(runner);
    TestPooledMoveConstruct(runner);
    TestPooledMoveAssignWithData(runner);

    TestDeleteSocketNull(runner);
    TestDeleteSocketReal(runner);

    TestPoolStatsInitial(runner);
    TestPoolGetConfig(runner);
    TestPoolRecycleNull(runner);
    TestPoolRecycleClosedSocket(runner);
    TestPoolDestruct(runner);
    TestPoolStartIdempotent(runner);

    return runner.Summary();
}

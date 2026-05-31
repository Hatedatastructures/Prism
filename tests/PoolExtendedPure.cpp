/**
 * @file PoolExtendedPure.cpp
 * @brief 连接池扩展纯函数单元测试
 * @details 测试 pool_config 默认值、pool_stats 默认值、
 *          pooled_connection RAII、endpoint_key 相等比较。
 *          不 #include 源文件，仅使用公共 API。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/connect/pool/pool.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /**
     * @brief pool config 默认配置验证
     */
    void TestPoolConfigDefaults(TestRunner &runner)
    {
        psm::connect::config cfg;
        runner.Check(cfg.cache_peraddr == 32, "config: cache_peraddr=32");
        runner.Check(cfg.conn_timeout == 300, "config: conn_timeout=300");
        runner.Check(cfg.idle_sec == 30, "config: idle_sec=30");
        runner.Check(cfg.clean_interval == 10, "config: clean_interval=10");
        runner.Check(cfg.tcp_nodelay, "config: tcp_nodelay=true");
        runner.Check(cfg.keep_alive, "config: keep_alive=true");
        runner.Check(!cfg.cache_ipv6, "config: cache_ipv6=false");
        runner.Check(cfg.recv_bufsz == 65536, "config: recv_bufsz=65536");
        runner.Check(cfg.send_bufsz == 65536, "config: send_bufsz=65536");
    }

    /**
     * @brief pool_stats 默认值全零
     */
    void TestPoolStatsDefault(TestRunner &runner)
    {
        psm::connect::pool_stats stats;
        runner.Check(stats.total_acquires == 0, "pool_stats: total_acquires=0");
        runner.Check(stats.total_hits == 0, "pool_stats: total_hits=0");
        runner.Check(stats.total_creates == 0, "pool_stats: total_creates=0");
        runner.Check(stats.total_recycles == 0, "pool_stats: total_recycles=0");
        runner.Check(stats.total_evictions == 0, "pool_stats: total_evictions=0");
        runner.Check(stats.idle_count == 0, "pool_stats: idle_count=0");
        runner.Check(stats.endpoint_count == 0, "pool_stats: endpoint_count=0");
    }

    /**
     * @brief connection_pool 构造与 stats() 返回零值
     */
    void TestPoolStatsEmpty(TestRunner &runner)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        auto stats = pool.stats();
        runner.Check(stats.total_acquires == 0, "pool: initial stats zero");
        runner.Check(stats.idle_count == 0, "pool: initial idle_count=0");
        runner.Check(stats.endpoint_count == 0, "pool: initial endpoint_count=0");
    }

    /**
     * @brief pooled_connection 默认构造为空
     */
    void TestPooledConnectionDefault(TestRunner &runner)
    {
        psm::connect::pooled_connection conn;
        runner.Check(conn.release() == nullptr, "pooled: default → release nullptr");
    }

    /**
     * @brief pooled_connection 析构不崩溃
     */
    void TestPooledConnectionDestruct(TestRunner &runner)
    {
        {
            psm::connect::pooled_connection conn;
            // 析构不崩溃
        }
        runner.Check(true, "pooled: destruct no crash");
    }

    /**
     * @brief endpoint_key 比较
     */
    void TestEndpointKeyEquality(TestRunner &runner)
    {
        psm::connect::endpoint_key a{};
        a.family = 4;
        a.port = 80;
        psm::connect::endpoint_key b{};
        b.family = 4;
        b.port = 80;
        runner.Check(a == b, "endpoint_key: same key equals");

        b.port = 443;
        runner.Check(!(a == b), "endpoint_key: different port not equal");

        b.port = 80;
        b.family = 6;
        runner.Check(!(a == b), "endpoint_key: different family not equal");
    }

    /**
     * @brief to_key IPv4 转换
     */
    void TestToKeyIPv4(TestRunner &runner)
    {
        net::io_context ioc;
        auto addr = net::ip::make_address("127.0.0.1");
        tcp::endpoint ep(addr, 8080);
        auto key = psm::connect::to_key(ep);
        runner.Check(key.family == 4, "to_key: IPv4 family=4");
        runner.Check(key.port == 8080, "to_key: port=8080");
    }

    /**
     * @brief to_key IPv6 转换
     */
    void TestToKeyIPv6(TestRunner &runner)
    {
        auto addr = net::ip::make_address("::1");
        tcp::endpoint ep(addr, 443);
        auto key = psm::connect::to_key(ep);
        runner.Check(key.family == 6, "to_key: IPv6 family=6");
        runner.Check(key.port == 443, "to_key: port=443");
    }

    /**
     * @brief endpoint_hash 对相同 key 返回相同哈希
     */
    void TestEndpointHashConsistent(TestRunner &runner)
    {
        psm::connect::endpoint_key a{};
        a.family = 4;
        a.port = 80;
        psm::connect::endpoint_key b{};
        b.family = 4;
        b.port = 80;
        psm::connect::endpoint_hash hasher;
        runner.Check(hasher(a) == hasher(b), "endpoint_hash: same key same hash");

        b.port = 443;
        runner.Check(hasher(a) != hasher(b), "endpoint_hash: different key different hash");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("PoolExtendedPure");

    TestPoolConfigDefaults(runner);
    TestPoolStatsDefault(runner);
    TestPoolStatsEmpty(runner);
    TestPooledConnectionDefault(runner);
    TestPooledConnectionDestruct(runner);
    TestEndpointKeyEquality(runner);
    TestToKeyIPv4(runner);
    TestToKeyIPv6(runner);
    TestEndpointHashConsistent(runner);

    return runner.Summary();
}

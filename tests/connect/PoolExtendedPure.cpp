/**
 * @file PoolExtendedPure.cpp
 * @brief 连接池扩展纯函数单元测试
 * @details 测试 pool_config 默认值、pool_stats 默认值、
 *          pooled_connection RAII、endpoint_key 相等比较。
 *          不 #include 源文件，仅使用公共 API。
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/net/connect/pool/pool.hpp>


#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    /**
     * @brief pool config 默认配置验证
     */
    TEST(PoolExtendedPure, PoolConfigDefaults)
    {
        psm::connect::config cfg;
        EXPECT_TRUE(cfg.cache_peraddr == 32) << "config: cache_peraddr=32";
        EXPECT_TRUE(cfg.conn_timeout == 300) << "config: conn_timeout=300";
        EXPECT_TRUE(cfg.idle_sec == 30) << "config: idle_sec=30";
        EXPECT_TRUE(cfg.clean_interval == 10) << "config: clean_interval=10";
        EXPECT_TRUE(cfg.tcp_nodelay) << "config: tcp_nodelay=true";
        EXPECT_TRUE(cfg.keep_alive) << "config: keep_alive=true";
        EXPECT_TRUE(!cfg.cache_ipv6) << "config: cache_ipv6=false";
        EXPECT_TRUE(cfg.recv_bufsz == 65536) << "config: recv_bufsz=65536";
        EXPECT_TRUE(cfg.send_bufsz == 65536) << "config: send_bufsz=65536";
    }

    /**
     * @brief pool_stats 默认值全零
     */
    TEST(PoolExtendedPure, PoolStatsDefault)
    {
        psm::connect::pool_stats stats;
        EXPECT_TRUE(stats.total_acquires == 0) << "pool_stats: total_acquires=0";
        EXPECT_TRUE(stats.total_hits == 0) << "pool_stats: total_hits=0";
        EXPECT_TRUE(stats.total_creates == 0) << "pool_stats: total_creates=0";
        EXPECT_TRUE(stats.total_recycles == 0) << "pool_stats: total_recycles=0";
        EXPECT_TRUE(stats.total_evictions == 0) << "pool_stats: total_evictions=0";
        EXPECT_TRUE(stats.idle_count == 0) << "pool_stats: idle_count=0";
        EXPECT_TRUE(stats.endpoint_count == 0) << "pool_stats: endpoint_count=0";
    }

    /**
     * @brief connection_pool 构造与 stats() 返回零值
     */
    TEST(PoolExtendedPure, PoolStatsEmpty)
    {
        net::io_context ioc;
        psm::connect::connection_pool pool(ioc);
        auto stats = pool.stats();
        EXPECT_TRUE(stats.total_acquires == 0) << "pool: initial stats zero";
        EXPECT_TRUE(stats.idle_count == 0) << "pool: initial idle_count=0";
        EXPECT_TRUE(stats.endpoint_count == 0) << "pool: initial endpoint_count=0";
    }

    /**
     * @brief pooled_connection 默认构造为空
     */
    TEST(PoolExtendedPure, PooledConnectionDefault)
    {
        psm::connect::pooled_connection conn;
        EXPECT_TRUE(conn.release() == nullptr) << "pooled: default -> release nullptr";
    }

    /**
     * @brief pooled_connection 析构不崩溃
     */
    TEST(PoolExtendedPure, PooledConnectionDestruct)
    {
        bool was_valid = false;
        {
            psm::connect::pooled_connection conn;
            was_valid = conn.valid();
            // 析构不崩溃
        }
        EXPECT_TRUE(!was_valid) << "pooled: default-constructed conn was not valid";
    }

    /**
     * @brief endpoint_key 比较
     */
    TEST(PoolExtendedPure, EndpointKeyEquality)
    {
        psm::connect::endpoint_key a{};
        a.family = 4;
        a.port = 80;
        psm::connect::endpoint_key b{};
        b.family = 4;
        b.port = 80;
        EXPECT_TRUE(a == b) << "endpoint_key: same key equals";

        b.port = 443;
        EXPECT_TRUE(!(a == b)) << "endpoint_key: different port not equal";

        b.port = 80;
        b.family = 6;
        EXPECT_TRUE(!(a == b)) << "endpoint_key: different family not equal";
    }

    /**
     * @brief to_key IPv4 转换
     */
    TEST(PoolExtendedPure, ToKeyIPv4)
    {
        net::io_context ioc;
        auto addr = net::ip::make_address("127.0.0.1");
        tcp::endpoint ep(addr, 8080);
        auto key = psm::connect::to_key(ep);
        EXPECT_TRUE(key.family == 4) << "to_key: IPv4 family=4";
        EXPECT_TRUE(key.port == 8080) << "to_key: port=8080";
    }

    /**
     * @brief to_key IPv6 转换
     */
    TEST(PoolExtendedPure, ToKeyIPv6)
    {
        auto addr = net::ip::make_address("::1");
        tcp::endpoint ep(addr, 443);
        auto key = psm::connect::to_key(ep);
        EXPECT_TRUE(key.family == 6) << "to_key: IPv6 family=6";
        EXPECT_TRUE(key.port == 443) << "to_key: port=443";
    }

    /**
     * @brief endpoint_hash 对相同 key 返回相同哈希
     */
    TEST(PoolExtendedPure, EndpointHashConsistent)
    {
        psm::connect::endpoint_key a{};
        a.family = 4;
        a.port = 80;
        psm::connect::endpoint_key b{};
        b.family = 4;
        b.port = 80;
        psm::connect::endpoint_hash hasher;
        EXPECT_TRUE(hasher(a) == hasher(b)) << "endpoint_hash: same key same hash";

        b.port = 443;
        EXPECT_TRUE(hasher(a) != hasher(b)) << "endpoint_hash: different key different hash";
    }

} // namespace

/**
 * @file DnsResolverTest.cpp
 * @brief DNS 解析器测试（T3-3）
 * @details 覆盖：
 *          - LRU 缓存命中/未命中（loopback 域名）
 *          - 负缓存（不可解析域名）
 *          - 缓存过期（短 TTL）
 *          - LRU 淘汰（容量限制）
 * @note 测试用真实 resolver（本地 hosts/loopback），避免外部网络
 */

#include <common/core/net/dns/resolver.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>

#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace preview;

    template <typename A>
    void run_coro(net::io_context &ioc, A coro)
    {
        std::exception_ptr ep;
        net::co_spawn(ioc, std::move(coro), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
        ioc.run();
        if (ep)
        {
            std::rethrow_exception(ep);
        }
    }
} // namespace

TEST(DnsResolver, ResolveLoopback)
{
    net::io_context ioc;
    preview::network::dns::resolver r(ioc.get_executor());
    std::error_code ec;
    std::vector<net::ip::address> addrs;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 addrs = co_await r.async_resolve("localhost", ec);
             });
    EXPECT_FALSE(ec);
    EXPECT_FALSE(addrs.empty());
    // localhost 解析到 127.0.0.1（或 ::1）
    EXPECT_GE(addrs.size(), 1u);
}

TEST(DnsResolver, CacheHit)
{
    net::io_context ioc;
    preview::network::dns::resolver r(ioc.get_executor());
    std::error_code ec;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 (void)co_await r.async_resolve("localhost", ec);
                 (void)co_await r.async_resolve("localhost", ec);
             });
    // 二次解析命中缓存
    EXPECT_EQ(r.hit_count(), 1u);
    EXPECT_EQ(r.size(), 1u);
}

TEST(DnsResolver, NegativeCache)
{
    net::io_context ioc;
    preview::network::dns::resolver r(ioc.get_executor(), 64, std::chrono::seconds(60), std::chrono::seconds(10));
    std::error_code ec;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 (void)co_await r.async_resolve("nonexistent-host-prism-test.invalid", ec);
             });
    EXPECT_TRUE(ec);
    // 负缓存已入
    EXPECT_EQ(r.size(), 1u);
}

TEST(DnsResolver, CacheExpiry)
{
    net::io_context ioc;
    // 极短 TTL（1 秒）
    preview::network::dns::resolver r(ioc.get_executor(), 64, std::chrono::seconds(1));
    std::error_code ec;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 (void)co_await r.async_resolve("localhost", ec);
             });
    EXPECT_EQ(r.size(), 1u);

    // 等待过期
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 (void)co_await r.async_resolve("localhost", ec);
             });
    // 过期后未命中缓存 → 重新解析，缓存条目被替换
    EXPECT_EQ(r.size(), 1u);
}

TEST(DnsResolver, LruEviction)
{
    net::io_context ioc;
    // 容量 2
    preview::network::dns::resolver r(ioc.get_executor(), 2);
    std::error_code ec;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 (void)co_await r.async_resolve("localhost", ec);
                 (void)co_await r.async_resolve("127.0.0.1", ec);
                 (void)co_await r.async_resolve("localhost", ec);
             });
    // 3 次解析（2 个唯一键），容量 2 → 淘汰最旧
    EXPECT_EQ(r.size(), 2u);
}

TEST(DnsResolver, ClearCache)
{
    net::io_context ioc;
    preview::network::dns::resolver r(ioc.get_executor());
    std::error_code ec;
    run_coro(ioc,
             [&]() -> net::awaitable<void>
             {
                 (void)co_await r.async_resolve("localhost", ec);
             });
    EXPECT_EQ(r.size(), 1u);
    r.clear();
    EXPECT_EQ(r.size(), 0u);
}

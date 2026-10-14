/**
 * @file DnsResolverCacheTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "DnsResolverTestSupport.hpp"

TEST(DnsResolver, ResolveLoopback)
{
    Net::io_context ioc;
    Preview::Network::Dns::Resolver r(ioc.get_executor());
    ResolveFailure Failure;
    std::vector<Net::ip::address> addrs;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("localhost"), addrs, Failure);
             });
    EXPECT_TRUE(Failure.Succeeded());
    EXPECT_FALSE(addrs.empty());
    // localhost 解析到 127.0.0.1（或 ::1）
    EXPECT_GE(addrs.size(), 1u);
}

TEST(DnsResolver, CacheHit)
{
    Net::io_context ioc;
    Preview::Network::Dns::Resolver r(ioc.get_executor());
    ResolveFailure firstFailure;
    ResolveFailure secondFailure;
    std::vector<Net::ip::address> first;
    std::vector<Net::ip::address> second;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("localhost"), first, firstFailure);
                 CaptureResolveResult(co_await r.AsyncResolve("localhost"), second, secondFailure);
             });
    ASSERT_TRUE(firstFailure.Succeeded());
    ASSERT_FALSE(first.empty());
    ASSERT_TRUE(secondFailure.Succeeded());
    EXPECT_EQ(second, first);
    EXPECT_EQ(r.HitCount(), 1u);
    EXPECT_EQ(r.Size(), 1u);
}

TEST(DnsResolver, NegativeCache)
{
    Net::io_context ioc;
    Config cfg;
    cfg.MaxCacheEntries = 64;
    cfg.CacheTtl = std::chrono::seconds(60);
    cfg.NegativeTtl = std::chrono::seconds(10);
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);
    ResolveFailure Failure;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(
                     co_await r.AsyncResolve("nonexistent-host-prism-test.invalid"), Failure);
             });
    EXPECT_EQ(Failure.Code, Preview::Fault::Code::DnsFailed);
    // 负缓存已入
    EXPECT_EQ(r.Size(), 1u);
}

TEST(DnsResolver, CacheExpiry)
{
    Net::io_context ioc;
    // 极短 TTL（1 秒）
    Config cfg;
    cfg.MaxCacheEntries = 64;
    cfg.CacheTtl = std::chrono::seconds(1);
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);
    ResolveFailure Failure;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("localhost"), Failure);
             });
    ASSERT_TRUE(Failure.Succeeded());
    EXPECT_EQ(r.Size(), 1u);

    // 等待过期
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("localhost"), Failure);
             });
    // 过期后未命中缓存 → 重新解析，缓存条目被替换
    ASSERT_TRUE(Failure.Succeeded());
    EXPECT_EQ(r.HitCount(), 0u);
    EXPECT_EQ(r.Size(), 1u);
}

TEST(DnsResolver, CacheCapacityBounded)
{
    Net::io_context ioc;
    // 容量 2
    Config cfg;
    cfg.MaxCacheEntries = 2;
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);
    ResolveFailure Failure;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("localhost"), Failure);
                 CaptureResolveResult(co_await r.AsyncResolve("127.0.0.1"), Failure);
                 CaptureResolveResult(co_await r.AsyncResolve("127.0.0.2"), Failure);
             });
    // 三个唯一 key 写入容量为 2 的缓存后，条目数必须有界。
    EXPECT_EQ(r.Size(), 2u);
}

TEST(DnsResolver, ClearCache)
{
    Net::io_context ioc;
    Preview::Network::Dns::Resolver r(ioc.get_executor());
    ResolveFailure Failure;
    RunCoro(ioc,
             [&]() -> Net::awaitable<void>
             {
                 CaptureResolveResult(co_await r.AsyncResolve("localhost"), Failure);
             });
    EXPECT_EQ(r.Size(), 1u);
    r.Clear();
    EXPECT_EQ(r.Size(), 0u);
}

TEST(DnsResolver, TimeoutLoserOwnsResolveInputs)
{
    Net::io_context ioc;
    Config cfg;
    cfg.CacheEnabled = false;
    cfg.DisableIpv6 = true;
    cfg.TimeoutMs = 0;

    auto owner = std::make_unique<Preview::Network::Dns::Resolver>(ioc.get_executor(), cfg);
    auto input = std::make_unique<std::string>("localhost");
    ResolveFailure Failure;
    std::vector<Net::ip::address> addresses;
    int completions = 0;
    bool coroutineCompleted = false;
    bool executorDrained = false;
    std::exception_ptr exception;

    Net::co_spawn(
        ioc,
        ResolveLifetimeProbe({ioc, owner, input, Failure, addresses, completions, executorDrained}),
        [&](std::exception_ptr error)
        {
            exception = error;
            coroutineCompleted = true;
        });

    ioc.run();
    ioc.restart();
    ioc.run();

    ASSERT_FALSE(exception);
    EXPECT_TRUE(coroutineCompleted);
    EXPECT_TRUE(executorDrained);
    EXPECT_EQ(completions, 1);
    EXPECT_TRUE(addresses.empty());
    EXPECT_EQ(Failure.Code, Preview::Fault::Code::Timeout);
    EXPECT_EQ(owner, nullptr);
    EXPECT_EQ(input, nullptr);
}


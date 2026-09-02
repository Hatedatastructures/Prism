/**
 * @file DnsCacheTest.cpp
 * @brief DNS 响应缓存层测试
 * @details 覆盖：Get 三态语义（未命中/负命中/正命中）、TTL 钳制、
 *          FIFO 淘汰顺序（含刷新）、serve-stale 策略、负缓存过期
 */

#include <preview/Net/Dns/Cache.hpp>

#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <thread>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace Preview;
    using Preview::Network::Dns::Cache;
    using Preview::Network::Dns::CacheOptions;
    using Preview::Network::Dns::PutInput;

    constexpr std::uint16_t QtA = 1;

    auto V4(const char *s) -> net::ip::address
    {
        return net::ip::make_address(s);
    }

    auto MakePut(const std::string &domain, const char *ip, std::chrono::seconds ttl) -> PutInput
    {
        PutInput in;
        in.Domain = domain;
        in.QType = QtA;
        in.Ips = {V4(ip)};
        in.Ttl = ttl;
        return in;
    }
} // namespace

TEST(DnsCache, TestThreeStateGet)
{
    Cache c(CacheOptions{});

    // 未命中 → nullopt
    EXPECT_FALSE(c.Get("miss.com", QtA).has_value());

    // 正缓存 → 非空 vector
    c.Put(MakePut("hit.com", "1.1.1.1", std::chrono::seconds(60)));
    auto hit = c.Get("hit.com", QtA);
    ASSERT_TRUE(hit.has_value());
    ASSERT_EQ(hit->size(), 1u);
    EXPECT_EQ((*hit)[0], V4("1.1.1.1"));

    // 负缓存 → 空 vector（与未命中区分）
    c.PutNegative("neg.com", QtA);
    auto neg = c.Get("neg.com", QtA);
    ASSERT_TRUE(neg.has_value());
    EXPECT_TRUE(neg->empty());

    // PutInput.Failed=true 也必须保持负缓存语义
    PutInput failed;
    failed.Domain = "failed.com";
    failed.QType = QtA;
    failed.Ttl = std::chrono::seconds(60);
    failed.Failed = true;
    c.Put(failed);
    auto failedHit = c.Get("failed.com", QtA);
    ASSERT_TRUE(failedHit.has_value());
    EXPECT_TRUE(failedHit->empty());

    // 键按 qtype 区分
    EXPECT_FALSE(c.Get("hit.com", 28).has_value());
}

TEST(DnsCache, TestTtlClamp)
{
    CacheOptions opts;
    opts.TtlMin = std::chrono::seconds(2);
    opts.TtlMax = std::chrono::seconds(3600);
    Cache c(opts);

    // TTL=0 被下限抬升到 2s：立即查询仍命中（无钳制时 Expire=now 必然过期）
    c.Put(MakePut("floor.com", "2.2.2.2", std::chrono::seconds(0)));
    EXPECT_TRUE(c.Get("floor.com", QtA).has_value());
}

TEST(DnsCache, TestFifoEvictionRefreshesOnOverwrite)
{
    CacheOptions opts;
    opts.MaxEntries = 2;
    Cache c(opts);

    c.Put(MakePut("a.com", "1.0.0.1", std::chrono::seconds(60)));
    c.Put(MakePut("b.com", "1.0.0.2", std::chrono::seconds(60)));
    // 覆盖写入 a.com 刷新其插入时间
    c.Put(MakePut("a.com", "1.0.0.9", std::chrono::seconds(60)));
    c.Put(MakePut("c.com", "1.0.0.3", std::chrono::seconds(60)));

    // b.com 最旧被淘汰；a.com 因覆盖保留且值已更新
    EXPECT_FALSE(c.Get("b.com", QtA).has_value());
    auto a = c.Get("a.com", QtA);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ((*a)[0], V4("1.0.0.9"));
    EXPECT_TRUE(c.Get("c.com", QtA).has_value());
    EXPECT_EQ(c.Size(), 2u);
}

TEST(DnsCache, TestServeStalePolicy)
{
    CacheOptions staleOpts;
    staleOpts.NegativeTtl = std::chrono::seconds(1);
    staleOpts.Policy = Preview::Network::Dns::StalePolicy::Serve;
    Cache stale(staleOpts);

    stale.Put(MakePut("old.com", "3.3.3.3", std::chrono::seconds(1)));
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // Serve 策略：过期仍返回旧数据
    auto served = stale.Get("old.com", QtA);
    ASSERT_TRUE(served.has_value());
    EXPECT_EQ((*served)[0], V4("3.3.3.3"));

    CacheOptions discardOpts;
    discardOpts.NegativeTtl = std::chrono::seconds(1);
    discardOpts.Policy = Preview::Network::Dns::StalePolicy::Discard;
    Cache discard(discardOpts);

    discard.Put(MakePut("old.com", "3.3.3.3", std::chrono::seconds(1)));
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // Discard 策略：过期擦除并返回未命中
    EXPECT_FALSE(discard.Get("old.com", QtA).has_value());
    EXPECT_EQ(discard.Size(), 0u);
}

TEST(DnsCache, TestNegativeExpiry)
{
    CacheOptions opts;
    opts.NegativeTtl = std::chrono::seconds(1);
    Cache c(opts);

    c.PutNegative("gone.com", QtA);
    EXPECT_TRUE(c.Get("gone.com", QtA).has_value());

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    EXPECT_FALSE(c.Get("gone.com", QtA).has_value());
}

TEST(DnsCache, TestClearAndSize)
{
    Cache c(CacheOptions{});
    c.Put(MakePut("x.com", "1.1.1.1", std::chrono::seconds(60)));
    c.PutNegative("y.com", QtA);
    EXPECT_EQ(c.Size(), 2u);

    c.Clear();
    EXPECT_EQ(c.Size(), 0u);
    EXPECT_FALSE(c.Get("x.com", QtA).has_value());
}

TEST(DnsCache, TestMaxEntriesZeroUnlimited)
{
    // MaxEntries==0 视为无限：永不淘汰，所有写入均可命中
    CacheOptions opts;
    opts.MaxEntries = 0;
    Cache c(opts);

    for (char i = 'a'; i <= 'z'; ++i)
    {
        c.Put(MakePut(std::string(1, i) + ".com", "9.9.9.9", std::chrono::seconds(60)));
    }
    EXPECT_EQ(c.Size(), 26u);
    for (char i = 'a'; i <= 'z'; ++i)
    {
        EXPECT_TRUE(c.Get(std::string(1, i) + ".com", QtA).has_value());
    }
}

TEST(DnsCache, TestFifoEvictionOldestOrder)
{
    // 纯插入顺序 FIFO：超额时淘汰最旧（Inserted 最早）者
    CacheOptions opts;
    opts.MaxEntries = 3;
    Cache c(opts);

    c.Put(MakePut("a.com", "1.0.0.1", std::chrono::seconds(60)));
    c.Put(MakePut("b.com", "1.0.0.2", std::chrono::seconds(60)));
    c.Put(MakePut("c.com", "1.0.0.3", std::chrono::seconds(60)));
    // 第 4 条触发淘汰：a.com（最旧）出局
    c.Put(MakePut("d.com", "1.0.0.4", std::chrono::seconds(60)));

    EXPECT_FALSE(c.Get("a.com", QtA).has_value());
    EXPECT_TRUE(c.Get("b.com", QtA).has_value());
    EXPECT_TRUE(c.Get("c.com", QtA).has_value());
    EXPECT_TRUE(c.Get("d.com", QtA).has_value());
    EXPECT_EQ(c.Size(), 3u);
}

TEST(DnsCache, TestOverwriteKeepsFifoPosition)
{
    // 覆盖已有键视为刷新为最新（FIFO 顺序更新），仅更新值
    CacheOptions opts;
    opts.MaxEntries = 2;
    Cache c(opts);

    c.Put(MakePut("keep.com", "1.0.0.1", std::chrono::seconds(60)));
    c.Put(MakePut("old.com", "1.0.0.2", std::chrono::seconds(60)));
    // 覆盖 keep.com（位置不变），再插入新键触发淘汰
    c.Put(MakePut("keep.com", "1.0.0.9", std::chrono::seconds(60)));
    c.Put(MakePut("new.com", "1.0.0.3", std::chrono::seconds(60)));

    // old.com 是最旧且未被覆盖 → 被淘汰；keep.com 因覆盖保留
    EXPECT_FALSE(c.Get("old.com", QtA).has_value());
    auto keep = c.Get("keep.com", QtA);
    ASSERT_TRUE(keep.has_value());
    EXPECT_EQ((*keep)[0], V4("1.0.0.9"));
    EXPECT_TRUE(c.Get("new.com", QtA).has_value());
}

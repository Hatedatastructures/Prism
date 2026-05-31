/**
 * @file DnsCacheDeep.cpp
 * @brief DNS 缓存深度测试
 * @details 测试 cache 类的完整同步逻辑：构造、put/get 往返、
 *          LRU 淘汰、过期驱逐、负缓存、serve_stale 模式、
 *          make_key/key_view 辅助方法。
 */

#include <prism/memory.hpp>
#include <prism/resolve/dns/detail/cache.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace dns = psm::resolve::dns::detail;
    namespace net = boost::asio;

    auto make_cache(std::size_t max = 100, bool serve_stale = true)
        -> dns::cache
    {
        dns::cache_options opts;
        opts.mr = psm::memory::current_resource();
        opts.ttl = std::chrono::seconds(120);
        opts.max_entries = max;
        opts.stale = serve_stale ? dns::stale_policy::serve : dns::stale_policy::discard;
        return dns::cache(opts);
    }

    auto make_ips(std::initializer_list<std::string_view> strs)
        -> psm::memory::vector<net::ip::address>
    {
        psm::memory::vector<net::ip::address> ips;
        for (auto s : strs)
        {
            ips.push_back(net::ip::make_address(s));
        }
        return ips;
    }

    // ─── 基本构造 ──────────────────────────────────

    void TestCacheConstruct(TestRunner &runner)
    {
        auto c = make_cache();
        runner.Check(true, "cache: constructed without error");
    }

    // ─── put/get 往返 ──────────────────────────────

    void TestCachePutGetMiss(TestRunner &runner)
    {
        auto c = make_cache();
        auto result = c.get("nonexistent.com", dns::qtype::a);
        runner.Check(!result.has_value(), "cache: get miss returns nullopt");
    }

    void TestCachePutGetHit(TestRunner &runner)
    {
        auto c = make_cache();
        auto ips = make_ips({"1.2.3.4"});
        c.put(dns::put_input{"example.com", dns::qtype::a, ips, 300});

        auto result = c.get("example.com", dns::qtype::a);
        runner.Check(result.has_value(), "cache: get hit after put");
        runner.Check(result->size() == 1, "cache: hit returns 1 ip");
        runner.Check(result->at(0).to_string() == "1.2.3.4", "cache: ip matches");
    }

    void TestCachePutGetMultipleIps(TestRunner &runner)
    {
        auto c = make_cache();
        auto ips = make_ips({"1.1.1.1", "2.2.2.2", "3.3.3.3"});
        c.put(dns::put_input{"multi.com", dns::qtype::a, ips, 60});

        auto result = c.get("multi.com", dns::qtype::a);
        runner.Check(result.has_value(), "cache: multi ip hit");
        runner.Check(result->size() == 3, "cache: multi ip returns 3");
    }

    void TestCacheDifferentQtype(TestRunner &runner)
    {
        auto c = make_cache();
        auto ips4 = make_ips({"1.2.3.4"});
        auto ips6 = make_ips({"::1"});
        c.put(dns::put_input{"dual.com", dns::qtype::a, ips4, 300});
        c.put(dns::put_input{"dual.com", dns::qtype::aaaa, ips6, 300});

        auto r4 = c.get("dual.com", dns::qtype::a);
        auto r6 = c.get("dual.com", dns::qtype::aaaa);
        runner.Check(r4.has_value(), "cache: A record found");
        runner.Check(r6.has_value(), "cache: AAAA record found");
        runner.Check(r4->at(0).to_string() == "1.2.3.4", "cache: A ip correct");
        runner.Check(r6->at(0).to_string() == "::1", "cache: AAAA ip correct");
    }

    void TestCachePutUpdate(TestRunner &runner)
    {
        auto c = make_cache();
        auto ips1 = make_ips({"1.1.1.1"});
        auto ips2 = make_ips({"2.2.2.2"});
        c.put(dns::put_input{"update.com", dns::qtype::a, ips1, 300});
        c.put(dns::put_input{"update.com", dns::qtype::a, ips2, 300});

        auto result = c.get("update.com", dns::qtype::a);
        runner.Check(result.has_value(), "cache: updated entry exists");
        runner.Check(result->at(0).to_string() == "2.2.2.2", "cache: updated ip correct");
    }

    // ─── 负缓存 ────────────────────────────────────

    void TestCacheNegativePutGet(TestRunner &runner)
    {
        auto c = make_cache();
        c.put_negative("bad.com", dns::qtype::a, std::chrono::seconds(30));

        auto result = c.get("bad.com", dns::qtype::a);
        runner.Check(result.has_value(), "cache: negative hit has value");
        runner.Check(result->empty(), "cache: negative hit returns empty vector");
    }

    void TestCacheNegativeUpdate(TestRunner &runner)
    {
        auto c = make_cache();
        auto ips = make_ips({"1.2.3.4"});
        c.put(dns::put_input{"flip.com", dns::qtype::a, ips, 300});
        c.put_negative("flip.com", dns::qtype::a, std::chrono::seconds(10));

        auto result = c.get("flip.com", dns::qtype::a);
        runner.Check(result.has_value(), "cache: flipped to negative has value");
        runner.Check(result->empty(), "cache: flipped to negative returns empty");
    }

    // ─── 过期驱逐 ──────────────────────────────────

    void TestCacheEvictExpired(TestRunner &runner)
    {
        auto c = make_cache();
        auto ips = make_ips({"1.2.3.4"});
        // TTL=0 秒，应立即过期
        c.put(dns::put_input{"expire.com", dns::qtype::a, ips, 0});

        // serve_stale 模式下仍可获取过期数据
        auto result_stale = c.get("expire.com", dns::qtype::a);
        runner.Check(result_stale.has_value(), "cache: stale available after 0 TTL");

        // 驱逐过期条目
        c.evict_expired();
        auto result_after = c.get("expire.com", dns::qtype::a);
        runner.Check(!result_after.has_value(), "cache: expired after eviction");
    }

    // ─── 非服务过期模式 ────────────────────────────

    void TestCacheDiscardExpired(TestRunner &runner)
    {
        auto c = make_cache(100, false); // serve_stale=false
        auto ips = make_ips({"1.2.3.4"});
        c.put(dns::put_input{"discard.com", dns::qtype::a, ips, 0});

        // 非 serve_stale 模式下过期条目立即被删除
        auto result = c.get("discard.com", dns::qtype::a);
        runner.Check(!result.has_value(), "cache: discard mode removes expired");
    }

    // ─── LRU 淘汰 ──────────────────────────────────

    void TestCacheLruEviction(TestRunner &runner)
    {
        auto c = make_cache(3); // 最大 3 个条目
        auto ips = make_ips({"1.1.1.1"});

        c.put(dns::put_input{"a.com", dns::qtype::a, ips, 300});
        c.put(dns::put_input{"b.com", dns::qtype::a, ips, 300});
        c.put(dns::put_input{"c.com", dns::qtype::a, ips, 300});

        // 插入第 4 个条目后，恰好有 1 个被淘汰（LRU 尾部）
        c.put(dns::put_input{"d.com", dns::qtype::a, ips, 300});

        // d.com 必然存在
        runner.Check(c.get("d.com", dns::qtype::a).has_value(), "cache: d.com present after LRU eviction");
        // 恰好 3 个条目存在
        std::size_t found = 0;
        for (auto name : {"a.com", "b.com", "c.com", "d.com"})
        {
            if (c.get(name, dns::qtype::a).has_value())
                ++found;
        }
        runner.Check(found == 3, "cache: exactly 3 entries after LRU eviction");
    }

    // ─── LRU 访问提升 ──────────────────────────────

    void TestCacheLruAccessPromotes(TestRunner &runner)
    {
        auto c = make_cache(3);
        auto ips = make_ips({"1.1.1.1"});

        c.put(dns::put_input{"a.com", dns::qtype::a, ips, 300});
        c.put(dns::put_input{"b.com", dns::qtype::a, ips, 300});
        c.put(dns::put_input{"c.com", dns::qtype::a, ips, 300});

        // 访问 a.com 使其不再是 LRU 尾部
        auto r = c.get("a.com", dns::qtype::a);
        runner.Check(r.has_value(), "cache: access a.com for promotion");

        // 插入新条目，b.com 应被淘汰（现在是 LRU 尾部）
        c.put(dns::put_input{"d.com", dns::qtype::a, ips, 300});

        runner.Check(c.get("a.com", dns::qtype::a).has_value(), "cache: a.com promoted, still present");
        runner.Check(!c.get("b.com", dns::qtype::a).has_value(), "cache: b.com evicted instead");
    }

    // ─── make_key 验证 ─────────────────────────────

    void TestCacheKeyFormat(TestRunner &runner)
    {
        // 通过 put/get 间接验证键格式
        auto c = make_cache();
        auto ips = make_ips({"1.2.3.4"});
        c.put(dns::put_input{"test.com", dns::qtype::a, ips, 300});

        // 不同域名不应命中
        runner.Check(!c.get("test.com", dns::qtype::aaaa).has_value(),
                     "cache: different qtype is cache miss");
        runner.Check(!c.get("other.com", dns::qtype::a).has_value(),
                     "cache: different domain is cache miss");
    }

    // ─── 大量条目 ──────────────────────────────────

    void TestCacheManyEntries(TestRunner &runner)
    {
        auto c = make_cache(1000);
        auto ips = make_ips({"1.1.1.1"});

        for (int i = 0; i < 50; ++i)
        {
            auto domain = "domain" + std::to_string(i) + ".com";
            c.put(dns::put_input{domain, dns::qtype::a, ips, 300});
        }

        runner.Check(c.get("domain0.com", dns::qtype::a).has_value(), "cache: domain0 found");
        runner.Check(c.get("domain49.com", dns::qtype::a).has_value(), "cache: domain49 found");
        runner.Check(!c.get("domain50.com", dns::qtype::a).has_value(), "cache: domain50 not found");
    }

    // ─── 负缓存后更新为正缓存 ──────────────────────

    void TestCacheNegativeToPositive(TestRunner &runner)
    {
        auto c = make_cache();
        c.put_negative("recover.com", dns::qtype::a, std::chrono::seconds(10));

        auto neg = c.get("recover.com", dns::qtype::a);
        runner.Check(neg.has_value() && neg->empty(), "cache: negative before recovery");

        auto ips = make_ips({"5.5.5.5"});
        c.put(dns::put_input{"recover.com", dns::qtype::a, ips, 300});

        auto pos = c.get("recover.com", dns::qtype::a);
        runner.Check(pos.has_value() && !pos->empty(), "cache: positive after recovery");
        runner.Check(pos->at(0).to_string() == "5.5.5.5", "cache: recovered ip correct");
    }

    // ─── evict_expired 空缓存 ──────────────────────

    void TestCacheEvictEmpty(TestRunner &runner)
    {
        auto c = make_cache();
        // 不应崩溃
        c.evict_expired();
        runner.Check(true, "cache: evict_expired on empty cache ok");
    }

    // ─── evict_expired 只清理过期 ───────────────────

    void TestCacheEvictSelective(TestRunner &runner)
    {
        auto c = make_cache();
        auto ips = make_ips({"1.1.1.1"});

        c.put(dns::put_input{"fresh.com", dns::qtype::a, ips, 300}); // 长TTL
        c.put(dns::put_input{"old.com", dns::qtype::a, ips, 0});    // 立即过期

        c.evict_expired();

        runner.Check(c.get("fresh.com", dns::qtype::a).has_value(), "cache: fresh survives eviction");
        // serve_stale 模式下 evict 会清理过期条目
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("DnsCacheDeep");

    TestCacheConstruct(runner);
    TestCachePutGetMiss(runner);
    TestCachePutGetHit(runner);
    TestCachePutGetMultipleIps(runner);
    TestCacheDifferentQtype(runner);
    TestCachePutUpdate(runner);
    TestCacheNegativePutGet(runner);
    TestCacheNegativeUpdate(runner);
    TestCacheEvictExpired(runner);
    TestCacheDiscardExpired(runner);
    TestCacheLruEviction(runner);
    TestCacheLruAccessPromotes(runner);
    TestCacheKeyFormat(runner);
    TestCacheManyEntries(runner);
    TestCacheNegativeToPositive(runner);
    TestCacheEvictEmpty(runner);
    TestCacheEvictSelective(runner);

    return runner.Summary();
}

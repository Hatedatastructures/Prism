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


#include <gtest/gtest.h>

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

    TEST(DnsCacheDeep, CacheConstruct)
    {
        auto c = make_cache();
        EXPECT_TRUE(c.get("test.com", dns::qtype::a) == std::nullopt)
            << "cache: constructed, empty lookup returns nullopt";
    }

    TEST(DnsCacheDeep, CachePutGetMiss)
    {
        auto c = make_cache();
        auto result = c.get("nonexistent.com", dns::qtype::a);
        EXPECT_TRUE(!result.has_value()) << "cache: get miss returns nullopt";
    }

    TEST(DnsCacheDeep, CachePutGetHit)
    {
        auto c = make_cache();
        auto ips = make_ips({"1.2.3.4"});
        c.put(dns::put_input{"example.com", dns::qtype::a, ips, 300});

        auto result = c.get("example.com", dns::qtype::a);
        EXPECT_TRUE(result.has_value()) << "cache: get hit after put";
        EXPECT_TRUE(result->size() == 1) << "cache: hit returns 1 ip";
        EXPECT_TRUE(result->at(0).to_string() == "1.2.3.4") << "cache: ip matches";
    }

    TEST(DnsCacheDeep, CachePutGetMultipleIps)
    {
        auto c = make_cache();
        auto ips = make_ips({"1.1.1.1", "2.2.2.2", "3.3.3.3"});
        c.put(dns::put_input{"multi.com", dns::qtype::a, ips, 60});

        auto result = c.get("multi.com", dns::qtype::a);
        EXPECT_TRUE(result.has_value()) << "cache: multi ip hit";
        EXPECT_TRUE(result->size() == 3) << "cache: multi ip returns 3";
    }

    TEST(DnsCacheDeep, CacheDifferentQtype)
    {
        auto c = make_cache();
        auto ips4 = make_ips({"1.2.3.4"});
        auto ips6 = make_ips({"::1"});
        c.put(dns::put_input{"dual.com", dns::qtype::a, ips4, 300});
        c.put(dns::put_input{"dual.com", dns::qtype::aaaa, ips6, 300});

        auto r4 = c.get("dual.com", dns::qtype::a);
        auto r6 = c.get("dual.com", dns::qtype::aaaa);
        EXPECT_TRUE(r4.has_value()) << "cache: A record found";
        EXPECT_TRUE(r6.has_value()) << "cache: AAAA record found";
        EXPECT_TRUE(r4->at(0).to_string() == "1.2.3.4") << "cache: A ip correct";
        EXPECT_TRUE(r6->at(0).to_string() == "::1") << "cache: AAAA ip correct";
    }

    TEST(DnsCacheDeep, CachePutUpdate)
    {
        auto c = make_cache();
        auto ips1 = make_ips({"1.1.1.1"});
        auto ips2 = make_ips({"2.2.2.2"});
        c.put(dns::put_input{"update.com", dns::qtype::a, ips1, 300});
        c.put(dns::put_input{"update.com", dns::qtype::a, ips2, 300});

        auto result = c.get("update.com", dns::qtype::a);
        EXPECT_TRUE(result.has_value()) << "cache: updated entry exists";
        EXPECT_TRUE(result->at(0).to_string() == "2.2.2.2") << "cache: updated ip correct";
    }

    TEST(DnsCacheDeep, CacheNegativePutGet)
    {
        auto c = make_cache();
        c.put_negative("bad.com", dns::qtype::a, std::chrono::seconds(30));

        auto result = c.get("bad.com", dns::qtype::a);
        EXPECT_TRUE(result.has_value()) << "cache: negative hit has value";
        EXPECT_TRUE(result->empty()) << "cache: negative hit returns empty vector";
    }

    TEST(DnsCacheDeep, CacheNegativeUpdate)
    {
        auto c = make_cache();
        auto ips = make_ips({"1.2.3.4"});
        c.put(dns::put_input{"flip.com", dns::qtype::a, ips, 300});
        c.put_negative("flip.com", dns::qtype::a, std::chrono::seconds(10));

        auto result = c.get("flip.com", dns::qtype::a);
        EXPECT_TRUE(result.has_value()) << "cache: flipped to negative has value";
        EXPECT_TRUE(result->empty()) << "cache: flipped to negative returns empty";
    }

    TEST(DnsCacheDeep, CacheEvictExpired)
    {
        auto c = make_cache();
        auto ips = make_ips({"1.2.3.4"});
        c.put(dns::put_input{"expire.com", dns::qtype::a, ips, 0});

        auto result_stale = c.get("expire.com", dns::qtype::a);
        EXPECT_TRUE(result_stale.has_value()) << "cache: stale available after 0 TTL";

        c.evict_expired();
        auto result_after = c.get("expire.com", dns::qtype::a);
        EXPECT_TRUE(!result_after.has_value()) << "cache: expired after eviction";
    }

    TEST(DnsCacheDeep, CacheDiscardExpired)
    {
        auto c = make_cache(100, false);
        auto ips = make_ips({"1.2.3.4"});
        c.put(dns::put_input{"discard.com", dns::qtype::a, ips, 0});

        auto result = c.get("discard.com", dns::qtype::a);
        EXPECT_TRUE(!result.has_value()) << "cache: discard mode removes expired";
    }

    TEST(DnsCacheDeep, CacheLruEviction)
    {
        auto c = make_cache(3);
        auto ips = make_ips({"1.1.1.1"});

        c.put(dns::put_input{"a.com", dns::qtype::a, ips, 300});
        c.put(dns::put_input{"b.com", dns::qtype::a, ips, 300});
        c.put(dns::put_input{"c.com", dns::qtype::a, ips, 300});

        c.put(dns::put_input{"d.com", dns::qtype::a, ips, 300});

        EXPECT_TRUE(c.get("d.com", dns::qtype::a).has_value()) << "cache: d.com present after LRU eviction";

        std::size_t found = 0;
        for (auto name : {"a.com", "b.com", "c.com", "d.com"})
        {
            if (c.get(name, dns::qtype::a).has_value())
                ++found;
        }
        EXPECT_TRUE(found == 3) << "cache: exactly 3 entries after LRU eviction";
    }

    TEST(DnsCacheDeep, CacheLruAccessPromotes)
    {
        auto c = make_cache(3);
        auto ips = make_ips({"1.1.1.1"});

        c.put(dns::put_input{"a.com", dns::qtype::a, ips, 300});
        c.put(dns::put_input{"b.com", dns::qtype::a, ips, 300});
        c.put(dns::put_input{"c.com", dns::qtype::a, ips, 300});

        auto r = c.get("a.com", dns::qtype::a);
        EXPECT_TRUE(r.has_value()) << "cache: access a.com for promotion";

        c.put(dns::put_input{"d.com", dns::qtype::a, ips, 300});

        EXPECT_TRUE(c.get("a.com", dns::qtype::a).has_value()) << "cache: a.com promoted, still present";
        EXPECT_TRUE(!c.get("b.com", dns::qtype::a).has_value()) << "cache: b.com evicted instead";
    }

    TEST(DnsCacheDeep, CacheKeyFormat)
    {
        auto c = make_cache();
        auto ips = make_ips({"1.2.3.4"});
        c.put(dns::put_input{"test.com", dns::qtype::a, ips, 300});

        EXPECT_TRUE(!c.get("test.com", dns::qtype::aaaa).has_value())
            << "cache: different qtype is cache miss";
        EXPECT_TRUE(!c.get("other.com", dns::qtype::a).has_value())
            << "cache: different domain is cache miss";
    }

    TEST(DnsCacheDeep, CacheManyEntries)
    {
        auto c = make_cache(1000);
        auto ips = make_ips({"1.1.1.1"});

        for (int i = 0; i < 50; ++i)
        {
            auto domain = "domain" + std::to_string(i) + ".com";
            c.put(dns::put_input{domain, dns::qtype::a, ips, 300});
        }

        EXPECT_TRUE(c.get("domain0.com", dns::qtype::a).has_value()) << "cache: domain0 found";
        EXPECT_TRUE(c.get("domain49.com", dns::qtype::a).has_value()) << "cache: domain49 found";
        EXPECT_TRUE(!c.get("domain50.com", dns::qtype::a).has_value()) << "cache: domain50 not found";
    }

    TEST(DnsCacheDeep, CacheNegativeToPositive)
    {
        auto c = make_cache();
        c.put_negative("recover.com", dns::qtype::a, std::chrono::seconds(10));

        auto neg = c.get("recover.com", dns::qtype::a);
        EXPECT_TRUE(neg.has_value() && neg->empty()) << "cache: negative before recovery";

        auto ips = make_ips({"5.5.5.5"});
        c.put(dns::put_input{"recover.com", dns::qtype::a, ips, 300});

        auto pos = c.get("recover.com", dns::qtype::a);
        EXPECT_TRUE(pos.has_value() && !pos->empty()) << "cache: positive after recovery";
        EXPECT_TRUE(pos->at(0).to_string() == "5.5.5.5") << "cache: recovered ip correct";
    }

    TEST(DnsCacheDeep, CacheEvictEmpty)
    {
        auto c = make_cache();
        c.evict_expired();
        EXPECT_TRUE(!c.get("nonexistent.com", dns::qtype::a).has_value())
            << "cache: evict_expired on empty cache, get returns nullopt";
    }

    TEST(DnsCacheDeep, CacheEvictSelective)
    {
        auto c = make_cache();
        auto ips = make_ips({"1.1.1.1"});

        c.put(dns::put_input{"fresh.com", dns::qtype::a, ips, 300});
        c.put(dns::put_input{"old.com", dns::qtype::a, ips, 0});

        c.evict_expired();

        EXPECT_TRUE(c.get("fresh.com", dns::qtype::a).has_value()) << "cache: fresh survives eviction";
    }

} // namespace

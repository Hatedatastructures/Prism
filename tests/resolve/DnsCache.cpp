/**
 * @file DnsCache.cpp
 * @brief DNS Cache 单元测试
 * @details 测试 DNS 缓存的 LRU 淘汰、TTL 过期、serve-stale、负向缓存等核心逻辑。
 */

#include <prism/resolve/dns/detail/cache.hpp>
#include <prism/resolve/dns/detail/format.hpp>
#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <chrono>
#include <thread>


#include <gtest/gtest.h>

namespace net = boost::asio;

using psm::resolve::dns::detail::cache;
using psm::resolve::dns::detail::cache_options;
using psm::resolve::dns::detail::put_input;
using psm::resolve::dns::detail::qtype;
using psm::resolve::dns::detail::stale_policy;

namespace
{
    auto MakeIps(std::initializer_list<const char *> strs)
        -> psm::memory::vector<net::ip::address>
    {
        psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
        for (auto s : strs)
        {
            ips.push_back(net::ip::make_address(s));
        }
        return ips;
    }

    TEST(DnsCache, BasicPutGet)
    {
        cache c(cache_options{psm::memory::current_resource(), std::chrono::seconds(300), 100, stale_policy::discard});

        // 缓存未命中
        auto miss = c.get("example.com", qtype::a);
        EXPECT_TRUE(!miss.has_value()) << "basic: miss returns nullopt";

        // 存入并命中
        auto ips = MakeIps({"1.2.3.4"});
        c.put({"example.com", qtype::a, ips, 300});
        auto hit = c.get("example.com", qtype::a);
        EXPECT_TRUE(hit.has_value() && hit->size() == 1) << "basic: hit returns 1 IP";
        if (hit && !hit->empty())
        {
            EXPECT_TRUE(hit->at(0).to_string() == "1.2.3.4") << "basic: correct IP";
        }

        // 不同 qtype 不冲突
        auto miss_aaaa = c.get("example.com", qtype::aaaa);
        EXPECT_TRUE(!miss_aaaa.has_value()) << "basic: different qtype is miss";
    }

    TEST(DnsCache, LruEviction)
    {
        cache c(cache_options{psm::memory::current_resource(), std::chrono::seconds(300), 3, stale_policy::discard});

        auto ips = MakeIps({"1.1.1.1"});
        c.put({"a.com", qtype::a, ips, 300});
        c.put({"b.com", qtype::a, ips, 300});
        c.put({"c.com", qtype::a, ips, 300});

        EXPECT_TRUE(c.get("a.com", qtype::a).has_value()) << "lru: a.com exists";
        EXPECT_TRUE(c.get("b.com", qtype::a).has_value()) << "lru: b.com exists";
        EXPECT_TRUE(c.get("c.com", qtype::a).has_value()) << "lru: c.com exists";

        c.put({"d.com", qtype::a, ips, 300});
        EXPECT_TRUE(!c.get("a.com", qtype::a).has_value()) << "lru: a.com evicted";
        EXPECT_TRUE(c.get("d.com", qtype::a).has_value()) << "lru: d.com exists";
    }

    TEST(DnsCache, TtlExpiry)
    {
        cache c(cache_options{psm::memory::current_resource(), std::chrono::seconds(300), 100, stale_policy::discard});

        auto ips = MakeIps({"9.9.9.9"});
        c.put({"short.com", qtype::a, ips, 1});

        EXPECT_TRUE(c.get("short.com", qtype::a).has_value()) << "ttl: immediate hit";

        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        auto expired = c.get("short.com", qtype::a);
        EXPECT_TRUE(!expired.has_value()) << "ttl: expired entry returns nullopt (serve_stale=false)";
    }

    TEST(DnsCache, ServeStale)
    {
        cache c(cache_options{psm::memory::current_resource(), std::chrono::seconds(300), 100, stale_policy::serve});

        auto ips = MakeIps({"10.0.0.1"});
        c.put({"stale.com", qtype::a, ips, 1});

        EXPECT_TRUE(c.get("stale.com", qtype::a).has_value()) << "stale: immediate hit";

        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        auto stale = c.get("stale.com", qtype::a);
        EXPECT_TRUE(stale.has_value() && !stale->empty()) << "stale: expired entry returns stale data (serve_stale=true)";
    }

    TEST(DnsCache, NegativeCache)
    {
        cache c(cache_options{psm::memory::current_resource(), std::chrono::seconds(300), 100, stale_policy::discard});

        c.put_negative("nx.com", qtype::a, std::chrono::seconds(60));

        auto neg = c.get("nx.com", qtype::a);
        EXPECT_TRUE(neg.has_value()) << "negative: returns value (not nullopt)";
        EXPECT_TRUE(neg.has_value() && neg->empty()) << "negative: returns empty IP list";
    }

    TEST(DnsCache, EvictExpired)
    {
        cache c(cache_options{psm::memory::current_resource(), std::chrono::seconds(300), 100, stale_policy::discard});

        auto ips = MakeIps({"1.0.0.1"});
        c.put({"expire.com", qtype::a, ips, 1});

        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        c.evict_expired();

        auto result = c.get("expire.com", qtype::a);
        EXPECT_TRUE(!result.has_value()) << "evict: expired entry removed";
    }

    TEST(DnsCache, PutUpdateExisting)
    {
        cache c(cache_options{psm::memory::current_resource(), std::chrono::seconds(300), 100, stale_policy::discard});

        auto ips1 = MakeIps({"1.0.0.1"});
        c.put({"update.com", qtype::a, ips1, 300});

        auto result1 = c.get("update.com", qtype::a);
        EXPECT_TRUE(result1.has_value() && result1->size() == 1) << "put update: initial 1 IP";

        auto ips2 = MakeIps({"2.0.0.2", "3.0.0.3"});
        c.put({"update.com", qtype::a, ips2, 300});

        auto result2 = c.get("update.com", qtype::a);
        EXPECT_TRUE(result2.has_value() && result2->size() == 2) << "put update: updated to 2 IPs";
    }

    TEST(DnsCache, PutEvictionLoop)
    {
        cache c(cache_options{psm::memory::current_resource(), std::chrono::seconds(300), 2, stale_policy::discard});

        auto ips = MakeIps({"1.0.0.1"});

        c.put({"a.com", qtype::a, ips, 300});
        c.put({"b.com", qtype::a, ips, 300});
        c.put({"c.com", qtype::a, ips, 300});

        EXPECT_TRUE(!c.get("a.com", qtype::a).has_value()) << "eviction loop: a.com evicted";
        EXPECT_TRUE(c.get("b.com", qtype::a).has_value()) << "eviction loop: b.com exists";
        EXPECT_TRUE(c.get("c.com", qtype::a).has_value()) << "eviction loop: c.com exists";
    }

    TEST(DnsCache, PutNegativeUpdate)
    {
        cache c(cache_options{psm::memory::current_resource(), std::chrono::seconds(300), 100, stale_policy::discard});

        c.put_negative("neg.com", qtype::a, std::chrono::seconds(30));
        c.put_negative("neg.com", qtype::a, std::chrono::seconds(60));

        auto result = c.get("neg.com", qtype::a);
        EXPECT_TRUE(result.has_value()) << "put_negative update: has_value";
        EXPECT_TRUE(result->empty()) << "put_negative update: empty IPs (negative)";
    }

    TEST(DnsCache, NegativeCacheGet)
    {
        cache c(cache_options{psm::memory::current_resource(), std::chrono::seconds(300), 100, stale_policy::discard});

        c.put_negative("negget.com", qtype::aaaa, std::chrono::seconds(300));

        auto result = c.get("negget.com", qtype::aaaa);
        EXPECT_TRUE(result.has_value()) << "negative get: has_value";
        EXPECT_TRUE(result->empty()) << "negative get: empty vector";
    }

    TEST(DnsCache, ServeStaleNegative)
    {
        cache c(cache_options{psm::memory::current_resource(), std::chrono::seconds(300), 100, stale_policy::serve});

        c.put_negative("stalneg.com", qtype::a, std::chrono::seconds(1));

        std::this_thread::sleep_for(std::chrono::milliseconds(1100));

        auto result = c.get("stalneg.com", qtype::a);
        EXPECT_TRUE(result.has_value()) << "stale negative: has_value";
        EXPECT_TRUE(result->empty()) << "stale negative: empty vector";
    }

} // namespace

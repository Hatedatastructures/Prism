/**
 * @file DnsCacheExtended.cpp
 * @brief DNS 缓存扩展测试 — 交叉覆盖/批量淘汰/过期清理
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/resolve/dns/detail/cache.hpp>
#include <prism/trace/spdlog.hpp>

#include <chrono>
#include <thread>


#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;

    using psm::resolve::dns::detail::cache;
    using psm::resolve::dns::detail::cache_options;
    using psm::resolve::dns::detail::put_input;
    using psm::resolve::dns::detail::qtype;
    using psm::resolve::dns::detail::stale_policy;

    auto make_addr(std::string_view ip) -> net::ip::address
    {
        return net::ip::make_address(ip);
    }

    TEST(DnsCacheExtended, PutNegativeOverwritePositive)
    {
        cache_options opts;
        opts.max_entries = 100;
        opts.stale = stale_policy::discard;
        cache c(opts);

        psm::memory::vector<net::ip::address> ips;
        ips.push_back(make_addr("1.2.3.4"));
        c.put(put_input{"example.com", qtype::a, ips, 300});

        auto result = c.get("example.com", qtype::a);
        EXPECT_TRUE(result.has_value() && !result->empty()) << "overwrite: positive exists";

        c.put_negative("example.com", qtype::a, std::chrono::seconds(30));
        result = c.get("example.com", qtype::a);
        EXPECT_TRUE(result.has_value() && result->empty())
            << "overwrite: negative overwrites positive";
    }

    TEST(DnsCacheExtended, PutPositiveOverwriteNegative)
    {
        cache_options opts;
        opts.max_entries = 100;
        opts.stale = stale_policy::discard;
        cache c(opts);

        c.put_negative("example.com", qtype::a, std::chrono::seconds(30));
        auto result = c.get("example.com", qtype::a);
        EXPECT_TRUE(result.has_value() && result->empty()) << "overwrite: negative exists";

        psm::memory::vector<net::ip::address> ips;
        ips.push_back(make_addr("5.6.7.8"));
        c.put(put_input{"example.com", qtype::a, ips, 300});

        result = c.get("example.com", qtype::a);
        EXPECT_TRUE(result.has_value() && !result->empty()) << "overwrite: positive overwrites negative";
        EXPECT_TRUE(result->size() == 1) << "overwrite: IP count=1";
    }

    TEST(DnsCacheExtended, BatchEvictionOnPut)
    {
        cache_options opts;
        opts.max_entries = 3;
        opts.stale = stale_policy::discard;
        cache c(opts);

        psm::memory::vector<net::ip::address> ips;
        ips.push_back(make_addr("1.1.1.1"));

        c.put(put_input{"a.com", qtype::a, ips, 300});
        c.put(put_input{"b.com", qtype::a, ips, 300});
        c.put(put_input{"c.com", qtype::a, ips, 300});

        c.put(put_input{"d.com", qtype::a, ips, 300});
        EXPECT_TRUE(!c.get("a.com", qtype::a).has_value()) << "batch: a.com evicted";
        EXPECT_TRUE(c.get("d.com", qtype::a).has_value()) << "batch: d.com exists";
        EXPECT_TRUE(c.get("b.com", qtype::a).has_value()) << "batch: b.com exists";
    }

    TEST(DnsCacheExtended, ExpiredDiscardNoStale)
    {
        cache_options opts;
        opts.stale = stale_policy::discard;
        cache c(opts);

        psm::memory::vector<net::ip::address> ips;
        ips.push_back(make_addr("9.8.7.6"));
        c.put(put_input{"short.com", qtype::a, ips, 1});

        auto result = c.get("short.com", qtype::a);
        EXPECT_TRUE(result.has_value()) << "expire: immediate get succeeds";

        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        result = c.get("short.com", qtype::a);
        EXPECT_TRUE(!result.has_value()) << "expire: after TTL+sleep -> nullopt";
    }

    TEST(DnsCacheExtended, EvictExpiredWithStale)
    {
        cache_options opts;
        opts.stale = stale_policy::serve;
        cache c(opts);

        psm::memory::vector<net::ip::address> ips;
        ips.push_back(make_addr("10.0.0.1"));
        c.put(put_input{"expire.com", qtype::a, ips, 1});

        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        auto result = c.get("expire.com", qtype::a);
        EXPECT_TRUE(result.has_value()) << "stale+expire: serve_stale returns data";

        c.evict_expired();
        result = c.get("expire.com", qtype::a);
        EXPECT_TRUE(!result.has_value()) << "stale+expire: evict_expired removes stale";
    }

    TEST(DnsCacheExtended, NegativeExpiryDiscard)
    {
        cache_options opts;
        opts.stale = stale_policy::discard;
        cache c(opts);

        c.put_negative("fail.com", qtype::a, std::chrono::seconds(1));
        auto result = c.get("fail.com", qtype::a);
        EXPECT_TRUE(result.has_value() && result->empty()) << "neg-expire: immediate negative hit";

        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        result = c.get("fail.com", qtype::a);
        EXPECT_TRUE(!result.has_value()) << "neg-expire: expired negative discarded";
    }

} // namespace

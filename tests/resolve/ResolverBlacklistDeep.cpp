/**
 * @file ResolverBlacklistDeep.cpp
 * @brief resolve/dns/resolver 深度纯函数测试
 * @details 通过 #include 源文件访问 resolver.cpp 中所有同步函数，
 *          覆盖 is_blacklisted（IPv4/IPv6 CIDR）、filter_ips、
 *          store_cache、check_rules、check_cache。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/dns/resolver.hpp>
#include <prism/net/dns/detail/cache.hpp>
#include <prism/net/dns/detail/rules.hpp>
#include <prism/trace/spdlog.hpp>

#include <any>
#include <optional>
#include <algorithm>
#include <cctype>
#include <cstdint>


#include <gtest/gtest.h>

// 预包含完成后，通过预处理器 hack 访问 private 成员
#define private public
#include "../../src/prism/net/dns/resolver.cpp"
#undef private

namespace
{
    namespace dns = psm::dns;
    namespace detail = psm::dns::detail;
    namespace net = boost::asio;
    namespace memory = psm::memory;

    // 辅助：创建 resolver_impl 实例（用完需手动析构，会停止 eviction 协程）
    auto make_impl(net::io_context &ioc, dns::config cfg = dns::config())
        -> std::unique_ptr<dns::resolver_impl>
    {
        return std::make_unique<dns::resolver_impl>(ioc, std::move(cfg));
    }

    // ─── is_blacklisted IPv4 测试 ─────────────────

    TEST(ResolverBlacklistDeep, BlacklistV4ExactMatch)
    {
        dns::config cfg;
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("10.0.0.0/24"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto ip = net::ip::make_address_v4("10.0.0.5");
        EXPECT_TRUE(impl->is_blacklisted(net::ip::address(ip)))
            << "bl_v4: 10.0.0.5 in 10.0.0.0/24 -> true";
    }

    TEST(ResolverBlacklistDeep, BlacklistV4OutsideRange)
    {
        dns::config cfg;
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("10.0.0.0/24"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto ip = net::ip::make_address_v4("10.0.1.5");
        EXPECT_TRUE(!impl->is_blacklisted(net::ip::address(ip)))
            << "bl_v4: 10.0.1.5 not in 10.0.0.0/24 -> false";
    }

    TEST(ResolverBlacklistDeep, BlacklistV4NetworkBoundary)
    {
        dns::config cfg;
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("192.168.1.0/24"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto first = net::ip::make_address_v4("192.168.1.0");
        EXPECT_TRUE(impl->is_blacklisted(net::ip::address(first)))
            << "bl_v4: network address 192.168.1.0 -> true";

        auto last = net::ip::make_address_v4("192.168.1.255");
        EXPECT_TRUE(impl->is_blacklisted(net::ip::address(last)))
            << "bl_v4: broadcast 192.168.1.255 -> true";
    }

    TEST(ResolverBlacklistDeep, BlacklistV4MultipleNetworks)
    {
        dns::config cfg;
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("10.0.0.0/8"));
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("172.16.0.0/12"));
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("192.168.0.0/16"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        EXPECT_TRUE(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("10.5.5.5"))))
            << "bl_v4: 10.5.5.5 in 10.0.0.0/8 -> true";
        EXPECT_TRUE(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("172.20.0.1"))))
            << "bl_v4: 172.20.0.1 in 172.16.0.0/12 -> true";
        EXPECT_TRUE(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("192.168.100.1"))))
            << "bl_v4: 192.168.100.1 in 192.168.0.0/16 -> true";
        EXPECT_TRUE(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("8.8.8.8"))))
            << "bl_v4: 8.8.8.8 not in any blacklist -> false";
    }

    TEST(ResolverBlacklistDeep, BlacklistV4Empty)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        EXPECT_TRUE(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("10.0.0.1"))))
            << "bl_v4: empty blacklist -> false";
    }

    TEST(ResolverBlacklistDeep, BlacklistV4Slash16)
    {
        dns::config cfg;
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("1.2.3.0/16"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        // /16 只看前两个字节
        EXPECT_TRUE(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("1.2.99.99"))))
            << "bl_v4: 1.2.99.99 in 1.2.0.0/16 -> true";
        EXPECT_TRUE(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("1.3.0.0"))))
            << "bl_v4: 1.3.0.0 not in 1.2.0.0/16 -> false";
    }

    // ─── is_blacklisted IPv6 测试 ─────────────────

    TEST(ResolverBlacklistDeep, BlacklistV6ExactMatch)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("2001:db8::/32"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto ip = net::ip::make_address_v6("2001:db8:85a3::8a2e:370:7334");
        EXPECT_TRUE(impl->is_blacklisted(net::ip::address(ip)))
            << "bl_v6: 2001:db8:85a3:: in 2001:db8::/32 -> true";
    }

    TEST(ResolverBlacklistDeep, BlacklistV6OutsideRange)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("2001:db8::/32"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto ip = net::ip::make_address_v6("2001:db9::1");
        EXPECT_TRUE(!impl->is_blacklisted(net::ip::address(ip)))
            << "bl_v6: 2001:db9::1 not in 2001:db8::/32 -> false";
    }

    TEST(ResolverBlacklistDeep, BlacklistV6Prefix128)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("::1/128"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        EXPECT_TRUE(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("::1"))))
            << "bl_v6: ::1 in ::1/128 -> true";
        EXPECT_TRUE(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("::2"))))
            << "bl_v6: ::2 not in ::1/128 -> false";
    }

    TEST(ResolverBlacklistDeep, BlacklistV6Prefix64)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("fd00::/64"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        EXPECT_TRUE(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("fd00::1234:5678:abcd:ef01"))))
            << "bl_v6: fd00::... in fd00::/64 -> true";
        EXPECT_TRUE(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("fd00:0:0:1::1"))))
            << "bl_v6: fd00:0:0:1::1 not in fd00::/64 -> false";
    }

    TEST(ResolverBlacklistDeep, BlacklistV6Prefix10NonByteAligned)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("fc00::/10"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        EXPECT_TRUE(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("fc00::1"))))
            << "bl_v6: fc00::1 in fc00::/10 -> true";

        EXPECT_TRUE(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("fc3f::"))))
            << "bl_v6: fc3f:: in fc00::/10 -> true";
        EXPECT_TRUE(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("fc40::"))))
            << "bl_v6: fc40:: not in fc00::/10 -> false";
    }

    TEST(ResolverBlacklistDeep, BlacklistV6Prefix47NonByteAligned)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("2001:db8:8000::/47"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        EXPECT_TRUE(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("2001:db8:8000::1"))))
            << "bl_v6: 2001:db8:8000::1 in /47 -> true";
        EXPECT_TRUE(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("2001:db8:8001::"))))
            << "bl_v6: 2001:db8:8001:: in /47 -> true";
        EXPECT_TRUE(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("2001:db8:8002::"))))
            << "bl_v6: 2001:db8:8002:: not in /47 -> false";
    }

    TEST(ResolverBlacklistDeep, BlacklistV6Empty)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        EXPECT_TRUE(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("::1"))))
            << "bl_v6: empty blacklist -> false";
    }

    TEST(ResolverBlacklistDeep, BlacklistV6Loopback)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("::1/128"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        EXPECT_TRUE(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("::1"))))
            << "bl_v6: loopback in blacklist -> true";
        EXPECT_TRUE(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("::"))))
            << "bl_v6: :: not in ::1/128 -> false";
    }

    // ─── filter_ips 测试 ──────────────────────

    TEST(ResolverBlacklistDeep, FilterIpsNoBlacklist)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        memory::vector<net::ip::address> ips(impl->mr_);
        ips.push_back(net::ip::address(net::ip::make_address_v4("1.1.1.1")));
        ips.push_back(net::ip::address(net::ip::make_address_v4("8.8.8.8")));

        auto filtered = impl->filter_ips(ips, detail::qtype::a);
        EXPECT_TRUE(filtered.size() == 2) << "filter: no blacklist -> all pass";
    }

    TEST(ResolverBlacklistDeep, FilterIpsBlacklistRemoves)
    {
        dns::config cfg;
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("10.0.0.0/8"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        memory::vector<net::ip::address> ips(impl->mr_);
        ips.push_back(net::ip::address(net::ip::make_address_v4("10.0.0.1")));
        ips.push_back(net::ip::address(net::ip::make_address_v4("8.8.8.8")));
        ips.push_back(net::ip::address(net::ip::make_address_v4("10.1.2.3")));

        auto filtered = impl->filter_ips(ips, detail::qtype::a);
        EXPECT_TRUE(filtered.size() == 1) << "filter: 2 blacklisted -> 1 remains";
        EXPECT_TRUE(filtered[0] == net::ip::address(net::ip::make_address_v4("8.8.8.8")))
            << "filter: remaining is 8.8.8.8";
    }

    TEST(ResolverBlacklistDeep, FilterIpsTypeFilterV4Only)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        memory::vector<net::ip::address> ips(impl->mr_);
        ips.push_back(net::ip::address(net::ip::make_address_v4("1.1.1.1")));
        ips.push_back(net::ip::address(net::ip::make_address_v6("::1")));

        auto filtered_a = impl->filter_ips(ips, detail::qtype::a);
        EXPECT_TRUE(filtered_a.size() == 1) << "filter: qtype::a keeps v4 only";

        auto filtered_aaaa = impl->filter_ips(ips, detail::qtype::aaaa);
        EXPECT_TRUE(filtered_aaaa.size() == 1) << "filter: qtype::aaaa keeps v6 only";
    }

    TEST(ResolverBlacklistDeep, FilterIpsEmptyInput)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        memory::vector<net::ip::address> ips(impl->mr_);
        auto filtered = impl->filter_ips(ips, detail::qtype::a);
        EXPECT_TRUE(filtered.empty()) << "filter: empty input -> empty output";
    }

    TEST(ResolverBlacklistDeep, FilterIpsAllBlacklisted)
    {
        dns::config cfg;
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("0.0.0.0/0"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        memory::vector<net::ip::address> ips(impl->mr_);
        ips.push_back(net::ip::address(net::ip::make_address_v4("1.2.3.4")));
        ips.push_back(net::ip::address(net::ip::make_address_v4("8.8.8.8")));

        auto filtered = impl->filter_ips(ips, detail::qtype::a);
        EXPECT_TRUE(filtered.empty()) << "filter: all blacklisted -> empty";
    }

    // ─── check_rules 测试 ────────────────────

    TEST(ResolverBlacklistDeep, CheckRulesBlocked)
    {
        dns::config cfg;
        dns::address_rule rule;
        rule.domain = psm::memory::string("ads.example.com");
        rule.negative = true;
        cfg.address_rules.push_back(std::move(rule));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_rules("ads.example.com");
        EXPECT_TRUE(result.has_value()) << "rules: ads.example.com -> hit";
        EXPECT_TRUE(result->first == psm::fault::code::blocked)
            << "rules: blocked rule -> blocked code";
    }

    TEST(ResolverBlacklistDeep, CheckRulesNegative)
    {
        dns::config cfg;
        dns::address_rule rule;
        rule.domain = psm::memory::string("nx.example.com");
        rule.negative = true;
        cfg.address_rules.push_back(std::move(rule));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_rules("nx.example.com");
        EXPECT_TRUE(result.has_value()) << "rules: negative -> hit";
        EXPECT_TRUE(result->first == psm::fault::code::blocked)
            << "rules: negative -> blocked code";
        EXPECT_TRUE(result->second.empty()) << "rules: negative -> empty ips";
    }

    TEST(ResolverBlacklistDeep, CheckRulesStaticAddress)
    {
        dns::config cfg;
        dns::address_rule rule;
        rule.domain = psm::memory::string("static.example.com");
        rule.addresses.push_back(
            net::ip::address(net::ip::make_address_v4("1.2.3.4")));
        rule.addresses.push_back(
            net::ip::address(net::ip::make_address_v4("5.6.7.8")));
        cfg.address_rules.push_back(std::move(rule));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_rules("static.example.com");
        EXPECT_TRUE(result.has_value()) << "rules: static -> hit";
        EXPECT_TRUE(result->first == psm::fault::code::success)
            << "rules: static -> success code";
        EXPECT_TRUE(result->second.size() == 2) << "rules: static -> 2 ips";
    }

    TEST(ResolverBlacklistDeep, CheckRulesNoMatch)
    {
        dns::config cfg;
        dns::address_rule rule;
        rule.domain = psm::memory::string("other.example.com");
        rule.negative = true;
        cfg.address_rules.push_back(std::move(rule));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_rules("unknown.example.com");
        EXPECT_TRUE(!result.has_value()) << "rules: no match -> nullopt";
    }

    TEST(ResolverBlacklistDeep, CheckRulesEmpty)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_rules("anything.com");
        EXPECT_TRUE(!result.has_value()) << "rules: empty rules -> nullopt";
    }

    // ─── check_cache 测试 ─────────────────────

    TEST(ResolverBlacklistDeep, CheckCacheDisabled)
    {
        dns::config cfg;
        cfg.cache_enabled = false;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_cache("example.com", detail::qtype::a);
        EXPECT_TRUE(!result.has_value()) << "cache: disabled -> nullopt";
    }

    TEST(ResolverBlacklistDeep, CheckCacheMiss)
    {
        dns::config cfg;
        cfg.cache_enabled = true;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_cache("missing.com", detail::qtype::a);
        EXPECT_TRUE(!result.has_value()) << "cache: miss -> nullopt";
    }

    TEST(ResolverBlacklistDeep, CheckCachePositiveHit)
    {
        dns::config cfg;
        cfg.cache_enabled = true;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        // 通过 store_cache 写入正向缓存
        dns::query_result qr(impl->mr_);
        qr.error = psm::fault::code::success;
        qr.ips.push_back(net::ip::address(net::ip::make_address_v4("1.2.3.4")));
        qr.response.answers.push_back(detail::record(impl->mr_));
        qr.response.answers.back().ttl = 300;

        psm::memory::string qname("cached.com", impl->mr_);
        impl->store_cache(qname, detail::qtype::a, qr);

        auto result = impl->check_cache("cached.com", detail::qtype::a);
        EXPECT_TRUE(result.has_value()) << "cache: positive hit -> has_value";
        EXPECT_TRUE(result->first == psm::fault::code::success)
            << "cache: positive hit -> success";
        EXPECT_TRUE(result->second.size() == 1) << "cache: positive hit -> 1 ip";
    }

    TEST(ResolverBlacklistDeep, CheckCacheNegativeHit)
    {
        dns::config cfg;
        cfg.cache_enabled = true;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        // 通过 store_cache 写入负缓存（失败结果）
        dns::query_result qr(impl->mr_);
        qr.error = psm::fault::code::dns_failed;

        psm::memory::string qname("failed.com", impl->mr_);
        impl->store_cache(qname, detail::qtype::a, qr);

        auto result = impl->check_cache("failed.com", detail::qtype::a);
        EXPECT_TRUE(result.has_value()) << "cache: negative hit -> has_value";
        EXPECT_TRUE(result->first == psm::fault::code::dns_failed)
            << "cache: negative hit -> dns_failed";
        EXPECT_TRUE(result->second.empty()) << "cache: negative hit -> empty ips";
    }

    // ─── store_cache 测试 ─────────────────────

    TEST(ResolverBlacklistDeep, StoreCacheDisabled)
    {
        dns::config cfg;
        cfg.cache_enabled = false;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        dns::query_result qr(impl->mr_);
        qr.error = psm::fault::code::success;
        qr.ips.push_back(net::ip::address(net::ip::make_address_v4("1.1.1.1")));

        psm::memory::string qname("test.com", impl->mr_);
        impl->store_cache(qname, detail::qtype::a, qr);

        // 不应缓存
        auto result = impl->check_cache("test.com", detail::qtype::a);
        EXPECT_TRUE(!result.has_value()) << "store: disabled -> no cache written";
    }

    TEST(ResolverBlacklistDeep, StoreCacheSuccessWithIps)
    {
        dns::config cfg;
        cfg.cache_enabled = true;
        cfg.ttl_min = 10;
        cfg.ttl_max = 86400;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        dns::query_result qr(impl->mr_);
        qr.error = psm::fault::code::success;
        qr.ips.push_back(net::ip::address(net::ip::make_address_v4("9.9.9.9")));
        qr.ips.push_back(net::ip::address(net::ip::make_address_v4("9.9.9.10")));
        // 添加一个 answer 记录提供 TTL
        detail::record rec(impl->mr_);
        rec.ttl = 600;
        qr.response.answers.push_back(std::move(rec));

        psm::memory::string qname("success.com", impl->mr_);
        impl->store_cache(qname, detail::qtype::a, qr);

        auto result = impl->check_cache("success.com", detail::qtype::a);
        EXPECT_TRUE(result.has_value()) << "store: success -> cached";
        EXPECT_TRUE(result->second.size() == 2) << "store: success -> 2 ips";
    }

    TEST(ResolverBlacklistDeep, StoreCacheSuccessEmptyIps)
    {
        dns::config cfg;
        cfg.cache_enabled = true;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        dns::query_result qr(impl->mr_);
        qr.error = psm::fault::code::success;
        // ips 为空 -> 走负缓存路径

        psm::memory::string qname("empty.com", impl->mr_);
        impl->store_cache(qname, detail::qtype::a, qr);

        auto result = impl->check_cache("empty.com", detail::qtype::a);
        EXPECT_TRUE(result.has_value()) << "store: success+empty -> negative cache";
        EXPECT_TRUE(result->first == psm::fault::code::dns_failed)
            << "store: success+empty -> dns_failed code";
    }

    TEST(ResolverBlacklistDeep, StoreCacheFailure)
    {
        dns::config cfg;
        cfg.cache_enabled = true;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        dns::query_result qr(impl->mr_);
        qr.error = psm::fault::code::dns_failed;

        psm::memory::string qname("fail.com", impl->mr_);
        impl->store_cache(qname, detail::qtype::aaaa, qr);

        auto result = impl->check_cache("fail.com", detail::qtype::aaaa);
        EXPECT_TRUE(result.has_value()) << "store: failure -> negative cache";
        EXPECT_TRUE(result->second.empty()) << "store: failure -> empty ips";
    }

    TEST(ResolverBlacklistDeep, StoreCacheTtlClampedToMin)
    {
        dns::config cfg;
        cfg.cache_enabled = true;
        cfg.ttl_min = 300;
        cfg.ttl_max = 86400;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        dns::query_result qr(impl->mr_);
        qr.error = psm::fault::code::success;
        qr.ips.push_back(net::ip::address(net::ip::make_address_v4("1.2.3.4")));
        detail::record rec(impl->mr_);
        rec.ttl = 30; // 低于 ttl_min
        qr.response.answers.push_back(std::move(rec));

        psm::memory::string qname("clamp-min.com", impl->mr_);
        impl->store_cache(qname, detail::qtype::a, qr);

        auto result = impl->check_cache("clamp-min.com", detail::qtype::a);
        EXPECT_TRUE(result.has_value()) << "store: ttl clamped to min -> cached";
    }

    TEST(ResolverBlacklistDeep, StoreCacheNoAnswersTtlZero)
    {
        dns::config cfg;
        cfg.cache_enabled = true;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        dns::query_result qr(impl->mr_);
        qr.error = psm::fault::code::success;
        qr.ips.push_back(net::ip::address(net::ip::make_address_v4("1.2.3.4")));
        // answers 为空 -> ttl = 0 -> 不缓存

        psm::memory::string qname("no-answers.com", impl->mr_);
        impl->store_cache(qname, detail::qtype::a, qr);

        auto result = impl->check_cache("no-answers.com", detail::qtype::a);
        EXPECT_TRUE(!result.has_value()) << "store: no answers -> ttl=0 -> not cached";
    }

    // ─── ipv6_disabled 测试 ───────────────────

    TEST(ResolverBlacklistDeep, Ipv6Disabled)
    {
        dns::config cfg;
        cfg.disable_ipv6 = true;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        EXPECT_TRUE(impl->ipv6_disabled()) << "ipv6_disabled: true when set";
    }

    TEST(ResolverBlacklistDeep, Ipv6Enabled)
    {
        dns::config cfg;
        cfg.disable_ipv6 = false;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        EXPECT_TRUE(!impl->ipv6_disabled()) << "ipv6_disabled: false by default";
    }

    // ─── normalize 静态方法测试 ──────────────

    TEST(ResolverBlacklistDeep, NormalizeLowercase)
    {
        auto result = dns::resolver_impl::normalize("WWW.Example.COM", nullptr);
        EXPECT_TRUE(result == "www.example.com") << "normalize: lowercase";
    }

    TEST(ResolverBlacklistDeep, NormalizeTrailingDot)
    {
        auto result = dns::resolver_impl::normalize("example.com.", nullptr);
        EXPECT_TRUE(result == "example.com") << "normalize: trailing dot removed";
    }

    TEST(ResolverBlacklistDeep, NormalizeMultipleTrailingDots)
    {
        auto result = dns::resolver_impl::normalize("example.com...", nullptr);
        EXPECT_TRUE(result == "example.com") << "normalize: multiple trailing dots removed";
    }

    TEST(ResolverBlacklistDeep, NormalizeEmpty)
    {
        auto result = dns::resolver_impl::normalize("", nullptr);
        EXPECT_TRUE(result.empty()) << "normalize: empty stays empty";
    }

    TEST(ResolverBlacklistDeep, NormalizeAllDots)
    {
        auto result = dns::resolver_impl::normalize("...", nullptr);
        EXPECT_TRUE(result.empty()) << "normalize: all dots -> empty";
    }

} // namespace

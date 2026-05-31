/**
 * @file ResolverBlacklistDeep.cpp
 * @brief resolve/dns/resolver 深度纯函数测试
 * @details 通过 #include 源文件访问 resolver.cpp 中所有同步函数，
 *          覆盖 is_blacklisted（IPv4/IPv6 CIDR）、filter_ips、
 *          store_cache、check_rules、check_cache。
 */

#include <prism/memory.hpp>
#include <prism/resolve/dns/dns.hpp>
#include <prism/resolve/dns/detail/cache.hpp>
#include <prism/resolve/dns/detail/rules.hpp>
#include <prism/trace/spdlog.hpp>

#include <any>
#include <optional>
#include <algorithm>
#include <cctype>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// 预包含完成后，通过预处理器 hack 访问 private 成员
#define private public
#include "../src/prism/resolve/dns/resolver.cpp"
#undef private

using psm::testing::TestRunner;

namespace
{
    namespace dns = psm::resolve::dns;
    namespace detail = psm::resolve::dns::detail;
    namespace net = boost::asio;
    namespace memory = psm::memory;

    // 辅助：创建 resolver_impl 实例（用完需手动析构，会停止 eviction 协程）
    auto make_impl(net::io_context &ioc, dns::config cfg = dns::config())
        -> std::unique_ptr<dns::resolver_impl>
    {
        return std::make_unique<dns::resolver_impl>(ioc, std::move(cfg));
    }

    // ─── is_blacklisted IPv4 测试 ─────────────────

    void TestBlacklistV4ExactMatch(TestRunner &runner)
    {
        dns::config cfg;
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("10.0.0.0/24"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto ip = net::ip::make_address_v4("10.0.0.5");
        runner.Check(impl->is_blacklisted(net::ip::address(ip)),
                     "bl_v4: 10.0.0.5 in 10.0.0.0/24 -> true");
    }

    void TestBlacklistV4OutsideRange(TestRunner &runner)
    {
        dns::config cfg;
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("10.0.0.0/24"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto ip = net::ip::make_address_v4("10.0.1.5");
        runner.Check(!impl->is_blacklisted(net::ip::address(ip)),
                     "bl_v4: 10.0.1.5 not in 10.0.0.0/24 -> false");
    }

    void TestBlacklistV4NetworkBoundary(TestRunner &runner)
    {
        dns::config cfg;
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("192.168.1.0/24"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto first = net::ip::make_address_v4("192.168.1.0");
        runner.Check(impl->is_blacklisted(net::ip::address(first)),
                     "bl_v4: network address 192.168.1.0 -> true");

        auto last = net::ip::make_address_v4("192.168.1.255");
        runner.Check(impl->is_blacklisted(net::ip::address(last)),
                     "bl_v4: broadcast 192.168.1.255 -> true");
    }

    void TestBlacklistV4MultipleNetworks(TestRunner &runner)
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

        runner.Check(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("10.5.5.5"))),
            "bl_v4: 10.5.5.5 in 10.0.0.0/8 -> true");
        runner.Check(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("172.20.0.1"))),
            "bl_v4: 172.20.0.1 in 172.16.0.0/12 -> true");
        runner.Check(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("192.168.100.1"))),
            "bl_v4: 192.168.100.1 in 192.168.0.0/16 -> true");
        runner.Check(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("8.8.8.8"))),
            "bl_v4: 8.8.8.8 not in any blacklist -> false");
    }

    void TestBlacklistV4Empty(TestRunner &runner)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        runner.Check(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("10.0.0.1"))),
            "bl_v4: empty blacklist -> false");
    }

    void TestBlacklistV4Slash16(TestRunner &runner)
    {
        dns::config cfg;
        cfg.blacklist_v4.push_back(
            net::ip::make_network_v4("1.2.3.0/16"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        // /16 只看前两个字节
        runner.Check(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("1.2.99.99"))),
            "bl_v4: 1.2.99.99 in 1.2.0.0/16 -> true");
        runner.Check(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v4("1.3.0.0"))),
            "bl_v4: 1.3.0.0 not in 1.2.0.0/16 -> false");
    }

    // ─── is_blacklisted IPv6 测试 ─────────────────

    void TestBlacklistV6ExactMatch(TestRunner &runner)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("2001:db8::/32"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto ip = net::ip::make_address_v6("2001:db8:85a3::8a2e:370:7334");
        runner.Check(impl->is_blacklisted(net::ip::address(ip)),
                     "bl_v6: 2001:db8:85a3:: in 2001:db8::/32 -> true");
    }

    void TestBlacklistV6OutsideRange(TestRunner &runner)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("2001:db8::/32"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto ip = net::ip::make_address_v6("2001:db9::1");
        runner.Check(!impl->is_blacklisted(net::ip::address(ip)),
                     "bl_v6: 2001:db9::1 not in 2001:db8::/32 -> false");
    }

    void TestBlacklistV6Prefix128(TestRunner &runner)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("::1/128"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        runner.Check(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("::1"))),
            "bl_v6: ::1 in ::1/128 -> true");
        runner.Check(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("::2"))),
            "bl_v6: ::2 not in ::1/128 -> false");
    }

    void TestBlacklistV6Prefix64(TestRunner &runner)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("fd00::/64"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        runner.Check(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("fd00::1234:5678:abcd:ef01"))),
            "bl_v6: fd00::... in fd00::/64 -> true");
        runner.Check(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("fd00:0:0:1::1"))),
            "bl_v6: fd00:0:0:1::1 not in fd00::/64 -> false");
    }

    void TestBlacklistV6Prefix10NonByteAligned(TestRunner &runner)
    {
        dns::config cfg;
        // /10 → 前 10 位匹配，前缀 0xfc00 的前 10 位 = 0xfc 二进制 11111100
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("fc00::/10"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        // fc00:.. → 第一个字节 0xfc (11111100)，& 0xc0 (11000000) = 0xc0 (11000000)
        // 实际上 /10 的 mask = 0xFF << (8 - (10 - 0*8)) = 0xFF << (8-10)...
        // 不对，i=0, i*8+8 = 8 <= 10? 不。i*8=0, prefix_len=10, 0+8=8 <= 10 不成立
        // 所以走 else: bits = 0xFF << (8 - (10 - 0)) = 0xFF << (8-10)... 不对
        // bits = 0xFF << (8 - (prefix_len - i * 8)) = 0xFF << (8 - (10 - 0)) = 0xFF << (8-10)
        // 8-10 = -2... 不行，unsigned 下溢
        // 等等：i=0, i*8=0, prefix_len=10。i*8+8 = 8 <= 10? 不对，8 <= 10 是 true
        // 所以 bits = 0xFF, 全字节匹配第一个字节
        // i=1, i*8=8, prefix_len=10。i*8 < prefix_len 且 i*8+8 = 16 <= 10? false
        // else: bits = 0xFF << (8 - (10 - 8)) = 0xFF << 6 = 0xC0
        // 匹配第二个字节的高 2 位

        // fc00 → 字节 [0xfc, 0x00, ...]
        // fd00 → 字节 [0xfd, 0x00, ...] → 0xfd & 0xFF = 0xfd vs 0xfc → 不匹配
        runner.Check(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("fc00::1"))),
            "bl_v6: fc00::1 in fc00::/10 -> true");

        // fc40 → 0xfc40 的前 10 位 = 0xfc40 >> 6 = 0x3f1。fc00 >> 6 = 0x3f0
        // 字节级：byte[0]=0xfc 匹配。byte[1]=0x40 & 0xC0 = 0x40, net byte[1]=0x00 & 0xC0 = 0x00 → 不匹配
        // 所以 fc40 不在 fc00::/10
        // 但 fc00:: 匹配，fc00 到 fc3f 都应该匹配
        // fc00:: → byte[0]=0xfc, byte[1]=0x00 & 0xC0 = 0x00
        // fc3f:: → byte[0]=0xfc, byte[1]=0x3f & 0xC0 = 0x00 → 匹配!
        runner.Check(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("fc3f::"))),
            "bl_v6: fc3f:: in fc00::/10 -> true");
        runner.Check(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("fc40::"))),
            "bl_v6: fc40:: not in fc00::/10 -> false");
    }

    void TestBlacklistV6Prefix47NonByteAligned(TestRunner &runner)
    {
        dns::config cfg;
        // /47 → 前 5 字节完整 + 第 6 字节高 7 位
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("2001:db8:8000::/47"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        // 2001:0db8:8000 → bytes [0x20,0x01,0x0d,0xb8,0x80,0x00,...]
        // 2001:0db8:8001 → bytes [0x20,0x01,0x0d,0xb8,0x80,0x01,...]
        // /47: i=0..4 → bits=0xFF (5 full bytes), i=5: i*8=40, 40+8=48 > 47
        //   bits = 0xFF << (8 - (47 - 40)) = 0xFF << 1 = 0xFE
        // byte[5] & 0xFE: 0x00 & 0xFE = 0x00, net 0x00 & 0xFE = 0x00 → match
        // byte[5] & 0xFE: 0x01 & 0xFE = 0x00, net 0x00 & 0xFE = 0x00 → match
        runner.Check(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("2001:db8:8000::1"))),
            "bl_v6: 2001:db8:8000::1 in /47 -> true");
        runner.Check(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("2001:db8:8001::"))),
            "bl_v6: 2001:db8:8001:: in /47 -> true");
        // 2001:0db8:8002 → byte[5]=0x02 & 0xFE = 0x02, net byte[5]=0x00 & 0xFE = 0x00 → no match
        runner.Check(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("2001:db8:8002::"))),
            "bl_v6: 2001:db8:8002:: not in /47 -> false");
    }

    void TestBlacklistV6Empty(TestRunner &runner)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        runner.Check(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("::1"))),
            "bl_v6: empty blacklist -> false");
    }

    void TestBlacklistV6Loopback(TestRunner &runner)
    {
        dns::config cfg;
        cfg.blacklist_v6.push_back(
            net::ip::make_network_v6("::1/128"));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        runner.Check(impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("::1"))),
            "bl_v6: loopback in blacklist -> true");
        runner.Check(!impl->is_blacklisted(
            net::ip::address(net::ip::make_address_v6("::"))),
            "bl_v6: :: not in ::1/128 -> false");
    }

    // ─── is_blacklisted 非_v4非_v6 分支 ──────

    // boost::ip::address 只可能是 v4 或 v6，第三个 return false 无法直接触发
    // 但仍然测试确保不会崩溃

    // ─── filter_ips 测试 ──────────────────────

    void TestFilterIpsNoBlacklist(TestRunner &runner)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        memory::vector<net::ip::address> ips(impl->mr_);
        ips.push_back(net::ip::address(net::ip::make_address_v4("1.1.1.1")));
        ips.push_back(net::ip::address(net::ip::make_address_v4("8.8.8.8")));

        auto filtered = impl->filter_ips(ips, detail::qtype::a);
        runner.Check(filtered.size() == 2, "filter: no blacklist -> all pass");
    }

    void TestFilterIpsBlacklistRemoves(TestRunner &runner)
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
        runner.Check(filtered.size() == 1, "filter: 2 blacklisted -> 1 remains");
        runner.Check(filtered[0] == net::ip::address(net::ip::make_address_v4("8.8.8.8")),
                     "filter: remaining is 8.8.8.8");
    }

    void TestFilterIpsTypeFilterV4Only(TestRunner &runner)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        memory::vector<net::ip::address> ips(impl->mr_);
        ips.push_back(net::ip::address(net::ip::make_address_v4("1.1.1.1")));
        ips.push_back(net::ip::address(net::ip::make_address_v6("::1")));

        auto filtered_a = impl->filter_ips(ips, detail::qtype::a);
        runner.Check(filtered_a.size() == 1, "filter: qtype::a keeps v4 only");

        auto filtered_aaaa = impl->filter_ips(ips, detail::qtype::aaaa);
        runner.Check(filtered_aaaa.size() == 1, "filter: qtype::aaaa keeps v6 only");
    }

    void TestFilterIpsEmptyInput(TestRunner &runner)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        memory::vector<net::ip::address> ips(impl->mr_);
        auto filtered = impl->filter_ips(ips, detail::qtype::a);
        runner.Check(filtered.empty(), "filter: empty input -> empty output");
    }

    void TestFilterIpsAllBlacklisted(TestRunner &runner)
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
        runner.Check(filtered.empty(), "filter: all blacklisted -> empty");
    }

    // ─── check_rules 测试 ────────────────────

    void TestCheckRulesBlocked(TestRunner &runner)
    {
        dns::config cfg;
        dns::address_rule rule;
        rule.domain = psm::memory::string("ads.example.com");
        rule.negative = true;
        cfg.address_rules.push_back(std::move(rule));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_rules("ads.example.com");
        runner.Check(result.has_value(), "rules: ads.example.com -> hit");
        runner.Check(result->first == psm::fault::code::blocked,
                     "rules: blocked rule -> blocked code");
    }

    void TestCheckRulesNegative(TestRunner &runner)
    {
        dns::config cfg;
        dns::address_rule rule;
        rule.domain = psm::memory::string("nx.example.com");
        rule.negative = true;
        cfg.address_rules.push_back(std::move(rule));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_rules("nx.example.com");
        runner.Check(result.has_value(), "rules: negative -> hit");
        // add_neg_rule 设置 blocked=true，所以返回 blocked 而非 success
        runner.Check(result->first == psm::fault::code::blocked,
                     "rules: negative -> blocked code");
        runner.Check(result->second.empty(), "rules: negative -> empty ips");
    }

    void TestCheckRulesStaticAddress(TestRunner &runner)
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
        runner.Check(result.has_value(), "rules: static -> hit");
        runner.Check(result->first == psm::fault::code::success,
                     "rules: static -> success code");
        runner.Check(result->second.size() == 2, "rules: static -> 2 ips");
    }

    void TestCheckRulesNoMatch(TestRunner &runner)
    {
        dns::config cfg;
        dns::address_rule rule;
        rule.domain = psm::memory::string("other.example.com");
        rule.negative = true;
        cfg.address_rules.push_back(std::move(rule));

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_rules("unknown.example.com");
        runner.Check(!result.has_value(), "rules: no match -> nullopt");
    }

    void TestCheckRulesEmpty(TestRunner &runner)
    {
        dns::config cfg;
        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_rules("anything.com");
        runner.Check(!result.has_value(), "rules: empty rules -> nullopt");
    }

    // ─── check_cache 测试 ─────────────────────

    void TestCheckCacheDisabled(TestRunner &runner)
    {
        dns::config cfg;
        cfg.cache_enabled = false;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_cache("example.com", detail::qtype::a);
        runner.Check(!result.has_value(), "cache: disabled -> nullopt");
    }

    void TestCheckCacheMiss(TestRunner &runner)
    {
        dns::config cfg;
        cfg.cache_enabled = true;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        auto result = impl->check_cache("missing.com", detail::qtype::a);
        runner.Check(!result.has_value(), "cache: miss -> nullopt");
    }

    void TestCheckCachePositiveHit(TestRunner &runner)
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
        runner.Check(result.has_value(), "cache: positive hit -> has_value");
        runner.Check(result->first == psm::fault::code::success,
                     "cache: positive hit -> success");
        runner.Check(result->second.size() == 1, "cache: positive hit -> 1 ip");
    }

    void TestCheckCacheNegativeHit(TestRunner &runner)
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
        runner.Check(result.has_value(), "cache: negative hit -> has_value");
        runner.Check(result->first == psm::fault::code::dns_failed,
                     "cache: negative hit -> dns_failed");
        runner.Check(result->second.empty(), "cache: negative hit -> empty ips");
    }

    // ─── store_cache 测试 ─────────────────────

    void TestStoreCacheDisabled(TestRunner &runner)
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
        runner.Check(!result.has_value(), "store: disabled -> no cache written");
    }

    void TestStoreCacheSuccessWithIps(TestRunner &runner)
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
        runner.Check(result.has_value(), "store: success -> cached");
        runner.Check(result->second.size() == 2, "store: success -> 2 ips");
    }

    void TestStoreCacheSuccessEmptyIps(TestRunner &runner)
    {
        dns::config cfg;
        cfg.cache_enabled = true;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        dns::query_result qr(impl->mr_);
        qr.error = psm::fault::code::success;
        // ips 为空 → 走负缓存路径

        psm::memory::string qname("empty.com", impl->mr_);
        impl->store_cache(qname, detail::qtype::a, qr);

        auto result = impl->check_cache("empty.com", detail::qtype::a);
        runner.Check(result.has_value(), "store: success+empty -> negative cache");
        runner.Check(result->first == psm::fault::code::dns_failed,
                     "store: success+empty -> dns_failed code");
    }

    void TestStoreCacheFailure(TestRunner &runner)
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
        runner.Check(result.has_value(), "store: failure -> negative cache");
        runner.Check(result->second.empty(), "store: failure -> empty ips");
    }

    void TestStoreCacheTtlClampedToMin(TestRunner &runner)
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
        runner.Check(result.has_value(), "store: ttl clamped to min -> cached");
    }

    void TestStoreCacheNoAnswersTtlZero(TestRunner &runner)
    {
        dns::config cfg;
        cfg.cache_enabled = true;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        dns::query_result qr(impl->mr_);
        qr.error = psm::fault::code::success;
        qr.ips.push_back(net::ip::address(net::ip::make_address_v4("1.2.3.4")));
        // answers 为空 → ttl = 0 → 不缓存

        psm::memory::string qname("no-answers.com", impl->mr_);
        impl->store_cache(qname, detail::qtype::a, qr);

        auto result = impl->check_cache("no-answers.com", detail::qtype::a);
        runner.Check(!result.has_value(), "store: no answers -> ttl=0 -> not cached");
    }

    // ─── ipv6_disabled 测试 ───────────────────

    void TestIpv6Disabled(TestRunner &runner)
    {
        dns::config cfg;
        cfg.disable_ipv6 = true;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        runner.Check(impl->ipv6_disabled(), "ipv6_disabled: true when set");
    }

    void TestIpv6Enabled(TestRunner &runner)
    {
        dns::config cfg;
        cfg.disable_ipv6 = false;

        net::io_context ioc;
        auto impl = make_impl(ioc, std::move(cfg));

        runner.Check(!impl->ipv6_disabled(), "ipv6_disabled: false by default");
    }

    // ─── normalize 静态方法测试 ──────────────

    void TestNormalizeLowercase(TestRunner &runner)
    {
        auto result = dns::resolver_impl::normalize("WWW.Example.COM", nullptr);
        runner.Check(result == "www.example.com", "normalize: lowercase");
    }

    void TestNormalizeTrailingDot(TestRunner &runner)
    {
        auto result = dns::resolver_impl::normalize("example.com.", nullptr);
        runner.Check(result == "example.com", "normalize: trailing dot removed");
    }

    void TestNormalizeMultipleTrailingDots(TestRunner &runner)
    {
        auto result = dns::resolver_impl::normalize("example.com...", nullptr);
        runner.Check(result == "example.com", "normalize: multiple trailing dots removed");
    }

    void TestNormalizeEmpty(TestRunner &runner)
    {
        auto result = dns::resolver_impl::normalize("", nullptr);
        runner.Check(result.empty(), "normalize: empty stays empty");
    }

    void TestNormalizeAllDots(TestRunner &runner)
    {
        auto result = dns::resolver_impl::normalize("...", nullptr);
        runner.Check(result.empty(), "normalize: all dots -> empty");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ResolverBlacklistDeep");

    // is_blacklisted IPv4
    TestBlacklistV4ExactMatch(runner);
    TestBlacklistV4OutsideRange(runner);
    TestBlacklistV4NetworkBoundary(runner);
    TestBlacklistV4MultipleNetworks(runner);
    TestBlacklistV4Empty(runner);
    TestBlacklistV4Slash16(runner);

    // is_blacklisted IPv6
    TestBlacklistV6ExactMatch(runner);
    TestBlacklistV6OutsideRange(runner);
    TestBlacklistV6Prefix128(runner);
    TestBlacklistV6Prefix64(runner);
    TestBlacklistV6Prefix10NonByteAligned(runner);
    TestBlacklistV6Prefix47NonByteAligned(runner);
    TestBlacklistV6Empty(runner);
    TestBlacklistV6Loopback(runner);

    // filter_ips
    TestFilterIpsNoBlacklist(runner);
    TestFilterIpsBlacklistRemoves(runner);
    TestFilterIpsTypeFilterV4Only(runner);
    TestFilterIpsEmptyInput(runner);
    TestFilterIpsAllBlacklisted(runner);

    // check_rules
    TestCheckRulesBlocked(runner);
    TestCheckRulesNegative(runner);
    TestCheckRulesStaticAddress(runner);
    TestCheckRulesNoMatch(runner);
    TestCheckRulesEmpty(runner);

    // check_cache
    TestCheckCacheDisabled(runner);
    TestCheckCacheMiss(runner);
    TestCheckCachePositiveHit(runner);
    TestCheckCacheNegativeHit(runner);

    // store_cache
    TestStoreCacheDisabled(runner);
    TestStoreCacheSuccessWithIps(runner);
    TestStoreCacheSuccessEmptyIps(runner);
    TestStoreCacheFailure(runner);
    TestStoreCacheTtlClampedToMin(runner);
    TestStoreCacheNoAnswersTtlZero(runner);

    // ipv6_disabled
    TestIpv6Disabled(runner);
    TestIpv6Enabled(runner);

    // normalize
    TestNormalizeLowercase(runner);
    TestNormalizeTrailingDot(runner);
    TestNormalizeMultipleTrailingDots(runner);
    TestNormalizeEmpty(runner);
    TestNormalizeAllDots(runner);

    return runner.Summary();
}

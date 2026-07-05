/**
 * @file DnsResolverPure.cpp
 * @brief DNS 解析器纯函数单元测试
 * @details 测试 resolver_impl 内部的三组纯逻辑函数：
 *          1. normalize（域名规范化：小写 + 去末尾点号）
 *          2. is_blacklisted（IPv4/IPv6 黑名单 CIDR 匹配）
 *          3. filter_ips（按查询类型过滤 + 黑名单剔除）
 *          因这些函数为 resolver_impl 的 private 成员，且 resolver.cpp
 *          构造函数会启动协程、链接 BoringSSL，不适合直接 #include 源文件。
 *          改为在测试中独立复现等价逻辑，保持与源码同步。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/resolve/dns/detail/format.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <initializer_list>


#include <gtest/gtest.h>

namespace net = boost::asio;

namespace
{
    namespace detail = psm::resolve::dns::detail;

    // ─── 辅助：创建 IP 地址列表 ───────────────────────────────

    /**
     * @brief 从字符串列表构造 IP 地址向量
     */
    static auto MakeIps(std::initializer_list<const char *> strs)
        -> psm::memory::vector<net::ip::address>
    {
        psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
        for (auto s : strs)
        {
            ips.push_back(net::ip::make_address(s));
        }
        return ips;
    }

    // ─── 复现 normalize 逻辑（与 resolver.cpp:391-405 等价）───

    /**
     * @brief 域名规范化：转小写 + 去末尾点号
     */
    static auto Normalize(std::string_view domain, psm::memory::resource_pointer mr)
        -> psm::memory::string
    {
        psm::memory::string result(domain, mr);
        auto to_lower = [](std::uint8_t ch)
        {
            return static_cast<char>(std::tolower(ch));
        };
        std::transform(result.begin(), result.end(), result.begin(), to_lower);
        while (!result.empty() && result.back() == '.')
        {
            result.pop_back();
        }
        return result;
    }

    // ─── 复现 is_blacklisted 逻辑（与 resolver.cpp:407-461 等价）───

    /**
     * @brief 检查 IP 是否命中 IPv4/IPv6 黑名单 CIDR
     */
    static auto IsBlacklisted(
        const net::ip::address &ip,
        const psm::memory::vector<net::ip::network_v4> &blacklist_v4,
        const psm::memory::vector<net::ip::network_v6> &blacklist_v6) -> bool
    {
        if (ip.is_v4())
        {
            const auto v4 = ip.to_v4();
            const auto addr_uint = v4.to_uint();
            for (const auto &network : blacklist_v4)
            {
                const auto net_addr = network.address().to_uint();
                const auto mask = network.netmask().to_uint();
                if ((addr_uint & mask) == (net_addr & mask))
                {
                    return true;
                }
            }
            return false;
        }

        if (ip.is_v6())
        {
            const auto v6 = ip.to_v6();
            const auto &addr_bytes = v6.to_bytes();
            for (const auto &network : blacklist_v6)
            {
                const auto &net_bytes = network.address().to_bytes();
                const auto prefix_len = network.prefix_length();
                bool match = true;
                for (std::uint32_t i = 0; i < 16 && i * 8 < prefix_len; ++i)
                {
                    std::uint8_t bits;
                    if (i * 8 + 8 <= prefix_len)
                    {
                        bits = 0xFF;
                    }
                    else
                    {
                        bits = static_cast<std::uint8_t>(0xFF << (8 - (prefix_len - i * 8)));
                    }
                    if ((addr_bytes[i] & bits) != (net_bytes[i] & bits))
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    return true;
                }
            }
            return false;
        }

        return false;
    }

    // ─── 复现 filter_ips 逻辑（与 resolver.cpp:211-227 等价）───

    /**
     * @brief 按 qtype 过滤 IP 并剔除黑名单条目
     */
    static auto FilterIps(
        const psm::memory::vector<net::ip::address> &ips,
        detail::qtype qt,
        const psm::memory::vector<net::ip::network_v4> &blacklist_v4,
        const psm::memory::vector<net::ip::network_v6> &blacklist_v6)
        -> psm::memory::vector<net::ip::address>
    {
        psm::memory::vector<net::ip::address> filtered(psm::memory::current_resource());
        filtered.reserve(ips.size());
        const bool want_v4 = (qt == detail::qtype::a);
        const bool want_v6 = (qt == detail::qtype::aaaa);
        for (const auto &ip : ips)
        {
            if (!IsBlacklisted(ip, blacklist_v4, blacklist_v6) && ip.is_v4() == want_v4 && ip.is_v6() == want_v6)
            {
                filtered.push_back(ip);
            }
        }
        return filtered;
    }

    // ═══════════════════════════════════════════════════════════
    //  normalize 测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试小写转换
     */
    TEST(DnsResolverPure, NormalizeLowercase)
    {
        auto r = Normalize("EXAMPLE.COM", psm::memory::current_resource());
        EXPECT_TRUE(r == "example.com") << "normalize: 大写转小写";
    }

    /**
     * @brief 测试末尾点号移除
     */
    TEST(DnsResolverPure, NormalizeTrailingDot)
    {
        auto r = Normalize("example.com.", psm::memory::current_resource());
        EXPECT_TRUE(r == "example.com") << "normalize: 移除末尾点号";
    }

    /**
     * @brief 测试多个末尾点号
     */
    TEST(DnsResolverPure, NormalizeMultipleTrailingDots)
    {
        auto r = Normalize("example.com...", psm::memory::current_resource());
        EXPECT_TRUE(r == "example.com") << "normalize: 移除多个末尾点号";
    }

    /**
     * @brief 测试已经是规范形式
     */
    TEST(DnsResolverPure, NormalizeAlreadyCanonical)
    {
        auto r = Normalize("example.com", psm::memory::current_resource());
        EXPECT_TRUE(r == "example.com") << "normalize: 已规范形式不变";
    }

    /**
     * @brief 测试混合大小写 + 末尾点号
     */
    TEST(DnsResolverPure, NormalizeMixedCaseTrailingDot)
    {
        auto r = Normalize("ExAmPlE.CoM.", psm::memory::current_resource());
        EXPECT_TRUE(r == "example.com") << "normalize: 混合大小写 + 点号";
    }

    /**
     * @brief 测试空字符串
     */
    TEST(DnsResolverPure, NormalizeEmpty)
    {
        auto r = Normalize("", psm::memory::current_resource());
        EXPECT_TRUE(r.empty()) << "normalize: 空字符串保持空";
    }

    /**
     * @brief 测试纯点号字符串
     */
    TEST(DnsResolverPure, NormalizeOnlyDots)
    {
        auto r = Normalize("...", psm::memory::current_resource());
        EXPECT_TRUE(r.empty()) << "normalize: 纯点号变空串";
    }

    /**
     * @brief 测试子域名
     */
    TEST(DnsResolverPure, NormalizeSubdomain)
    {
        auto r = Normalize("WWW.Sub.EXAMPLE.COM.", psm::memory::current_resource());
        EXPECT_TRUE(r == "www.sub.example.com") << "normalize: 多级子域名规范化";
    }

    /**
     * @brief 测试单标签域名
     */
    TEST(DnsResolverPure, NormalizeSingleLabel)
    {
        auto r = Normalize("LOCALHOST", psm::memory::current_resource());
        EXPECT_TRUE(r == "localhost") << "normalize: 单标签域名小写";
    }

    /**
     * @brief 测试确定性和幂等性
     */
    TEST(DnsResolverPure, NormalizeDeterministic)
    {
        const auto mr = psm::memory::current_resource();
        auto r1 = Normalize("EXAMPLE.COM.", mr);
        auto r2 = Normalize("EXAMPLE.COM.", mr);
        EXPECT_TRUE(r1 == r2) << "normalize: 相同输入 -> 相同输出（确定性）";
    }

    // ═══════════════════════════════════════════════════════════
    //  is_blacklisted 测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 IPv4 匹配 /8 前缀
     */
    TEST(DnsResolverPure, BlacklistV4Slash8)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v4.push_back(net::ip::make_network_v4("10.0.0.0/8"));

        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("10.0.0.1"), bl_v4, bl_v6))
            << "blacklist v4: 10.0.0.1 命中 10.0.0.0/8";
        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("10.255.255.255"), bl_v4, bl_v6))
            << "blacklist v4: 10.255.255.255 命中 10.0.0.0/8";
        EXPECT_TRUE(
            !IsBlacklisted(net::ip::make_address("11.0.0.1"), bl_v4, bl_v6))
            << "blacklist v4: 11.0.0.1 不命中 10.0.0.0/8";
    }

    /**
     * @brief 测试 IPv4 匹配 /24 前缀
     */
    TEST(DnsResolverPure, BlacklistV4Slash24)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v4.push_back(net::ip::make_network_v4("192.168.1.0/24"));

        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("192.168.1.100"), bl_v4, bl_v6))
            << "blacklist v4: 192.168.1.100 命中 192.168.1.0/24";
        EXPECT_TRUE(
            !IsBlacklisted(net::ip::make_address("192.168.2.1"), bl_v4, bl_v6))
            << "blacklist v4: 192.168.2.1 不命中 192.168.1.0/24";
    }

    /**
     * @brief 测试 IPv4 匹配 /32（精确地址）
     */
    TEST(DnsResolverPure, BlacklistV4Slash32)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v4.push_back(net::ip::make_network_v4("1.2.3.4/32"));

        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("1.2.3.4"), bl_v4, bl_v6))
            << "blacklist v4: 1.2.3.4 命中 /32";
        EXPECT_TRUE(
            !IsBlacklisted(net::ip::make_address("1.2.3.5"), bl_v4, bl_v6))
            << "blacklist v4: 1.2.3.5 不命中 /32";
    }

    /**
     * @brief 测试空黑名单
     */
    TEST(DnsResolverPure, BlacklistEmpty)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());

        EXPECT_TRUE(
            !IsBlacklisted(net::ip::make_address("10.0.0.1"), bl_v4, bl_v6))
            << "blacklist: 空黑名单不命中 IPv4";
        EXPECT_TRUE(
            !IsBlacklisted(net::ip::make_address("::1"), bl_v4, bl_v6))
            << "blacklist: 空黑名单不命中 IPv6";
    }

    /**
     * @brief 测试多条 IPv4 黑名单规则
     */
    TEST(DnsResolverPure, BlacklistV4MultipleRules)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v4.push_back(net::ip::make_network_v4("10.0.0.0/8"));
        bl_v4.push_back(net::ip::make_network_v4("172.16.0.0/12"));
        bl_v4.push_back(net::ip::make_network_v4("192.168.0.0/16"));

        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("10.1.2.3"), bl_v4, bl_v6))
            << "blacklist v4: 10.1.2.3 命中第一条";
        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("172.20.0.1"), bl_v4, bl_v6))
            << "blacklist v4: 172.20.0.1 命中第二条";
        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("192.168.100.1"), bl_v4, bl_v6))
            << "blacklist v4: 192.168.100.1 命中第三条";
        EXPECT_TRUE(
            !IsBlacklisted(net::ip::make_address("8.8.8.8"), bl_v4, bl_v6))
            << "blacklist v4: 8.8.8.8 不命中任何规则";
    }

    /**
     * @brief 测试 IPv6 匹配 /64 前缀
     */
    TEST(DnsResolverPure, BlacklistV6Slash64)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v6.push_back(net::ip::make_network_v6("2001:db8::/64"));

        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("2001:db8::1"), bl_v4, bl_v6))
            << "blacklist v6: 2001:db8::1 命中 /64";
        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("2001:db8::ffff"), bl_v4, bl_v6))
            << "blacklist v6: 2001:db8::ffff 命中 /64";
        EXPECT_TRUE(
            !IsBlacklisted(net::ip::make_address("2001:db9::1"), bl_v4, bl_v6))
            << "blacklist v6: 2001:db9::1 不命中 /64";
    }

    /**
     * @brief 测试 IPv6 匹配 /128（精确地址）
     */
    TEST(DnsResolverPure, BlacklistV6Slash128)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v6.push_back(net::ip::make_network_v6("::1/128"));

        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("::1"), bl_v4, bl_v6))
            << "blacklist v6: ::1 命中 /128";
        EXPECT_TRUE(
            !IsBlacklisted(net::ip::make_address("::2"), bl_v4, bl_v6))
            << "blacklist v6: ::2 不命中 /128";
    }

    /**
     * @brief 测试 IPv6 非字节对齐前缀 (/48)
     */
    TEST(DnsResolverPure, BlacklistV6Slash48)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v6.push_back(net::ip::make_network_v6("2001:db8:abcd::/48"));

        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("2001:db8:abcd::1"), bl_v4, bl_v6))
            << "blacklist v6: 2001:db8:abcd::1 命中 /48";
        EXPECT_TRUE(
            !IsBlacklisted(net::ip::make_address("2001:db8:abce::1"), bl_v4, bl_v6))
            << "blacklist v6: 2001:db8:abce::1 不命中 /48";
    }

    /**
     * @brief 测试 IPv4 地址不命中 IPv6 黑名单，反之亦然
     */
    TEST(DnsResolverPure, BlacklistTypeMismatch)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v4.push_back(net::ip::make_network_v4("10.0.0.0/8"));
        bl_v6.push_back(net::ip::make_network_v6("2001:db8::/32"));

        // IPv4 地址仅检查 v4 黑名单
        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("10.0.0.1"), bl_v4, bl_v6))
            << "blacklist: IPv4 地址命中 v4 黑名单";
        // IPv6 地址仅检查 v6 黑名单
        EXPECT_TRUE(
            IsBlacklisted(net::ip::make_address("2001:db8::1"), bl_v4, bl_v6))
            << "blacklist: IPv6 地址命中 v6 黑名单";
    }

    // ═══════════════════════════════════════════════════════════
    //  filter_ips 测试
    // ═══════════════════════════════════════════════════════════

    /**
     * @brief 测试 qtype=A 只保留 IPv4
     */
    TEST(DnsResolverPure, FilterIpsOnlyV4)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());

        auto ips = MakeIps({"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888", "::1"});
        auto filtered = FilterIps(ips, detail::qtype::a, bl_v4, bl_v6);

        EXPECT_TRUE(filtered.size() == 2) << "filter: qtype=A 保留 2 个 IPv4";
        EXPECT_TRUE(filtered[0].is_v4()) << "filter: 第一个是 IPv4";
        EXPECT_TRUE(filtered[1].is_v4()) << "filter: 第二个是 IPv4";
    }

    /**
     * @brief 测试 qtype=AAAA 只保留 IPv6
     */
    TEST(DnsResolverPure, FilterIpsOnlyV6)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());

        auto ips = MakeIps({"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888", "::1"});
        auto filtered = FilterIps(ips, detail::qtype::aaaa, bl_v4, bl_v6);

        EXPECT_TRUE(filtered.size() == 2) << "filter: qtype=AAAA 保留 2 个 IPv6";
        EXPECT_TRUE(filtered[0].is_v6()) << "filter: 第一个是 IPv6";
        EXPECT_TRUE(filtered[1].is_v6()) << "filter: 第二个是 IPv6";
    }

    /**
     * @brief 测试过滤黑名单 IP
     */
    TEST(DnsResolverPure, FilterIpsRemoveBlacklisted)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v4.push_back(net::ip::make_network_v4("10.0.0.0/8"));

        auto ips = MakeIps({"1.1.1.1", "10.0.0.1", "8.8.8.8", "10.1.2.3"});
        auto filtered = FilterIps(ips, detail::qtype::a, bl_v4, bl_v6);

        EXPECT_TRUE(filtered.size() == 2) << "filter: 黑名单移除 2 个，保留 2 个";
        EXPECT_TRUE(filtered[0].to_string() == "1.1.1.1") << "filter: 保留 1.1.1.1";
        EXPECT_TRUE(filtered[1].to_string() == "8.8.8.8") << "filter: 保留 8.8.8.8";
    }

    /**
     * @brief 测试全部被黑名单移除
     */
    TEST(DnsResolverPure, FilterIpsAllBlacklisted)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v4.push_back(net::ip::make_network_v4("0.0.0.0/0"));

        auto ips = MakeIps({"1.1.1.1", "8.8.8.8", "10.0.0.1"});
        auto filtered = FilterIps(ips, detail::qtype::a, bl_v4, bl_v6);

        EXPECT_TRUE(filtered.empty()) << "filter: 0.0.0.0/0 黑名单移除全部 IPv4";
    }

    /**
     * @brief 测试空输入
     */
    TEST(DnsResolverPure, FilterIpsEmptyInput)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());

        psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
        auto filtered = FilterIps(ips, detail::qtype::a, bl_v4, bl_v6);

        EXPECT_TRUE(filtered.empty()) << "filter: 空输入返回空";
    }

    /**
     * @brief 测试 qtype 不匹配导致空结果
     */
    TEST(DnsResolverPure, FilterIpsQtypeMismatch)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());

        auto ips = MakeIps({"1.1.1.1", "8.8.8.8"});
        auto filtered = FilterIps(ips, detail::qtype::aaaa, bl_v4, bl_v6);

        EXPECT_TRUE(filtered.empty()) << "filter: 纯 IPv4 + qtype=AAAA 返回空";
    }

    /**
     * @brief 测试混合 IPv4/IPv6 + 黑名单 + qtype
     */
    TEST(DnsResolverPure, FilterIpsMixedComplex)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v4.push_back(net::ip::make_network_v4("10.0.0.0/8"));
        bl_v6.push_back(net::ip::make_network_v6("fe80::/10"));

        auto ips = MakeIps({
            "1.1.1.1",         // IPv4, 干净
            "10.0.0.1",        // IPv4, 黑名单
            "8.8.8.8",         // IPv4, 干净
            "2001:db8::1",     // IPv6, 干净
            "fe80::1",         // IPv6, 黑名单
            "::1",             // IPv6, 干净
        });

        // qtype=A 只保留干净 IPv4
        auto filtered_a = FilterIps(ips, detail::qtype::a, bl_v4, bl_v6);
        EXPECT_TRUE(filtered_a.size() == 2) << "filter complex: qtype=A 保留 2 个干净 IPv4";

        // qtype=AAAA 只保留干净 IPv6
        auto filtered_aaaa = FilterIps(ips, detail::qtype::aaaa, bl_v4, bl_v6);
        EXPECT_TRUE(filtered_aaaa.size() == 2) << "filter complex: qtype=AAAA 保留 2 个干净 IPv6";
    }

    /**
     * @brief 测试 IPv6 黑名单过滤
     */
    TEST(DnsResolverPure, FilterIpsV6Blacklist)
    {
        psm::memory::vector<net::ip::network_v4> bl_v4(psm::memory::current_resource());
        psm::memory::vector<net::ip::network_v6> bl_v6(psm::memory::current_resource());
        bl_v6.push_back(net::ip::make_network_v6("fc00::/7"));

        auto ips = MakeIps({"2001:db8::1", "fc00::1", "::1", "fd00::1"});
        auto filtered = FilterIps(ips, detail::qtype::aaaa, bl_v4, bl_v6);

        EXPECT_TRUE(filtered.size() == 2) << "filter v6: fc00::/7 黑名单移除 2 个，保留 2 个";
    }

} // namespace

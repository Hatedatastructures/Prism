/**
 * @file DnsRules.cpp
 * @brief DNS 规则引擎测试
 * @details 测试以下 DNS 解析模块组件：
 * 1. domain_trie：反转域名基数树的精确匹配、通配符匹配和大小写不敏感特性
 * 2. rules_engine：规则引擎的地址规则、否定规则、CNAME 规则及优先级合并
 * 3. parse_port：端口号解析工具函数的边界值和异常输入处理
 * 4. transparent_hash / transparent_equal：透明哈希与跨类型相等比较器的确定性
 * @note 当前 wildcard 断言以仓库现实现行为准：`*.example.com` 也会命中 `example.com`。
 */

#include <prism/net/resolve/dns/detail/rules.hpp>
#include <prism/net/resolve/dns/detail/utility.hpp>
#include <prism/net/resolve/dns/detail/transparent.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

#include <any>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace
{
    // ---------------------------------------------------------------------------
    // domain_trie 测试 (5)
    // ---------------------------------------------------------------------------

    TEST(DnsRules, TrieExactMatch)
    {
        psm::resolve::dns::detail::domain_trie trie;

        trie.insert("example.com", 42);

        {
            auto result = trie.search("example.com");
            ASSERT_TRUE(result.has_value()) << "search(\"example.com\") should return a value";

            auto val = std::any_cast<int>(result.value());
            EXPECT_TRUE(val == 42) << "search(\"example.com\") should return 42";
        }

        {
            auto result = trie.search("other.com");
            EXPECT_TRUE(!result.has_value()) << "search(\"other.com\") should return nullopt";
        }
    }

    TEST(DnsRules, TrieWildcardMatch)
    {
        psm::resolve::dns::detail::domain_trie trie;

        trie.insert("*.example.com", 100);

        {
            auto result = trie.search("www.example.com");
            ASSERT_TRUE(result.has_value()) << "search(\"www.example.com\") should match *.example.com";

            auto val = std::any_cast<int>(result.value());
            EXPECT_TRUE(val == 100) << "search(\"www.example.com\") should return 100";
        }

        {
            auto result = trie.search("example.com");
            ASSERT_TRUE(result.has_value()) << "search(\"example.com\") should match *.example.com under current trie semantics";

            auto val = std::any_cast<int>(result.value());
            EXPECT_TRUE(val == 100) << "search(\"example.com\") should return 100";
        }

        {
            auto result = trie.search("sub.example.com");
            ASSERT_TRUE(result.has_value()) << "search(\"sub.example.com\") should match *.example.com";

            auto val = std::any_cast<int>(result.value());
            EXPECT_TRUE(val == 100) << "search(\"sub.example.com\") should return 100";
        }
    }

    TEST(DnsRules, TrieCaseInsensitive)
    {
        psm::resolve::dns::detail::domain_trie trie;

        trie.insert("Example.COM", 77);

        auto result = trie.search("example.com");
        ASSERT_TRUE(result.has_value()) << "search(\"example.com\") should match inserted \"Example.COM\"";

        auto val = std::any_cast<int>(result.value());
        EXPECT_TRUE(val == 77) << "search(\"example.com\") should return 77";
    }

    TEST(DnsRules, TrieNoMatch)
    {
        // 空 trie 的查询应返回空
        {
            psm::resolve::dns::detail::domain_trie trie;

            auto result = trie.search("anything");
            EXPECT_TRUE(!result.has_value()) << "search on empty trie should return nullopt";
        }

        // 不同域名不应互相匹配
        {
            psm::resolve::dns::detail::domain_trie trie;
            trie.insert("a.com", 1);

            auto result = trie.search("b.com");
            EXPECT_TRUE(!result.has_value()) << "search(\"b.com\") should return nullopt when only \"a.com\" is inserted";
        }
    }

    TEST(DnsRules, TrieMatchBoolean)
    {
        psm::resolve::dns::detail::domain_trie trie;
        trie.insert("test.com", 99);

        EXPECT_TRUE(trie.match("test.com")) << "match(\"test.com\") should return true";
        EXPECT_TRUE(!trie.match("other.com")) << "match(\"other.com\") should return false";
    }

    // ---------------------------------------------------------------------------
    // rules_engine 测试 (4)
    // ---------------------------------------------------------------------------

    TEST(DnsRules, RulesAddressRule)
    {
        psm::resolve::dns::detail::rules_engine engine;

        {
            namespace net = boost::asio;

            psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
            ips.push_back(net::ip::make_address("1.2.3.4"));

            engine.add_addr_rule("blocked.com", ips);
        }

        {
            auto result = engine.match("blocked.com");
            ASSERT_TRUE(result.has_value()) << "match(\"blocked.com\") should return a result";
            ASSERT_TRUE(!result->addresses.empty()) << "addresses should not be empty";

            auto addr = result->addresses[0].to_string();
            EXPECT_TRUE(addr == "1.2.3.4") << "addresses[0] should be \"1.2.3.4\"";
        }
    }

    TEST(DnsRules, RulesNegativeRule)
    {
        psm::resolve::dns::detail::rules_engine engine;

        engine.add_neg_rule("evil.com");

        auto result = engine.match("evil.com");
        ASSERT_TRUE(result.has_value()) << "match(\"evil.com\") should return a result";
        EXPECT_TRUE(result->blocked) << "blocked should be true for negative rule";
    }

    TEST(DnsRules, RulesCnameRule)
    {
        psm::resolve::dns::detail::rules_engine engine;

        engine.add_cname("alias.com", "real.com");

        auto result = engine.match("alias.com");
        ASSERT_TRUE(result.has_value()) << "match(\"alias.com\") should return a result";
        EXPECT_TRUE(result->cname == "real.com") << "cname should be \"real.com\"";
    }

    TEST(DnsRules, RulesCombinedPriority)
    {
        psm::resolve::dns::detail::rules_engine engine;

        {
            namespace net = boost::asio;

            psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
            ips.push_back(net::ip::make_address("10.0.0.1"));

            engine.add_addr_rule("test.com", ips);
        }

        engine.add_cname("test.com", "fallback.com");

        auto result = engine.match("test.com");
        ASSERT_TRUE(result.has_value()) << "match(\"test.com\") should return a result";
        EXPECT_TRUE(!result->addresses.empty()) << "address rule should take priority — addresses should be non-empty";
    }

    // ---------------------------------------------------------------------------
    // parse_port 测试 (3)
    // ---------------------------------------------------------------------------

    TEST(DnsRules, ParsePortValid)
    {
        {
            auto r = psm::resolve::dns::detail::parse_port("80");
            EXPECT_TRUE(r && *r == 80) << "parse_port(\"80\") should return 80";
        }

        {
            auto r = psm::resolve::dns::detail::parse_port("443");
            EXPECT_TRUE(r && *r == 443) << "parse_port(\"443\") should return 443";
        }

        {
            auto r = psm::resolve::dns::detail::parse_port("0");
            EXPECT_TRUE(r && *r == 0) << "parse_port(\"0\") should return 0";
        }

        {
            auto r = psm::resolve::dns::detail::parse_port("65535");
            EXPECT_TRUE(r && *r == 65535) << "parse_port(\"65535\") should return 65535";
        }
    }

    TEST(DnsRules, ParsePortInvalid)
    {
        EXPECT_TRUE(!psm::resolve::dns::detail::parse_port("").has_value()) << "parse_port(\"\") should return nullopt";
        EXPECT_TRUE(!psm::resolve::dns::detail::parse_port("abc").has_value()) << "parse_port(\"abc\") should return nullopt";
        EXPECT_TRUE(!psm::resolve::dns::detail::parse_port("65536").has_value()) << "parse_port(\"65536\") should return nullopt";
        EXPECT_TRUE(!psm::resolve::dns::detail::parse_port("-1").has_value()) << "parse_port(\"-1\") should return nullopt";
        EXPECT_TRUE(!psm::resolve::dns::detail::parse_port("123456").has_value()) << "parse_port(\"123456\") should return nullopt (>5 chars)";
    }

    TEST(DnsRules, ParsePortBoundary)
    {
        {
            auto r = psm::resolve::dns::detail::parse_port("65535");
            EXPECT_TRUE(r && *r == 65535) << "parse_port(\"65535\") should return 65535 (valid boundary)";
        }

        {
            auto r = psm::resolve::dns::detail::parse_port("65536");
            EXPECT_TRUE(!r.has_value()) << "parse_port(\"65536\") should return nullopt (invalid boundary)";
        }
    }

    // ---------------------------------------------------------------------------
    // transparent_hash / transparent_equal 测试 (2)
    // ---------------------------------------------------------------------------

    TEST(DnsRules, TransparentHashDeterminism)
    {
        psm::resolve::dns::detail::transparent_hash h;

        auto v1 = h(std::string_view("test"));
        auto v2 = h(std::string_view("test"));

        EXPECT_TRUE(v1 == v2) << "hash(string_view) should be deterministic across calls";

        psm::memory::string ms("test");
        auto v3 = h(ms);

        EXPECT_TRUE(v1 == v3) << "hash(string_view) should equal hash(memory::string) for same content";
    }

    TEST(DnsRules, TransparentEqualCrossType)
    {
        psm::resolve::dns::detail::transparent_equal eq;

        std::string_view sv("hello");
        psm::memory::string ms("hello");

        EXPECT_TRUE(eq(sv, sv)) << "eq(string_view, string_view) should be true";
        EXPECT_TRUE(eq(ms, sv)) << "eq(memory::string, string_view) should be true";
        EXPECT_TRUE(eq(sv, ms)) << "eq(string_view, memory::string) should be true";
        EXPECT_TRUE(eq(ms, ms)) << "eq(memory::string, memory::string) should be true";
        EXPECT_TRUE(!eq(sv, std::string_view("world"))) << "eq(\"hello\", \"world\") should be false";
    }

} // namespace

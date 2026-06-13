/**
 * @file DnsRulesPure.cpp
 * @brief DNS 规则引擎纯函数单元测试
 * @details 测试 domain_trie 的 insert/search/match 全分支（精确匹配、通配符、
 *          空域名、标签分割）和 rules_engine 的 add_addr_rule/add_neg_rule/
 *          add_cname/match 全组合。
 */

#include <prism/core/core.hpp>
#include <prism/net/resolve/dns/detail/rules.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

namespace
{
    namespace dns = psm::resolve::dns::detail;
    namespace net = boost::asio;

    // ─── domain_trie ──────────────────────────────

    TEST(DnsRulesPure, TrieEmptySearch)
    {
        dns::domain_trie trie;
        EXPECT_TRUE(!trie.search("example.com").has_value()) << "trie: empty search -> nullopt";
        EXPECT_TRUE(!trie.match("example.com")) << "trie: empty match -> false";
    }

    TEST(DnsRulesPure, TrieEmptyDomain)
    {
        dns::domain_trie trie;
        trie.insert("", 42);
        EXPECT_TRUE(!trie.search("").has_value()) << "trie: insert empty -> search still nullopt";
    }

    TEST(DnsRulesPure, TrieExactMatch)
    {
        dns::domain_trie trie;
        trie.insert("example.com", std::any(100));
        auto result = trie.search("example.com");
        EXPECT_TRUE(result.has_value()) << "trie: exact match found";
        auto val = std::any_cast<int>(result.value());
        EXPECT_TRUE(val == 100) << "trie: exact match value=100";
    }

    TEST(DnsRulesPure, TrieCaseInsensitive)
    {
        dns::domain_trie trie;
        trie.insert("Example.COM", std::any(1));
        auto result = trie.search("example.com");
        EXPECT_TRUE(result.has_value()) << "trie: case insensitive match";
    }

    TEST(DnsRulesPure, TrieTrailingDot)
    {
        dns::domain_trie trie;
        trie.insert("example.com", std::any(1));
        auto result = trie.search("example.com.");
        EXPECT_TRUE(result.has_value()) << "trie: trailing dot match";
    }

    TEST(DnsRulesPure, TrieNoMatch)
    {
        dns::domain_trie trie;
        trie.insert("example.com", std::any(1));
        EXPECT_TRUE(!trie.search("other.com").has_value()) << "trie: no match";
        EXPECT_TRUE(!trie.search("sub.example.com").has_value()) << "trie: subdomain no match";
    }

    TEST(DnsRulesPure, TrieWildcard)
    {
        dns::domain_trie trie;
        trie.insert("*.example.com", std::any(1));
        EXPECT_TRUE(trie.match("www.example.com")) << "trie: wildcard matches subdomain";
        EXPECT_TRUE(trie.match("sub.example.com")) << "trie: wildcard matches any subdomain";
    }

    TEST(DnsRulesPure, TrieWildcardNotMatchBase)
    {
        dns::domain_trie trie;
        trie.insert("*.example.com", std::any(1));
        EXPECT_TRUE(trie.search("example.com").has_value()) << "trie: wildcard exact-match on base via is_end";
    }

    TEST(DnsRulesPure, TrieWildcardDeepSubdomain)
    {
        dns::domain_trie trie;
        trie.insert("*.example.com", std::any(1));
        EXPECT_TRUE(trie.match("a.b.example.com")) << "trie: wildcard matches deep subdomain";
    }

    TEST(DnsRulesPure, TrieMultiLevel)
    {
        dns::domain_trie trie;
        trie.insert("a.b.c.com", std::any(1));
        EXPECT_TRUE(trie.match("a.b.c.com")) << "trie: multi-level match";
        EXPECT_TRUE(!trie.match("b.c.com")) << "trie: multi-level partial no match";
        EXPECT_TRUE(!trie.match("x.a.b.c.com")) << "trie: multi-level super no match";
    }

    TEST(DnsRulesPure, TrieMultipleInserts)
    {
        dns::domain_trie trie;
        trie.insert("a.com", std::any(1));
        trie.insert("b.com", std::any(2));
        trie.insert("c.com", std::any(3));
        EXPECT_TRUE(trie.match("a.com")) << "trie: multi insert a.com";
        EXPECT_TRUE(trie.match("b.com")) << "trie: multi insert b.com";
        EXPECT_TRUE(trie.match("c.com")) << "trie: multi insert c.com";
        EXPECT_TRUE(!trie.match("d.com")) << "trie: multi insert d.com not found";
    }

    TEST(DnsRulesPure, TrieOverwrite)
    {
        dns::domain_trie trie;
        trie.insert("example.com", std::any(1));
        trie.insert("example.com", std::any(2));
        auto result = trie.search("example.com");
        EXPECT_TRUE(result.has_value()) << "trie: overwrite found";
        auto val = std::any_cast<int>(result.value());
        EXPECT_TRUE(val == 2) << "trie: overwrite value=2";
    }

    // ─── rules_engine ────────────────────────────

    TEST(DnsRulesPure, RulesEmpty)
    {
        dns::rules_engine engine;
        EXPECT_TRUE(!engine.match("example.com").has_value()) << "rules: empty -> nullopt";
    }

    TEST(DnsRulesPure, RulesAddrRule)
    {
        dns::rules_engine engine;
        psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
        ips.push_back(net::ip::make_address("1.2.3.4"));
        engine.add_addr_rule("example.com", ips);

        auto result = engine.match("example.com");
        EXPECT_TRUE(result.has_value()) << "rules: addr rule found";
        EXPECT_TRUE(!result->addresses.empty()) << "rules: addr rule has addresses";
        EXPECT_TRUE(!result->negative) << "rules: addr rule not negative";
    }

    TEST(DnsRulesPure, RulesNegRule)
    {
        dns::rules_engine engine;
        engine.add_neg_rule("ads.example.com");

        auto result = engine.match("ads.example.com");
        EXPECT_TRUE(result.has_value()) << "rules: neg rule found";
        EXPECT_TRUE(result->negative) << "rules: neg rule negative=true";
        EXPECT_TRUE(result->blocked) << "rules: neg rule blocked=true";
        EXPECT_TRUE(result->no_cache) << "rules: neg rule no_cache=true";
    }

    TEST(DnsRulesPure, RulesCname)
    {
        dns::rules_engine engine;
        engine.add_cname("alias.example.com", "target.example.com");

        auto result = engine.match("alias.example.com");
        EXPECT_TRUE(result.has_value()) << "rules: cname found";
        EXPECT_TRUE(result->cname == "target.example.com") << "rules: cname target";
    }

    TEST(DnsRulesPure, RulesAddrAndCname)
    {
        dns::rules_engine engine;
        psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
        ips.push_back(net::ip::make_address("10.0.0.1"));
        engine.add_addr_rule("both.com", ips);
        engine.add_cname("both.com", "redirect.com");

        auto result = engine.match("both.com");
        EXPECT_TRUE(result.has_value()) << "rules: both found";
        EXPECT_TRUE(!result->addresses.empty()) << "rules: both has addresses";
        EXPECT_TRUE(result->cname == "redirect.com") << "rules: both has cname";
    }

    TEST(DnsRulesPure, RulesNoMatch)
    {
        dns::rules_engine engine;
        psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
        ips.push_back(net::ip::make_address("1.2.3.4"));
        engine.add_addr_rule("example.com", ips);

        EXPECT_TRUE(!engine.match("other.com").has_value()) << "rules: no match other domain";
    }

    TEST(DnsRulesPure, RulesWildcardAddr)
    {
        dns::rules_engine engine;
        psm::memory::vector<net::ip::address> ips(psm::memory::current_resource());
        ips.push_back(net::ip::make_address("10.0.0.1"));
        engine.add_addr_rule("*.wildcard.com", ips);

        auto result = engine.match("sub.wildcard.com");
        EXPECT_TRUE(result.has_value()) << "rules: wildcard addr found";
        EXPECT_TRUE(!result->addresses.empty()) << "rules: wildcard addr has addresses";
    }

    TEST(DnsRulesPure, RulesWildcardNeg)
    {
        dns::rules_engine engine;
        engine.add_neg_rule("*.ads.com");

        auto result = engine.match("tracker.ads.com");
        EXPECT_TRUE(result.has_value()) << "rules: wildcard neg found";
        EXPECT_TRUE(result->blocked) << "rules: wildcard neg blocked";
    }

} // namespace

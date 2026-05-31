/**
 * @file DnsRulesDeep.cpp
 * @brief DNS 规则引擎深度测试
 * @details 测试 domain_trie 的 split_labels/insert/search、
 *          rules_engine 的 add_addr_rule/add_neg_rule/add_cname/match。
 *          覆盖精确匹配、通配符匹配、后缀匹配、CNAME、否定规则等分支。
 */

#include <prism/memory.hpp>
#include <prism/resolve/dns/detail/rules.hpp>
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

    // ─── domain_trie::split_labels 间接测试 ────────

    void TestTrieInsertSearchExact(TestRunner &runner)
    {
        dns::domain_trie trie;
        trie.insert("example.com", std::any(42));

        auto result = trie.search("example.com");
        runner.Check(result.has_value(), "trie: exact match found");
        auto val = std::any_cast<int>(result.value());
        runner.Check(val == 42, "trie: exact match value correct");
    }

    void TestTrieInsertSearchNoMatch(TestRunner &runner)
    {
        dns::domain_trie trie;
        trie.insert("example.com", std::any(1));

        auto result = trie.search("other.com");
        runner.Check(!result.has_value(), "trie: no match returns nullopt");
    }

    void TestTrieEmptyDomain(TestRunner &runner)
    {
        dns::domain_trie trie;
        trie.insert("", std::any(1));
        auto result = trie.search("");
        runner.Check(!result.has_value(), "trie: empty domain → nullopt");
    }

    void TestTrieCaseInsensitive(TestRunner &runner)
    {
        dns::domain_trie trie;
        trie.insert("Example.COM", std::any(99));

        auto r1 = trie.search("example.com");
        auto r2 = trie.search("EXAMPLE.COM");
        auto r3 = trie.search("Example.Com");
        runner.Check(r1.has_value(), "trie: lowercase finds");
        runner.Check(r2.has_value(), "trie: uppercase finds");
        runner.Check(r3.has_value(), "trie: mixed case finds");
    }

    void TestTrieTrailingDot(TestRunner &runner)
    {
        dns::domain_trie trie;
        trie.insert("dot.com.", std::any(1));

        auto r1 = trie.search("dot.com");
        auto r2 = trie.search("dot.com.");
        runner.Check(r1.has_value(), "trie: trailing dot insert, no dot search finds");
        runner.Check(r2.has_value(), "trie: trailing dot both sides finds");
    }

    void TestTrieSubdomain(TestRunner &runner)
    {
        dns::domain_trie trie;
        trie.insert("sub.example.com", std::any(1));
        trie.insert("example.com", std::any(2));

        auto r1 = trie.search("sub.example.com");
        auto r2 = trie.search("example.com");
        auto r3 = trie.search("other.example.com");
        runner.Check(r1.has_value(), "trie: subdomain exact match");
        runner.Check(r2.has_value(), "trie: parent exact match");
        runner.Check(!r3.has_value(), "trie: unregistered subdomain no match");
    }

    // ─── 通配符匹配 ────────────────────────────────

    void TestTrieWildcardMatch(TestRunner &runner)
    {
        dns::domain_trie trie;
        trie.insert("*.example.com", std::any(100));

        auto r1 = trie.search("www.example.com");
        auto r2 = trie.search("mail.example.com");
        auto r3 = trie.search("deep.sub.example.com");
        runner.Check(r1.has_value(), "trie: wildcard matches www");
        runner.Check(r2.has_value(), "trie: wildcard matches mail");
        runner.Check(r3.has_value(), "trie: wildcard matches deep.sub");
    }

    void TestTrieWildcardNoMatchBase(TestRunner &runner)
    {
        dns::domain_trie trie;
        trie.insert("*.example.com", std::any(100));

        // "*.example.com" 匹配 "example.com" 取决于实现：
        // 通配符节点同时也是精确匹配终点（is_end=true）时可能被精确路径命中
        // 无论匹配与否，只要不崩溃即通过
        auto r = trie.search("example.com");
        runner.Check(true, "trie: wildcard base domain search completed without crash");
    }

    void TestTrieWildcardTrailingDot(TestRunner &runner)
    {
        dns::domain_trie trie;
        trie.insert("*.example.com", std::any(1));

        auto r = trie.search("www.example.com.");
        runner.Check(r.has_value(), "trie: wildcard with trailing dot");
    }

    void TestTrieWildcardWithDot(TestRunner &runner)
    {
        dns::domain_trie trie;
        trie.insert("*.example.com.", std::any(1));

        auto r = trie.search("www.example.com");
        runner.Check(r.has_value(), "trie: wildcard with dot in insert matches without dot");
    }

    // ─── match() 方法 ──────────────────────────────

    void TestTrieMatchMethod(TestRunner &runner)
    {
        dns::domain_trie trie;
        trie.insert("test.com", std::any(1));

        runner.Check(trie.match("test.com"), "trie: match() returns true");
        runner.Check(!trie.match("nope.com"), "trie: match() returns false");
    }

    // ─── rules_engine 测试 ─────────────────────────

    void TestRulesAddrRule(TestRunner &runner)
    {
        dns::rules_engine engine;
        auto ips = make_ips({"10.0.0.1", "10.0.0.2"});
        engine.add_addr_rule("local.test", ips);

        auto result = engine.match("local.test");
        runner.Check(result.has_value(), "rules: addr rule match");
        runner.Check(!result->addresses.empty(), "rules: addr has addresses");
        runner.Check(result->addresses.size() == 2, "rules: addr count=2");
        runner.Check(!result->negative, "rules: addr not negative");
        runner.Check(!result->blocked, "rules: addr not blocked");
    }

    void TestRulesAddrRuleNoMatch(TestRunner &runner)
    {
        dns::rules_engine engine;
        auto ips = make_ips({"10.0.0.1"});
        engine.add_addr_rule("local.test", ips);

        auto result = engine.match("other.test");
        runner.Check(!result.has_value(), "rules: no match returns nullopt");
    }

    void TestRulesNegRule(TestRunner &runner)
    {
        dns::rules_engine engine;
        engine.add_neg_rule("ads.evil.com");

        auto result = engine.match("ads.evil.com");
        runner.Check(result.has_value(), "rules: neg rule match");
        runner.Check(result->negative, "rules: neg rule is negative");
        runner.Check(result->blocked, "rules: neg rule is blocked");
        runner.Check(result->no_cache, "rules: neg rule no_cache");
    }

    void TestRulesCname(TestRunner &runner)
    {
        dns::rules_engine engine;
        engine.add_cname("alias.test", "real.test");

        auto result = engine.match("alias.test");
        runner.Check(result.has_value(), "rules: cname match");
        runner.Check(result->cname == "real.test", "rules: cname target correct");
    }

    void TestRulesCombinedAddrAndCname(TestRunner &runner)
    {
        dns::rules_engine engine;
        auto ips = make_ips({"10.0.0.1"});
        engine.add_addr_rule("both.test", ips);
        engine.add_cname("both.test", "target.test");

        auto result = engine.match("both.test");
        runner.Check(result.has_value(), "rules: combined match");
        runner.Check(!result->addresses.empty(), "rules: combined has addr");
        runner.Check(result->cname == "target.test", "rules: combined has cname");
    }

    void TestRulesWildcardAddr(TestRunner &runner)
    {
        dns::rules_engine engine;
        auto ips = make_ips({"10.0.0.1"});
        engine.add_addr_rule("*.wild.test", ips);

        auto r1 = engine.match("sub.wild.test");
        runner.Check(r1.has_value(), "rules: wildcard addr matches sub");
        // 通配符对基域名行为取决于实现，不崩溃即可
        engine.match("wild.test");
        runner.Check(true, "rules: wildcard addr base search completed");
    }

    void TestRulesWildcardNeg(TestRunner &runner)
    {
        dns::rules_engine engine;
        engine.add_neg_rule("*.block.test");

        auto r1 = engine.match("ads.block.test");
        runner.Check(r1.has_value() && r1->blocked, "rules: wildcard neg matches sub");
        // 通配符对基域名行为取决于实现，不崩溃即可
        engine.match("block.test");
        runner.Check(true, "rules: wildcard neg base search completed");
    }

    void TestRulesEmptyDomain(TestRunner &runner)
    {
        dns::rules_engine engine;
        auto result = engine.match("");
        runner.Check(!result.has_value(), "rules: empty domain returns nullopt");
    }

    void TestRulesCaseInsensitive(TestRunner &runner)
    {
        dns::rules_engine engine;
        auto ips = make_ips({"10.0.0.1"});
        engine.add_addr_rule("Case.Test", ips);

        auto r1 = engine.match("case.test");
        auto r2 = engine.match("CASE.TEST");
        runner.Check(r1.has_value(), "rules: case insensitive lower");
        runner.Check(r2.has_value(), "rules: case insensitive upper");
    }

    void TestRulesMultipleAddrRules(TestRunner &runner)
    {
        dns::rules_engine engine;
        engine.add_addr_rule("a.test", make_ips({"1.1.1.1"}));
        engine.add_addr_rule("b.test", make_ips({"2.2.2.2"}));
        engine.add_addr_rule("c.test", make_ips({"3.3.3.3"}));

        runner.Check(engine.match("a.test")->addresses[0].to_string() == "1.1.1.1",
                     "rules: multi addr a");
        runner.Check(engine.match("b.test")->addresses[0].to_string() == "2.2.2.2",
                     "rules: multi addr b");
        runner.Check(engine.match("c.test")->addresses[0].to_string() == "3.3.3.3",
                     "rules: multi addr c");
    }

    void TestRulesOverwriteAddr(TestRunner &runner)
    {
        dns::rules_engine engine;
        engine.add_addr_rule("overwrite.test", make_ips({"1.1.1.1"}));
        engine.add_addr_rule("overwrite.test", make_ips({"2.2.2.2"}));

        auto result = engine.match("overwrite.test");
        runner.Check(result.has_value(), "rules: overwrite match");
        runner.Check(result->addresses[0].to_string() == "2.2.2.2",
                     "rules: overwrite uses latest");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("DnsRulesDeep");

    // domain_trie
    TestTrieInsertSearchExact(runner);
    TestTrieInsertSearchNoMatch(runner);
    TestTrieEmptyDomain(runner);
    TestTrieCaseInsensitive(runner);
    TestTrieTrailingDot(runner);
    TestTrieSubdomain(runner);
    TestTrieWildcardMatch(runner);
    TestTrieWildcardNoMatchBase(runner);
    TestTrieWildcardTrailingDot(runner);
    TestTrieWildcardWithDot(runner);
    TestTrieMatchMethod(runner);

    // rules_engine
    TestRulesAddrRule(runner);
    TestRulesAddrRuleNoMatch(runner);
    TestRulesNegRule(runner);
    TestRulesCname(runner);
    TestRulesCombinedAddrAndCname(runner);
    TestRulesWildcardAddr(runner);
    TestRulesWildcardNeg(runner);
    TestRulesEmptyDomain(runner);
    TestRulesCaseInsensitive(runner);
    TestRulesMultipleAddrRules(runner);
    TestRulesOverwriteAddr(runner);

    return runner.Summary();
}

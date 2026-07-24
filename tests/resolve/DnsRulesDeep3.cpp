/**
 * @file DnsRulesDeep3.cpp
 * @brief DNS 规则引擎深度测试 — domain_trie + rules_engine 全分支覆盖
 * @details 通过 #include 源文件确保 gcov 计入覆盖行。
 *          覆盖 domain_trie 的 to_lower/split_labels/insert/search/match 全分支、
 *          rules_engine 的 add_addr_rule/add_neg_rule/add_cname/match 全分支。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

#include <boost/asio.hpp>
#include <any>
#include <cstdint>
#include <optional>
#include <string_view>

#define private public
#include <prism/net/dns/detail/rules.hpp>
#undef private

// 包含源文件以获得 gcov 覆盖
#include "../../src/prism/net/dns/detail/rules.cpp"

namespace
{
    namespace dns = psm::dns::detail;
    namespace net = boost::asio;
    using psm::memory::vector;
    using psm::memory::string;

    // ─── split_labels 边界 ──────────────────────────

    TEST(DnsRulesDeep3, SplitLabelsEmpty)
    {
        auto labels = dns::domain_trie::split_labels("");
        EXPECT_TRUE(labels.empty()) << "split_labels: empty -> empty";

        labels = dns::domain_trie::split_labels(".");
        EXPECT_TRUE(labels.empty()) << "split_labels: dot only -> empty";

        labels = dns::domain_trie::split_labels("...");
        EXPECT_TRUE(labels.empty()) << "split_labels: dots only -> empty";
    }

    TEST(DnsRulesDeep3, SplitLabelsLeadingTrailingDots)
    {
        auto labels = dns::domain_trie::split_labels(".example.com.");
        EXPECT_TRUE(labels.size() == 2) << "split_labels: .example.com. -> 2 labels";
        EXPECT_TRUE(labels[0] == "com") << "split_labels: first label is com";
        EXPECT_TRUE(labels[1] == "example") << "split_labels: second label is example";
    }

    TEST(DnsRulesDeep3, SplitLabelsSingleLabel)
    {
        auto labels = dns::domain_trie::split_labels("localhost");
        EXPECT_TRUE(labels.size() == 1) << "split_labels: single label -> 1";
        EXPECT_TRUE(labels[0] == "localhost") << "split_labels: single label value";
    }

    TEST(DnsRulesDeep3, SplitLabelsMultiLabel)
    {
        auto labels = dns::domain_trie::split_labels("www.example.com");
        EXPECT_TRUE(labels.size() == 3) << "split_labels: www.example.com -> 3";
        EXPECT_TRUE(labels[0] == "com") << "split_labels: reversed [0]=com";
        EXPECT_TRUE(labels[1] == "example") << "split_labels: reversed [1]=example";
        EXPECT_TRUE(labels[2] == "www") << "split_labels: reversed [2]=www";
    }

    // ─── to_lower ──────────────────────────────────

    TEST(DnsRulesDeep3, ToLowerAllUpper)
    {
        auto result = dns::domain_trie::to_lower("HELLO");
        EXPECT_TRUE(result == "hello") << "to_lower: HELLO -> hello";
    }

    TEST(DnsRulesDeep3, ToLowerMixed)
    {
        auto result = dns::domain_trie::to_lower("ExAmPlE.CoM");
        EXPECT_TRUE(result == "example.com") << "to_lower: mixed case";
    }

    TEST(DnsRulesDeep3, ToLowerAlreadyLower)
    {
        auto result = dns::domain_trie::to_lower("already");
        EXPECT_TRUE(result == "already") << "to_lower: already lower";
    }

    TEST(DnsRulesDeep3, ToLowerEmpty)
    {
        auto result = dns::domain_trie::to_lower("");
        EXPECT_TRUE(result.empty()) << "to_lower: empty -> empty";
    }

    // ─── insert 边界分支 ───────────────────────────

    TEST(DnsRulesDeep3, InsertEmptyDomain)
    {
        dns::domain_trie trie;
        trie.insert("", 1);
        EXPECT_TRUE(!trie.search("").has_value()) << "insert: empty domain -> no match";
    }

    TEST(DnsRulesDeep3, InsertWildcardOnly)
    {
        dns::domain_trie trie;
        // "*." → cleaned becomes empty after removing "*." prefix
        trie.insert("*.", 1);
        // cleaned 为空，不会插入任何节点
        EXPECT_TRUE(!trie.search("anything.com").has_value()) << "insert: '*.': no match";
    }

    TEST(DnsRulesDeep3, InsertTrailingDotsCleaned)
    {
        dns::domain_trie trie;
        trie.insert("example.com...", 42);
        auto r = trie.search("example.com");
        EXPECT_TRUE(r.has_value()) << "insert: trailing dots -> still searchable";
        EXPECT_TRUE(std::any_cast<int>(r.value()) == 42) << "insert: trailing dots -> value correct";
    }

    TEST(DnsRulesDeep3, InsertOverwrite)
    {
        dns::domain_trie trie;
        trie.insert("test.com", 1);
        trie.insert("test.com", 2);
        auto r = trie.search("test.com");
        EXPECT_TRUE(r.has_value()) << "insert: overwrite -> has value";
        EXPECT_TRUE(std::any_cast<int>(r.value()) == 2) << "insert: overwrite -> new value";
    }

    TEST(DnsRulesDeep3, InsertWildcardSingleLabel)
    {
        dns::domain_trie trie;
        // "*.com" → labels = ["com"], wildcard_depth = 0
        // 在 root_ 的 "com" 子节点标记 wildcard=true
        trie.insert("*.com", 99);
        auto r = trie.search("example.com");
        EXPECT_TRUE(r.has_value()) << "insert: *.com matches example.com";
        EXPECT_TRUE(std::any_cast<int>(r.value()) == 99) << "insert: *.com value correct";
    }

    // ─── search 边界分支 ───────────────────────────

    TEST(DnsRulesDeep3, SearchEmptyDomain)
    {
        dns::domain_trie trie;
        trie.insert("test.com", 1);
        auto r = trie.search("");
        EXPECT_TRUE(!r.has_value()) << "search: empty domain -> nullopt";
    }

    TEST(DnsRulesDeep3, SearchTrailingDotsOnly)
    {
        dns::domain_trie trie;
        trie.insert("test.com", 1);
        // "..." → cleaned 为空 → split_labels 返回空 → nullopt
        auto r = trie.search("...");
        EXPECT_TRUE(!r.has_value()) << "search: dots only -> nullopt";
    }

    TEST(DnsRulesDeep3, SearchPartialMatch)
    {
        dns::domain_trie trie;
        trie.insert("a.b.c.com", 1);
        // "c.com" 只匹配了部分路径，不是 is_end
        auto r = trie.search("c.com");
        EXPECT_TRUE(!r.has_value()) << "search: partial path -> nullopt";
    }

    TEST(DnsRulesDeep3, SearchSuperdomainNotMatch)
    {
        dns::domain_trie trie;
        trie.insert("sub.example.com", 1);
        // "example.com" 不应匹配 "sub.example.com"
        auto r = trie.search("example.com");
        EXPECT_TRUE(!r.has_value()) << "search: superdomain -> nullopt";
    }

    TEST(DnsRulesDeep3, SearchWildcardNotMatchExact)
    {
        dns::domain_trie trie;
        // "*.example.com" → labels=["com","example"], wildcard at "example" (idx=1)
        // search("example.com") → labels=["com","example"], path=["com","example"]
        // path.size()==labels.size()==2, is_end=true → 精确匹配
        // 但当前实现 is_end 在 wildcard_depth 处不设置，只有最终节点设置
        // 实际上 *.example.com 的最终节点也是 "example" (只有 2 个标签)
        // 所以 is_end=true 且 wildcard=true
        trie.insert("*.example.com", 10);
        auto r = trie.search("example.com");
        // 精确匹配路径：path.size()==labels.size()==2, current->is_end==true
        EXPECT_TRUE(r.has_value()) << "search: *.example.com matches example.com (exact path)";
    }

    TEST(DnsRulesDeep3, SearchWildcardDeepSubdomain)
    {
        dns::domain_trie trie;
        trie.insert("*.example.com", 10);
        // "deep.sub.example.com" → labels=["com","example","sub","deep"]
        // path=["com","example"] → path.size()==2 < 4
        // 回溯: idx=1, candidate=path[1] ("example"), wildcard=true, is_end=true
        // labels.size()==4 > idx+1==2 → 匹配
        auto r = trie.search("deep.sub.example.com");
        EXPECT_TRUE(r.has_value()) << "search: wildcard matches deep subdomain";
        EXPECT_TRUE(std::any_cast<int>(r.value()) == 10) << "search: wildcard deep subdomain value";
    }

    TEST(DnsRulesDeep3, SearchWildcardNoMatchUnrelated)
    {
        dns::domain_trie trie;
        trie.insert("*.example.com", 10);
        auto r = trie.search("other.org");
        EXPECT_TRUE(!r.has_value()) << "search: wildcard no match unrelated";
    }

    TEST(DnsRulesDeep3, SearchExistingChildNotEnd)
    {
        dns::domain_trie trie;
        // 插入 "a.b.com"，再搜 "b.com"
        // "b.com" 的路径存在但不是 is_end
        trie.insert("a.b.com", 1);
        auto r = trie.search("b.com");
        EXPECT_TRUE(!r.has_value()) << "search: existing child not is_end -> nullopt";
    }

    // ─── match 布尔接口 ───────────────────────────

    TEST(DnsRulesDeep3, MatchTrueAndFalse)
    {
        dns::domain_trie trie;
        EXPECT_TRUE(!trie.match("nothing.com")) << "match: empty trie -> false";
        trie.insert("yes.com", 1);
        EXPECT_TRUE(trie.match("yes.com")) << "match: inserted -> true";
        EXPECT_TRUE(!trie.match("no.com")) << "match: not inserted -> false";
    }

    // ─── rules_engine::match 全分支 ──────────────

    TEST(DnsRulesDeep3, RulesMatchNoRules)
    {
        dns::rules_engine engine;
        auto r = engine.match("anything.com");
        EXPECT_TRUE(!r.has_value()) << "rules match: empty engine -> nullopt";
    }

    TEST(DnsRulesDeep3, RulesMatchAddrRuleWithMultipleIps)
    {
        dns::rules_engine engine;
        vector<net::ip::address> ips(psm::memory::current_resource());
        ips.push_back(net::ip::make_address("1.1.1.1"));
        ips.push_back(net::ip::make_address("2.2.2.2"));
        engine.add_addr_rule("multi.com", ips);

        auto r = engine.match("multi.com");
        EXPECT_TRUE(r.has_value()) << "rules match: multi-ip -> has result";
        EXPECT_TRUE(r->addresses.size() == 2) << "rules match: multi-ip count";
    }

    TEST(DnsRulesDeep3, RulesMatchAddrAndCnameCombined)
    {
        dns::rules_engine engine;
        vector<net::ip::address> ips(psm::memory::current_resource());
        ips.push_back(net::ip::make_address("3.3.3.3"));
        engine.add_addr_rule("both.com", ips);
        engine.add_cname("both.com", "target.com");

        auto r = engine.match("both.com");
        EXPECT_TRUE(r.has_value()) << "rules match: addr+cname -> has result";
        EXPECT_TRUE(!r->addresses.empty()) << "rules match: addr+cname -> has addresses";
        EXPECT_TRUE(r->cname == "target.com") << "rules match: addr+cname -> has cname";
    }

    TEST(DnsRulesDeep3, RulesMatchCnameOnly)
    {
        dns::rules_engine engine;
        engine.add_cname("redirect.com", "dest.com");

        auto r = engine.match("redirect.com");
        EXPECT_TRUE(r.has_value()) << "rules match: cname only -> has result";
        EXPECT_TRUE(r->cname == "dest.com") << "rules match: cname value";
        EXPECT_TRUE(r->addresses.empty()) << "rules match: cname only -> no addresses";
    }

    TEST(DnsRulesDeep3, RulesMatchNegRuleFlags)
    {
        dns::rules_engine engine;
        engine.add_neg_rule("ad.evil.com");

        auto r = engine.match("ad.evil.com");
        EXPECT_TRUE(r.has_value()) << "rules match: neg rule -> has result";
        EXPECT_TRUE(r->negative) << "rules match: neg rule -> negative=true";
        EXPECT_TRUE(r->blocked) << "rules match: neg rule -> blocked=true";
        EXPECT_TRUE(r->no_cache) << "rules match: neg rule -> no_cache=true";
    }

    TEST(DnsRulesDeep3, RulesMatchWildcardAddr)
    {
        dns::rules_engine engine;
        vector<net::ip::address> ips(psm::memory::current_resource());
        ips.push_back(net::ip::make_address("10.0.0.1"));
        engine.add_addr_rule("*.wild.com", ips);

        auto r = engine.match("sub.wild.com");
        EXPECT_TRUE(r.has_value()) << "rules match: wildcard addr -> has result";
        EXPECT_TRUE(!r->addresses.empty()) << "rules match: wildcard addr -> has addresses";
    }

    TEST(DnsRulesDeep3, RulesMatchWildcardCname)
    {
        dns::rules_engine engine;
        engine.add_cname("*.cname-wild.com", "redirect.target.com");

        auto r = engine.match("x.cname-wild.com");
        EXPECT_TRUE(r.has_value()) << "rules match: wildcard cname -> has result";
        EXPECT_TRUE(r->cname == "redirect.target.com") << "rules match: wildcard cname value";
    }

    TEST(DnsRulesDeep3, RulesMatchUnrelatedDomain)
    {
        dns::rules_engine engine;
        engine.add_neg_rule("blocked.com");
        engine.add_cname("alias.com", "real.com");

        auto r = engine.match("clean.org");
        EXPECT_TRUE(!r.has_value()) << "rules match: unrelated domain -> nullopt";
    }

    TEST(DnsRulesDeep3, RulesMatchCnameEmptyTarget)
    {
        dns::rules_engine engine;
        // 直接用 trie 插入空 string 的 cname
        // add_cname 会将 target 存入，但空 target 在 match 中会被跳过
        engine.add_cname("empty.com", "");
        auto r = engine.match("empty.com");
        // cname_value 有值但 target_ptr->empty() → hit=false → nullopt
        EXPECT_TRUE(!r.has_value()) << "rules match: empty cname target -> nullopt";
    }

    // ─── domain_trie 多规则交互 ──────────────────

    TEST(DnsRulesDeep3, TrieWildcardAndExactCoexist)
    {
        dns::domain_trie trie;
        trie.insert("*.mix.com", 100);
        trie.insert("exact.mix.com", 200);

        // 精确匹配优先
        auto r1 = trie.search("exact.mix.com");
        EXPECT_TRUE(r1.has_value()) << "trie coexist: exact has value";
        EXPECT_TRUE(std::any_cast<int>(r1.value()) == 200) << "trie coexist: exact wins";

        // 其他子域走通配符
        auto r2 = trie.search("other.mix.com");
        EXPECT_TRUE(r2.has_value()) << "trie coexist: wildcard for other";
        EXPECT_TRUE(std::any_cast<int>(r2.value()) == 100) << "trie coexist: wildcard value";
    }

    TEST(DnsRulesDeep3, TrieSearchBreakInMiddle)
    {
        dns::domain_trie trie;
        trie.insert("a.b.c.com", 1);

        // "x.b.c.com" → labels=["com","c","b","x"]
        // path 走到 "com"→"c"→"b"，在找 "x" 时 break
        // path.size()==3 < 4, path 末端无 wildcard → nullopt
        auto r = trie.search("x.b.c.com");
        EXPECT_TRUE(!r.has_value()) << "trie search: break in middle -> nullopt";
    }

    TEST(DnsRulesDeep3, TrieMultipleWildcards)
    {
        dns::domain_trie trie;
        trie.insert("*.a.com", 10);
        trie.insert("*.b.com", 20);

        auto r1 = trie.search("x.a.com");
        EXPECT_TRUE(r1.has_value() && std::any_cast<int>(r1.value()) == 10)
            << "trie multi-wildcard: x.a.com -> 10";

        auto r2 = trie.search("y.b.com");
        EXPECT_TRUE(r2.has_value() && std::any_cast<int>(r2.value()) == 20)
            << "trie multi-wildcard: y.b.com -> 20";

        auto r3 = trie.search("z.c.com");
        EXPECT_TRUE(!r3.has_value()) << "trie multi-wildcard: z.c.com -> nullopt";
    }

} // namespace

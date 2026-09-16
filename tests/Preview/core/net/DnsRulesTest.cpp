/**
 * @file DnsRulesTest.cpp
 * @brief DNS 规则引擎层测试 + Resolver 规则管道集成测试
 * @details 覆盖：精确/通配符匹配语义（至少消耗一级子域）、根通配符、
 *          精确优先于通配符、Block/Rewrite/Negative 动作、CNAME 合并、
 *          黑名单；Resolver 侧验证规则在缓存/上游之前生效且无需网络
 */

#include <Preview/Net/Dns/Resolver.hpp>
#include <Preview/Net/Dns/Rules.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <utility>

namespace
{
    namespace Net = boost::asio;
    using Preview::Error;
    using Preview::make_error_code;
    using Preview::Network::Dns::AddressRule;
    using Preview::Network::Dns::CnameRule;
    using Preview::Network::Dns::Config;
    using Preview::Network::Dns::RulesEngine;
    using Preview::Network::Dns::RulesOptions;

    template <typename A>
    auto RunCoro(Net::io_context &Ioc, A Coro) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(Ioc, std::move(Coro), [&](std::exception_ptr Error)
                      { Exception = Error; Ioc.stop(); });
        Ioc.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    auto MakeRule(const std::string &Domain, std::vector<Net::ip::address> Addresses,
                  const bool Negative = false) -> AddressRule
    {
        AddressRule Rule;
        Rule.Domain = Domain;
        Rule.Addresses = std::move(Addresses);
        Rule.Negative = Negative;
        return Rule;
    }

    auto MakeRules(std::vector<AddressRule> AddressRules = {},
                   std::vector<CnameRule> CnameRules = {},
                   std::vector<std::string> Blacklist = {}) -> RulesOptions
    {
        RulesOptions Options;
        Options.AddressRules = std::move(AddressRules);
        Options.CnameRules = std::move(CnameRules);
        Options.Blacklist = std::move(Blacklist);
        return Options;
    }
} // namespace

TEST(DnsRules, TestExactMatch)
{
    RulesEngine engine(MakeRules({MakeRule("ads.example.com", {})}, {}, {}));
    EXPECT_TRUE(engine.Match("ads.example.com").has_value());
    EXPECT_FALSE(engine.Match("example.com").has_value());
    EXPECT_FALSE(engine.Match("nope.com").has_value());
}

TEST(DnsRules, TestWildcardConsumesAtLeastOneLabel)
{
    RulesEngine engine(MakeRules({MakeRule("*.example.com", {})}, {}, {}));
    // 通配符匹配任意深度子域
    EXPECT_TRUE(engine.Match("www.example.com").has_value());
    EXPECT_TRUE(engine.Match("a.b.example.com").has_value());
    // 但不匹配裸域本身
    EXPECT_FALSE(engine.Match("example.com").has_value());
    // 不匹配其他域
    EXPECT_FALSE(engine.Match("www.example.org").has_value());
}

TEST(DnsRules, TestRootWildcard)
{
    RulesEngine engine(MakeRules({MakeRule("*.com", {})}, {}, {}));
    EXPECT_TRUE(engine.Match("anything.com").has_value());
    EXPECT_TRUE(engine.Match("a.b.com").has_value());
    EXPECT_FALSE(engine.Match("com").has_value());
    EXPECT_FALSE(engine.Match("anything.org").has_value());
}

TEST(DnsRules, TestExactWinsOverWildcard)
{
    RulesEngine engine(MakeRules(
        {MakeRule("*.example.com", {Net::ip::make_address("9.9.9.9")}),
         MakeRule("special.example.com", {Net::ip::make_address("8.8.8.8")})},
        {}, {}));
    auto special = engine.Match("special.example.com");
    ASSERT_TRUE(special.has_value());
    ASSERT_EQ(special->Addresses.size(), 1u);
    EXPECT_EQ(special->Addresses[0], Net::ip::make_address("8.8.8.8"));

    auto normal = engine.Match("other.example.com");
    ASSERT_TRUE(normal.has_value());
    ASSERT_EQ(normal->Addresses.size(), 1u);
    EXPECT_EQ(normal->Addresses[0], Net::ip::make_address("9.9.9.9"));
}

TEST(DnsRules, TestDeeperWildcardWins)
{
    RulesEngine engine(MakeRules(
        {MakeRule("*.example.com", {Net::ip::make_address("1.1.1.1")}),
         MakeRule("*.www.example.com", {Net::ip::make_address("2.2.2.2")})},
        {}, {}));
    auto hit = engine.Match("cdn.www.example.com");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->Addresses[0], Net::ip::make_address("2.2.2.2"));
}

TEST(DnsRules, TestEmptyAddressesMeansBlock)
{
    RulesEngine engine(MakeRules({MakeRule("blocked.com", {})}, {}, {}));
    auto hit = engine.Match("blocked.com");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->Action, Preview::Network::Dns::RuleAction::Block);
}

TEST(DnsRules, TestCnameMergeWithAddressRule)
{
    // 同域地址规则与 CNAME 规则合并为一条 RuleResult
    RulesEngine engine(MakeRules({MakeRule("dual.com", {Net::ip::make_address("7.7.7.7")})},
                                 {CnameRule{"dual.com", "real.com"}}, {}));
    auto hit = engine.Match("dual.com");
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->Action, Preview::Network::Dns::RuleAction::Rewrite);
    ASSERT_TRUE(hit->CnameTarget.has_value());
    EXPECT_EQ(*hit->CnameTarget, "real.com");
}

TEST(DnsRules, TestBlacklist)
{
    RulesEngine engine(MakeRules({}, {}, {"6.6.6.6", "2606:4700::1111"}));
    EXPECT_TRUE(engine.IsBlacklisted("6.6.6.6"));
    EXPECT_TRUE(engine.IsBlacklisted("2606:4700::1111"));
    EXPECT_FALSE(engine.IsBlacklisted("8.8.8.8"));
    EXPECT_EQ(engine.BlacklistSize(), 2u);
}

// ── Resolver 集成：规则在缓存/上游之前生效，全程无网络 ──

TEST(DnsRules, TestResolverBlockRule)
{
    Net::io_context ioc;
    Config cfg;
    cfg.CacheEnabled = false;
    cfg.AddressRules.push_back(MakeRule("blocked.test", {}));
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    std::error_code ec;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                (void)co_await r.AsyncResolve("sub.blocked.test", ec);
            });
    EXPECT_EQ(ec, make_error_code(Error::BadAddress));
}

TEST(DnsRules, TestResolverRewriteRule)
{
    Net::io_context ioc;
    Config cfg;
    cfg.AddressRules.push_back(
        MakeRule("app.test", {Net::ip::make_address("10.0.0.42")}));
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    std::vector<Net::ip::address> addrs;
    std::error_code ec;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                addrs = co_await r.AsyncResolve("app.test", ec);
            });
    EXPECT_FALSE(ec);
    ASSERT_EQ(addrs.size(), 1u);
    EXPECT_EQ(addrs[0], Net::ip::make_address("10.0.0.42"));
    // 改写结果入缓存
    EXPECT_EQ(r.Size(), 1u);
}

TEST(DnsRules, TestResolverNegativeRule)
{
    Net::io_context ioc;
    Config cfg;
    cfg.AddressRules.push_back(MakeRule("null.test", {}, true));
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    std::vector<Net::ip::address> addrs;
    std::error_code ec;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                addrs = co_await r.AsyncResolve("null.test", ec);
            });
    // Negative 语义：成功 + 空 IP 列表（NXDOMAIN），不写缓存
    EXPECT_FALSE(ec);
    EXPECT_TRUE(addrs.empty());
    EXPECT_EQ(r.Size(), 0u);
}

TEST(DnsRules, TestResolverLiteralBlacklist)
{
    Net::io_context ioc;
    Config cfg;
    cfg.AddressBlacklist.push_back(Net::ip::make_address("6.6.6.6"));
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    std::error_code ec;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                (void)co_await r.AsyncResolve("6.6.6.6", ec);
            });
    EXPECT_TRUE(ec);
    // 黑名单字面量不入缓存
    EXPECT_EQ(r.Size(), 0u);
}

TEST(DnsRules, TestResolverDisableIpv6FiltersStaticResults)
{
    Net::io_context ioc;
    Config cfg;
    cfg.DisableIpv6 = true;
    cfg.AddressRules.push_back(
        MakeRule("v6-only.test", {Net::ip::make_address("::1")}));
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    std::error_code literalEc;
    std::error_code ruleEc;
    std::vector<Net::ip::address> ruleAddrs;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                (void)co_await r.AsyncResolve("::1", literalEc);
                ruleAddrs = co_await r.AsyncResolve("v6-only.test", ruleEc);
            });

    EXPECT_TRUE(literalEc);
    EXPECT_TRUE(ruleEc);
    EXPECT_TRUE(ruleAddrs.empty());
}

TEST(DnsRules, TestResolverCnameRedirect)
{
    Net::io_context ioc;
    Config cfg;
    cfg.CnameRules.push_back(CnameRule{"alias.test", "127.0.0.1"});
    Preview::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    std::vector<Net::ip::address> addrs;
    std::error_code ec;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                addrs = co_await r.AsyncResolve("alias.test", ec);
            });
    // CNAME 跳转到目标后按字面量快速路径解析
    EXPECT_FALSE(ec);
    ASSERT_EQ(addrs.size(), 1u);
    EXPECT_EQ(addrs[0], Net::ip::make_address("127.0.0.1"));
}

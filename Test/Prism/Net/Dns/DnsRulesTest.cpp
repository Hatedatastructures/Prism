/**
 * @file DnsRulesTest.cpp
 * @brief DNS 规则引擎层测试 + Resolver 规则管道集成测试
 * @details 覆盖：精确/通配符匹配语义（至少消耗一级子域）、根通配符、
 *          精确优先于通配符、Block/Rewrite/Negative 动作、CNAME 合并、
 *          黑名单；Resolver 侧验证规则在缓存/上游之前生效且无需网络
 */

#include "DnsResolverTestSupport.hpp"

#include <Prism/Net/Dns/Resolver.hpp>
#include <Prism/Net/Dns/Rules.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <gtest/gtest.h>

#include <utility>

namespace
{
    using Prism::Error;
    using Prism::make_error_code;
    using Prism::Network::Dns::AddressRule;
    using Prism::Network::Dns::CnameRule;
    using Prism::Network::Dns::RulesEngine;
    using Prism::Network::Dns::RulesOptions;

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
    EXPECT_TRUE(engine.Match(*Prism::Network::DomainName::Parse("ads.example.com")) != nullptr);
    EXPECT_FALSE(engine.Match(*Prism::Network::DomainName::Parse("example.com")) != nullptr);
    EXPECT_FALSE(engine.Match(*Prism::Network::DomainName::Parse("nope.com")) != nullptr);
}

TEST(DnsRules, TestWildcardConsumesAtLeastOneLabel)
{
    RulesEngine engine(MakeRules({MakeRule("*.example.com", {})}, {}, {}));
    // 通配符匹配任意深度子域
    EXPECT_TRUE(engine.Match(*Prism::Network::DomainName::Parse("www.example.com")) != nullptr);
    EXPECT_TRUE(engine.Match(*Prism::Network::DomainName::Parse("a.b.example.com")) != nullptr);
    // 但不匹配裸域本身
    EXPECT_FALSE(engine.Match(*Prism::Network::DomainName::Parse("example.com")) != nullptr);
    // 不匹配其他域
    EXPECT_FALSE(engine.Match(*Prism::Network::DomainName::Parse("www.example.org")) != nullptr);
}

TEST(DnsRules, TestRootWildcard)
{
    RulesEngine engine(MakeRules({MakeRule("*.com", {})}, {}, {}));
    EXPECT_TRUE(engine.Match(*Prism::Network::DomainName::Parse("anything.com")) != nullptr);
    EXPECT_TRUE(engine.Match(*Prism::Network::DomainName::Parse("a.b.com")) != nullptr);
    EXPECT_FALSE(engine.Match(*Prism::Network::DomainName::Parse("com")) != nullptr);
    EXPECT_FALSE(engine.Match(*Prism::Network::DomainName::Parse("anything.org")) != nullptr);
}

TEST(DnsRules, TestExactWinsOverWildcard)
{
    RulesEngine engine(MakeRules(
        {MakeRule("*.example.com", {Net::ip::make_address("9.9.9.9")}),
         MakeRule("special.example.com", {Net::ip::make_address("8.8.8.8")})},
        {}, {}));
    auto special = engine.Match(*Prism::Network::DomainName::Parse("special.example.com"));
    ASSERT_TRUE(special != nullptr);
    ASSERT_EQ(special->Addresses.size(), 1u);
    EXPECT_EQ(special->Addresses[0], Net::ip::make_address("8.8.8.8"));

    auto normal = engine.Match(*Prism::Network::DomainName::Parse("other.example.com"));
    ASSERT_TRUE(normal != nullptr);
    ASSERT_EQ(normal->Addresses.size(), 1u);
    EXPECT_EQ(normal->Addresses[0], Net::ip::make_address("9.9.9.9"));
}

TEST(DnsRules, TestDeeperWildcardWins)
{
    RulesEngine engine(MakeRules(
        {MakeRule("*.example.com", {Net::ip::make_address("1.1.1.1")}),
         MakeRule("*.www.example.com", {Net::ip::make_address("2.2.2.2")})},
        {}, {}));
    auto hit = engine.Match(*Prism::Network::DomainName::Parse("cdn.www.example.com"));
    ASSERT_TRUE(hit != nullptr);
    EXPECT_EQ(hit->Addresses[0], Net::ip::make_address("2.2.2.2"));
}

TEST(DnsRules, TestEmptyAddressesMeansBlock)
{
    RulesEngine engine(MakeRules({MakeRule("blocked.com", {})}, {}, {}));
    auto hit = engine.Match(*Prism::Network::DomainName::Parse("blocked.com"));
    ASSERT_TRUE(hit != nullptr);
    EXPECT_EQ(hit->Action, Prism::Network::Dns::RuleAction::Block);
}

TEST(DnsRules, TestCnameMergeWithAddressRule)
{
    // 同域地址规则与 CNAME 规则合并为一条 RuleResult
    RulesEngine engine(MakeRules({MakeRule("dual.com", {Net::ip::make_address("7.7.7.7")})},
                                 {CnameRule{"dual.com", "real.com"}}, {}));
    auto hit = engine.Match(*Prism::Network::DomainName::Parse("dual.com"));
    ASSERT_TRUE(hit != nullptr);
    EXPECT_EQ(hit->Action, Prism::Network::Dns::RuleAction::Rewrite);
    ASSERT_TRUE(hit->CnameTarget.has_value());
    EXPECT_EQ(hit->CnameTarget->View(), "real.com");
}

TEST(DnsRules, TestBlacklist)
{
    RulesEngine engine(MakeRules({}, {}, {"6.6.6.6", "2606:4700::1111"}));
    EXPECT_TRUE(engine.IsBlacklisted(Net::ip::make_address("6.6.6.6")));
    EXPECT_TRUE(engine.IsBlacklisted(Net::ip::make_address("2606:4700::1111")));
    EXPECT_FALSE(engine.IsBlacklisted(Net::ip::make_address("8.8.8.8")));
    EXPECT_EQ(engine.BlacklistSize(), 2u);
}

// ── Resolver 集成：规则在缓存/上游之前生效，全程无网络 ──

TEST(DnsRules, TestResolverBlockRule)
{
    Net::io_context ioc;
    Config cfg;
    cfg.CacheEnabled = false;
    cfg.AddressRules.push_back(MakeRule("*.blocked.test", {}));
    Prism::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    ResolveFailure Failure;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                CaptureResolveResult(co_await r.AsyncResolve("sub.blocked.test"), Failure);
            });
    EXPECT_EQ(Failure.Code, Prism::Fault::Code::Blocked);
}

TEST(DnsRules, TestResolverRewriteRule)
{
    Net::io_context ioc;
    Config cfg;
    cfg.AddressRules.push_back(
        MakeRule("app.test", {Net::ip::make_address("10.0.0.42")}));
    Prism::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    std::vector<Net::ip::address> addrs;
    ResolveFailure Failure;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                CaptureResolveResult(co_await r.AsyncResolve("app.test"), addrs, Failure);
            });
    EXPECT_TRUE(Failure.Succeeded());
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
    Prism::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    std::vector<Net::ip::address> addrs;
    ResolveFailure Failure;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                CaptureResolveResult(co_await r.AsyncResolve("null.test"), addrs, Failure);
            });
    // Negative 语义：成功 + 空 IP 列表（NXDOMAIN），不写缓存
    EXPECT_TRUE(Failure.Succeeded());
    EXPECT_TRUE(addrs.empty());
    EXPECT_EQ(r.Size(), 0u);
}

TEST(DnsRules, TestResolverLiteralBlacklist)
{
    Net::io_context ioc;
    Config cfg;
    cfg.AddressBlacklist.push_back(Net::ip::make_address("6.6.6.6"));
    Prism::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    ResolveFailure Failure;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                CaptureResolveResult(co_await r.AsyncResolve("6.6.6.6"), Failure);
            });
    EXPECT_EQ(Failure.Code, Prism::Fault::Code::Blocked);
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
    Prism::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    ResolveFailure literalFailure;
    ResolveFailure ruleFailure;
    std::vector<Net::ip::address> ruleAddrs;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                CaptureResolveResult(co_await r.AsyncResolve("::1"), literalFailure);
                CaptureResolveResult(co_await r.AsyncResolve("v6-only.test"), ruleAddrs, ruleFailure);
            });

    EXPECT_EQ(literalFailure.Code, Prism::Fault::Code::Ipv6Disabled);
    EXPECT_EQ(ruleFailure.Code, Prism::Fault::Code::Ipv6Disabled);
    EXPECT_TRUE(ruleAddrs.empty());
}

TEST(DnsRules, TestResolverCnameRedirect)
{
    Net::io_context ioc;
    Config cfg;
    cfg.CnameRules.push_back(CnameRule{"alias.test", "127.0.0.1"});
    Prism::Network::Dns::Resolver r(ioc.get_executor(), cfg);

    std::vector<Net::ip::address> addrs;
    ResolveFailure Failure;
    RunCoro(ioc,
            [&]() -> Net::awaitable<void>
            {
                CaptureResolveResult(co_await r.AsyncResolve("alias.test"), addrs, Failure);
            });
    // CNAME 跳转到目标后按字面量快速路径解析
    EXPECT_TRUE(Failure.Succeeded());
    ASSERT_EQ(addrs.size(), 1u);
    EXPECT_EQ(addrs[0], Net::ip::make_address("127.0.0.1"));
}

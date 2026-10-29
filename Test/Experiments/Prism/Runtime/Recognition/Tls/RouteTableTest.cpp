/**
 * @file RouteTableTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include <Test/Experiments/Prism/Runtime/Recognition/Pipeline/RecognitionSupport.hpp>

TEST(TlsReassemblyTest, RouteUsesExactLongestWildcardThenDefault)
    {
        rec::Experiment::SniRouteTable Routes;
        Routes.Add("*.example.com", "wild");
        Routes.Add("*.deep.example.com", "deep");
        Routes.Add("api.example.com", "exact", rec::Experiment::RouteOptions{});
        Routes.SetDefault("default", Prism::Contract::ProtocolType::Tls, true);

        const auto Exact = Routes.LookupValue("API.EXAMPLE.COM.");
        const auto Wildcard = Routes.LookupValue("node.deep.example.com");
        const auto Root = Routes.LookupValue("example.com");
        const auto Nested = Routes.LookupValue("a.b.example.com");
        ASSERT_TRUE(Exact.has_value());
        ASSERT_TRUE(Wildcard.has_value());
        ASSERT_TRUE(Root.has_value());
        ASSERT_TRUE(Nested.has_value());
        EXPECT_EQ(Exact->Scheme, "exact");
        EXPECT_EQ(Wildcard->Scheme, "deep");
        EXPECT_EQ(Root->Scheme, "default");
        EXPECT_EQ(Nested->Scheme, "default");
        EXPECT_EQ(Root->Protocol, Prism::Contract::ProtocolType::Tls);
        EXPECT_TRUE(Root->AllowFallback);
    }

TEST(TlsReassemblyTest, RouteValueResultRemainsStableAfterTableMutation)
    {
        rec::Experiment::SniRouteTable Routes;
        Routes.Add("example.com", "first");
        const auto Stable = Routes.LookupValue("example.com");
        ASSERT_TRUE(Stable.has_value());

        Routes.Add("example.com", "second");

        EXPECT_EQ(Stable->Scheme, "first");
        EXPECT_EQ(Routes.Lookup("example.com"), "second");
    }

TEST(TlsReassemblyTest, RouteOptionsPreserveFallbackAndProtocol)
    {
        rec::Experiment::SniRouteTable Routes;
        Routes.Add("legacy.example", "native",
                   rec::Experiment::RouteOptions{Prism::Contract::ProtocolType::Trojan, true});

        const auto Entry = Routes.LookupValue("legacy.example");
        ASSERT_TRUE(Entry.has_value());
        EXPECT_EQ(Entry->Scheme, "native");
        EXPECT_EQ(Entry->Protocol, Prism::Contract::ProtocolType::Trojan);
        EXPECT_TRUE(Entry->AllowFallback);
    }

TEST(TlsReassemblyTest, EmptyRoutePatternDoesNotBecomeImplicitDefault)
    {
        rec::Experiment::SniRouteTable Routes;
        Routes.Add("", "native", rec::Experiment::RouteOptions{Prism::Contract::ProtocolType::Tls, true});

        EXPECT_FALSE(Routes.LookupValue("").has_value());
    }

TEST(TlsReassemblyTest, ThreeArgumentProtocolRouteAddDefaultsFallback)
    {
        rec::Experiment::SniRouteTable Routes;
        Routes.Add("three-arg.example", "native", Prism::Contract::ProtocolType::Vless);

        const auto Entry = Routes.LookupValue("three-arg.example");
        ASSERT_TRUE(Entry.has_value());
        EXPECT_EQ(Entry->Protocol, Prism::Contract::ProtocolType::Vless);
        EXPECT_FALSE(Entry->AllowFallback);
    }

TEST(TlsReassemblyTest, ClearRemovesExplicitDefaultRoute)
    {
        rec::Experiment::SniRouteTable Routes;
        Routes.SetDefault("fallback");
        ASSERT_TRUE(Routes.LookupValue("unknown.example").has_value());

        Routes.Clear();

        EXPECT_FALSE(Routes.LookupValue("unknown.example").has_value());
    }


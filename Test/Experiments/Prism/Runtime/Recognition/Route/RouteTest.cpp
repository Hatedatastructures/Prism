/**
 * @file RouteTest.cpp
 * @brief SNI 路由 Experiment 的行为契约。
 */

#include <Test/Experiments/Prism/Runtime/Recognition/Pipeline/RecognitionSupport.hpp>

#include <array>
#include <atomic>
#include <thread>

namespace
{
    struct RouteMutationRequest final
    {
        rec::Experiment::SniRouteTable &Routes;
        std::atomic<bool> &Failed;
    };

    /** @brief 并发修改 route snapshot。 */
    auto RunRouteWriter(RouteMutationRequest Request) -> void
    {
        for (int Index = 0; Index < 500; ++Index)
        {
            const char *CandidateName = Index % 2 == 0 ? "first" : "second";
            Request.Routes.Add("*.example.com", CandidateName);
            Request.Routes.SetDefault(CandidateName);
            if (Index % 3 == 0)
            {
                Request.Routes.ClearDefault();
            }
        }
    }

    /** @brief 并发读取 route snapshot 并报告不可接受的候选值。 */
    auto RunRouteReader(RouteMutationRequest Request) -> void
    {
        for (int Index = 0; Index < 1000; ++Index)
        {
            const auto Value = Request.Routes.LookupValue("node.example.com");
            if (Value && Value->Scheme != "initial" && Value->Scheme != "first" &&
                Value->Scheme != "second")
            {
                Request.Failed.store(true, std::memory_order_release);
            }
        }
    }
} // namespace

TEST(RecognitionRoute, ExactMatch)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("example.com", "reality");
    EXPECT_EQ(routes.Lookup("example.com"), "reality");
    EXPECT_EQ(routes.Lookup("other.com"), "");
}

TEST(RecognitionRoute, WildcardMatch)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("*.example.com", "shadowtls");
    EXPECT_EQ(routes.Lookup("sub.example.com"), "shadowtls");
    EXPECT_EQ(routes.Lookup("example.com"), ""); // 通配不含根域
    EXPECT_EQ(routes.Lookup("other.example.com"), "shadowtls");
}

TEST(RecognitionRoute, MultipleRoutes)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("a.com", "reality");
    routes.Add("b.com", "shadowtls");
    EXPECT_EQ(routes.Lookup("a.com"), "reality");
    EXPECT_EQ(routes.Lookup("b.com"), "shadowtls");
    EXPECT_EQ(routes.Size(), 2u);
    routes.Clear();
    EXPECT_EQ(routes.Size(), 0u);
}

TEST(RecognitionRoute, LookupNormalizesAsciiCase)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("Example.COM", "reality");
    EXPECT_EQ(routes.Lookup("example.com"), "reality");
}

TEST(RecognitionRoute, LongestWildcardWins)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("*.example.com", "shadowtls");
    routes.Add("*.deep.example.com", "reality");
    EXPECT_EQ(routes.Lookup("node.deep.example.com"), "reality");
}

TEST(RecognitionRoute, WildcardMatchesSingleLabelOnly)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("*.example.com", "shadowtls");
    EXPECT_EQ(routes.Lookup("a.b.example.com"), "");
}

TEST(RecognitionRoute, LookupEntryCarriesProtocolAndFallback)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("api.example.com", "native", rec::Experiment::RouteOptions{Prism::Contract::ProtocolType::Vless, true});
    const auto entry = routes.LookupEntry("API.EXAMPLE.COM.");
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->Scheme, "native");
    EXPECT_EQ(entry->Protocol, Prism::Contract::ProtocolType::Vless);
    EXPECT_TRUE(entry->AllowFallback);
}

TEST(RecognitionRoute, LookupEntryReturnsOwnedValue)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("example.com", "native");

    const auto entry = routes.LookupEntry("example.com");
    ASSERT_TRUE(entry.has_value());
    routes.Clear();

    EXPECT_EQ(entry->Scheme, "native");
}

TEST(RecognitionRoute, ConcurrentLookupAndMutationUsesStableSnapshots)
{
    rec::Experiment::SniRouteTable routes;
    routes.Add("*.example.com", "initial");
    std::atomic<bool> failed{false};

    std::thread Writer(RunRouteWriter, RouteMutationRequest{routes, failed});
    std::array<std::thread, 4> readers;
    for (auto &reader : readers)
    {
        reader = std::thread(RunRouteReader, RouteMutationRequest{routes, failed});
    }
    Writer.join();
    for (auto &reader : readers)
    {
        reader.join();
    }

    EXPECT_FALSE(failed.load());
    EXPECT_EQ(routes.Size(), 1u);
}

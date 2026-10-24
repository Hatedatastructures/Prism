/**
 * @file RouteTest.cpp
 * @brief 反向路由表实验测试。
 * @details 覆盖反向映射、正向端点、未命中、大小和清空。
 */

#include <Experiments/Prism/Net/Route/Route.hpp>

#include <gtest/gtest.h>

namespace
{
    TEST(RouteTable, ReverseMatch)
    {
        Prism::Experiments::Routing::RouteTable routes;
        routes.AddReverse("internal.example", Prism::Experiments::Routing::Endpoint{"10.0.0.1", 8080});
        EXPECT_TRUE(routes.IsReverse("internal.example"));
        EXPECT_FALSE(routes.IsReverse("other.example"));
        const auto r = routes.Lookup("internal.example");
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->Host, "10.0.0.1");
        EXPECT_EQ(r->Port, 8080u);
    }

    TEST(RouteTable, PositiveFallback)
    {
        Prism::Experiments::Routing::RouteTable routes;
        routes.SetPositive(Prism::Experiments::Routing::Endpoint{"127.0.0.1", 443});
        const auto r = routes.Lookup("any.example");
        ASSERT_TRUE(r.has_value());
        EXPECT_EQ(r->Host, "127.0.0.1");
        EXPECT_EQ(r->Port, 443u);
    }

    TEST(RouteTable, NoMatchNoPositive)
    {
        Prism::Experiments::Routing::RouteTable routes;
        EXPECT_FALSE(routes.Lookup("unknown").has_value());
    }

    TEST(RouteTable, SizeAndClear)
    {
        Prism::Experiments::Routing::RouteTable routes;
        routes.AddReverse("a", Prism::Experiments::Routing::Endpoint{"1.1.1.1", 1});
        routes.AddReverse("b", Prism::Experiments::Routing::Endpoint{"2.2.2.2", 2});
        EXPECT_EQ(routes.Size(), 2u);
        routes.Clear();
        EXPECT_EQ(routes.Size(), 0u);
        EXPECT_FALSE(routes.Lookup("a").has_value());
    }
} // namespace

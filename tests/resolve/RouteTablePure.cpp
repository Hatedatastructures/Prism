/**
 * @file RouteTablePure.cpp
 * @brief SNI 路由表纯函数测试
 * @details 通过 #define private public 访问 add_route，
 *          测试 add_route/lookup/matches_any/registered_snis/empty
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>


#include <gtest/gtest.h>

// 通过预处理器 hack 访问 private 方法
#define private public
#include <prism/stealth/recognition/routes.hpp>
#undef private

namespace
{
    TEST(RouteTablePure, EmptyTable)
    {
        psm::recognition::route_table table;
        EXPECT_TRUE(table.empty()) << "route: initially empty";
        EXPECT_TRUE(table.registered_snis().empty()) << "route: no registered SNIs";
    }

    TEST(RouteTablePure, AddSingleRoute)
    {
        psm::recognition::route_table table;
        table.add_route("example.com", "reality");

        EXPECT_TRUE(!table.empty()) << "route: not empty after add";
        EXPECT_TRUE(table.matches_any("example.com")) << "route: matches added SNI";
        EXPECT_TRUE(!table.matches_any("other.com")) << "route: no match for other";

        auto result = table.lookup("example.com");
        EXPECT_TRUE(result.size() == 1) << "route: lookup returns 1";
        EXPECT_TRUE(result[0] == "reality") << "route: lookup returns reality";
    }

    TEST(RouteTablePure, LookupEmpty)
    {
        psm::recognition::route_table table;
        table.add_route("test.com", "shadowtls");

        auto result = table.lookup("");
        EXPECT_TRUE(result.empty()) << "route: empty sni -> empty result";
    }

    TEST(RouteTablePure, MatchesAnyEmpty)
    {
        psm::recognition::route_table table;
        table.add_route("test.com", "reality");
        EXPECT_TRUE(!table.matches_any("")) << "route: empty sni -> false";
    }

    TEST(RouteTablePure, AddRouteEmptySni)
    {
        psm::recognition::route_table table;
        table.add_route("", "reality");
        EXPECT_TRUE(table.empty()) << "route: empty SNI not added";
    }

    TEST(RouteTablePure, MultiSchemeSameSNI)
    {
        psm::recognition::route_table table;
        table.add_route("shared.com", "reality");
        table.add_route("shared.com", "shadowtls");

        auto result = table.lookup("shared.com");
        EXPECT_TRUE(result.size() == 2) << "route: multi scheme -> 2 results";
        EXPECT_TRUE(result[0] == "reality") << "route: first = reality";
        EXPECT_TRUE(result[1] == "shadowtls") << "route: second = shadowtls";
    }

    TEST(RouteTablePure, DuplicateSchemeIgnored)
    {
        psm::recognition::route_table table;
        table.add_route("dup.com", "reality");
        table.add_route("dup.com", "reality");

        auto result = table.lookup("dup.com");
        EXPECT_TRUE(result.size() == 1) << "route: duplicate scheme not added";
    }

    TEST(RouteTablePure, RegisteredSnis)
    {
        psm::recognition::route_table table;
        table.add_route("a.com", "reality");
        table.add_route("b.com", "shadowtls");

        auto snis = table.registered_snis();
        EXPECT_TRUE(snis.size() == 2) << "route: 2 registered SNIs";
    }

    TEST(RouteTablePure, MultipleRoutes)
    {
        psm::recognition::route_table table;
        table.add_route("one.com", "reality");
        table.add_route("two.com", "shadowtls");
        table.add_route("three.com", "restls");

        EXPECT_TRUE(table.matches_any("one.com")) << "route: one.com exists";
        EXPECT_TRUE(table.matches_any("two.com")) << "route: two.com exists";
        EXPECT_TRUE(table.matches_any("three.com")) << "route: three.com exists";
        EXPECT_TRUE(!table.matches_any("four.com")) << "route: four.com not exists";
    }
} // namespace

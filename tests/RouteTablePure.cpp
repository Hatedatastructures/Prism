/**
 * @file RouteTablePure.cpp
 * @brief SNI 路由表纯函数测试
 * @details 通过 #define private public 访问 add_route，
 *          测试 add_route/lookup/matches_any/registered_snis/empty
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

// 通过预处理器 hack 访问 private 方法
#define private public
#include <prism/recognition/routes.hpp>
#undef private

using psm::testing::TestRunner;

namespace
{
    void TestEmptyTable(TestRunner &runner)
    {
        psm::recognition::route_table table;
        runner.Check(table.empty(), "route: initially empty");
        runner.Check(table.registered_snis().empty(), "route: no registered SNIs");
    }

    void TestAddSingleRoute(TestRunner &runner)
    {
        psm::recognition::route_table table;
        table.add_route("example.com", "reality");

        runner.Check(!table.empty(), "route: not empty after add");
        runner.Check(table.matches_any("example.com"), "route: matches added SNI");
        runner.Check(!table.matches_any("other.com"), "route: no match for other");

        auto result = table.lookup("example.com");
        runner.Check(result.size() == 1, "route: lookup returns 1");
        runner.Check(result[0] == "reality", "route: lookup returns reality");
    }

    void TestLookupEmpty(TestRunner &runner)
    {
        psm::recognition::route_table table;
        table.add_route("test.com", "shadowtls");

        auto result = table.lookup("");
        runner.Check(result.empty(), "route: empty sni -> empty result");
    }

    void TestMatchesAnyEmpty(TestRunner &runner)
    {
        psm::recognition::route_table table;
        table.add_route("test.com", "reality");
        runner.Check(!table.matches_any(""), "route: empty sni -> false");
    }

    void TestAddRouteEmptySni(TestRunner &runner)
    {
        psm::recognition::route_table table;
        table.add_route("", "reality");
        runner.Check(table.empty(), "route: empty SNI not added");
    }

    void TestMultiSchemeSameSNI(TestRunner &runner)
    {
        psm::recognition::route_table table;
        table.add_route("shared.com", "reality");
        table.add_route("shared.com", "shadowtls");

        auto result = table.lookup("shared.com");
        runner.Check(result.size() == 2, "route: multi scheme -> 2 results");
        runner.Check(result[0] == "reality", "route: first = reality");
        runner.Check(result[1] == "shadowtls", "route: second = shadowtls");
    }

    void TestDuplicateSchemeIgnored(TestRunner &runner)
    {
        psm::recognition::route_table table;
        table.add_route("dup.com", "reality");
        table.add_route("dup.com", "reality");

        auto result = table.lookup("dup.com");
        runner.Check(result.size() == 1, "route: duplicate scheme not added");
    }

    void TestRegisteredSnis(TestRunner &runner)
    {
        psm::recognition::route_table table;
        table.add_route("a.com", "reality");
        table.add_route("b.com", "shadowtls");

        auto snis = table.registered_snis();
        runner.Check(snis.size() == 2, "route: 2 registered SNIs");
    }

    void TestMultipleRoutes(TestRunner &runner)
    {
        psm::recognition::route_table table;
        table.add_route("one.com", "reality");
        table.add_route("two.com", "shadowtls");
        table.add_route("three.com", "restls");

        runner.Check(table.matches_any("one.com"), "route: one.com exists");
        runner.Check(table.matches_any("two.com"), "route: two.com exists");
        runner.Check(table.matches_any("three.com"), "route: three.com exists");
        runner.Check(!table.matches_any("four.com"), "route: four.com not exists");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RouteTablePure");

    TestEmptyTable(runner);
    TestAddSingleRoute(runner);
    TestLookupEmpty(runner);
    TestMatchesAnyEmpty(runner);
    TestAddRouteEmptySni(runner);
    TestMultiSchemeSameSNI(runner);
    TestDuplicateSchemeIgnored(runner);
    TestRegisteredSnis(runner);
    TestMultipleRoutes(runner);

    return runner.Summary();
}

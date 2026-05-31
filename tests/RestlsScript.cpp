/**
 * @file RestlsScript.cpp
 * @brief Restls script 解析器单元测试
 * @details 测试 script_engine 构造、parse_line、allocate 等纯逻辑函数。
 */

#include <prism/memory.hpp>
#include <prism/stealth/facade/restls/script.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestDefaultScript(TestRunner &runner)
    {
        // 默认构造 = default，lines_ 为空。需要显式传入空字符串才使用内置默认脚本。
        psm::stealth::restls::script_engine engine; // NOLINT: intentionally default-constructed
        runner.Check(engine.size() == 0, "default-constructed engine has 0 lines");
    }

    void TestCustomScript(TestRunner &runner)
    {
        psm::stealth::restls::script_engine engine("100<1,200~50,300");
        runner.Check(engine.size() == 3, "custom script has 3 lines");
    }

    void TestEmptyScriptUsesDefault(TestRunner &runner)
    {
        // 传入空字符串 → 使用内置默认脚本 "250?100<1,350~100<1,600~100,300~200,300~100" (5 entries)
        psm::stealth::restls::script_engine engine("");
        runner.Check(engine.size() == 5, "empty string uses default script (5 entries)");
    }

    void TestFixedRandomModifier(TestRunner &runner)
    {
        // ? syntax: resolved at parse time
        psm::stealth::restls::script_engine engine("500?0");
        // With range=0, target should be exactly base
        auto alloc = engine.allocate(0, 600);
        runner.Check(alloc.payload_len > 0, "fixed random modifier produces payload");
    }

    void TestDynamicRandomModifier(TestRunner &runner)
    {
        // ~ syntax: resolved at each call
        psm::stealth::restls::script_engine engine("500~100");
        auto alloc1 = engine.allocate(0, 600);
        auto alloc2 = engine.allocate(0, 600);
        // Both should produce valid payloads
        runner.Check(alloc1.payload_len > 0, "dynamic modifier first call");
        runner.Check(alloc2.payload_len > 0, "dynamic modifier second call");
    }

    void TestResponseCommand(TestRunner &runner)
    {
        psm::stealth::restls::script_engine engine("200<1,300");
        runner.Check(engine.size() == 2, "response script has 2 lines");

        auto alloc = engine.allocate(0, 100);
        runner.Check(alloc.write_blocking == true, "first line is blocking");
        runner.Check(alloc.response_count == 1, "response_count is 1");

        auto alloc2 = engine.allocate(1, 100);
        runner.Check(alloc2.write_blocking == false, "second line is non-blocking");
    }

    void TestAllocateNoData(TestRunner &runner)
    {
        psm::stealth::restls::script_engine engine("500");
        auto alloc = engine.allocate(0, 0);
        runner.Check(alloc.data_len == 0, "no data → data_len is 0");
        runner.Check(alloc.padding_len > 0, "no data → random padding");
    }

    void TestAllocateDataFits(TestRunner &runner)
    {
        psm::stealth::restls::script_engine engine("500");
        // auth_hdrlen is internal, but data > target should work
        auto alloc = engine.allocate(0, 600);
        runner.Check(alloc.data_len > 0, "data available → data_len > 0");
    }

    void TestAllocateCounterBeyondScript(TestRunner &runner)
    {
        psm::stealth::restls::script_engine engine("100,200");
        auto alloc = engine.allocate(100, 500); // way beyond
        runner.Check(alloc.data_len > 0, "beyond script → still produces allocation");
        runner.Check(alloc.write_blocking == false, "beyond script → non-blocking");
    }

    void TestAllocateZeroDataWithResponse(TestRunner &runner)
    {
        psm::stealth::restls::script_engine engine("200<2");
        auto alloc = engine.allocate(0, 0);
        runner.Check(alloc.data_len == 0, "zero data with response → data_len 0");
        runner.Check(alloc.padding_len > 0, "zero data with response → has padding");
        runner.Check(alloc.response_count == 2, "response_count is 2");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RestlsScript");

    TestDefaultScript(runner);
    TestCustomScript(runner);
    TestEmptyScriptUsesDefault(runner);
    TestFixedRandomModifier(runner);
    TestDynamicRandomModifier(runner);
    TestResponseCommand(runner);
    TestAllocateNoData(runner);
    TestAllocateDataFits(runner);
    TestAllocateCounterBeyondScript(runner);
    TestAllocateZeroDataWithResponse(runner);

    return runner.Summary();
}

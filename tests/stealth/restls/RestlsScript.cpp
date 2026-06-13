/**
 * @file RestlsScript.cpp
 * @brief Restls script 解析器单元测试
 * @details 测试 script_engine 构造、parse_line、allocate 等纯逻辑函数。
 */

#include <gtest/gtest.h>

#include <prism/core/core.hpp>
#include <prism/stealth/facade/restls/script.hpp>

namespace
{
    TEST(RestlsScript, DefaultScript)
    {
        // 默认构造 = default，lines_ 为空。需要显式传入空字符串才使用内置默认脚本。
        psm::stealth::restls::script_engine engine; // NOLINT: intentionally default-constructed
        EXPECT_TRUE(engine.size() == 0) << "default-constructed engine has 0 lines";
    }

    TEST(RestlsScript, CustomScript)
    {
        psm::stealth::restls::script_engine engine("100<1,200~50,300");
        EXPECT_TRUE(engine.size() == 3) << "custom script has 3 lines";
    }

    TEST(RestlsScript, EmptyScriptUsesDefault)
    {
        // 传入空字符串 → 使用内置默认脚本 "250?100<1,350~100<1,600~100,300~200,300~100" (5 entries)
        psm::stealth::restls::script_engine engine("");
        EXPECT_TRUE(engine.size() == 5) << "empty string uses default script (5 entries)";
    }

    TEST(RestlsScript, FixedRandomModifier)
    {
        // ? syntax: resolved at parse time
        psm::stealth::restls::script_engine engine("500?0");
        // With range=0, target should be exactly base
        auto alloc = engine.allocate(0, 600);
        EXPECT_TRUE(alloc.payload_len > 0) << "fixed random modifier produces payload";
    }

    TEST(RestlsScript, DynamicRandomModifier)
    {
        // ~ syntax: resolved at each call
        psm::stealth::restls::script_engine engine("500~100");
        auto alloc1 = engine.allocate(0, 600);
        auto alloc2 = engine.allocate(0, 600);
        // Both should produce valid payloads
        EXPECT_TRUE(alloc1.payload_len > 0) << "dynamic modifier first call";
        EXPECT_TRUE(alloc2.payload_len > 0) << "dynamic modifier second call";
    }

    TEST(RestlsScript, ResponseCommand)
    {
        psm::stealth::restls::script_engine engine("200<1,300");
        EXPECT_TRUE(engine.size() == 2) << "response script has 2 lines";

        auto alloc = engine.allocate(0, 100);
        EXPECT_TRUE(alloc.write_blocking == true) << "first line is blocking";
        EXPECT_TRUE(alloc.response_count == 1) << "response_count is 1";

        auto alloc2 = engine.allocate(1, 100);
        EXPECT_TRUE(alloc2.write_blocking == false) << "second line is non-blocking";
    }

    TEST(RestlsScript, AllocateNoData)
    {
        psm::stealth::restls::script_engine engine("500");
        auto alloc = engine.allocate(0, 0);
        EXPECT_TRUE(alloc.data_len == 0) << "no data → data_len is 0";
        EXPECT_TRUE(alloc.padding_len > 0) << "no data → random padding";
    }

    TEST(RestlsScript, AllocateDataFits)
    {
        psm::stealth::restls::script_engine engine("500");
        // auth_hdrlen is internal, but data > target should work
        auto alloc = engine.allocate(0, 600);
        EXPECT_TRUE(alloc.data_len > 0) << "data available → data_len > 0";
    }

    TEST(RestlsScript, AllocateCounterBeyondScript)
    {
        psm::stealth::restls::script_engine engine("100,200");
        auto alloc = engine.allocate(100, 500); // way beyond
        EXPECT_TRUE(alloc.data_len > 0) << "beyond script → still produces allocation";
        EXPECT_TRUE(alloc.write_blocking == false) << "beyond script → non-blocking";
    }

    TEST(RestlsScript, AllocateZeroDataWithResponse)
    {
        psm::stealth::restls::script_engine engine("200<2");
        auto alloc = engine.allocate(0, 0);
        EXPECT_TRUE(alloc.data_len == 0) << "zero data with response → data_len 0";
        EXPECT_TRUE(alloc.padding_len > 0) << "zero data with response → has padding";
        EXPECT_TRUE(alloc.response_count == 2) << "response_count is 2";
    }

} // namespace

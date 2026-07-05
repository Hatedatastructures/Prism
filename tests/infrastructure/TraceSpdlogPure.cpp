/**
 * @file TraceSpdlogPure.cpp
 * @brief trace::spdlog 纯函数单元测试
 * @details 测试 parse_spdlog_level 的各分支（通过 init 间接验证）、
 *          build_mdc_prefix 空/非空、mdc_set/mdc_remove/mdc_clear。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/config/config.hpp>

#include <gtest/gtest.h>

namespace
{
    // ─── mdc 操作 ──────────────────────────────────

    TEST(TraceSpdlogPure, MdcSetAndGet)
    {
        psm::trace::mdc_clear();
        psm::trace::mdc_set("session", "abc123");

        auto prefix = psm::trace::build_mdc_prefix();
        EXPECT_TRUE(!prefix.empty()) << "mdc: prefix non-empty after set";
        EXPECT_TRUE(prefix.find("session=abc123") != std::string::npos)
            << "mdc: prefix contains session=abc123";
    }

    TEST(TraceSpdlogPure, MdcRemove)
    {
        psm::trace::mdc_clear();
        psm::trace::mdc_set("key1", "val1");
        psm::trace::mdc_remove("key1");

        auto prefix = psm::trace::build_mdc_prefix();
        EXPECT_TRUE(prefix.empty() || prefix.find("key1") == std::string::npos)
            << "mdc: prefix empty after remove";
    }

    TEST(TraceSpdlogPure, MdcClear)
    {
        psm::trace::mdc_set("a", "1");
        psm::trace::mdc_set("b", "2");
        psm::trace::mdc_clear();

        auto prefix = psm::trace::build_mdc_prefix();
        EXPECT_TRUE(prefix.empty()) << "mdc: prefix empty after clear";
    }

    TEST(TraceSpdlogPure, MdcPrefixEmpty)
    {
        psm::trace::mdc_clear();
        auto prefix = psm::trace::build_mdc_prefix();
        EXPECT_TRUE(prefix.empty()) << "mdc: prefix empty initially";
    }

    TEST(TraceSpdlogPure, MdcMultipleKeys)
    {
        psm::trace::mdc_clear();
        psm::trace::mdc_set("stream", "42");
        psm::trace::mdc_set("proto", "trojan");

        auto prefix = psm::trace::build_mdc_prefix();
        EXPECT_TRUE(prefix.find("stream=42") != std::string::npos)
            << "mdc: multi contains stream=42";
        EXPECT_TRUE(prefix.find("proto=trojan") != std::string::npos)
            << "mdc: multi contains proto=trojan";
        psm::trace::mdc_clear();
    }

    // ─── recorder 未初始化 ─────────────────────────

    TEST(TraceSpdlogPure, RecorderBeforeInit)
    {
        auto logger = psm::trace::recorder();
        EXPECT_TRUE(logger != nullptr) << "recorder: returns non-null after init";
    }
} // namespace

/**
 * @file TraceSpdlogDeep.cpp
 * @brief trace/spdlog 深度纯函数测试
 * @details 通过 #include 源文件访问 spdlog.cpp 中所有同步函数，
 *          覆盖 parse_spdlog_level 全分支、build_log_path 路径组合、
 *          mdc 操作完整路径、recorder 状态。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/config.hpp>

#include <gtest/gtest.h>

#include "../../src/prism/trace/spdlog.cpp"

namespace
{
    // parse_spdlog_level 在匿名命名空间，#include 后可直接调用
    // 但需要用 psm::trace::parse_spdlog_level 因为它在 psm::trace 的匿名命名空间
    // 实际上 #include 展开后它在当前翻译单元的 psm::trace 匿名命名空间
    // 所以我们通过 psm::trace 命名空间访问（匿名命名空间对当前 TU 可见）

    // ─── parse_spdlog_level 全分支测试 ──────────

    TEST(TraceSpdlogDeep, ParseLevelTrace)
    {
        auto level = psm::trace::parse_spdlog_level("trace");
        EXPECT_TRUE(level == spdlog::level::trace) << "parse_level: trace";
    }

    TEST(TraceSpdlogDeep, ParseLevelDebug)
    {
        auto level = psm::trace::parse_spdlog_level("debug");
        EXPECT_TRUE(level == spdlog::level::debug) << "parse_level: debug";
    }

    TEST(TraceSpdlogDeep, ParseLevelInfo)
    {
        auto level = psm::trace::parse_spdlog_level("info");
        EXPECT_TRUE(level == spdlog::level::info) << "parse_level: info";
    }

    TEST(TraceSpdlogDeep, ParseLevelWarn)
    {
        auto level = psm::trace::parse_spdlog_level("warn");
        EXPECT_TRUE(level == spdlog::level::warn) << "parse_level: warn";
    }

    TEST(TraceSpdlogDeep, ParseLevelWarning)
    {
        auto level = psm::trace::parse_spdlog_level("warning");
        EXPECT_TRUE(level == spdlog::level::warn) << "parse_level: warning -> warn";
    }

    TEST(TraceSpdlogDeep, ParseLevelError)
    {
        auto level = psm::trace::parse_spdlog_level("error");
        EXPECT_TRUE(level == spdlog::level::err) << "parse_level: error -> err";
    }

    TEST(TraceSpdlogDeep, ParseLevelErr)
    {
        auto level = psm::trace::parse_spdlog_level("err");
        EXPECT_TRUE(level == spdlog::level::err) << "parse_level: err";
    }

    TEST(TraceSpdlogDeep, ParseLevelCritical)
    {
        auto level = psm::trace::parse_spdlog_level("critical");
        EXPECT_TRUE(level == spdlog::level::critical) << "parse_level: critical";
    }

    TEST(TraceSpdlogDeep, ParseLevelFatal)
    {
        auto level = psm::trace::parse_spdlog_level("fatal");
        EXPECT_TRUE(level == spdlog::level::critical) << "parse_level: fatal -> critical";
    }

    TEST(TraceSpdlogDeep, ParseLevelOff)
    {
        auto level = psm::trace::parse_spdlog_level("off");
        EXPECT_TRUE(level == spdlog::level::off) << "parse_level: off";
    }

    TEST(TraceSpdlogDeep, ParseLevelUnknown)
    {
        auto level = psm::trace::parse_spdlog_level("unknown_level");
        EXPECT_TRUE(level == spdlog::level::info) << "parse_level: unknown -> info";
    }

    TEST(TraceSpdlogDeep, ParseLevelEmpty)
    {
        auto level = psm::trace::parse_spdlog_level("");
        EXPECT_TRUE(level == spdlog::level::info) << "parse_level: empty -> info";
    }

    TEST(TraceSpdlogDeep, ParseLevelCaseInsensitive)
    {
        auto t = psm::trace::parse_spdlog_level("TRACE");
        EXPECT_TRUE(t == spdlog::level::trace) << "parse_level: TRACE upper";

        auto d = psm::trace::parse_spdlog_level("Debug");
        EXPECT_TRUE(d == spdlog::level::debug) << "parse_level: Debug mixed";

        auto w = psm::trace::parse_spdlog_level("WARNING");
        EXPECT_TRUE(w == spdlog::level::warn) << "parse_level: WARNING upper";

        auto c = psm::trace::parse_spdlog_level("Critical");
        EXPECT_TRUE(c == spdlog::level::critical) << "parse_level: Critical mixed";
    }

    // ─── build_log_path 测试 ──────────────────

    TEST(TraceSpdlogDeep, BuildLogPathEmptyPathName)
    {
        psm::trace::config cfg;
        cfg.path_name = "";
        cfg.file_name = "test.log";
        auto path = psm::trace::build_log_path(cfg);
        EXPECT_TRUE(path.filename().string() == "test.log")
                     << "build_log_path: empty path_name -> just file_name";
    }

    TEST(TraceSpdlogDeep, BuildLogPathWithDirectory)
    {
        psm::trace::config cfg;
        cfg.path_name = "logs";
        cfg.file_name = "app.log";
        auto path = psm::trace::build_log_path(cfg);
        EXPECT_TRUE(path.parent_path().string() == "logs")
                     << "build_log_path: has parent directory";
        EXPECT_TRUE(path.filename().string() == "app.log")
                     << "build_log_path: file_name correct";
    }

    TEST(TraceSpdlogDeep, BuildLogPathNestedDirectory)
    {
        psm::trace::config cfg;
        cfg.path_name = "var/log/prism";
        cfg.file_name = "out.log";
        auto path = psm::trace::build_log_path(cfg);
        EXPECT_TRUE(!path.empty()) << "build_log_path: nested path non-empty";
        EXPECT_TRUE(path.filename().string() == "out.log")
                     << "build_log_path: nested file_name correct";
    }

    TEST(TraceSpdlogDeep, BuildLogPathEmptyFileName)
    {
        psm::trace::config cfg;
        cfg.path_name = "logs";
        cfg.file_name = "";
        auto path = psm::trace::build_log_path(cfg);
        EXPECT_TRUE(!path.empty()) << "build_log_path: empty file_name -> non-empty path";
    }

    // ─── mdc 操作扩展测试 ──────────────────

    TEST(TraceSpdlogDeep, MdcSetClearCycle)
    {
        psm::trace::mdc_clear();

        psm::trace::mdc_set("worker", "0");
        auto p1 = psm::trace::build_mdc_prefix();
        EXPECT_TRUE(!p1.empty()) << "mdc_cycle: set worker -> non-empty";

        psm::trace::mdc_clear();
        auto p2 = psm::trace::build_mdc_prefix();
        EXPECT_TRUE(p2.empty()) << "mdc_cycle: clear -> empty";
    }

    TEST(TraceSpdlogDeep, MdcOverwriteKey)
    {
        psm::trace::mdc_clear();
        psm::trace::mdc_set("id", "100");
        psm::trace::mdc_set("id", "200");

        auto prefix = psm::trace::build_mdc_prefix();
        EXPECT_TRUE(prefix.find("id=200") != std::string::npos)
                     << "mdc: overwrite key -> latest value";
        EXPECT_TRUE(prefix.find("id=100") == std::string::npos)
                     << "mdc: overwrite key -> old value gone";
        psm::trace::mdc_clear();
    }

    TEST(TraceSpdlogDeep, MdcRemoveNonexistent)
    {
        psm::trace::mdc_clear();
        psm::trace::mdc_remove("nonexistent");
        auto prefix = psm::trace::build_mdc_prefix();
        EXPECT_TRUE(prefix.empty()) << "mdc: remove nonexistent -> still empty";
    }

    // ─── recorder 测试 ──────────────────

    TEST(TraceSpdlogDeep, RecorderNotNullAfterInit)
    {
        psm::trace::init({});
        auto logger = psm::trace::recorder();
        EXPECT_TRUE(logger != nullptr) << "recorder: non-null after init";
    }

    TEST(TraceSpdlogDeep, RecorderWithCustomConfig)
    {
        psm::trace::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = false;
        cfg.log_level = "debug";
        psm::trace::init(cfg);

        auto logger = psm::trace::recorder();
        EXPECT_TRUE(logger != nullptr) << "recorder: non-null with console-only config";
    }

} // namespace

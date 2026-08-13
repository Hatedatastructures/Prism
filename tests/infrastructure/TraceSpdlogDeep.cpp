/**
 * @file TraceSpdlogDeep.cpp
 * @brief trace/spdlog 深度纯函数测试
 * @details 通过 #include 源文件访问 spdlog.cpp 中所有同步函数，
 *          覆盖 parse_spdlog_level 全分支、build_log_path 路径组合、
 *          mdc 操作完整路径、recorder 状态。
 */

#include <prism/diagnose/log.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/settings/settings.hpp>

#include "../../src/prism/diagnose/spdlog.cpp"
#include <gtest/gtest.h>

namespace
{
    // parse_spdlog_level 在匿名命名空间，#include 后可直接调用
    // 但需要用 psm::diagnose::parse_spdlog_level 因为它在 psm::diagnose 的匿名命名空间
    // 实际上 #include 展开后它在当前翻译单元的 psm::diagnose 匿名命名空间
    // 所以我们通过 psm::diagnose 命名空间访问（匿名命名空间对当前 TU 可见）

    // ─── parse_spdlog_level 全分支测试 ──────────

    TEST(TraceSpdlogDeep, ParseLevelTrace)
    {
        auto level = psm::diagnose::parse_spdlog_level("trace");
        EXPECT_EQ(level, spdlog::level::trace) << "parse_level: trace";
    }

    TEST(TraceSpdlogDeep, ParseLevelDebug)
    {
        auto level = psm::diagnose::parse_spdlog_level("debug");
        EXPECT_EQ(level, spdlog::level::debug) << "parse_level: debug";
    }

    TEST(TraceSpdlogDeep, ParseLevelInfo)
    {
        auto level = psm::diagnose::parse_spdlog_level("info");
        EXPECT_EQ(level, spdlog::level::info) << "parse_level: info";
    }

    TEST(TraceSpdlogDeep, ParseLevelWarn)
    {
        auto level = psm::diagnose::parse_spdlog_level("warn");
        EXPECT_EQ(level, spdlog::level::warn) << "parse_level: warn";
    }

    TEST(TraceSpdlogDeep, ParseLevelWarning)
    {
        auto level = psm::diagnose::parse_spdlog_level("warning");
        EXPECT_EQ(level, spdlog::level::warn) << "parse_level: warning -> warn";
    }

    TEST(TraceSpdlogDeep, ParseLevelError)
    {
        auto level = psm::diagnose::parse_spdlog_level("error");
        EXPECT_EQ(level, spdlog::level::err) << "parse_level: error -> err";
    }

    TEST(TraceSpdlogDeep, ParseLevelErr)
    {
        auto level = psm::diagnose::parse_spdlog_level("err");
        EXPECT_EQ(level, spdlog::level::err) << "parse_level: err";
    }

    TEST(TraceSpdlogDeep, ParseLevelCritical)
    {
        auto level = psm::diagnose::parse_spdlog_level("critical");
        EXPECT_EQ(level, spdlog::level::critical) << "parse_level: critical";
    }

    TEST(TraceSpdlogDeep, ParseLevelFatal)
    {
        auto level = psm::diagnose::parse_spdlog_level("fatal");
        EXPECT_EQ(level, spdlog::level::critical) << "parse_level: fatal -> critical";
    }

    TEST(TraceSpdlogDeep, ParseLevelOff)
    {
        // off 实现返回自定义级别 8（高于 access_level=7），保证 off 时访问日志也关闭
        auto level = psm::diagnose::parse_spdlog_level("off");
        EXPECT_EQ(static_cast<int>(level), 8) << "parse_level: off";
    }

    TEST(TraceSpdlogDeep, ParseLevelUnknown)
    {
        auto level = psm::diagnose::parse_spdlog_level("unknown_level");
        EXPECT_EQ(level, spdlog::level::info) << "parse_level: unknown -> info";
    }

    TEST(TraceSpdlogDeep, ParseLevelEmpty)
    {
        auto level = psm::diagnose::parse_spdlog_level("");
        EXPECT_EQ(level, spdlog::level::info) << "parse_level: empty -> info";
    }

    TEST(TraceSpdlogDeep, ParseLevelCaseInsensitive)
    {
        auto t = psm::diagnose::parse_spdlog_level("TRACE");
        EXPECT_EQ(t, spdlog::level::trace) << "parse_level: TRACE upper";

        auto d = psm::diagnose::parse_spdlog_level("Debug");
        EXPECT_EQ(d, spdlog::level::debug) << "parse_level: Debug mixed";

        auto w = psm::diagnose::parse_spdlog_level("WARNING");
        EXPECT_EQ(w, spdlog::level::warn) << "parse_level: WARNING upper";

        auto c = psm::diagnose::parse_spdlog_level("Critical");
        EXPECT_EQ(c, spdlog::level::critical) << "parse_level: Critical mixed";
    }

    // ─── build_log_path 测试 ──────────────────

    TEST(TraceSpdlogDeep, BuildLogPathEmptyPathName)
    {
        psm::diagnose::config cfg;
        cfg.path_name = "";
        cfg.file_name = "test.log";
        auto path = psm::diagnose::build_log_path(cfg);
        EXPECT_EQ(path.filename().string(), "test.log")
            << "build_log_path: empty path_name -> just file_name";
    }

    TEST(TraceSpdlogDeep, BuildLogPathWithDirectory)
    {
        psm::diagnose::config cfg;
        cfg.path_name = "logs";
        cfg.file_name = "app.log";
        auto path = psm::diagnose::build_log_path(cfg);
        EXPECT_EQ(path.parent_path().string(), "logs") << "build_log_path: has parent directory";
        EXPECT_EQ(path.filename().string(), "app.log") << "build_log_path: file_name correct";
    }

    TEST(TraceSpdlogDeep, BuildLogPathNestedDirectory)
    {
        psm::diagnose::config cfg;
        cfg.path_name = "var/log/prism";
        cfg.file_name = "out.log";
        auto path = psm::diagnose::build_log_path(cfg);
        EXPECT_TRUE(!path.empty()) << "build_log_path: nested path non-empty";
        EXPECT_EQ(path.filename().string(), "out.log") << "build_log_path: nested file_name correct";
    }

    TEST(TraceSpdlogDeep, BuildLogPathEmptyFileName)
    {
        psm::diagnose::config cfg;
        cfg.path_name = "logs";
        cfg.file_name = "";
        auto path = psm::diagnose::build_log_path(cfg);
        EXPECT_TRUE(!path.empty()) << "build_log_path: empty file_name -> non-empty path";
    }

    // ─── mdc 操作扩展测试 ──────────────────

    TEST(TraceSpdlogDeep, MdcSetClearCycle)
    {
        psm::diagnose::mdc_clear();

        psm::diagnose::mdc_set("worker", "0");
        auto p1 = psm::diagnose::build_mdc_prefix();
        EXPECT_TRUE(!p1.empty()) << "mdc_cycle: set worker -> non-empty";

        psm::diagnose::mdc_clear();
        auto p2 = psm::diagnose::build_mdc_prefix();
        EXPECT_TRUE(p2.empty()) << "mdc_cycle: clear -> empty";
    }

    TEST(TraceSpdlogDeep, MdcOverwriteKey)
    {
        psm::diagnose::mdc_clear();
        psm::diagnose::mdc_set("id", "100");
        psm::diagnose::mdc_set("id", "200");

        auto prefix = psm::diagnose::build_mdc_prefix();
        EXPECT_NE(prefix.find("id=200"), std::string::npos) << "mdc: overwrite key -> latest value";
        EXPECT_EQ(prefix.find("id=100"), std::string::npos) << "mdc: overwrite key -> old value gone";
        psm::diagnose::mdc_clear();
    }

    TEST(TraceSpdlogDeep, MdcRemoveNonexistent)
    {
        psm::diagnose::mdc_clear();
        psm::diagnose::mdc_remove("nonexistent");
        auto prefix = psm::diagnose::build_mdc_prefix();
        EXPECT_TRUE(prefix.empty()) << "mdc: remove nonexistent -> still empty";
    }

    // ─── recorder 测试 ──────────────────

    TEST(TraceSpdlogDeep, RecorderNotNullAfterInit)
    {
        psm::diagnose::init({});
        auto logger = psm::diagnose::recorder();
        EXPECT_NE(logger, nullptr) << "recorder: non-null after init";
    }

    TEST(TraceSpdlogDeep, RecorderWithCustomConfig)
    {
        psm::diagnose::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = false;
        cfg.log_level = "debug";
        psm::diagnose::init(cfg);

        auto logger = psm::diagnose::recorder();
        EXPECT_NE(logger, nullptr) << "recorder: non-null with console-only config";
    }

} // namespace

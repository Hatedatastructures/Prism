/**
 * @file Trace.cpp
 * @brief 日志模块单元测试
 * @details 测试 psm::trace 模块的核心功能：初始化/关闭生命周期、
 * 日志级别配置、各级别日志输出、重复初始化、空日志器安全调用等。
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/trace/config.hpp>

#include <gtest/gtest.h>

namespace
{
    TEST(Trace, ConfigDefaults)
    {
        psm::trace::config cfg;

        EXPECT_TRUE(cfg.file_name == "prism.log") << "file_name default";
        EXPECT_TRUE(cfg.path_name == "logs") << "path_name default";
        EXPECT_TRUE(cfg.max_size == 64 * 1024 * 1024) << "max_size default";
        EXPECT_TRUE(cfg.max_files == 8) << "max_files default";
        EXPECT_TRUE(cfg.enable_console) << "enable_console should be true";
        EXPECT_TRUE(cfg.enable_file) << "enable_file should be true";
        EXPECT_TRUE(cfg.log_level == "info") << "log_level default";
        EXPECT_TRUE(cfg.trace_name == "prism") << "trace_name default";
    }

    TEST(Trace, ShutdownNullRecorder)
    {
        psm::trace::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = false;
        psm::trace::init(cfg);

        auto logger = psm::trace::recorder();
        ASSERT_TRUE(logger) << "recorder should not be null after init";

        psm::trace::shutdown();

        logger = psm::trace::recorder();
        EXPECT_TRUE(logger == nullptr) << "recorder should be null after shutdown";
    }

    TEST(Trace, LogWithoutInit)
    {
        psm::trace::shutdown();

        psm::trace::debug("debug without init");
        psm::trace::info("info without init");
        psm::trace::warn("warn without init");
        psm::trace::error("error without init");
        psm::trace::fatal("fatal without init");

        EXPECT_TRUE(true) << "log without init: completed without exception";
    }

    TEST(Trace, LogWithFormatArgs)
    {
        psm::trace::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = false;
        psm::trace::init(cfg);

        psm::trace::debug("debug message: {}", 42);
        psm::trace::info("info message: {} + {} = {}", 1, 2, 3);
        psm::trace::warn("warn message: {}", "string arg");
        psm::trace::error("error code: {}", 0xDEAD);
        psm::trace::fatal("fatal: {} {} {}", "a", "b", "c");

        EXPECT_TRUE(true) << "log with format args: completed without exception";
    }

    TEST(Trace, RepeatedInit)
    {
        psm::trace::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = false;

        psm::trace::init(cfg);
        psm::trace::info("first init");

        psm::trace::init(cfg);
        psm::trace::info("second init");

        psm::trace::init(cfg);
        psm::trace::info("third init");

        auto logger = psm::trace::recorder();
        EXPECT_TRUE(logger) << "recorder should not be null after repeated init";
    }

    TEST(Trace, ConsoleOnly)
    {
        psm::trace::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = false;
        psm::trace::init(cfg);

        psm::trace::info("console only message");

        auto logger = psm::trace::recorder();
        EXPECT_TRUE(logger) << "recorder should exist in console-only mode";
    }

    TEST(Trace, LogLevelStrings)
    {
        const psm::trace::config base_cfg = []
        {
            psm::trace::config c;
            c.enable_console = true;
            c.enable_file = false;
            return c;
        }();

        const char *levels[] = {
            "trace", "debug", "info", "warn", "warning", "error", "err",
            "critical", "fatal", "off", "INFO", "DeBuG", "UNKNOWN_LEVEL"};

        for (const auto *level : levels)
        {
            psm::trace::config cfg = base_cfg;
            cfg.log_level = psm::memory::string(level);
            psm::trace::init(cfg);

            auto logger = psm::trace::recorder();
            ASSERT_TRUE(logger) << "recorder null for level: " << level;

            psm::trace::info("level test: {}", level);
        }
    }

    TEST(Trace, EmptyFileNameFallback)
    {
        psm::trace::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = true;
        cfg.file_name = "";
        cfg.trace_name = "test_trace";
        psm::trace::init(cfg);

        psm::trace::info("empty file name fallback test");

        auto logger = psm::trace::recorder();
        EXPECT_TRUE(logger) << "recorder should exist with empty file name";
    }
} // namespace

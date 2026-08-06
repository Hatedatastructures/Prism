/**
 * @file Trace.cpp
 * @brief 日志模块单元测试
 * @details 测试 psm::diagnose 模块的核心功能：初始化/关闭生命周期、
 * 日志级别配置、各级别日志输出、重复初始化、空日志器安全调用等。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/diagnose/log.hpp>
#include <prism/diagnose/config.hpp>

#include <gtest/gtest.h>

namespace
{
    TEST(Trace, ConfigDefaults)
    {
        psm::diagnose::config cfg;

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
        psm::diagnose::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = false;
        psm::diagnose::init(cfg);

        auto logger = psm::diagnose::recorder();
        ASSERT_TRUE(logger) << "recorder should not be null after init";

        psm::diagnose::shutdown();

        logger = psm::diagnose::recorder();
        EXPECT_TRUE(logger == nullptr) << "recorder should be null after shutdown";
    }

    TEST(Trace, LogWithoutInit)
    {
        psm::diagnose::shutdown();

        psm::diagnose::debug("debug without init");
        psm::diagnose::info("info without init");
        psm::diagnose::warn("warn without init");
        psm::diagnose::error("error without init");
        psm::diagnose::fatal("fatal without init");

        EXPECT_TRUE(true) << "log without init: completed without exception";
    }

    TEST(Trace, LogWithFormatArgs)
    {
        psm::diagnose::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = false;
        psm::diagnose::init(cfg);

        psm::diagnose::debug("debug message: {}", 42);
        psm::diagnose::info("info message: {} + {} = {}", 1, 2, 3);
        psm::diagnose::warn("warn message: {}", "string arg");
        psm::diagnose::error("error code: {}", 0xDEAD);
        psm::diagnose::fatal("fatal: {} {} {}", "a", "b", "c");

        EXPECT_TRUE(true) << "log with format args: completed without exception";
    }

    TEST(Trace, RepeatedInit)
    {
        psm::diagnose::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = false;

        psm::diagnose::init(cfg);
        psm::diagnose::info("first init");

        psm::diagnose::init(cfg);
        psm::diagnose::info("second init");

        psm::diagnose::init(cfg);
        psm::diagnose::info("third init");

        auto logger = psm::diagnose::recorder();
        EXPECT_TRUE(logger) << "recorder should not be null after repeated init";
    }

    TEST(Trace, ConsoleOnly)
    {
        psm::diagnose::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = false;
        psm::diagnose::init(cfg);

        psm::diagnose::info("console only message");

        auto logger = psm::diagnose::recorder();
        EXPECT_TRUE(logger) << "recorder should exist in console-only mode";
    }

    TEST(Trace, LogLevelStrings)
    {
        const psm::diagnose::config base_cfg = []
        {
            psm::diagnose::config c;
            c.enable_console = true;
            c.enable_file = false;
            return c;
        }();

        const char *levels[] = {
            "trace", "debug", "info", "warn", "warning", "error", "err",
            "critical", "fatal", "off", "INFO", "DeBuG", "UNKNOWN_LEVEL"};

        for (const auto *level : levels)
        {
            psm::diagnose::config cfg = base_cfg;
            cfg.log_level = psm::memory::string(level);
            psm::diagnose::init(cfg);

            auto logger = psm::diagnose::recorder();
            ASSERT_TRUE(logger) << "recorder null for level: " << level;

            psm::diagnose::info("level test: {}", level);
        }
    }

    TEST(Trace, EmptyFileNameFallback)
    {
        psm::diagnose::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = true;
        cfg.file_name = "";
        cfg.trace_name = "test_trace";
        psm::diagnose::init(cfg);

        psm::diagnose::info("empty file name fallback test");

        auto logger = psm::diagnose::recorder();
        EXPECT_TRUE(logger) << "recorder should exist with empty file name";
    }
} // namespace

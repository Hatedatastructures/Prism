/**
 * @file Trace.cpp
 * @brief 日志模块单元测试
 * @details 测试 psm::trace 模块的核心功能：初始化/关闭生命周期、
 * 日志级别配置、各级别日志输出、重复初始化、空日志器安全调用等。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/trace/config.hpp>

#include "common/TestRunner.hpp"

namespace
{
    psm::testing::TestRunner runner("Trace");
} // namespace

/**
 * @brief 测试 config 默认值
 */
void TestConfigDefaults()
{
    runner.LogInfo("=== TestConfigDefaults ===");

    psm::trace::config cfg;

    if (cfg.file_name != "prism.log")
    {
        runner.LogFail("file_name default");
        return;
    }
    if (cfg.path_name != "logs")
    {
        runner.LogFail("path_name default");
        return;
    }
    if (cfg.max_size != 64 * 1024 * 1024)
    {
        runner.LogFail("max_size default");
        return;
    }
    if (cfg.max_files != 8)
    {
        runner.LogFail("max_files default");
        return;
    }
    if (!cfg.enable_console)
    {
        runner.LogFail("enable_console should be true");
        return;
    }
    if (!cfg.enable_file)
    {
        runner.LogFail("enable_file should be true");
        return;
    }
    if (cfg.log_level != "info")
    {
        runner.LogFail("log_level default");
        return;
    }
    if (cfg.trace_name != "prism")
    {
        runner.LogFail("trace_name default");
        return;
    }

    runner.LogPass("config defaults");
}

/**
 * @brief 测试 shutdown 后 recorder 为空
 */
void TestShutdownNullRecorder()
{
    runner.LogInfo("=== TestShutdownNullRecorder ===");

    psm::trace::config cfg;
    cfg.enable_console = true;
    cfg.enable_file = false;
    psm::trace::init(cfg);

    auto logger = psm::trace::recorder();
    if (!logger)
    {
        runner.LogFail("recorder should not be null after init");
        return;
    }

    psm::trace::shutdown();

    logger = psm::trace::recorder();
    if (logger != nullptr)
    {
        runner.LogFail("recorder should be null after shutdown");
        return;
    }

    runner.LogPass("shutdown null recorder");
}

/**
 * @brief 测试未初始化时调用日志函数不崩溃
 */
void TestLogWithoutInit()
{
    runner.LogInfo("=== TestLogWithoutInit ===");

    psm::trace::shutdown();

    psm::trace::debug("debug without init");
    psm::trace::info("info without init");
    psm::trace::warn("warn without init");
    psm::trace::error("error without init");
    psm::trace::fatal("fatal without init");

    runner.LogPass("log without init no crash");
}

/**
 * @brief 测试带格式化参数的日志输出
 */
void TestLogWithFormatArgs()
{
    runner.LogInfo("=== TestLogWithFormatArgs ===");

    psm::trace::config cfg;
    cfg.enable_console = true;
    cfg.enable_file = false;
    psm::trace::init(cfg);

    psm::trace::debug("debug message: {}", 42);
    psm::trace::info("info message: {} + {} = {}", 1, 2, 3);
    psm::trace::warn("warn message: {}", "string arg");
    psm::trace::error("error code: {}", 0xDEAD);
    psm::trace::fatal("fatal: {} {} {}", "a", "b", "c");

    runner.LogPass("log with format args");
}

/**
 * @brief 测试重复 init 覆盖不崩溃
 */
void TestRepeatedInit()
{
    runner.LogInfo("=== TestRepeatedInit ===");

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
    if (!logger)
    {
        runner.LogFail("recorder should not be null after repeated init");
        return;
    }

    runner.LogPass("repeated init");
}

/**
 * @brief 测试仅控制台输出模式
 */
void TestConsoleOnly()
{
    runner.LogInfo("=== TestConsoleOnly ===");

    psm::trace::config cfg;
    cfg.enable_console = true;
    cfg.enable_file = false;
    psm::trace::init(cfg);

    psm::trace::info("console only message");

    auto logger = psm::trace::recorder();
    if (!logger)
    {
        runner.LogFail("recorder should exist in console-only mode");
        return;
    }

    runner.LogPass("console only mode");
}

/**
 * @brief 测试不同日志级别字符串
 */
void TestLogLevelStrings()
{
    runner.LogInfo("=== TestLogLevelStrings ===");

    const psm::trace::config base_cfg = []
    {
        psm::trace::config c;
        c.enable_console = true;
        c.enable_file = false;
        return c;
    }();

    const char *levels[] = {"trace", "debug", "info", "warn", "warning", "error", "err", "critical", "fatal", "off", "INFO", "DeBuG", "UNKNOWN_LEVEL"};

    for (const auto *level : levels)
    {
        psm::trace::config cfg = base_cfg;
        cfg.log_level = psm::memory::string(level);
        psm::trace::init(cfg);

        auto logger = psm::trace::recorder();
        if (!logger)
        {
            runner.LogFail(std::string("recorder null for level: ") + level);
            return;
        }

        psm::trace::info("level test: {}", level);
    }

    runner.LogPass("log level strings");
}

/**
 * @brief 测试空文件名自动替换
 */
void TestEmptyFileNameFallback()
{
    runner.LogInfo("=== TestEmptyFileNameFallback ===");

    psm::trace::config cfg;
    cfg.enable_console = true;
    cfg.enable_file = true;
    cfg.file_name = "";
    cfg.trace_name = "test_trace";
    psm::trace::init(cfg);

    psm::trace::info("empty file name fallback test");

    auto logger = psm::trace::recorder();
    if (!logger)
    {
        runner.LogFail("recorder should exist with empty file name");
        return;
    }

    runner.LogPass("empty file name fallback");
}

int main()
{
    psm::memory::system::enable_global_pooling();
    psm::trace::init({});

    runner.LogInfo("========== Trace Tests ==========");

    TestConfigDefaults();
    TestLogWithoutInit();
    TestConsoleOnly();
    TestLogWithFormatArgs();
    TestRepeatedInit();
    TestLogLevelStrings();
    TestEmptyFileNameFallback();
    TestShutdownNullRecorder();

    return runner.Summary();
}

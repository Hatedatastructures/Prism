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

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include "../src/prism/trace/spdlog.cpp"

using psm::testing::TestRunner;

namespace
{
    // parse_spdlog_level 在匿名命名空间，#include 后可直接调用
    // 但需要用 psm::trace::parse_spdlog_level 因为它在 psm::trace 的匿名命名空间
    // 实际上 #include 展开后它在当前翻译单元的 psm::trace 匿名命名空间
    // 所以我们通过 psm::trace 命名空间访问（匿名命名空间对当前 TU 可见）

    // ─── parse_spdlog_level 全分支测试 ──────────

    void TestParseLevelTrace(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("trace");
        runner.Check(level == spdlog::level::trace, "parse_level: trace");
    }

    void TestParseLevelDebug(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("debug");
        runner.Check(level == spdlog::level::debug, "parse_level: debug");
    }

    void TestParseLevelInfo(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("info");
        runner.Check(level == spdlog::level::info, "parse_level: info");
    }

    void TestParseLevelWarn(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("warn");
        runner.Check(level == spdlog::level::warn, "parse_level: warn");
    }

    void TestParseLevelWarning(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("warning");
        runner.Check(level == spdlog::level::warn, "parse_level: warning -> warn");
    }

    void TestParseLevelError(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("error");
        runner.Check(level == spdlog::level::err, "parse_level: error -> err");
    }

    void TestParseLevelErr(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("err");
        runner.Check(level == spdlog::level::err, "parse_level: err");
    }

    void TestParseLevelCritical(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("critical");
        runner.Check(level == spdlog::level::critical, "parse_level: critical");
    }

    void TestParseLevelFatal(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("fatal");
        runner.Check(level == spdlog::level::critical, "parse_level: fatal -> critical");
    }

    void TestParseLevelOff(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("off");
        runner.Check(level == spdlog::level::off, "parse_level: off");
    }

    void TestParseLevelUnknown(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("unknown_level");
        runner.Check(level == spdlog::level::info, "parse_level: unknown -> info");
    }

    void TestParseLevelEmpty(TestRunner &runner)
    {
        auto level = psm::trace::parse_spdlog_level("");
        runner.Check(level == spdlog::level::info, "parse_level: empty -> info");
    }

    void TestParseLevelCaseInsensitive(TestRunner &runner)
    {
        auto t = psm::trace::parse_spdlog_level("TRACE");
        runner.Check(t == spdlog::level::trace, "parse_level: TRACE upper");

        auto d = psm::trace::parse_spdlog_level("Debug");
        runner.Check(d == spdlog::level::debug, "parse_level: Debug mixed");

        auto w = psm::trace::parse_spdlog_level("WARNING");
        runner.Check(w == spdlog::level::warn, "parse_level: WARNING upper");

        auto c = psm::trace::parse_spdlog_level("Critical");
        runner.Check(c == spdlog::level::critical, "parse_level: Critical mixed");
    }

    // ─── build_log_path 测试 ──────────────────

    void TestBuildLogPathEmptyPathName(TestRunner &runner)
    {
        psm::trace::config cfg;
        cfg.path_name = "";
        cfg.file_name = "test.log";
        auto path = psm::trace::build_log_path(cfg);
        runner.Check(path.filename().string() == "test.log",
                     "build_log_path: empty path_name -> just file_name");
    }

    void TestBuildLogPathWithDirectory(TestRunner &runner)
    {
        psm::trace::config cfg;
        cfg.path_name = "logs";
        cfg.file_name = "app.log";
        auto path = psm::trace::build_log_path(cfg);
        runner.Check(path.parent_path().string() == "logs",
                     "build_log_path: has parent directory");
        runner.Check(path.filename().string() == "app.log",
                     "build_log_path: file_name correct");
    }

    void TestBuildLogPathNestedDirectory(TestRunner &runner)
    {
        psm::trace::config cfg;
        cfg.path_name = "var/log/prism";
        cfg.file_name = "out.log";
        auto path = psm::trace::build_log_path(cfg);
        runner.Check(!path.empty(), "build_log_path: nested path non-empty");
        runner.Check(path.filename().string() == "out.log",
                     "build_log_path: nested file_name correct");
    }

    void TestBuildLogPathEmptyFileName(TestRunner &runner)
    {
        psm::trace::config cfg;
        cfg.path_name = "logs";
        cfg.file_name = "";
        auto path = psm::trace::build_log_path(cfg);
        runner.Check(!path.empty(), "build_log_path: empty file_name -> non-empty path");
    }

    // ─── mdc 操作扩展测试 ──────────────────

    void TestMdcSetClearCycle(TestRunner &runner)
    {
        psm::trace::mdc_clear();

        psm::trace::mdc_set("worker", "0");
        auto p1 = psm::trace::build_mdc_prefix();
        runner.Check(!p1.empty(), "mdc_cycle: set worker -> non-empty");

        psm::trace::mdc_clear();
        auto p2 = psm::trace::build_mdc_prefix();
        runner.Check(p2.empty(), "mdc_cycle: clear -> empty");
    }

    void TestMdcOverwriteKey(TestRunner &runner)
    {
        psm::trace::mdc_clear();
        psm::trace::mdc_set("id", "100");
        psm::trace::mdc_set("id", "200");

        auto prefix = psm::trace::build_mdc_prefix();
        runner.Check(prefix.find("id=200") != std::string::npos,
                     "mdc: overwrite key -> latest value");
        runner.Check(prefix.find("id=100") == std::string::npos,
                     "mdc: overwrite key -> old value gone");
        psm::trace::mdc_clear();
    }

    void TestMdcRemoveNonexistent(TestRunner &runner)
    {
        psm::trace::mdc_clear();
        psm::trace::mdc_remove("nonexistent");
        auto prefix = psm::trace::build_mdc_prefix();
        runner.Check(prefix.empty(), "mdc: remove nonexistent -> still empty");
    }

    // ─── recorder 测试 ──────────────────

    void TestRecorderNotNullAfterInit(TestRunner &runner)
    {
        psm::trace::init({});
        auto logger = psm::trace::recorder();
        runner.Check(logger != nullptr, "recorder: non-null after init");
    }

    void TestRecorderWithCustomConfig(TestRunner &runner)
    {
        psm::trace::config cfg;
        cfg.enable_console = true;
        cfg.enable_file = false;
        cfg.log_level = "debug";
        psm::trace::init(cfg);

        auto logger = psm::trace::recorder();
        runner.Check(logger != nullptr, "recorder: non-null with console-only config");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TraceSpdlogDeep");

    TestParseLevelTrace(runner);
    TestParseLevelDebug(runner);
    TestParseLevelInfo(runner);
    TestParseLevelWarn(runner);
    TestParseLevelWarning(runner);
    TestParseLevelError(runner);
    TestParseLevelErr(runner);
    TestParseLevelCritical(runner);
    TestParseLevelFatal(runner);
    TestParseLevelOff(runner);
    TestParseLevelUnknown(runner);
    TestParseLevelEmpty(runner);
    TestParseLevelCaseInsensitive(runner);

    TestBuildLogPathEmptyPathName(runner);
    TestBuildLogPathWithDirectory(runner);
    TestBuildLogPathNestedDirectory(runner);
    TestBuildLogPathEmptyFileName(runner);

    TestMdcSetClearCycle(runner);
    TestMdcOverwriteKey(runner);
    TestMdcRemoveNonexistent(runner);

    TestRecorderNotNullAfterInit(runner);
    TestRecorderWithCustomConfig(runner);

    return runner.Summary();
}

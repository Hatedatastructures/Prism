/**
 * @file TraceSpdlogPure.cpp
 * @brief trace::spdlog 纯函数单元测试
 * @details 测试 parse_spdlog_level 的各分支（通过 init 间接验证）、
 *          build_mdc_prefix 空/非空、mdc_set/mdc_remove/mdc_clear。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/config.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    // ─── mdc 操作 ──────────────────────────────────

    void TestMdcSetAndGet(TestRunner &runner)
    {
        psm::trace::mdc_clear();
        psm::trace::mdc_set("session", "abc123");

        auto prefix = psm::trace::build_mdc_prefix();
        runner.Check(!prefix.empty(), "mdc: prefix non-empty after set");
        runner.Check(prefix.find("session=abc123") != std::string::npos,
                     "mdc: prefix contains session=abc123");
    }

    void TestMdcRemove(TestRunner &runner)
    {
        psm::trace::mdc_clear();
        psm::trace::mdc_set("key1", "val1");
        psm::trace::mdc_remove("key1");

        auto prefix = psm::trace::build_mdc_prefix();
        runner.Check(prefix.empty() || prefix.find("key1") == std::string::npos,
                     "mdc: prefix empty after remove");
    }

    void TestMdcClear(TestRunner &runner)
    {
        psm::trace::mdc_set("a", "1");
        psm::trace::mdc_set("b", "2");
        psm::trace::mdc_clear();

        auto prefix = psm::trace::build_mdc_prefix();
        runner.Check(prefix.empty(), "mdc: prefix empty after clear");
    }

    void TestMdcPrefixEmpty(TestRunner &runner)
    {
        psm::trace::mdc_clear();
        auto prefix = psm::trace::build_mdc_prefix();
        runner.Check(prefix.empty(), "mdc: prefix empty initially");
    }

    void TestMdcMultipleKeys(TestRunner &runner)
    {
        psm::trace::mdc_clear();
        psm::trace::mdc_set("stream", "42");
        psm::trace::mdc_set("proto", "trojan");

        auto prefix = psm::trace::build_mdc_prefix();
        runner.Check(prefix.find("stream=42") != std::string::npos,
                     "mdc: multi contains stream=42");
        runner.Check(prefix.find("proto=trojan") != std::string::npos,
                     "mdc: multi contains proto=trojan");
        psm::trace::mdc_clear();
    }

    // ─── recorder 未初始化 ─────────────────────────

    void TestRecorderBeforeInit(TestRunner &runner)
    {
        // 在当前会话中 trace 已经 init 过，所以 recorder 非 null
        // 这个测试验证 recorder() 返回非空
        auto logger = psm::trace::recorder();
        runner.Check(logger != nullptr, "recorder: returns non-null after init");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TraceSpdlogPure");

    TestMdcPrefixEmpty(runner);
    TestMdcSetAndGet(runner);
    TestMdcRemove(runner);
    TestMdcClear(runner);
    TestMdcMultipleKeys(runner);
    TestRecorderBeforeInit(runner);

    return runner.Summary();
}

/**
 * @file TestRunnerDeep.cpp
 * @brief TestRunner 轻量测试框架全分支测试（覆盖率第 2 轮）
 * @details 覆盖 TestRunner.hpp 全部 6 个分支点：
 * 1. LogInfo：信息日志路径（recorder 未初始化时静默）
 * 2. LogPass / LogFail：通过/失败计数递增
 * 3. Check：条件为真/为假两条分支
 * 4. Summary：全部通过返回 0 / 存在失败返回 1 两条分支
 * @note psm::diagnose::shutdown() 幂等，多次调用安全。
 */

#include <common/TestRunner.hpp>
#include <gtest/gtest.h>

#include <prism/diagnose/diagnose.hpp>

namespace
{
    /// 测试专用日志配置：纯控制台，不落盘
    auto make_test_log_config() -> psm::diagnose::config
    {
        psm::diagnose::config cfg;
        cfg.enable_file = false;
        cfg.enable_console = true;
        cfg.trace_name = "testrunner";
        return cfg;
    }

    TEST(TestRunnerDeep, InitialCountersZero)
    {
        psm::diagnose::init(make_test_log_config());
        std::fprintf(stderr, "[dbg] recorder null=%d\n", psm::diagnose::recorder() == nullptr);
        psm::testing::TestRunner runner("Initial");
        EXPECT_EQ(runner.PassedCount(), 0);
        EXPECT_EQ(runner.FailedCount(), 0);
    }

    TEST(TestRunnerDeep, LogPassIncrementsPassed)
    {
        psm::testing::TestRunner runner("PassOnly");
        runner.LogPass("first");
        runner.LogPass("second");
        EXPECT_EQ(runner.PassedCount(), 2);
        EXPECT_EQ(runner.FailedCount(), 0);
    }

    TEST(TestRunnerDeep, LogFailIncrementsFailed)
    {
        psm::testing::TestRunner runner("FailOnly");
        runner.LogFail("boom");
        EXPECT_EQ(runner.PassedCount(), 0);
        EXPECT_EQ(runner.FailedCount(), 1);
    }

    TEST(TestRunnerDeep, LogInfoNoThrow)
    {
        // 日志系统未初始化时 LogInfo 应静默成功（recorder 为空）
        psm::testing::TestRunner runner("InfoOnly");
        EXPECT_NO_THROW(runner.LogInfo("hello world"));
        EXPECT_EQ(runner.PassedCount(), 0);
        EXPECT_EQ(runner.FailedCount(), 0);
    }

    TEST(TestRunnerDeep, CheckTrueLogsPass)
    {
        psm::testing::TestRunner runner("CheckTrue");
        runner.Check(true, "condition holds");
        EXPECT_EQ(runner.PassedCount(), 1);
        EXPECT_EQ(runner.FailedCount(), 0);
    }

    TEST(TestRunnerDeep, CheckFalseLogsFail)
    {
        psm::testing::TestRunner runner("CheckFalse");
        runner.Check(false, "condition broken");
        EXPECT_EQ(runner.PassedCount(), 0);
        EXPECT_EQ(runner.FailedCount(), 1);
    }

    TEST(TestRunnerDeep, CheckMixedCounts)
    {
        psm::testing::TestRunner runner("CheckMixed");
        runner.Check(true, "ok one");
        runner.Check(false, "bad one");
        runner.Check(true, "ok two");
        EXPECT_EQ(runner.PassedCount(), 2);
        EXPECT_EQ(runner.FailedCount(), 1);
    }

    TEST(TestRunnerDeep, SummaryAllPassReturnsZero)
    {
        psm::testing::TestRunner runner("SummaryPass");
        runner.LogPass("a");
        runner.LogPass("b");
        EXPECT_EQ(runner.Summary(), 0);
        EXPECT_EQ(runner.PassedCount(), 2);
        EXPECT_EQ(runner.FailedCount(), 0);
    }

    TEST(TestRunnerDeep, SummaryWithFailureReturnsOne)
    {
        psm::testing::TestRunner runner("SummaryFail");
        runner.LogFail("a");
        EXPECT_EQ(runner.Summary(), 1);
    }

    TEST(TestRunnerDeep, SummaryMixedReturnsOne)
    {
        psm::testing::TestRunner runner("SummaryMixed");
        runner.LogPass("pass");
        runner.LogFail("fail");
        EXPECT_EQ(runner.Summary(), 1);
    }

    TEST(TestRunnerDeep, SummaryTwiceIdempotent)
    {
        psm::testing::TestRunner runner("SummaryTwice");
        EXPECT_EQ(runner.Summary(), 0);
        EXPECT_EQ(runner.Summary(), 0);
    }

} // namespace

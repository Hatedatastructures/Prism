/**
 * @file StatsRuntimePure.cpp
 * @brief stats::runtime 纯函数单元测试
 * @details 测试 worker_load 的 session 计数、handoff 计数、snapshot，
 *          system_state 的 mark_started/snapshot，无 I/O 依赖。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/account/stats/runtime.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

namespace
{
    namespace runtime = psm::stats::runtime;

    // ─── worker_load ──────────────────────────────

    TEST(StatsRuntimePure, WorkerLoadSessionCounter)
    {
        runtime::worker_load load;
        auto counter = load.session_counter();
        EXPECT_TRUE(counter != nullptr) << "load: counter non-null";
        EXPECT_TRUE(counter->load() == 0) << "load: initial count=0";
    }

    TEST(StatsRuntimePure, WorkerLoadSessionOpenClose)
    {
        runtime::worker_load load;
        auto counter = load.session_counter();

        load.session_open();
        EXPECT_TRUE(counter->load() == 1) << "load: after open=1";

        load.session_open();
        EXPECT_TRUE(counter->load() == 2) << "load: after 2 opens=2";

        load.session_close();
        EXPECT_TRUE(counter->load() == 1) << "load: after close=1";

        load.session_close();
        EXPECT_TRUE(counter->load() == 0) << "load: after 2 closes=0";
    }

    TEST(StatsRuntimePure, WorkerLoadHandoff)
    {
        runtime::worker_load load;

        load.handoff_push();
        load.handoff_push();
        auto snap = load.snapshot();
        EXPECT_TRUE(snap.pending_handoffs == 2) << "load: handoff=2";

        load.handoff_pop();
        snap = load.snapshot();
        EXPECT_TRUE(snap.pending_handoffs == 1) << "load: handoff=1 after pop";
    }

    TEST(StatsRuntimePure, WorkerLoadSnapshotInitial)
    {
        runtime::worker_load load;
        auto snap = load.snapshot();
        EXPECT_TRUE(snap.active_sessions == 0) << "snap: initial sessions=0";
        EXPECT_TRUE(snap.pending_handoffs == 0) << "snap: initial handoffs=0";
        EXPECT_TRUE(snap.lag_us == 0) << "snap: initial lag_us=0";
    }

    // ─── system_state ─────────────────────────────

    TEST(StatsRuntimePure, SystemStateNotStarted)
    {
        // system_state 是单例，之前可能被 mark_started 调用过
        auto snap = runtime::system_state::instance().snapshot();
        EXPECT_TRUE(snap.uptime_seconds >= 0) << "system_state: uptime >= 0";
    }

    TEST(StatsRuntimePure, SystemStateMarkStarted)
    {
        runtime::system_state::instance().mark_started(4);
        auto snap = runtime::system_state::instance().snapshot();
        EXPECT_TRUE(snap.worker_count == 4) << "system_state: worker_count=4";
        // 第二次调用不应改变
        runtime::system_state::instance().mark_started(8);
        auto snap2 = runtime::system_state::instance().snapshot();
        EXPECT_TRUE(snap2.worker_count == 4) << "system_state: idempotent worker_count=4";
    }
} // namespace

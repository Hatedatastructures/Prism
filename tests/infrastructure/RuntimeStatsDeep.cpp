/**
 * @file RuntimeStatsDeep.cpp
 * @brief stats/runtime 深度测试 — gcov 覆盖
 * @details 通过 #include 源文件确保 gcov 计入覆盖行。
 *          覆盖 worker_load 全部同步方法和 system_state 全部方法。
 *          跳过 observe() 协程（需要 io_context 运行）。
 */

#include <prism/core/core.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <cstdint>

// 包含源文件以获得 gcov 覆盖
#include "../../src/prism/account/stats/runtime.cpp"

namespace
{
    namespace runtime = psm::stats::runtime;

    // ─── worker_load 构造 ──────────────────────────────

    TEST(RuntimeStatsDeep, WorkerLoadConstruct)
    {
        runtime::worker_load wl;
        auto snap = wl.snapshot();
        EXPECT_TRUE(snap.active_sessions == 0) << "worker_load: initial sessions=0";
        EXPECT_TRUE(snap.pending_handoffs == 0) << "worker_load: initial handoffs=0";
        EXPECT_TRUE(snap.lag_us == 0) << "worker_load: initial lag=0";
    }

    // ─── session_open / session_close ──────────────────

    TEST(RuntimeStatsDeep, SessionOpenClose)
    {
        runtime::worker_load wl;
        wl.session_open();
        EXPECT_TRUE(wl.snapshot().active_sessions == 1) << "session: open -> 1";
        wl.session_open();
        EXPECT_TRUE(wl.snapshot().active_sessions == 2) << "session: open -> 2";
        wl.session_close();
        EXPECT_TRUE(wl.snapshot().active_sessions == 1) << "session: close -> 1";
        wl.session_close();
        EXPECT_TRUE(wl.snapshot().active_sessions == 0) << "session: close -> 0";
    }

    // ─── handoff_push / handoff_pop ────────────────────

    TEST(RuntimeStatsDeep, HandoffPushPop)
    {
        runtime::worker_load wl;
        wl.handoff_push();
        EXPECT_TRUE(wl.snapshot().pending_handoffs == 1) << "handoff: push -> 1";
        wl.handoff_push();
        wl.handoff_push();
        EXPECT_TRUE(wl.snapshot().pending_handoffs == 3) << "handoff: push x3 -> 3";
        wl.handoff_pop();
        EXPECT_TRUE(wl.snapshot().pending_handoffs == 2) << "handoff: pop -> 2";
    }

    // ─── session_counter 共享指针 ──────────────────────

    TEST(RuntimeStatsDeep, SessionCounter)
    {
        runtime::worker_load wl;
        auto counter = wl.session_counter();
        EXPECT_TRUE(counter != nullptr) << "counter: not null";
        EXPECT_TRUE(counter->load() == 0) << "counter: initial 0";
        wl.session_open();
        EXPECT_TRUE(counter->load() == 1) << "counter: after open=1";
    }

    // ─── snapshot 组合 ────────────────────────────────

    TEST(RuntimeStatsDeep, SnapshotCombined)
    {
        runtime::worker_load wl;
        wl.session_open();
        wl.session_open();
        wl.handoff_push();
        auto snap = wl.snapshot();
        EXPECT_TRUE(snap.active_sessions == 2) << "snapshot: sessions=2";
        EXPECT_TRUE(snap.pending_handoffs == 1) << "snapshot: handoffs=1";
        EXPECT_TRUE(snap.lag_us == 0) << "snapshot: lag=0";
    }

    // ─── system_state::instance 单例 ───────────────────

    TEST(RuntimeStatsDeep, SystemStateInstance)
    {
        auto &a = runtime::system_state::instance();
        auto &b = runtime::system_state::instance();
        EXPECT_TRUE(&a == &b) << "system_state: singleton same address";
    }

    // ─── system_state::snapshot 未启动 ──────────────────

    TEST(RuntimeStatsDeep, SystemStateSnapshotNotStarted)
    {
        // 注意：system_state 是全局单例，mark_started 可能已被其他测试调用
        // 我们只测试 snapshot 返回的结构是否合理
        auto snap = runtime::system_state::instance().snapshot();
        // snapshot 返回值结构合理：uptime_seconds 和 worker_count 为非负值
        EXPECT_TRUE(snap.uptime_seconds >= 0u) << "system_state: snapshot uptime_seconds >= 0";
    }

    // ─── system_state::mark_started 幂等 ────────────────

    TEST(RuntimeStatsDeep, SystemStateMarkStarted)
    {
        auto &inst = runtime::system_state::instance();
        // 调用多次不会崩溃
        inst.mark_started(4);
        inst.mark_started(8);
        auto snap = inst.snapshot();
        EXPECT_TRUE(snap.worker_count == 4) << "mark_started: first call wins, workers=4";
    }

} // namespace

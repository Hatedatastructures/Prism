/**
 * @file RuntimeDeep.cpp
 * @brief stats/runtime 深度纯函数测试
 * @details 通过 #include 源文件访问 runtime.cpp 中所有同步函数，
 *          覆盖 worker_load 构造/session_open/close/handoff_push/pop、
 *          session_counter、snapshot、system_state 单例/mark_started/snapshot。
 *          observe() 协程不在本测试范围。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/diagnose/log.hpp>

#include <gtest/gtest.h>

#include "../../src/prism/user/stats/runtime.cpp"

namespace
{
    namespace runtime = psm::stats::runtime;

    // ─── worker_load 构造 + session ─────────────

    TEST(RuntimeDeep, WorkerLoadConstruct)
    {
        runtime::worker_load wl;
        auto s = wl.snapshot();
        EXPECT_EQ(s.active_sessions, 0) << "worker_load: initial sessions=0";
        EXPECT_EQ(s.pending_handoffs, 0) << "worker_load: initial handoffs=0";
        EXPECT_EQ(s.lag_us, 0) << "worker_load: initial lag=0";
    }

    TEST(RuntimeDeep, WorkerLoadSessionOpen)
    {
        runtime::worker_load wl;
        wl.session_open();
        auto s = wl.snapshot();
        EXPECT_EQ(s.active_sessions, 1) << "worker_load: session_open -> 1";
    }

    TEST(RuntimeDeep, WorkerLoadSessionClose)
    {
        runtime::worker_load wl;
        wl.session_open();
        wl.session_open();
        wl.session_close();
        auto s = wl.snapshot();
        EXPECT_EQ(s.active_sessions, 1) << "worker_load: open x2 close x1 -> 1";
    }

    TEST(RuntimeDeep, WorkerLoadSessionMultiple)
    {
        runtime::worker_load wl;
        for (int i = 0; i < 100; ++i)
        {
            wl.session_open();
        }
        for (int i = 0; i < 50; ++i)
        {
            wl.session_close();
        }
        auto s = wl.snapshot();
        EXPECT_EQ(s.active_sessions, 50) << "worker_load: 100 open 50 close -> 50";
    }

    // ─── handoff ──────────────────────────────

    TEST(RuntimeDeep, WorkerLoadHandoffPush)
    {
        runtime::worker_load wl;
        wl.handoff_push();
        auto s = wl.snapshot();
        EXPECT_EQ(s.pending_handoffs, 1) << "worker_load: handoff_push -> 1";
    }

    TEST(RuntimeDeep, WorkerLoadHandoffPop)
    {
        runtime::worker_load wl;
        wl.handoff_push();
        wl.handoff_push();
        wl.handoff_pop();
        auto s = wl.snapshot();
        EXPECT_EQ(s.pending_handoffs, 1) << "worker_load: push x2 pop x1 -> 1";
    }

    TEST(RuntimeDeep, WorkerLoadHandoffMultiple)
    {
        runtime::worker_load wl;
        for (int i = 0; i < 200; ++i)
        {
            wl.handoff_push();
        }
        for (int i = 0; i < 200; ++i)
        {
            wl.handoff_pop();
        }
        auto s = wl.snapshot();
        EXPECT_EQ(s.pending_handoffs, 0) << "worker_load: 200 push 200 pop -> 0";
    }

    // ─── session_counter ──────────────────────

    TEST(RuntimeDeep, WorkerLoadSessionCounter)
    {
        runtime::worker_load wl;
        auto counter = wl.session_counter();
        EXPECT_NE(counter, nullptr) << "worker_load: session_counter not null";
        EXPECT_TRUE(counter->load() == 0) << "worker_load: counter initial=0";

        wl.session_open();
        EXPECT_TRUE(counter->load() == 1) << "worker_load: counter after open=1";

        auto counter2 = wl.session_counter();
        EXPECT_EQ(counter.get(), counter2.get()) << "worker_load: same counter ptr";
    }

    // ─── snapshot ─────────────────────────────

    TEST(RuntimeDeep, WorkerLoadSnapshotAfterOps)
    {
        runtime::worker_load wl;
        wl.session_open();
        wl.session_open();
        wl.handoff_push();
        auto s = wl.snapshot();
        EXPECT_EQ(s.active_sessions, 2) << "worker_load: snapshot sessions=2";
        EXPECT_EQ(s.pending_handoffs, 1) << "worker_load: snapshot handoffs=1";
    }

    // ─── system_state 单例 ─────────────────────

    TEST(RuntimeDeep, SystemStateInstance)
    {
        auto &a = runtime::system_state::instance();
        auto &b = runtime::system_state::instance();
        EXPECT_EQ(&a, &b) << "system_state: same instance";
    }

    TEST(RuntimeDeep, SystemStateMarkStarted)
    {
        auto &st = runtime::system_state::instance();
        st.mark_started(8);
        auto s = st.snapshot();
        EXPECT_EQ(s.worker_count, 8) << "system_state: worker_count=8 after mark_started";
        EXPECT_GE(s.uptime_seconds, 0) << "system_state: uptime >= 0 after mark_started";
    }

    TEST(RuntimeDeep, SystemStateMarkStartedIdempotent)
    {
        auto &st = runtime::system_state::instance();
        // 单例可能已被同进程其它用例标记：未标记则设置生效，已标记则幂等保留
        auto before = st.snapshot();
        st.mark_started(42);
        auto after = st.snapshot();
        if (before.worker_count == 0)
        {
            EXPECT_EQ(after.worker_count, 42)
                << "system_state: first mark_started sets 42";
        }
        else
        {
            EXPECT_EQ(after.worker_count, before.worker_count)
                << "system_state: idempotent -> worker_count unchanged";
        }
    }

    TEST(RuntimeDeep, SystemStateSnapshot)
    {
        auto &st = runtime::system_state::instance();
        st.mark_started(16);
        auto s = st.snapshot();
        EXPECT_GE(s.uptime_seconds, 0) << "system_state: snapshot uptime non-negative";
        EXPECT_GE(s.worker_count, 1) << "system_state: snapshot worker_count marked";
    }

} // namespace

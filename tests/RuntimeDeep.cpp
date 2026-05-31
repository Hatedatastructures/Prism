/**
 * @file RuntimeDeep.cpp
 * @brief stats/runtime 深度纯函数测试
 * @details 通过 #include 源文件访问 runtime.cpp 中所有同步函数，
 *          覆盖 worker_load 构造/session_open/close/handoff_push/pop、
 *          session_counter、snapshot、system_state 单例/mark_started/snapshot。
 *          observe() 协程不在本测试范围。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include "../src/prism/stats/runtime.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace runtime = psm::stats::runtime;

    // ─── worker_load 构造 + session ─────────────

    void TestWorkerLoadConstruct(TestRunner &runner)
    {
        runtime::worker_load wl;
        auto s = wl.snapshot();
        runner.Check(s.active_sessions == 0, "worker_load: initial sessions=0");
        runner.Check(s.pending_handoffs == 0, "worker_load: initial handoffs=0");
        runner.Check(s.lag_us == 0, "worker_load: initial lag=0");
    }

    void TestWorkerLoadSessionOpen(TestRunner &runner)
    {
        runtime::worker_load wl;
        wl.session_open();
        auto s = wl.snapshot();
        runner.Check(s.active_sessions == 1, "worker_load: session_open -> 1");
    }

    void TestWorkerLoadSessionClose(TestRunner &runner)
    {
        runtime::worker_load wl;
        wl.session_open();
        wl.session_open();
        wl.session_close();
        auto s = wl.snapshot();
        runner.Check(s.active_sessions == 1, "worker_load: open x2 close x1 -> 1");
    }

    void TestWorkerLoadSessionMultiple(TestRunner &runner)
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
        runner.Check(s.active_sessions == 50, "worker_load: 100 open 50 close -> 50");
    }

    // ─── handoff ──────────────────────────────

    void TestWorkerLoadHandoffPush(TestRunner &runner)
    {
        runtime::worker_load wl;
        wl.handoff_push();
        auto s = wl.snapshot();
        runner.Check(s.pending_handoffs == 1, "worker_load: handoff_push -> 1");
    }

    void TestWorkerLoadHandoffPop(TestRunner &runner)
    {
        runtime::worker_load wl;
        wl.handoff_push();
        wl.handoff_push();
        wl.handoff_pop();
        auto s = wl.snapshot();
        runner.Check(s.pending_handoffs == 1, "worker_load: push x2 pop x1 -> 1");
    }

    void TestWorkerLoadHandoffMultiple(TestRunner &runner)
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
        runner.Check(s.pending_handoffs == 0, "worker_load: 200 push 200 pop -> 0");
    }

    // ─── session_counter ──────────────────────

    void TestWorkerLoadSessionCounter(TestRunner &runner)
    {
        runtime::worker_load wl;
        auto counter = wl.session_counter();
        runner.Check(counter != nullptr, "worker_load: session_counter not null");
        runner.Check(counter->load() == 0, "worker_load: counter initial=0");

        wl.session_open();
        runner.Check(counter->load() == 1, "worker_load: counter after open=1");

        auto counter2 = wl.session_counter();
        runner.Check(counter.get() == counter2.get(), "worker_load: same counter ptr");
    }

    // ─── snapshot ─────────────────────────────

    void TestWorkerLoadSnapshotAfterOps(TestRunner &runner)
    {
        runtime::worker_load wl;
        wl.session_open();
        wl.session_open();
        wl.handoff_push();
        auto s = wl.snapshot();
        runner.Check(s.active_sessions == 2, "worker_load: snapshot sessions=2");
        runner.Check(s.pending_handoffs == 1, "worker_load: snapshot handoffs=1");
    }

    // ─── system_state 单例 ─────────────────────

    void TestSystemStateInstance(TestRunner &runner)
    {
        auto &a = runtime::system_state::instance();
        auto &b = runtime::system_state::instance();
        runner.Check(&a == &b, "system_state: same instance");
    }

    void TestSystemStateMarkStarted(TestRunner &runner)
    {
        // 使用单例，先获取引用
        auto &st = runtime::system_state::instance();
        st.mark_started(8);
        auto s = st.snapshot();
        runner.Check(s.worker_count == 8, "system_state: worker_count=8");
        runner.Check(s.uptime_seconds >= 0, "system_state: uptime >= 0 after mark_started");
    }

    void TestSystemStateMarkStartedIdempotent(TestRunner &runner)
    {
        auto &st = runtime::system_state::instance();
        // 第二次调用应为空操作
        st.mark_started(999);
        auto s = st.snapshot();
        // worker_count 应仍为之前设置的值（8）
        runner.Check(s.worker_count == 8, "system_state: idempotent -> still 8");
    }

    void TestSystemStateSnapshot(TestRunner &runner)
    {
        auto &st = runtime::system_state::instance();
        auto s = st.snapshot();
        runner.Check(s.uptime_seconds >= 0, "system_state: snapshot uptime non-negative");
        runner.Check(s.worker_count == 8, "system_state: snapshot worker_count=8");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RuntimeDeep");

    TestWorkerLoadConstruct(runner);
    TestWorkerLoadSessionOpen(runner);
    TestWorkerLoadSessionClose(runner);
    TestWorkerLoadSessionMultiple(runner);

    TestWorkerLoadHandoffPush(runner);
    TestWorkerLoadHandoffPop(runner);
    TestWorkerLoadHandoffMultiple(runner);

    TestWorkerLoadSessionCounter(runner);
    TestWorkerLoadSnapshotAfterOps(runner);

    TestSystemStateInstance(runner);
    TestSystemStateMarkStarted(runner);
    TestSystemStateMarkStartedIdempotent(runner);
    TestSystemStateSnapshot(runner);

    return runner.Summary();
}

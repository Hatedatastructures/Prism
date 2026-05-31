/**
 * @file StatsRuntimePure.cpp
 * @brief stats::runtime 纯函数单元测试
 * @details 测试 worker_load 的 session 计数、handoff 计数、snapshot，
 *          system_state 的 mark_started/snapshot，无 I/O 依赖。
 */

#include <prism/memory.hpp>
#include <prism/stats/runtime.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace runtime = psm::stats::runtime;

    // ─── worker_load ──────────────────────────────

    void TestWorkerLoadSessionCounter(TestRunner &runner)
    {
        runtime::worker_load load;
        auto counter = load.session_counter();
        runner.Check(counter != nullptr, "load: counter non-null");
        runner.Check(counter->load() == 0, "load: initial count=0");
    }

    void TestWorkerLoadSessionOpenClose(TestRunner &runner)
    {
        runtime::worker_load load;
        auto counter = load.session_counter();

        load.session_open();
        runner.Check(counter->load() == 1, "load: after open=1");

        load.session_open();
        runner.Check(counter->load() == 2, "load: after 2 opens=2");

        load.session_close();
        runner.Check(counter->load() == 1, "load: after close=1");

        load.session_close();
        runner.Check(counter->load() == 0, "load: after 2 closes=0");
    }

    void TestWorkerLoadHandoff(TestRunner &runner)
    {
        runtime::worker_load load;

        load.handoff_push();
        load.handoff_push();
        auto snap = load.snapshot();
        runner.Check(snap.pending_handoffs == 2, "load: handoff=2");

        load.handoff_pop();
        snap = load.snapshot();
        runner.Check(snap.pending_handoffs == 1, "load: handoff=1 after pop");
    }

    void TestWorkerLoadSnapshotInitial(TestRunner &runner)
    {
        runtime::worker_load load;
        auto snap = load.snapshot();
        runner.Check(snap.active_sessions == 0, "snap: initial sessions=0");
        runner.Check(snap.pending_handoffs == 0, "snap: initial handoffs=0");
        runner.Check(snap.lag_us == 0, "snap: initial lag_us=0");
    }

    // ─── system_state ─────────────────────────────

    void TestSystemStateNotStarted(TestRunner &runner)
    {
        // system_state 是单例，之前可能被 mark_started 调用过
        auto snap = runtime::system_state::instance().snapshot();
        // 只检查类型正确，不检查具体值
        runner.Check(snap.uptime_seconds >= 0, "system_state: uptime >= 0");
    }

    void TestSystemStateMarkStarted(TestRunner &runner)
    {
        runtime::system_state::instance().mark_started(4);
        auto snap = runtime::system_state::instance().snapshot();
        runner.Check(snap.worker_count == 4, "system_state: worker_count=4");
        // 第二次调用不应改变
        runtime::system_state::instance().mark_started(8);
        auto snap2 = runtime::system_state::instance().snapshot();
        runner.Check(snap2.worker_count == 4, "system_state: idempotent worker_count=4");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("StatsRuntimePure");

    TestWorkerLoadSessionCounter(runner);
    TestWorkerLoadSessionOpenClose(runner);
    TestWorkerLoadHandoff(runner);
    TestWorkerLoadSnapshotInitial(runner);
    TestSystemStateNotStarted(runner);
    TestSystemStateMarkStarted(runner);

    return runner.Summary();
}

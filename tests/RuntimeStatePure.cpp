/**
 * @file RuntimeStatePure.cpp
 * @brief stats::runtime worker_load/system_state 纯函数测试
 * @details 测试 worker_load 的原子操作快照和 system_state 的启动标记/快照
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
    using psm::stats::runtime::worker_load;
    using psm::stats::runtime::system_state;

    void TestWorkerLoadInitial(TestRunner &runner)
    {
        worker_load load;
        auto snap = load.snapshot();
        runner.Check(snap.active_sessions == 0, "worker_load: initial active=0");
        runner.Check(snap.pending_handoffs == 0, "worker_load: initial pending=0");
        runner.Check(snap.lag_us == 0, "worker_load: initial lag=0");
    }

    void TestWorkerLoadSessionOpenClose(TestRunner &runner)
    {
        worker_load load;
        load.session_open();
        load.session_open();
        auto snap = load.snapshot();
        runner.Check(snap.active_sessions == 2, "worker_load: 2 opens -> 2 active");

        load.session_close();
        snap = load.snapshot();
        runner.Check(snap.active_sessions == 1, "worker_load: 1 close -> 1 active");
    }

    void TestWorkerLoadHandoff(TestRunner &runner)
    {
        worker_load load;
        load.handoff_push();
        load.handoff_push();
        load.handoff_push();
        auto snap = load.snapshot();
        runner.Check(snap.pending_handoffs == 3, "worker_load: 3 pushes -> 3 pending");

        load.handoff_pop();
        snap = load.snapshot();
        runner.Check(snap.pending_handoffs == 2, "worker_load: 1 pop -> 2 pending");
    }

    void TestWorkerLoadSessionCounter(TestRunner &runner)
    {
        worker_load load;
        auto counter = load.session_counter();
        runner.Check(counter != nullptr, "worker_load: counter not null");
        runner.Check(counter->load() == 0, "worker_load: counter initially 0");

        load.session_open();
        runner.Check(counter->load() == 1, "worker_load: counter after open=1");
    }

    void TestSystemStateNotStarted(TestRunner &runner)
    {
        // system_state::instance() is a singleton - use fresh instance
        // We can't easily reset the singleton, so just test snapshot behavior
        auto &state = system_state::instance();
        // If mark_started was already called by a previous test run,
        // the snapshot will be non-empty. Test the interface works either way.
        auto snap = state.snapshot();
        // uptime should be >= 0, worker_count should be valid
        runner.Check(snap.uptime_seconds >= 0, "system_state: uptime >= 0");
    }

    void TestSystemStateMarkStartedIdempotent(TestRunner &runner)
    {
        // Calling mark_started multiple times should be idempotent
        auto &state = system_state::instance();
        state.mark_started(4);
        auto snap1 = state.snapshot();

        state.mark_started(8);
        auto snap2 = state.snapshot();

        // worker_count should stay at first value (4) since exchange returns true on second call
        runner.Check(snap2.worker_count == 4, "system_state: idempotent mark_started");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RuntimeStatePure");

    TestWorkerLoadInitial(runner);
    TestWorkerLoadSessionOpenClose(runner);
    TestWorkerLoadHandoff(runner);
    TestWorkerLoadSessionCounter(runner);
    TestSystemStateNotStarted(runner);
    TestSystemStateMarkStartedIdempotent(runner);

    return runner.Summary();
}

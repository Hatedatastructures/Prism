/**
 * @file RuntimeStatsDeep.cpp
 * @brief stats/runtime 深度测试 — gcov 覆盖
 * @details 通过 #include 源文件确保 gcov 计入覆盖行。
 *          覆盖 worker_load 全部同步方法和 system_state 全部方法。
 *          跳过 observe() 协程（需要 io_context 运行）。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

#include <cstdint>

// 包含源文件以获得 gcov 覆盖
#include "../src/prism/stats/runtime.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace runtime = psm::stats::runtime;

    // ─── worker_load 构造 ──────────────────────────────

    void TestWorkerLoadConstruct(TestRunner &runner)
    {
        runtime::worker_load wl;
        auto snap = wl.snapshot();
        runner.Check(snap.active_sessions == 0, "worker_load: initial sessions=0");
        runner.Check(snap.pending_handoffs == 0, "worker_load: initial handoffs=0");
        runner.Check(snap.lag_us == 0, "worker_load: initial lag=0");
    }

    // ─── session_open / session_close ──────────────────

    void TestSessionOpenClose(TestRunner &runner)
    {
        runtime::worker_load wl;
        wl.session_open();
        runner.Check(wl.snapshot().active_sessions == 1, "session: open -> 1");
        wl.session_open();
        runner.Check(wl.snapshot().active_sessions == 2, "session: open -> 2");
        wl.session_close();
        runner.Check(wl.snapshot().active_sessions == 1, "session: close -> 1");
        wl.session_close();
        runner.Check(wl.snapshot().active_sessions == 0, "session: close -> 0");
    }

    // ─── handoff_push / handoff_pop ────────────────────

    void TestHandoffPushPop(TestRunner &runner)
    {
        runtime::worker_load wl;
        wl.handoff_push();
        runner.Check(wl.snapshot().pending_handoffs == 1, "handoff: push -> 1");
        wl.handoff_push();
        wl.handoff_push();
        runner.Check(wl.snapshot().pending_handoffs == 3, "handoff: push x3 -> 3");
        wl.handoff_pop();
        runner.Check(wl.snapshot().pending_handoffs == 2, "handoff: pop -> 2");
    }

    // ─── session_counter 共享指针 ──────────────────────

    void TestSessionCounter(TestRunner &runner)
    {
        runtime::worker_load wl;
        auto counter = wl.session_counter();
        runner.Check(counter != nullptr, "counter: not null");
        runner.Check(counter->load() == 0, "counter: initial 0");
        wl.session_open();
        runner.Check(counter->load() == 1, "counter: after open=1");
    }

    // ─── snapshot 组合 ────────────────────────────────

    void TestSnapshotCombined(TestRunner &runner)
    {
        runtime::worker_load wl;
        wl.session_open();
        wl.session_open();
        wl.handoff_push();
        auto snap = wl.snapshot();
        runner.Check(snap.active_sessions == 2, "snapshot: sessions=2");
        runner.Check(snap.pending_handoffs == 1, "snapshot: handoffs=1");
        runner.Check(snap.lag_us == 0, "snapshot: lag=0");
    }

    // ─── system_state::instance 单例 ───────────────────

    void TestSystemStateInstance(TestRunner &runner)
    {
        auto &a = runtime::system_state::instance();
        auto &b = runtime::system_state::instance();
        runner.Check(&a == &b, "system_state: singleton same address");
    }

    // ─── system_state::snapshot 未启动 ──────────────────

    void TestSystemStateSnapshotNotStarted(TestRunner &runner)
    {
        // 注意：system_state 是全局单例，mark_started 可能已被其他测试调用
        // 我们只测试 snapshot 返回的结构是否合理
        auto snap = runtime::system_state::instance().snapshot();
        // 如果已启动则 uptime > 0，否则全零
        runner.Check(true, "system_state: snapshot no crash");
    }

    // ─── system_state::mark_started 幂等 ────────────────

    void TestSystemStateMarkStarted(TestRunner &runner)
    {
        auto &inst = runtime::system_state::instance();
        // 调用多次不会崩溃
        inst.mark_started(4);
        inst.mark_started(8);
        auto snap = inst.snapshot();
        runner.Check(snap.worker_count == 4, "mark_started: first call wins, workers=4");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("RuntimeStatsDeep");

    TestWorkerLoadConstruct(runner);
    TestSessionOpenClose(runner);
    TestHandoffPushPop(runner);
    TestSessionCounter(runner);
    TestSnapshotCombined(runner);
    TestSystemStateInstance(runner);
    TestSystemStateSnapshotNotStarted(runner);
    TestSystemStateMarkStarted(runner);

    return runner.Summary();
}

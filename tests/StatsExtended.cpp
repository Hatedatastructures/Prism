/**
 * @file StatsExtended.cpp
 * @brief Stats 模块扩展测试 — counter/gauge/traffic_state/worker_load 分支覆盖
 */

#include <prism/memory.hpp>
#include <prism/protocol/types.hpp>
#include <prism/stats/stats.hpp>
#include <prism/trace/spdlog.hpp>

#include <atomic>
#include <cstdint>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    void TestCounterBasic(TestRunner &runner)
    {
        psm::stats::counter c;
        runner.Check(c.load() == 0, "counter: initial=0");

        c.increment();
        runner.Check(c.load() == 1, "counter: increment to 1");

        c.increment(9);
        runner.Check(c.load() == 10, "counter: increment(9) to 10");

        c.decrement(3);
        runner.Check(c.load() == 7, "counter: decrement(3) to 7");

        c.decrement();
        runner.Check(c.load() == 6, "counter: decrement to 6");
    }

    void TestCounterExchange(TestRunner &runner)
    {
        psm::stats::counter c;
        c.increment(42);
        auto old = c.exchange(100);
        runner.Check(old == 42, "counter: exchange old=42");
        runner.Check(c.load() == 100, "counter: exchange new=100");
    }

    void TestCounterOverflow(TestRunner &runner)
    {
        psm::stats::counter c;
        c.increment(UINT64_MAX);
        runner.Check(c.load() == UINT64_MAX, "counter: max uint64");
    }

    void TestGaugeBasic(TestRunner &runner)
    {
        psm::stats::gauge g(0.5);
        runner.Check(g.value() == 0.0, "gauge: initial=0.0");

        g.update(100.0);
        runner.Check(g.value() > 0, "gauge: update > 0");

        g.reset();
        runner.Check(g.value() == 0.0, "gauge: reset to 0.0");
    }

    void TestGaugetDefaultAlpha(TestRunner &runner)
    {
        psm::stats::gauge g;
        g.update(1000.0);
        runner.Check(g.value() > 0, "gauge: default alpha update > 0");
    }

    void TestGaugeSmoothing(TestRunner &runner)
    {
        psm::stats::gauge g(0.0);
        g.update(50.0);
        runner.Check(g.value() == 50.0, "gauge: alpha=0 => value=sample");

        psm::stats::gauge g2(1.0);
        g2.update(50.0);
        runner.Check(g2.value() == 0.0, "gauge: alpha=1 => value unchanged");
    }

    void TestTrafficStateBasic(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state ts;
        auto snap = ts.snapshot();
        runner.Check(snap.total_connections == 0, "traffic: initial connections=0");
        runner.Check(snap.total_active == 0, "traffic: initial active=0");

        ts.on_connect();
        snap = ts.snapshot();
        runner.Check(snap.total_connections == 1, "traffic: on_connect connections=1");
        runner.Check(snap.total_active == 1, "traffic: on_connect active=1");
    }

    void TestTrafficStateProtocol(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state ts;
        ts.on_connect();
        ts.on_protocol_detected(psm::protocol::protocol_type::http);

        auto snap = ts.snapshot();
        auto idx = static_cast<std::uint8_t>(psm::protocol::protocol_type::http);
        runner.Check(snap.protocols[idx].connections == 1, "traffic: http connections=1");
        runner.Check(snap.protocols[idx].active == 1, "traffic: http active=1");

        ts.on_disconnect(psm::protocol::protocol_type::http);
        snap = ts.snapshot();
        runner.Check(snap.total_active == 0, "traffic: after disconnect active=0");
        runner.Check(snap.protocols[idx].active == 0, "traffic: after disconnect http active=0");
    }

    void TestTrafficStateFlush(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state ts;
        ts.flush_traffic(psm::protocol::protocol_type::socks5, 1024, 2048);
        auto snap = ts.snapshot();
        runner.Check(snap.total_uplink == 1024, "traffic: uplink=1024");
        runner.Check(snap.total_downlink == 2048, "traffic: downlink=2048");
    }

    void TestTrafficStateFlushZero(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state ts;
        ts.flush_traffic(psm::protocol::protocol_type::http, 0, 0);
        auto snap = ts.snapshot();
        runner.Check(snap.total_uplink == 0, "traffic: flush zero uplink");
        runner.Check(snap.total_downlink == 0, "traffic: flush zero downlink");
    }

    void TestTrafficStateFlushPartial(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state ts;
        ts.flush_traffic(psm::protocol::protocol_type::http, 100, 0);
        auto snap = ts.snapshot();
        runner.Check(snap.total_uplink == 100, "traffic: flush partial uplink");
        runner.Check(snap.total_downlink == 0, "traffic: flush partial downlink=0");
    }

    void TestTrafficStateAuth(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state ts;
        ts.on_auth_success();
        ts.on_auth_failure();
        ts.on_auth_failure();
        auto snap = ts.snapshot();
        runner.Check(snap.auth_success == 1, "traffic: auth_success=1");
        runner.Check(snap.auth_failure == 2, "traffic: auth_failure=2");
    }

    void TestTrafficStateReset(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state ts;
        ts.on_connect();
        ts.on_auth_success();
        ts.flush_traffic(psm::protocol::protocol_type::http, 100, 200);
        ts.reset();
        auto snap = ts.snapshot();
        runner.Check(snap.total_connections == 0, "traffic: reset connections=0");
        runner.Check(snap.total_active == 0, "traffic: reset active=0");
        runner.Check(snap.total_uplink == 0, "traffic: reset uplink=0");
        runner.Check(snap.auth_success == 0, "traffic: reset auth_success=0");
    }

    void TestWorkerLoadBasic(TestRunner &runner)
    {
        psm::stats::runtime::worker_load wl;
        auto snap = wl.snapshot();
        runner.Check(snap.active_sessions == 0, "worker_load: initial sessions=0");
        runner.Check(snap.pending_handoffs == 0, "worker_load: initial handoffs=0");

        wl.session_open();
        wl.session_open();
        snap = wl.snapshot();
        runner.Check(snap.active_sessions == 2, "worker_load: sessions=2");

        wl.session_close();
        snap = wl.snapshot();
        runner.Check(snap.active_sessions == 1, "worker_load: sessions=1 after close");
    }

    void TestWorkerLoadHandoff(TestRunner &runner)
    {
        psm::stats::runtime::worker_load wl;
        wl.handoff_push();
        wl.handoff_push();
        auto snap = wl.snapshot();
        runner.Check(snap.pending_handoffs == 2, "worker_load: handoffs=2");

        wl.handoff_pop();
        snap = wl.snapshot();
        runner.Check(snap.pending_handoffs == 1, "worker_load: handoffs=1 after pop");
    }

    void TestWorkerLoadSessionCounter(TestRunner &runner)
    {
        psm::stats::runtime::worker_load wl;
        auto ptr = wl.session_counter();
        runner.Check(ptr != nullptr, "worker_load: session_counter not null");
        runner.Check(ptr->load() == 0, "worker_load: counter initial=0");
    }

    void TestMemoryTrackerBasic(TestRunner &runner)
    {
        auto &mt = psm::stats::memory_tracker::instance();
        auto before = mt.snapshot();
        auto baseline = before.current_usage;

        mt.on_allocate(1024);
        auto snap = mt.snapshot();
        runner.Check(snap.current_usage == baseline + 1024, "memory: allocate 1024");

        mt.on_deallocate(512);
        snap = mt.snapshot();
        runner.Check(snap.current_usage == baseline + 512, "memory: deallocate 512");
    }

    void TestSystemStateSnapshot(TestRunner &runner)
    {
        auto &ss = psm::stats::runtime::system_state::instance();
        ss.mark_started(4);
        auto snap = ss.snapshot();
        runner.Check(snap.worker_count == 4, "system_state: worker_count=4");
        runner.Check(snap.uptime_seconds >= 0, "system_state: uptime >= 0");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("StatsExtended");

    TestCounterBasic(runner);
    TestCounterExchange(runner);
    TestCounterOverflow(runner);

    TestGaugeBasic(runner);
    TestGaugetDefaultAlpha(runner);
    TestGaugeSmoothing(runner);

    TestTrafficStateBasic(runner);
    TestTrafficStateProtocol(runner);
    TestTrafficStateFlush(runner);
    TestTrafficStateFlushZero(runner);
    TestTrafficStateFlushPartial(runner);
    TestTrafficStateAuth(runner);
    TestTrafficStateReset(runner);

    TestWorkerLoadBasic(runner);
    TestWorkerLoadHandoff(runner);
    TestWorkerLoadSessionCounter(runner);

    TestMemoryTrackerBasic(runner);
    TestSystemStateSnapshot(runner);

    return runner.Summary();
}

/**
 * @file StatsExtended.cpp
 * @brief Stats 模块扩展测试 — counter/gauge/traffic_state/worker_load 分支覆盖
 */

#include <prism/foundation/foundation.hpp>
#include <prism/net/connect/types.hpp>
#include <prism/account/stats/stats.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <cstdint>

namespace
{
    TEST(StatsExtended, CounterBasic)
    {
        psm::stats::counter c;
        EXPECT_TRUE(c.load() == 0) << "counter: initial=0";

        c.increment();
        EXPECT_TRUE(c.load() == 1) << "counter: increment to 1";

        c.increment(9);
        EXPECT_TRUE(c.load() == 10) << "counter: increment(9) to 10";

        c.decrement(3);
        EXPECT_TRUE(c.load() == 7) << "counter: decrement(3) to 7";

        c.decrement();
        EXPECT_TRUE(c.load() == 6) << "counter: decrement to 6";
    }

    TEST(StatsExtended, CounterExchange)
    {
        psm::stats::counter c;
        c.increment(42);
        auto old = c.exchange(100);
        EXPECT_TRUE(old == 42) << "counter: exchange old=42";
        EXPECT_TRUE(c.load() == 100) << "counter: exchange new=100";
    }

    TEST(StatsExtended, CounterOverflow)
    {
        psm::stats::counter c;
        c.increment(UINT64_MAX);
        EXPECT_TRUE(c.load() == UINT64_MAX) << "counter: max uint64";
    }

    TEST(StatsExtended, GaugeBasic)
    {
        psm::stats::gauge g(0.5);
        EXPECT_TRUE(g.value() == 0.0) << "gauge: initial=0.0";

        g.update(100.0);
        EXPECT_TRUE(g.value() > 0) << "gauge: update > 0";

        g.reset();
        EXPECT_TRUE(g.value() == 0.0) << "gauge: reset to 0.0";
    }

    TEST(StatsExtended, GaugeDefaultAlpha)
    {
        psm::stats::gauge g;
        g.update(1000.0);
        EXPECT_TRUE(g.value() > 0) << "gauge: default alpha update > 0";
    }

    TEST(StatsExtended, GaugeSmoothing)
    {
        psm::stats::gauge g(0.0);
        g.update(50.0);
        EXPECT_TRUE(g.value() == 50.0) << "gauge: alpha=0 => value=sample";

        psm::stats::gauge g2(1.0);
        g2.update(50.0);
        EXPECT_TRUE(g2.value() == 0.0) << "gauge: alpha=1 => value unchanged";
    }

    TEST(StatsExtended, TrafficStateBasic)
    {
        psm::stats::traffic::traffic_state ts;
        auto snap = ts.snapshot();
        EXPECT_TRUE(snap.total_connections == 0) << "traffic: initial connections=0";
        EXPECT_TRUE(snap.total_active == 0) << "traffic: initial active=0";

        ts.on_connect();
        snap = ts.snapshot();
        EXPECT_TRUE(snap.total_connections == 1) << "traffic: on_connect connections=1";
        EXPECT_TRUE(snap.total_active == 1) << "traffic: on_connect active=1";
    }

    TEST(StatsExtended, TrafficStateProtocol)
    {
        psm::stats::traffic::traffic_state ts;
        ts.on_connect();
        ts.on_protocol_detected(psm::connect::protocol_type::http);

        auto snap = ts.snapshot();
        auto idx = static_cast<std::uint8_t>(psm::connect::protocol_type::http);
        EXPECT_TRUE(snap.protocols[idx].connections == 1) << "traffic: http connections=1";
        EXPECT_TRUE(snap.protocols[idx].active == 1) << "traffic: http active=1";

        ts.on_disconnect(psm::connect::protocol_type::http);
        snap = ts.snapshot();
        EXPECT_TRUE(snap.total_active == 0) << "traffic: after disconnect active=0";
        EXPECT_TRUE(snap.protocols[idx].active == 0) << "traffic: after disconnect http active=0";
    }

    TEST(StatsExtended, TrafficStateFlush)
    {
        psm::stats::traffic::traffic_state ts;
        ts.flush_traffic(psm::connect::protocol_type::socks5, 1024, 2048);
        auto snap = ts.snapshot();
        EXPECT_TRUE(snap.total_uplink == 1024) << "traffic: uplink=1024";
        EXPECT_TRUE(snap.total_downlink == 2048) << "traffic: downlink=2048";
    }

    TEST(StatsExtended, TrafficStateFlushZero)
    {
        psm::stats::traffic::traffic_state ts;
        ts.flush_traffic(psm::connect::protocol_type::http, 0, 0);
        auto snap = ts.snapshot();
        EXPECT_TRUE(snap.total_uplink == 0) << "traffic: flush zero uplink";
        EXPECT_TRUE(snap.total_downlink == 0) << "traffic: flush zero downlink";
    }

    TEST(StatsExtended, TrafficStateFlushPartial)
    {
        psm::stats::traffic::traffic_state ts;
        ts.flush_traffic(psm::connect::protocol_type::http, 100, 0);
        auto snap = ts.snapshot();
        EXPECT_TRUE(snap.total_uplink == 100) << "traffic: flush partial uplink";
        EXPECT_TRUE(snap.total_downlink == 0) << "traffic: flush partial downlink=0";
    }

    TEST(StatsExtended, TrafficStateAuth)
    {
        psm::stats::traffic::traffic_state ts;
        ts.on_auth_success();
        ts.on_auth_failure();
        ts.on_auth_failure();
        auto snap = ts.snapshot();
        EXPECT_TRUE(snap.auth_success == 1) << "traffic: auth_success=1";
        EXPECT_TRUE(snap.auth_failure == 2) << "traffic: auth_failure=2";
    }

    TEST(StatsExtended, TrafficStateReset)
    {
        psm::stats::traffic::traffic_state ts;
        ts.on_connect();
        ts.on_auth_success();
        ts.flush_traffic(psm::connect::protocol_type::http, 100, 200);
        ts.reset();
        auto snap = ts.snapshot();
        EXPECT_TRUE(snap.total_connections == 0) << "traffic: reset connections=0";
        EXPECT_TRUE(snap.total_active == 0) << "traffic: reset active=0";
        EXPECT_TRUE(snap.total_uplink == 0) << "traffic: reset uplink=0";
        EXPECT_TRUE(snap.auth_success == 0) << "traffic: reset auth_success=0";
    }

    TEST(StatsExtended, WorkerLoadBasic)
    {
        psm::stats::runtime::worker_load wl;
        auto snap = wl.snapshot();
        EXPECT_TRUE(snap.active_sessions == 0) << "worker_load: initial sessions=0";
        EXPECT_TRUE(snap.pending_handoffs == 0) << "worker_load: initial handoffs=0";

        wl.session_open();
        wl.session_open();
        snap = wl.snapshot();
        EXPECT_TRUE(snap.active_sessions == 2) << "worker_load: sessions=2";

        wl.session_close();
        snap = wl.snapshot();
        EXPECT_TRUE(snap.active_sessions == 1) << "worker_load: sessions=1 after close";
    }

    TEST(StatsExtended, WorkerLoadHandoff)
    {
        psm::stats::runtime::worker_load wl;
        wl.handoff_push();
        wl.handoff_push();
        auto snap = wl.snapshot();
        EXPECT_TRUE(snap.pending_handoffs == 2) << "worker_load: handoffs=2";

        wl.handoff_pop();
        snap = wl.snapshot();
        EXPECT_TRUE(snap.pending_handoffs == 1) << "worker_load: handoffs=1 after pop";
    }

    TEST(StatsExtended, WorkerLoadSessionCounter)
    {
        psm::stats::runtime::worker_load wl;
        auto ptr = wl.session_counter();
        EXPECT_TRUE(ptr != nullptr) << "worker_load: session_counter not null";
        EXPECT_TRUE(ptr->load() == 0) << "worker_load: counter initial=0";
    }

    TEST(StatsExtended, MemoryTrackerBasic)
    {
        auto &mt = psm::stats::memory_tracker::instance();
        auto before = mt.snapshot();
        auto baseline = before.current_usage;

        mt.on_allocate(1024);
        auto snap = mt.snapshot();
        EXPECT_TRUE(snap.current_usage == baseline + 1024) << "memory: allocate 1024";

        mt.on_deallocate(512);
        snap = mt.snapshot();
        EXPECT_TRUE(snap.current_usage == baseline + 512) << "memory: deallocate 512";
    }

    TEST(StatsExtended, SystemStateSnapshot)
    {
        auto &ss = psm::stats::runtime::system_state::instance();
        ss.mark_started(4);
        auto snap = ss.snapshot();
        EXPECT_TRUE(snap.worker_count == 4) << "system_state: worker_count=4";
        EXPECT_TRUE(snap.uptime_seconds >= 0) << "system_state: uptime >= 0";
    }
} // namespace

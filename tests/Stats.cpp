/**
 * @file Stats.cpp
 * @brief 运行统计模块单元测试
 * @details 测试 worker_load、system_state、traffic_state 的原子计数器操作。
 */

#include <prism/memory.hpp>
#include <prism/stats/runtime.hpp>
#include <prism/stats/traffic.hpp>
#include <prism/protocol/types.hpp>
#include <prism/trace/spdlog.hpp>

#include <cstdint>
#include <thread>

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    // === worker_load ===

    void TestWorkerLoadSessionOpenClose(TestRunner &runner)
    {
        psm::stats::runtime::worker_load load;
        runner.Check(load.snapshot().active_sessions == 0, "initial sessions = 0");

        load.session_open();
        runner.Check(load.snapshot().active_sessions == 1, "after open = 1");

        load.session_open();
        runner.Check(load.snapshot().active_sessions == 2, "after second open = 2");

        load.session_close();
        runner.Check(load.snapshot().active_sessions == 1, "after close = 1");
    }

    void TestWorkerLoadHandoff(TestRunner &runner)
    {
        psm::stats::runtime::worker_load load;
        runner.Check(load.snapshot().pending_handoffs == 0, "initial handoffs = 0");

        load.handoff_push();
        load.handoff_push();
        runner.Check(load.snapshot().pending_handoffs == 2, "after 2 pushes = 2");

        load.handoff_pop();
        runner.Check(load.snapshot().pending_handoffs == 1, "after pop = 1");
    }

    void TestWorkerLoadSessionCounter(TestRunner &runner)
    {
        psm::stats::runtime::worker_load load;
        auto counter = load.session_counter();
        runner.Check(counter != nullptr, "session_counter not null");
        runner.Check(counter->load() == 0, "counter initial = 0");

        load.session_open();
        runner.Check(counter->load() == 1, "counter after open = 1");
    }

    // === system_state ===

    void TestSystemStateMarkStarted(TestRunner &runner)
    {
        auto &state = psm::stats::runtime::system_state::instance();

        // system_state is a singleton, mark_started may have been called before
        // but we can still test snapshot
        state.mark_started(4);
        auto snap = state.snapshot();
        runner.Check(snap.worker_count == 4, "worker_count = 4");
        runner.Check(snap.uptime_seconds >= 0, "uptime >= 0");
    }

    void TestSystemStateMarkStartedIdempotent(TestRunner &runner)
    {
        auto &state = psm::stats::runtime::system_state::instance();
        state.mark_started(4);
        state.mark_started(8); // second call should be no-op
        auto snap = state.snapshot();
        runner.Check(snap.worker_count == 4, "mark_started idempotent: worker_count stays 4");
    }

    // === traffic_state ===

    void TestTrafficStateConnectDisconnect(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.on_connect();
        auto snap = traffic.snapshot();
        runner.Check(snap.total_connections == 1, "after connect: total = 1");
        runner.Check(snap.total_active == 1, "after connect: active = 1");

        traffic.on_disconnect(psm::protocol::protocol_type::unknown);
        snap = traffic.snapshot();
        runner.Check(snap.total_active == 0, "after disconnect: active = 0");
        runner.Check(snap.total_connections == 1, "after disconnect: total still 1");
    }

    void TestTrafficStateProtocolDetection(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.on_protocol_detected(psm::protocol::protocol_type::http);
        auto snap = traffic.snapshot();
        auto idx = static_cast<std::uint8_t>(psm::protocol::protocol_type::http);
        runner.Check(snap.protocols[idx].connections == 1, "protocol connections = 1");
        runner.Check(snap.protocols[idx].active == 1, "protocol active = 1");
    }

    void TestTrafficStateFlushTraffic(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.flush_traffic(psm::protocol::protocol_type::socks5, 1000, 2000);
        auto snap = traffic.snapshot();
        runner.Check(snap.total_uplink == 1000, "total uplink = 1000");
        runner.Check(snap.total_downlink == 2000, "total downlink = 2000");

        auto idx = static_cast<std::uint8_t>(psm::protocol::protocol_type::socks5);
        runner.Check(snap.protocols[idx].uplink_bytes == 1000, "protocol uplink = 1000");
        runner.Check(snap.protocols[idx].downlink_bytes == 2000, "protocol downlink = 2000");
    }

    void TestTrafficStateFlushZeroSkipped(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.flush_traffic(psm::protocol::protocol_type::http, 0, 0);
        auto snap = traffic.snapshot();
        runner.Check(snap.total_uplink == 0, "zero uplink not flushed");
        runner.Check(snap.total_downlink == 0, "zero downlink not flushed");
    }

    void TestTrafficStateAuth(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.on_auth_success();
        traffic.on_auth_success();
        traffic.on_auth_failure();
        auto snap = traffic.snapshot();
        runner.Check(snap.auth_success == 2, "auth_success = 2");
        runner.Check(snap.auth_failure == 1, "auth_failure = 1");
    }

    void TestTrafficStateReset(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.on_connect();
        traffic.flush_traffic(psm::protocol::protocol_type::http, 100, 200);
        traffic.on_auth_success();
        traffic.reset();

        auto snap = traffic.snapshot();
        runner.Check(snap.total_connections == 0, "reset: total_connections = 0");
        runner.Check(snap.total_active == 0, "reset: total_active = 0");
        runner.Check(snap.total_uplink == 0, "reset: total_uplink = 0");
        runner.Check(snap.total_downlink == 0, "reset: total_downlink = 0");
        runner.Check(snap.auth_success == 0, "reset: auth_success = 0");
        runner.Check(snap.auth_failure == 0, "reset: auth_failure = 0");
    }

    void TestTrafficStateAggregate(TestRunner &runner)
    {
        psm::stats::traffic::traffic_state traffic1;
        psm::stats::traffic::traffic_state traffic2;

        psm::stats::traffic::traffic_state::register_instance(&traffic1);
        psm::stats::traffic::traffic_state::register_instance(&traffic2);

        traffic1.on_connect();
        traffic2.on_connect();
        traffic2.on_connect();

        auto agg = psm::stats::traffic::traffic_state::aggregate();
        runner.Check(agg.total_connections == 3, "aggregate total_connections = 3");

        psm::stats::traffic::traffic_state::unregister_instance(&traffic1);
        psm::stats::traffic::traffic_state::unregister_instance(&traffic2);
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("Stats");

    TestWorkerLoadSessionOpenClose(runner);
    TestWorkerLoadHandoff(runner);
    TestWorkerLoadSessionCounter(runner);
    TestSystemStateMarkStarted(runner);
    TestSystemStateMarkStartedIdempotent(runner);
    TestTrafficStateConnectDisconnect(runner);
    TestTrafficStateProtocolDetection(runner);
    TestTrafficStateFlushTraffic(runner);
    TestTrafficStateFlushZeroSkipped(runner);
    TestTrafficStateAuth(runner);
    TestTrafficStateReset(runner);
    TestTrafficStateAggregate(runner);

    return runner.Summary();
}

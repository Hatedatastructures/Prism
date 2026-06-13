/**
 * @file Stats.cpp
 * @brief 运行统计模块单元测试
 * @details 测试 worker_load、system_state、traffic_state 的原子计数器操作。
 */

#include <prism/core/core.hpp>
#include <prism/account/stats/runtime.hpp>
#include <prism/account/stats/traffic.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include <cstdint>

namespace
{
    // === worker_load ===

    TEST(Stats, WorkerLoadSessionOpenClose)
    {
        psm::stats::runtime::worker_load load;
        EXPECT_TRUE(load.snapshot().active_sessions == 0) << "initial sessions = 0";

        load.session_open();
        EXPECT_TRUE(load.snapshot().active_sessions == 1) << "after open = 1";

        load.session_open();
        EXPECT_TRUE(load.snapshot().active_sessions == 2) << "after second open = 2";

        load.session_close();
        EXPECT_TRUE(load.snapshot().active_sessions == 1) << "after close = 1";
    }

    TEST(Stats, WorkerLoadHandoff)
    {
        psm::stats::runtime::worker_load load;
        EXPECT_TRUE(load.snapshot().pending_handoffs == 0) << "initial handoffs = 0";

        load.handoff_push();
        load.handoff_push();
        EXPECT_TRUE(load.snapshot().pending_handoffs == 2) << "after 2 pushes = 2";

        load.handoff_pop();
        EXPECT_TRUE(load.snapshot().pending_handoffs == 1) << "after pop = 1";
    }

    TEST(Stats, WorkerLoadSessionCounter)
    {
        psm::stats::runtime::worker_load load;
        auto counter = load.session_counter();
        EXPECT_TRUE(counter != nullptr) << "session_counter not null";
        EXPECT_TRUE(counter->load() == 0) << "counter initial = 0";

        load.session_open();
        EXPECT_TRUE(counter->load() == 1) << "counter after open = 1";
    }

    // === system_state ===

    TEST(Stats, SystemStateMarkStarted)
    {
        auto &state = psm::stats::runtime::system_state::instance();

        state.mark_started(4);
        auto snap = state.snapshot();
        EXPECT_TRUE(snap.worker_count == 4) << "worker_count = 4";
        EXPECT_TRUE(snap.uptime_seconds >= 0) << "uptime >= 0";
    }

    TEST(Stats, SystemStateMarkStartedIdempotent)
    {
        auto &state = psm::stats::runtime::system_state::instance();
        state.mark_started(4);
        state.mark_started(8); // second call should be no-op
        auto snap = state.snapshot();
        EXPECT_TRUE(snap.worker_count == 4) << "mark_started idempotent: worker_count stays 4";
    }

    // === traffic_state ===

    TEST(Stats, TrafficStateConnectDisconnect)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.on_connect();
        auto snap = traffic.snapshot();
        EXPECT_TRUE(snap.total_connections == 1) << "after connect: total = 1";
        EXPECT_TRUE(snap.total_active == 1) << "after connect: active = 1";

        traffic.on_disconnect(psm::protocol::protocol_type::unknown);
        snap = traffic.snapshot();
        EXPECT_TRUE(snap.total_active == 0) << "after disconnect: active = 0";
        EXPECT_TRUE(snap.total_connections == 1) << "after disconnect: total still 1";
    }

    TEST(Stats, TrafficStateProtocolDetection)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.on_protocol_detected(psm::protocol::protocol_type::http);
        auto snap = traffic.snapshot();
        auto idx = static_cast<std::uint8_t>(psm::protocol::protocol_type::http);
        EXPECT_TRUE(snap.protocols[idx].connections == 1) << "protocol connections = 1";
        EXPECT_TRUE(snap.protocols[idx].active == 1) << "protocol active = 1";
    }

    TEST(Stats, TrafficStateFlushTraffic)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.flush_traffic(psm::protocol::protocol_type::socks5, 1000, 2000);
        auto snap = traffic.snapshot();
        EXPECT_TRUE(snap.total_uplink == 1000) << "total uplink = 1000";
        EXPECT_TRUE(snap.total_downlink == 2000) << "total downlink = 2000";

        auto idx = static_cast<std::uint8_t>(psm::protocol::protocol_type::socks5);
        EXPECT_TRUE(snap.protocols[idx].uplink_bytes == 1000) << "protocol uplink = 1000";
        EXPECT_TRUE(snap.protocols[idx].downlink_bytes == 2000) << "protocol downlink = 2000";
    }

    TEST(Stats, TrafficStateFlushZeroSkipped)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.flush_traffic(psm::protocol::protocol_type::http, 0, 0);
        auto snap = traffic.snapshot();
        EXPECT_TRUE(snap.total_uplink == 0) << "zero uplink not flushed";
        EXPECT_TRUE(snap.total_downlink == 0) << "zero downlink not flushed";
    }

    TEST(Stats, TrafficStateAuth)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.on_auth_success();
        traffic.on_auth_success();
        traffic.on_auth_failure();
        auto snap = traffic.snapshot();
        EXPECT_TRUE(snap.auth_success == 2) << "auth_success = 2";
        EXPECT_TRUE(snap.auth_failure == 1) << "auth_failure = 1";
    }

    TEST(Stats, TrafficStateReset)
    {
        psm::stats::traffic::traffic_state traffic;

        traffic.on_connect();
        traffic.flush_traffic(psm::protocol::protocol_type::http, 100, 200);
        traffic.on_auth_success();
        traffic.reset();

        auto snap = traffic.snapshot();
        EXPECT_TRUE(snap.total_connections == 0) << "reset: total_connections = 0";
        EXPECT_TRUE(snap.total_active == 0) << "reset: total_active = 0";
        EXPECT_TRUE(snap.total_uplink == 0) << "reset: total_uplink = 0";
        EXPECT_TRUE(snap.total_downlink == 0) << "reset: total_downlink = 0";
        EXPECT_TRUE(snap.auth_success == 0) << "reset: auth_success = 0";
        EXPECT_TRUE(snap.auth_failure == 0) << "reset: auth_failure = 0";
    }

    TEST(Stats, TrafficStateAggregate)
    {
        psm::stats::traffic::traffic_state traffic1;
        psm::stats::traffic::traffic_state traffic2;

        psm::stats::traffic::traffic_state::register_instance(&traffic1);
        psm::stats::traffic::traffic_state::register_instance(&traffic2);

        traffic1.on_connect();
        traffic2.on_connect();
        traffic2.on_connect();

        auto agg = psm::stats::traffic::traffic_state::aggregate();
        EXPECT_TRUE(agg.total_connections == 3) << "aggregate total_connections = 3";

        psm::stats::traffic::traffic_state::unregister_instance(&traffic1);
        psm::stats::traffic::traffic_state::unregister_instance(&traffic2);
    }
} // namespace

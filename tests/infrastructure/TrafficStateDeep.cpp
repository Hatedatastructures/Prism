/**
 * @file TrafficStateDeep.cpp
 * @brief stats::traffic 深度测试
 * @details 测试 traffic_state 的全同步方法：on_connect/on_disconnect、
 *          flush_traffic、on_auth_success/failure、snapshot、reset、
 *          register_instance/unregister_instance、aggregate。
 */

#include <prism/memory.hpp>
#include <prism/stats/traffic.hpp>
#include <prism/trace/spdlog.hpp>
#include <prism/protocol/types.hpp>

#include <gtest/gtest.h>

namespace
{
    namespace traffic = psm::stats::traffic;
    namespace proto = psm::protocol;

    // ─── on_connect / on_disconnect ────────────────

    TEST(TrafficStateDeep, OnConnectDisconnect)
    {
        traffic::traffic_state ts;

        auto s1 = ts.snapshot();
        EXPECT_TRUE(s1.total_connections == 0) << "traffic: initial connections=0";
        EXPECT_TRUE(s1.total_active == 0) << "traffic: initial active=0";

        ts.on_connect();
        auto s2 = ts.snapshot();
        EXPECT_TRUE(s2.total_connections == 1) << "traffic: after connect total=1";
        EXPECT_TRUE(s2.total_active == 1) << "traffic: after connect active=1";

        ts.on_disconnect(proto::protocol_type::unknown);
        auto s3 = ts.snapshot();
        EXPECT_TRUE(s3.total_active == 0) << "traffic: after disconnect active=0";
        EXPECT_TRUE(s3.total_connections == 1) << "traffic: disconnect doesn't change total";
    }

    TEST(TrafficStateDeep, MultipleConnects)
    {
        traffic::traffic_state ts;

        ts.on_connect();
        ts.on_connect();
        ts.on_connect();
        auto s = ts.snapshot();
        EXPECT_TRUE(s.total_connections == 3) << "traffic: 3 connects -> total=3";
        EXPECT_TRUE(s.total_active == 3) << "traffic: 3 connects -> active=3";
    }

    // ─── on_protocol_detected ──────────────────────

    TEST(TrafficStateDeep, OnProtocolDetected)
    {
        traffic::traffic_state ts;
        ts.on_connect();
        ts.on_protocol_detected(proto::protocol_type::trojan);

        auto s = ts.snapshot();
        auto idx = static_cast<std::uint8_t>(proto::protocol_type::trojan);
        EXPECT_TRUE(s.protocols[idx].connections == 1) << "traffic: trojan connections=1";
        EXPECT_TRUE(s.protocols[idx].active == 1) << "traffic: trojan active=1";
    }

    // ─── flush_traffic ─────────────────────────────

    TEST(TrafficStateDeep, FlushTraffic)
    {
        traffic::traffic_state ts;

        ts.flush_traffic(proto::protocol_type::trojan, 100, 200);
        auto s = ts.snapshot();
        EXPECT_TRUE(s.total_uplink == 100) << "traffic: total_uplink=100";
        EXPECT_TRUE(s.total_downlink == 200) << "traffic: total_downlink=200";

        auto idx = static_cast<std::uint8_t>(proto::protocol_type::trojan);
        EXPECT_TRUE(s.protocols[idx].uplink_bytes == 100) << "traffic: trojan uplink=100";
        EXPECT_TRUE(s.protocols[idx].downlink_bytes == 200) << "traffic: trojan downlink=200";
    }

    TEST(TrafficStateDeep, FlushTrafficZeroSkipped)
    {
        traffic::traffic_state ts;
        ts.flush_traffic(proto::protocol_type::socks5, 0, 0);

        auto s = ts.snapshot();
        EXPECT_TRUE(s.total_uplink == 0) << "traffic: zero flush -> uplink=0";
        EXPECT_TRUE(s.total_downlink == 0) << "traffic: zero flush -> downlink=0";
    }

    TEST(TrafficStateDeep, FlushTrafficOnlyUplink)
    {
        traffic::traffic_state ts;
        ts.flush_traffic(proto::protocol_type::vless, 50, 0);

        auto s = ts.snapshot();
        EXPECT_TRUE(s.total_uplink == 50) << "traffic: only uplink=50";
        EXPECT_TRUE(s.total_downlink == 0) << "traffic: only uplink -> downlink=0";
    }

    // ─── on_auth_success / on_auth_failure ─────────

    TEST(TrafficStateDeep, AuthCounters)
    {
        traffic::traffic_state ts;

        ts.on_auth_success();
        ts.on_auth_success();
        ts.on_auth_failure();

        auto s = ts.snapshot();
        EXPECT_TRUE(s.auth_success == 2) << "traffic: auth_success=2";
        EXPECT_TRUE(s.auth_failure == 1) << "traffic: auth_failure=1";
    }

    // ─── reset ─────────────────────────────────────

    TEST(TrafficStateDeep, Reset)
    {
        traffic::traffic_state ts;
        ts.on_connect();
        ts.on_protocol_detected(proto::protocol_type::trojan);
        ts.flush_traffic(proto::protocol_type::trojan, 1000, 2000);
        ts.on_auth_success();
        ts.on_auth_failure();

        ts.reset();
        auto s = ts.snapshot();
        EXPECT_TRUE(s.total_connections == 0) << "traffic: reset connections=0";
        EXPECT_TRUE(s.total_active == 0) << "traffic: reset active=0";
        EXPECT_TRUE(s.total_uplink == 0) << "traffic: reset uplink=0";
        EXPECT_TRUE(s.total_downlink == 0) << "traffic: reset downlink=0";
        EXPECT_TRUE(s.auth_success == 0) << "traffic: reset auth_success=0";
        EXPECT_TRUE(s.auth_failure == 0) << "traffic: reset auth_failure=0";

        auto idx = static_cast<std::uint8_t>(proto::protocol_type::trojan);
        EXPECT_TRUE(s.protocols[idx].connections == 0) << "traffic: reset protocol connections=0";
        EXPECT_TRUE(s.protocols[idx].uplink_bytes == 0) << "traffic: reset protocol uplink=0";
    }

    // ─── snapshot 原子性 ───────────────────────────

    TEST(TrafficStateDeep, SnapshotIsCopy)
    {
        traffic::traffic_state ts;
        ts.on_connect();
        auto s1 = ts.snapshot();

        ts.on_connect();
        auto s2 = ts.snapshot();

        EXPECT_TRUE(s1.total_connections == 1) << "traffic: snapshot1 total=1";
        EXPECT_TRUE(s2.total_connections == 2) << "traffic: snapshot2 total=2";
    }

    // ─── register_instance / aggregate ─────────────

    TEST(TrafficStateDeep, RegisterAggregate)
    {
        traffic::traffic_state ts1, ts2;

        traffic::traffic_state::register_instance(&ts1);
        traffic::traffic_state::register_instance(&ts2);

        ts1.on_connect();
        ts1.flush_traffic(proto::protocol_type::trojan, 100, 0);
        ts2.on_connect();
        ts2.on_connect();
        ts2.flush_traffic(proto::protocol_type::socks5, 0, 300);

        auto agg = traffic::traffic_state::aggregate();
        EXPECT_TRUE(agg.total_connections == 3) << "traffic: aggregate total=3";
        EXPECT_TRUE(agg.total_uplink == 100) << "traffic: aggregate uplink=100";
        EXPECT_TRUE(agg.total_downlink == 300) << "traffic: aggregate downlink=300";

        traffic::traffic_state::unregister_instance(&ts1);
        traffic::traffic_state::unregister_instance(&ts2);
    }

    TEST(TrafficStateDeep, AggregateNoInstances)
    {
        // aggregate 在空注册表时不应崩溃
        auto agg = traffic::traffic_state::aggregate();
        EXPECT_TRUE(agg.total_connections == 0) << "traffic: aggregate empty -> 0";
    }

    TEST(TrafficStateDeep, UnregisterReducesAggregate)
    {
        traffic::traffic_state ts1, ts2;

        traffic::traffic_state::register_instance(&ts1);
        traffic::traffic_state::register_instance(&ts2);

        ts1.on_connect();
        ts2.on_connect();

        auto agg1 = traffic::traffic_state::aggregate();
        EXPECT_TRUE(agg1.total_connections == 2) << "traffic: before unregister total=2";

        traffic::traffic_state::unregister_instance(&ts2);

        auto agg2 = traffic::traffic_state::aggregate();
        EXPECT_TRUE(agg2.total_connections == 1) << "traffic: after unregister total=1";

        traffic::traffic_state::unregister_instance(&ts1);
    }

    TEST(TrafficStateDeep, UnregisterNotRegistered)
    {
        traffic::traffic_state ts;
        // 不注册直接注销，不应崩溃
        traffic::traffic_state::unregister_instance(&ts);
        auto agg = traffic::traffic_state::aggregate();
        EXPECT_TRUE(agg.total_connections >= 0u) << "traffic: unregister not registered -> aggregate safe";
    }

} // namespace

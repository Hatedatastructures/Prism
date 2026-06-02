/**
 * @file TrafficDeep.cpp
 * @brief stats/traffic 深度纯函数测试
 * @details 通过 #include 源文件访问 traffic.cpp 中所有同步函数，
 *          覆盖 on_connect、on_protocol_detected、on_disconnect、
 *          flush_traffic、on_auth_success/failure、snapshot、reset、
 *          register_instance、unregister_instance、aggregate。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <gtest/gtest.h>

#include "../../src/prism/stats/traffic.cpp"

namespace
{
    namespace traffic = psm::stats::traffic;
    using psm::protocol::protocol_type;

    // ─── on_connect / on_disconnect ─────────────

    TEST(TrafficDeep, OnConnectIncrements)
    {
        traffic::traffic_state st;
        st.on_connect();
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_connections == 1) << "on_connect: total_connections=1";
        EXPECT_TRUE(s.total_active == 1) << "on_connect: total_active=1";
    }

    TEST(TrafficDeep, OnConnectMultiple)
    {
        traffic::traffic_state st;
        st.on_connect();
        st.on_connect();
        st.on_connect();
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_connections == 3) << "on_connect: 3x -> total_connections=3";
        EXPECT_TRUE(s.total_active == 3) << "on_connect: 3x -> total_active=3";
    }

    TEST(TrafficDeep, OnDisconnectDecrements)
    {
        traffic::traffic_state st;
        st.on_connect();
        st.on_connect();
        st.on_disconnect(protocol_type::http);
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_active == 1) << "on_disconnect: total_active=1";
    }

    // ─── on_protocol_detected ──────────────────

    TEST(TrafficDeep, OnProtocolDetectedHttp)
    {
        traffic::traffic_state st;
        st.on_protocol_detected(protocol_type::http);
        auto s = st.snapshot();
        auto i = static_cast<std::uint8_t>(protocol_type::http);
        EXPECT_TRUE(s.protocols[i].connections == 1) << "on_protocol_detected: http connections=1";
        EXPECT_TRUE(s.protocols[i].active == 1) << "on_protocol_detected: http active=1";
    }

    TEST(TrafficDeep, OnProtocolDetectedMultiple)
    {
        traffic::traffic_state st;
        st.on_protocol_detected(protocol_type::socks5);
        st.on_protocol_detected(protocol_type::trojan);
        st.on_protocol_detected(protocol_type::socks5);
        auto s = st.snapshot();
        auto socks_idx = static_cast<std::uint8_t>(protocol_type::socks5);
        auto trojan_idx = static_cast<std::uint8_t>(protocol_type::trojan);
        EXPECT_TRUE(s.protocols[socks_idx].connections == 2) << "on_protocol_detected: socks5 x2";
        EXPECT_TRUE(s.protocols[trojan_idx].connections == 1) << "on_protocol_detected: trojan x1";
    }

    TEST(TrafficDeep, OnProtocolDetectedAllTypes)
    {
        traffic::traffic_state st;
        for (std::uint8_t i = 0; i <= static_cast<std::uint8_t>(protocol_type::tls); ++i)
        {
            st.on_protocol_detected(static_cast<protocol_type>(i));
        }
        auto s = st.snapshot();
        for (std::uint8_t i = 0; i <= static_cast<std::uint8_t>(protocol_type::tls); ++i)
        {
            EXPECT_TRUE(s.protocols[i].connections == 1) << "on_protocol_detected: all types have 1 connection";
        }
    }

    TEST(TrafficDeep, OnDisconnectDecrementsProtocolActive)
    {
        traffic::traffic_state st;
        st.on_protocol_detected(protocol_type::vless);
        st.on_disconnect(protocol_type::vless);
        auto s = st.snapshot();
        auto i = static_cast<std::uint8_t>(protocol_type::vless);
        EXPECT_TRUE(s.protocols[i].connections == 1) << "on_disconnect: connections still 1";
        EXPECT_TRUE(s.protocols[i].active == 0) << "on_disconnect: active decremented to 0";
    }

    // ─── flush_traffic ─────────────────────────

    TEST(TrafficDeep, FlushTrafficUplink)
    {
        traffic::traffic_state st;
        st.flush_traffic(protocol_type::http, 1000, 0);
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_uplink == 1000) << "flush_traffic: uplink=1000";
        EXPECT_TRUE(s.total_downlink == 0) << "flush_traffic: downlink=0 (not flushed)";
        auto i = static_cast<std::uint8_t>(protocol_type::http);
        EXPECT_TRUE(s.protocols[i].uplink_bytes == 1000) << "flush_traffic: http uplink=1000";
    }

    TEST(TrafficDeep, FlushTrafficDownlink)
    {
        traffic::traffic_state st;
        st.flush_traffic(protocol_type::socks5, 0, 500);
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_uplink == 0) << "flush_traffic: uplink=0 (not flushed)";
        EXPECT_TRUE(s.total_downlink == 500) << "flush_traffic: downlink=500";
        auto i = static_cast<std::uint8_t>(protocol_type::socks5);
        EXPECT_TRUE(s.protocols[i].downlink_bytes == 500) << "flush_traffic: socks5 downlink=500";
    }

    TEST(TrafficDeep, FlushTrafficBoth)
    {
        traffic::traffic_state st;
        st.flush_traffic(protocol_type::trojan, 200, 300);
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_uplink == 200) << "flush_traffic: both uplink=200";
        EXPECT_TRUE(s.total_downlink == 300) << "flush_traffic: both downlink=300";
    }

    TEST(TrafficDeep, FlushTrafficZeroSkipped)
    {
        traffic::traffic_state st;
        st.flush_traffic(protocol_type::http, 0, 0);
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_uplink == 0) << "flush_traffic: zero up -> skipped";
        EXPECT_TRUE(s.total_downlink == 0) << "flush_traffic: zero down -> skipped";
    }

    TEST(TrafficDeep, FlushTrafficAccumulates)
    {
        traffic::traffic_state st;
        st.flush_traffic(protocol_type::http, 100, 50);
        st.flush_traffic(protocol_type::http, 200, 150);
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_uplink == 300) << "flush_traffic: accumulates uplink";
        EXPECT_TRUE(s.total_downlink == 200) << "flush_traffic: accumulates downlink";
    }

    // ─── on_auth_success / on_auth_failure ──────

    TEST(TrafficDeep, AuthSuccess)
    {
        traffic::traffic_state st;
        st.on_auth_success();
        auto s = st.snapshot();
        EXPECT_TRUE(s.auth_success == 1) << "auth_success: count=1";
    }

    TEST(TrafficDeep, AuthFailure)
    {
        traffic::traffic_state st;
        st.on_auth_failure();
        auto s = st.snapshot();
        EXPECT_TRUE(s.auth_failure == 1) << "auth_failure: count=1";
    }

    TEST(TrafficDeep, AuthMultiple)
    {
        traffic::traffic_state st;
        st.on_auth_success();
        st.on_auth_success();
        st.on_auth_failure();
        auto s = st.snapshot();
        EXPECT_TRUE(s.auth_success == 2) << "auth: success=2";
        EXPECT_TRUE(s.auth_failure == 1) << "auth: failure=1";
    }

    // ─── snapshot ──────────────────────────────

    TEST(TrafficDeep, SnapshotInitial)
    {
        traffic::traffic_state st;
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_connections == 0) << "snapshot: initial connections=0";
        EXPECT_TRUE(s.total_active == 0) << "snapshot: initial active=0";
        EXPECT_TRUE(s.total_uplink == 0) << "snapshot: initial uplink=0";
        EXPECT_TRUE(s.total_downlink == 0) << "snapshot: initial downlink=0";
        EXPECT_TRUE(s.auth_success == 0) << "snapshot: initial auth_success=0";
        EXPECT_TRUE(s.auth_failure == 0) << "snapshot: initial auth_failure=0";
        for (std::size_t i = 0; i < psm::stats::slot_count; ++i)
        {
            EXPECT_TRUE(s.protocols[i].connections == 0) << "snapshot: initial protocol connections=0";
            EXPECT_TRUE(s.protocols[i].active == 0) << "snapshot: initial protocol active=0";
        }
    }

    TEST(TrafficDeep, SnapshotAfterOperations)
    {
        traffic::traffic_state st;
        st.on_connect();
        st.on_protocol_detected(protocol_type::http);
        st.flush_traffic(protocol_type::http, 500, 600);
        st.on_auth_success();
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_connections == 1) << "snapshot: after ops connections=1";
        EXPECT_TRUE(s.total_active == 1) << "snapshot: after ops active=1";
        EXPECT_TRUE(s.total_uplink == 500) << "snapshot: after ops uplink=500";
        EXPECT_TRUE(s.total_downlink == 600) << "snapshot: after ops downlink=600";
        EXPECT_TRUE(s.auth_success == 1) << "snapshot: after ops auth_success=1";
    }

    // ─── reset ─────────────────────────────────

    TEST(TrafficDeep, Reset)
    {
        traffic::traffic_state st;
        st.on_connect();
        st.on_protocol_detected(protocol_type::http);
        st.flush_traffic(protocol_type::http, 100, 200);
        st.on_auth_success();
        st.on_auth_failure();
        st.reset();
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_connections == 0) << "reset: connections=0";
        EXPECT_TRUE(s.total_active == 0) << "reset: active=0";
        EXPECT_TRUE(s.total_uplink == 0) << "reset: uplink=0";
        EXPECT_TRUE(s.total_downlink == 0) << "reset: downlink=0";
        EXPECT_TRUE(s.auth_success == 0) << "reset: auth_success=0";
        EXPECT_TRUE(s.auth_failure == 0) << "reset: auth_failure=0";
        for (std::size_t i = 0; i < psm::stats::slot_count; ++i)
        {
            EXPECT_TRUE(s.protocols[i].connections == 0) << "reset: protocol connections=0";
            EXPECT_TRUE(s.protocols[i].active == 0) << "reset: protocol active=0";
        }
    }

    TEST(TrafficDeep, ResetIdempotent)
    {
        traffic::traffic_state st;
        st.on_connect();
        st.reset();
        st.reset();
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_connections == 0) << "reset: double reset connections=0";
    }

    TEST(TrafficDeep, OperationsAfterReset)
    {
        traffic::traffic_state st;
        st.on_connect();
        st.reset();
        st.on_connect();
        st.on_connect();
        auto s = st.snapshot();
        EXPECT_TRUE(s.total_connections == 2) << "reset: ops after reset work";
        EXPECT_TRUE(s.total_active == 2) << "reset: active after reset work";
    }

    // ─── register_instance / unregister_instance / aggregate ────

    TEST(TrafficDeep, RegisterAndAggregate)
    {
        traffic::traffic_state st1;
        traffic::traffic_state st2;
        traffic::traffic_state::register_instance(&st1);
        traffic::traffic_state::register_instance(&st2);

        st1.on_connect();
        st1.flush_traffic(protocol_type::http, 100, 200);
        st2.on_connect();
        st2.on_connect();
        st2.flush_traffic(protocol_type::socks5, 50, 75);

        auto agg = traffic::traffic_state::aggregate();
        EXPECT_TRUE(agg.total_connections == 3) << "aggregate: connections=3";
        EXPECT_TRUE(agg.total_uplink == 150) << "aggregate: uplink=150";
        EXPECT_TRUE(agg.total_downlink == 275) << "aggregate: downlink=275";

        traffic::traffic_state::unregister_instance(&st1);
        traffic::traffic_state::unregister_instance(&st2);
    }

    TEST(TrafficDeep, AggregateNoRegistry)
    {
        // 如果没有注册任何实例，aggregate 返回空快照
        // (g_registry 可能已被之前的测试设置，此测试验证空注册表路径)
        // 注意：因为 COW 注册表是全局的，其他测试可能已注册了实例
        // 这里主要验证 aggregate 不崩溃
        auto agg = traffic::traffic_state::aggregate();
        EXPECT_TRUE(agg.total_connections >= 0u) << "aggregate: returns valid snapshot";
    }

    TEST(TrafficDeep, UnregisterNotRegistered)
    {
        traffic::traffic_state st;
        // unregister 一个未注册的实例不应崩溃
        traffic::traffic_state::unregister_instance(&st);
        auto agg = traffic::traffic_state::aggregate();
        EXPECT_TRUE(agg.total_connections >= 0u) << "unregister not registered: aggregate still valid";
    }

    TEST(TrafficDeep, UnregisterNull)
    {
        // unregister nullptr — 函数不会找到它，不崩溃即可
        traffic::traffic_state::unregister_instance(nullptr);
        auto agg2 = traffic::traffic_state::aggregate();
        EXPECT_TRUE(agg2.total_connections >= 0u) << "unregister nullptr: aggregate still valid";
    }

} // namespace

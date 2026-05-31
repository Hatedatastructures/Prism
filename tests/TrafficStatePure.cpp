/**
 * @file TrafficStatePure.cpp
 * @brief 流量统计纯函数测试 — traffic_state 操作与快照
 */

#include <prism/memory.hpp>
#include <prism/protocol/types.hpp>
#include <prism/stats/traffic.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    using psm::stats::traffic::traffic_state;
    using psm::protocol::protocol_type;

    void TestInitialState(TestRunner &runner)
    {
        traffic_state state;
        auto s = state.snapshot();
        runner.Check(s.total_connections == 0, "traffic: initial connections=0");
        runner.Check(s.total_active == 0, "traffic: initial active=0");
        runner.Check(s.total_uplink == 0, "traffic: initial uplink=0");
        runner.Check(s.total_downlink == 0, "traffic: initial downlink=0");
        runner.Check(s.auth_success == 0, "traffic: initial auth_success=0");
        runner.Check(s.auth_failure == 0, "traffic: initial auth_failure=0");
    }

    void TestOnConnect(TestRunner &runner)
    {
        traffic_state state;
        state.on_connect();
        state.on_connect();
        auto s = state.snapshot();
        runner.Check(s.total_connections == 2, "traffic: 2 connects");
        runner.Check(s.total_active == 2, "traffic: 2 active");
    }

    void TestOnProtocolDetected(TestRunner &runner)
    {
        traffic_state state;
        state.on_protocol_detected(protocol_type::http);
        state.on_protocol_detected(protocol_type::socks5);

        auto s = state.snapshot();
        auto http_idx = static_cast<std::uint8_t>(protocol_type::http);
        auto socks_idx = static_cast<std::uint8_t>(protocol_type::socks5);
        runner.Check(s.protocols[http_idx].connections == 1, "traffic: http connections=1");
        runner.Check(s.protocols[http_idx].active == 1, "traffic: http active=1");
        runner.Check(s.protocols[socks_idx].connections == 1, "traffic: socks5 connections=1");
    }

    void TestOnDisconnect(TestRunner &runner)
    {
        traffic_state state;
        state.on_connect();
        state.on_protocol_detected(protocol_type::trojan);
        state.on_disconnect(protocol_type::trojan);

        auto s = state.snapshot();
        runner.Check(s.total_active == 0, "traffic: after disconnect active=0");
        auto trojan_idx = static_cast<std::uint8_t>(protocol_type::trojan);
        runner.Check(s.protocols[trojan_idx].active == 0, "traffic: trojan active=0");
    }

    void TestFlushTraffic(TestRunner &runner)
    {
        traffic_state state;
        state.flush_traffic(protocol_type::vless, 100, 200);
        state.flush_traffic(protocol_type::vless, 50, 0); // uplink only

        auto s = state.snapshot();
        runner.Check(s.total_uplink == 150, "traffic: total uplink=150");
        runner.Check(s.total_downlink == 200, "traffic: total downlink=200");

        auto vless_idx = static_cast<std::uint8_t>(protocol_type::vless);
        runner.Check(s.protocols[vless_idx].uplink_bytes == 150, "traffic: vless uplink=150");
        runner.Check(s.protocols[vless_idx].downlink_bytes == 200, "traffic: vless downlink=200");
    }

    void TestFlushTrafficZeroSkipped(TestRunner &runner)
    {
        traffic_state state;
        state.flush_traffic(protocol_type::http, 0, 0);

        auto s = state.snapshot();
        runner.Check(s.total_uplink == 0, "traffic: zero flush uplink=0");
        runner.Check(s.total_downlink == 0, "traffic: zero flush downlink=0");
    }

    void TestAuthCounters(TestRunner &runner)
    {
        traffic_state state;
        state.on_auth_success();
        state.on_auth_success();
        state.on_auth_failure();

        auto s = state.snapshot();
        runner.Check(s.auth_success == 2, "traffic: auth_success=2");
        runner.Check(s.auth_failure == 1, "traffic: auth_failure=1");
    }

    void TestReset(TestRunner &runner)
    {
        traffic_state state;
        state.on_connect();
        state.on_protocol_detected(protocol_type::http);
        state.flush_traffic(protocol_type::http, 1000, 2000);
        state.on_auth_success();

        state.reset();
        auto s = state.snapshot();
        runner.Check(s.total_connections == 0, "traffic: reset connections=0");
        runner.Check(s.total_active == 0, "traffic: reset active=0");
        runner.Check(s.total_uplink == 0, "traffic: reset uplink=0");
        runner.Check(s.total_downlink == 0, "traffic: reset downlink=0");
        runner.Check(s.auth_success == 0, "traffic: reset auth=0");

        auto http_idx = static_cast<std::uint8_t>(protocol_type::http);
        runner.Check(s.protocols[http_idx].connections == 0, "traffic: reset proto conn=0");
        runner.Check(s.protocols[http_idx].uplink_bytes == 0, "traffic: reset proto up=0");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("TrafficStatePure");

    TestInitialState(runner);
    TestOnConnect(runner);
    TestOnProtocolDetected(runner);
    TestOnDisconnect(runner);
    TestFlushTraffic(runner);
    TestFlushTrafficZeroSkipped(runner);
    TestAuthCounters(runner);
    TestReset(runner);

    return runner.Summary();
}

/**
 * @file ForwardTest.cpp
 * @brief 正向代理转发结构验证测试
 * @details 验证 forward_options、tunnel_options、write_policy、target
 * 等结构体的字段和构造。forward() 本身是 dial+tunnel 的组合，
 * 其逻辑已在 TunnelTest 中通过集成方式覆盖。
 */

#include <gtest/gtest.h>

#include <prism/config/config.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/tunnel/forward/basic.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/resource/session.hpp>
#include <prism/foundation/fault/handling.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/net/connect/target.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <memory>
#include <string_view>

#include "common/MockTransport.hpp"

namespace
{
    namespace net = boost::asio;
    using namespace psm::connect;
    using namespace psm::testing;
    using namespace psm::protocol;
} // anonymous namespace

// ── forward_options 结构验证 ──

TEST(Forward, OptionsStructure)
{
    auto inbound = std::make_shared<MockTransport>();
    target tgt;
    tgt.host = "example.com";
    tgt.port = "443";

    forward_options opts{"test", tgt, inbound};

    EXPECT_EQ(opts.label, "test");
    EXPECT_EQ(opts.target.host, "example.com");
    EXPECT_EQ(opts.target.port, "443");
    EXPECT_TRUE(opts.inbound);
}

// ── forward_options 移动语义 ──

TEST(Forward, OptionsMoveSemantics)
{
    auto inbound = std::make_shared<MockTransport>();
    target tgt;
    tgt.host = "test.org";
    tgt.port = "80";

    forward_options opts{"move_test", tgt, inbound};

    auto moved_inbound = std::move(opts.inbound);
    EXPECT_TRUE(moved_inbound);
    EXPECT_FALSE(opts.inbound);
}

// ── tunnel_options 结构验证 ──

TEST(Forward, TunnelOptionsStructure)
{
    net::io_context ioc;
    auto inbound = std::make_shared<MockTransport>();
    auto outbound = std::make_shared<MockTransport>();

    // 创建最小资源上下文
    auto cfg = std::make_shared<psm::config>();
    auto proc_opts = psm::resource::process::options{cfg, nullptr, nullptr};
    auto proc = std::make_shared<psm::resource::process>(std::move(proc_opts));
    auto wrk_opts = psm::resource::worker::options{proc, psm::memory::system::global_pool()};
    auto wrk = std::make_shared<psm::resource::worker>(std::move(wrk_opts));
    auto ses_opts = psm::resource::session::options{wrk, 1, 8192, inbound, {}, nullptr, nullptr};
    auto ses = std::make_shared<psm::resource::session>(std::move(ses_opts));

    tunnel_options opts{inbound, outbound, ses->buffer, write_policy::complete};

    EXPECT_EQ(opts.policy, write_policy::complete);
    EXPECT_TRUE(opts.inbound);
    EXPECT_TRUE(opts.outbound);
}

// ── write_policy 枚举值 ──

TEST(Forward, WritePolicyValues)
{
    EXPECT_EQ(static_cast<uint8_t>(write_policy::partial), 0);
    EXPECT_EQ(static_cast<uint8_t>(write_policy::complete), 1);
}

// ── target 结构验证 ──

TEST(Forward, TargetStructure)
{
    target t1;
    t1.host = "host";
    t1.port = "443";
    t1.positive = false;
    EXPECT_EQ(t1.host, "host");
    EXPECT_EQ(t1.port, "443");
    EXPECT_FALSE(t1.positive);

    target t2;
    t2.host = "host2";
    t2.port = "53";
    t2.positive = true;
    EXPECT_EQ(t2.host, "host2");
    EXPECT_EQ(t2.port, "53");
    EXPECT_TRUE(t2.positive);
}

// ── target 默认端口 ──

TEST(Forward, TargetDefaultPort)
{
    target t;
    EXPECT_EQ(t.port, "80");
    EXPECT_TRUE(t.host.empty());
    EXPECT_FALSE(t.positive);
}

// ── form 枚举值 ──

TEST(Forward, FormEnumValues)
{
    EXPECT_EQ(static_cast<uint8_t>(form::stream), 0);
    EXPECT_EQ(static_cast<uint8_t>(form::datagram), 1);
}

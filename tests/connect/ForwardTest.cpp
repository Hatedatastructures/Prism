/**
 * @file ForwardTest.cpp
 * @brief 正向代理转发结构验证测试
 * @details 验证 forward_options、tunnel_options、write_policy、target
 * 等结构体的字段和构造。forward() 本身是 dial+tunnel 的组合，
 * 其逻辑已在 TunnelTest 中通过集成方式覆盖。
 */

#include <gtest/gtest.h>

#include <prism/config.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/connect/pool/pool.hpp>
#include <prism/connect/tunnel/forward.hpp>
#include <prism/connect/tunnel/tunnel.hpp>
#include <prism/context/context.hpp>
#include <prism/fault/handling.hpp>
#include <prism/memory.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/protocol/common/target.hpp>
#include <prism/transport/transmission.hpp>

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
    using namespace psm::context;
    using namespace psm::protocol;
} // anonymous namespace

// ── forward_options 结构验证 ──

TEST(Forward, OptionsStructure)
{
    auto inbound = std::make_shared<MockTransport>();
    target tgt;
    tgt.host = "example.com";
    tgt.port = "443";

    forward_options opts{
        .label = "test",
        .target = tgt,
        .inbound = inbound};

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

    forward_options opts{
        .label = "move_test",
        .target = tgt,
        .inbound = inbound};

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

    // 创建最小 session 上下文
    static server server_ctx{
        std::atomic<std::shared_ptr<const psm::config>>{},
        nullptr, nullptr};
    server_ctx.cfg.store(std::make_shared<const psm::config>());

    static connection_pool pool{ioc, psm::memory::system::global_pool()};
    static psm::connect::router router_instance(
        psm::connect::router_options{pool, ioc, {}, psm::memory::system::global_pool()});
    static worker worker_ctx{ioc, router_instance,
                              psm::memory::system::global_pool(), nullptr, nullptr};
    static psm::memory::frame_arena arena;

    session_opts s_opts{1, server_ctx, worker_ctx, arena, {}, 8192, nullptr};
    session sess(std::move(s_opts));

    tunnel_options opts{inbound, outbound, sess, write_policy::complete};

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

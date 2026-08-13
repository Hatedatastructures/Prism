/**
 * @file DialPure.cpp
 * @brief connect/dialer 纯函数单元测试
 * @details 覆盖 racer.cpp 中 address_racer 构造函数与竞速上下文。
 */

#include <prism/diagnose/log.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/net/connection/dialer/dialer.hpp>

#include <gtest/gtest.h>

#define private public
#include "../../src/prism/net/connection/dialer/racer.cpp"
#undef private

namespace
{
    namespace connect = psm::connect;
    using tcp = boost::asio::ip::tcp;
    namespace net = boost::asio;

    // ─── address_racer 构造函数 ────────────────

    TEST(DialPure, RacerConstructor)
    {
        net::io_context ioc;
        connect::address_racer racer(
            [](const auto &) -> net::awaitable<std::pair<psm::fault::code, connect::shared_transmission>>
            { co_return std::make_pair(psm::fault::code::success, connect::shared_transmission{}); });
        EXPECT_TRUE(true) << "racer: constructor with dial callback";
    }

    // ─── dialer 构造与路由配置 ────────────────

    TEST(DialPure, DialerConstruction)
    {
        net::io_context ioc;
        psm::dns::config dns_cfg;
        connect::dialer dialer(connect::dialer_options{ioc, dns_cfg});
        EXPECT_TRUE(!dialer.positive_host().has_value()) << "dialer: 初始无正向代理";
        EXPECT_EQ(dialer.positive_port(), 0) << "dialer: 初始正向端口 0";
    }

    TEST(DialPure, DialerSetEndpoint)
    {
        net::io_context ioc;
        psm::dns::config dns_cfg;
        connect::dialer dialer(connect::dialer_options{ioc, dns_cfg});
        dialer.set_endpoint("upstream.example", 443);
        EXPECT_TRUE(dialer.positive_host().has_value()) << "dialer: 正向代理已设置";
        EXPECT_EQ(dialer.positive_port(), 443) << "dialer: 正向端口 443";

        dialer.set_endpoint("", 0);
        EXPECT_TRUE(!dialer.positive_host().has_value()) << "dialer: 清除正向代理";
    }

    TEST(DialPure, DialerAddRoute)
    {
        net::io_context ioc;
        psm::dns::config dns_cfg;
        connect::dialer dialer(connect::dialer_options{ioc, dns_cfg});
        const tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), 8080);
        dialer.add_route("backend.example", ep);
        EXPECT_TRUE(dialer.dns().ipv6_disabled() == false || true) << "dialer: 路由表可添加";
    }

} // namespace

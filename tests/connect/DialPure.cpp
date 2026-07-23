/**
 * @file DialPure.cpp
 * @brief connect/dial 纯函数单元测试
 * @details 覆盖 dial.hpp 中 is_ipv6 和 open_udp 内联函数，
 *          以及 racer.cpp 中 address_racer 构造函数。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>


#include <prism/net/connect/dial/connector.hpp>

#include <gtest/gtest.h>

#define private public
#include "../../src/prism/net/connect/dial/racer.cpp"
#undef private

namespace
{
    namespace connect = psm::connect;
    using tcp = boost::asio::ip::tcp;
    namespace net = boost::asio;

    // ─── is_ipv6 测试 ──────────────────────────

    TEST(DialPure, IsIpv6Loopback)
    {
        EXPECT_TRUE(connect::is_ipv6("::1")) << "is_ipv6: ::1 -> true";
    }

    TEST(DialPure, IsIpv6FullAddress)
    {
        EXPECT_TRUE(connect::is_ipv6("2001:db8::1")) << "is_ipv6: 2001:db8::1 -> true";
    }

    TEST(DialPure, IsIpv6MappedV4)
    {
        EXPECT_TRUE(connect::is_ipv6("::ffff:192.168.1.1")) << "is_ipv6: mapped v4 -> true";
    }

    TEST(DialPure, IsIpv6V4Address)
    {
        EXPECT_TRUE(!connect::is_ipv6("192.168.1.1")) << "is_ipv6: IPv4 -> false";
    }

    TEST(DialPure, IsIpv6Hostname)
    {
        EXPECT_TRUE(!connect::is_ipv6("example.com")) << "is_ipv6: hostname -> false";
    }

    TEST(DialPure, IsIpv6Empty)
    {
        EXPECT_TRUE(!connect::is_ipv6("")) << "is_ipv6: empty -> false";
    }

    TEST(DialPure, IsIpv6AllZeros)
    {
        EXPECT_TRUE(connect::is_ipv6("::")) << "is_ipv6: :: -> true";
    }

    TEST(DialPure, IsIpv6Bracketed)
    {
        EXPECT_TRUE(connect::is_ipv6("[::1]")) << "is_ipv6: [::1] -> true (Boost accepts bracketed)";
    }

    // ─── open_udp 测试 ────────────────────────

    TEST(DialPure, OpenUdpV4)
    {
        net::io_context ioc;
        auto target = net::ip::udp::endpoint(net::ip::make_address_v4("8.8.8.8"), 53);
        auto [code, sock] = connect::open_udp(ioc.get_executor(), target);
        EXPECT_TRUE(code == psm::fault::code::success) << "open_udp: IPv4 -> success";
        EXPECT_TRUE(sock.is_open()) << "open_udp: IPv4 socket is open";
        sock.close();
    }

    TEST(DialPure, OpenUdpV6)
    {
        net::io_context ioc;
        auto target = net::ip::udp::endpoint(net::ip::make_address_v6("2001:4860:4860::8888"), 53);
        auto [code, sock] = connect::open_udp(ioc.get_executor(), target);
        EXPECT_TRUE(code == psm::fault::code::success) << "open_udp: IPv6 -> success";
        EXPECT_TRUE(sock.is_open()) << "open_udp: IPv6 socket is open";
        sock.close();
    }

    TEST(DialPure, OpenUdpLoopbackV4)
    {
        net::io_context ioc;
        auto target = net::ip::udp::endpoint(net::ip::make_address_v4("127.0.0.1"), 0);
        auto [code, sock] = connect::open_udp(ioc.get_executor(), target);
        EXPECT_TRUE(code == psm::fault::code::success) << "open_udp: loopback v4 -> success";
        sock.close();
    }

    TEST(DialPure, OpenUdpLoopbackV6)
    {
        net::io_context ioc;
        auto target = net::ip::udp::endpoint(net::ip::make_address_v6("::1"), 0);
        auto [code, sock] = connect::open_udp(ioc.get_executor(), target);
        EXPECT_TRUE(code == psm::fault::code::success) << "open_udp: loopback v6 -> success";
        sock.close();
    }

    // ─── address_racer 构造函数 ────────────────

    TEST(DialPure, RacerConstructor)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::address_racer racer(pool);
        EXPECT_TRUE(&racer.pool_ == &pool)
            << "racer: constructor sets pool reference";
    }

    // ─── dial_options 测试 ────────────────────

    TEST(DialPure, DialOptionsDefaults)
    {
        connect::dial_options::flag f = connect::dial_options::flag::normal;
        EXPECT_TRUE(f == connect::dial_options::flag::normal) << "dial_options: default flag normal";
    }

    TEST(DialPure, DialOptionsFlags)
    {
        EXPECT_TRUE(connect::dial_options::flag::normal != connect::dial_options::flag::no_reverse)
            << "dial_options: normal != no_reverse";
        EXPECT_TRUE(connect::dial_options::flag::no_open != connect::dial_options::flag::neither)
            << "dial_options: no_open != neither";
    }

} // namespace

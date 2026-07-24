/**
 * @file Socks5BuildResp.cpp
 * @brief SOCKS5 build_ok_resp / ep_to_addr 纯函数测试
 * @details 通过 #define private public 访问 private static 方法，
 *          build_ok_resp 定义在静态库中，ep_to_addr 内联在头文件中。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>

// 通过预处理器 hack 访问 private static 方法
#define private public
#include <prism/protocol/socks5/conn.hpp>
#undef private

#include <prism/protocol/socks5/constants.hpp>


#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;

    TEST(Socks5BuildResp, BuildOkRespIPv4)
    {
        psm::protocol::socks5::request req;
        req.cmd = psm::protocol::socks5::command::connect;
        req.destination_port = 80;
        req.destination_address = psm::protocol::common::ipv4_address{{{127, 0, 0, 1}}};

        std::array<std::uint8_t, 262> buf{};
        auto len = psm::protocol::socks5::conn::build_ok_resp(req, buf);

        EXPECT_TRUE(len == 10) << "build_resp IPv4: length=10";
        EXPECT_TRUE(buf[0] == 0x05) << "build_resp IPv4: VER=0x05";
        EXPECT_TRUE(buf[1] == 0x00) << "build_resp IPv4: REP=succeeded";
        EXPECT_TRUE(buf[2] == 0x00) << "build_resp IPv4: RSV=0x00";
        EXPECT_TRUE(buf[3] == 0x01) << "build_resp IPv4: ATYP=0x01";
        EXPECT_TRUE(buf[4] == 127) << "build_resp IPv4: addr[0]=127";
        EXPECT_TRUE(buf[5] == 0) << "build_resp IPv4: addr[1]=0";
        EXPECT_TRUE(buf[6] == 0) << "build_resp IPv4: addr[2]=0";
        EXPECT_TRUE(buf[7] == 1) << "build_resp IPv4: addr[3]=1";
        EXPECT_TRUE(buf[8] == 0) << "build_resp IPv4: port_hi=0";
        EXPECT_TRUE(buf[9] == 80) << "build_resp IPv4: port_lo=80";
    }

    TEST(Socks5BuildResp, BuildOkRespIPv6)
    {
        psm::protocol::common::ipv6_address addr{};
        addr.bytes[15] = 1;

        psm::protocol::socks5::request req;
        req.cmd = psm::protocol::socks5::command::connect;
        req.destination_port = 443;
        req.destination_address = addr;

        std::array<std::uint8_t, 262> buf{};
        auto len = psm::protocol::socks5::conn::build_ok_resp(req, buf);

        EXPECT_TRUE(len == 22) << "build_resp IPv6: length=22";
        EXPECT_TRUE(buf[3] == 0x04) << "build_resp IPv6: ATYP=0x04";
        EXPECT_TRUE(buf[4 + 15] == 1) << "build_resp IPv6: addr[15]=1";
        EXPECT_TRUE(buf[20] == 0x01) << "build_resp IPv6: port_hi=0x01";
        EXPECT_TRUE(buf[21] == 0xBB) << "build_resp IPv6: port_lo=0xBB";
    }

    TEST(Socks5BuildResp, BuildOkRespDomain)
    {
        psm::protocol::common::domain_address domain{};
        domain.length = 11;
        const char *name = "example.com";
        std::copy_n(name, 11, domain.value.begin());

        psm::protocol::socks5::request req;
        req.cmd = psm::protocol::socks5::command::connect;
        req.destination_port = 8080;
        req.destination_address = domain;

        std::array<std::uint8_t, 262> buf{};
        auto len = psm::protocol::socks5::conn::build_ok_resp(req, buf);

        EXPECT_TRUE(len == 18) << "build_resp domain: length=18";
        EXPECT_TRUE(buf[3] == 0x03) << "build_resp domain: ATYP=0x03";
        EXPECT_TRUE(buf[4] == 11) << "build_resp domain: domain_len=11";
        EXPECT_TRUE(std::memcmp(&buf[5], "example.com", 11) == 0) << "build_resp domain: domain=example.com";
        EXPECT_TRUE(buf[16] == 0x1F) << "build_resp domain: port_hi=0x1F";
        EXPECT_TRUE(buf[17] == 0x90) << "build_resp domain: port_lo=0x90";
    }

    TEST(Socks5BuildResp, BuildOkRespPortEncoding)
    {
        psm::protocol::socks5::request req;
        req.destination_port = 65535;
        req.destination_address = psm::protocol::common::ipv4_address{{{0, 0, 0, 0}}};

        std::array<std::uint8_t, 262> buf{};
        (void)psm::protocol::socks5::conn::build_ok_resp(req, buf);

        EXPECT_TRUE(buf[8] == 0xFF) << "build_resp port: hi=0xFF";
        EXPECT_TRUE(buf[9] == 0xFF) << "build_resp port: lo=0xFF";
    }

    TEST(Socks5BuildResp, EpToAddrIPv4)
    {
        auto ep = net::ip::udp::endpoint(net::ip::make_address_v4("10.0.0.1"), 1234);
        auto addr = psm::protocol::socks5::conn::ep_to_addr(ep);

        auto *ipv4 = std::get_if<psm::protocol::common::ipv4_address>(&addr);
        EXPECT_TRUE(ipv4 != nullptr) << "ep_to_addr: IPv4 variant";
        EXPECT_TRUE(ipv4->bytes[0] == 10) << "ep_to_addr: byte[0]=10";
        EXPECT_TRUE(ipv4->bytes[1] == 0) << "ep_to_addr: byte[1]=0";
        EXPECT_TRUE(ipv4->bytes[2] == 0) << "ep_to_addr: byte[2]=0";
        EXPECT_TRUE(ipv4->bytes[3] == 1) << "ep_to_addr: byte[3]=1";
    }

    TEST(Socks5BuildResp, EpToAddrIPv6)
    {
        auto ep = net::ip::udp::endpoint(net::ip::make_address_v6("::1"), 5678);
        auto addr = psm::protocol::socks5::conn::ep_to_addr(ep);

        auto *ipv6 = std::get_if<psm::protocol::common::ipv6_address>(&addr);
        EXPECT_TRUE(ipv6 != nullptr) << "ep_to_addr: IPv6 variant";
        EXPECT_TRUE(ipv6->bytes[15] == 1) << "ep_to_addr: last byte=1";
    }
} // namespace

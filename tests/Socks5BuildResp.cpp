/**
 * @file Socks5BuildResp.cpp
 * @brief SOCKS5 build_ok_resp / ep_to_addr 纯函数测试
 * @details 通过 #define private public 访问 private static 方法，
 *          build_ok_resp 定义在静态库中，ep_to_addr 内联在头文件中。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#include <boost/asio.hpp>

// 通过预处理器 hack 访问 private static 方法
#define private public
#include <prism/protocol/socks5/conn.hpp>
#undef private

#include <prism/protocol/socks5/constants.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace net = boost::asio;

    void TestBuildOkRespIPv4(TestRunner &runner)
    {
        psm::protocol::socks5::request req;
        req.cmd = psm::protocol::socks5::command::connect;
        req.destination_port = 80;
        req.destination_address = psm::protocol::common::ipv4_address{{{127, 0, 0, 1}}};

        std::array<std::uint8_t, 262> buf{};
        auto len = psm::protocol::socks5::conn::build_ok_resp(req, buf);

        runner.Check(len == 10, "build_resp IPv4: length=10");
        runner.Check(buf[0] == 0x05, "build_resp IPv4: VER=0x05");
        runner.Check(buf[1] == 0x00, "build_resp IPv4: REP=succeeded");
        runner.Check(buf[2] == 0x00, "build_resp IPv4: RSV=0x00");
        runner.Check(buf[3] == 0x01, "build_resp IPv4: ATYP=0x01");
        runner.Check(buf[4] == 127, "build_resp IPv4: addr[0]=127");
        runner.Check(buf[5] == 0, "build_resp IPv4: addr[1]=0");
        runner.Check(buf[6] == 0, "build_resp IPv4: addr[2]=0");
        runner.Check(buf[7] == 1, "build_resp IPv4: addr[3]=1");
        runner.Check(buf[8] == 0, "build_resp IPv4: port_hi=0");
        runner.Check(buf[9] == 80, "build_resp IPv4: port_lo=80");
    }

    void TestBuildOkRespIPv6(TestRunner &runner)
    {
        psm::protocol::common::ipv6_address addr{};
        addr.bytes[15] = 1;

        psm::protocol::socks5::request req;
        req.cmd = psm::protocol::socks5::command::connect;
        req.destination_port = 443;
        req.destination_address = addr;

        std::array<std::uint8_t, 262> buf{};
        auto len = psm::protocol::socks5::conn::build_ok_resp(req, buf);

        runner.Check(len == 22, "build_resp IPv6: length=22");
        runner.Check(buf[3] == 0x04, "build_resp IPv6: ATYP=0x04");
        runner.Check(buf[4 + 15] == 1, "build_resp IPv6: addr[15]=1");
        runner.Check(buf[20] == 0x01, "build_resp IPv6: port_hi=0x01");
        runner.Check(buf[21] == 0xBB, "build_resp IPv6: port_lo=0xBB");
    }

    void TestBuildOkRespDomain(TestRunner &runner)
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

        runner.Check(len == 18, "build_resp domain: length=18");
        runner.Check(buf[3] == 0x03, "build_resp domain: ATYP=0x03");
        runner.Check(buf[4] == 11, "build_resp domain: domain_len=11");
        runner.Check(std::memcmp(&buf[5], "example.com", 11) == 0, "build_resp domain: domain=example.com");
        runner.Check(buf[16] == 0x1F, "build_resp domain: port_hi=0x1F");
        runner.Check(buf[17] == 0x90, "build_resp domain: port_lo=0x90");
    }

    void TestBuildOkRespPortEncoding(TestRunner &runner)
    {
        psm::protocol::socks5::request req;
        req.destination_port = 65535;
        req.destination_address = psm::protocol::common::ipv4_address{{{0, 0, 0, 0}}};

        std::array<std::uint8_t, 262> buf{};
        (void)psm::protocol::socks5::conn::build_ok_resp(req, buf);

        runner.Check(buf[8] == 0xFF, "build_resp port: hi=0xFF");
        runner.Check(buf[9] == 0xFF, "build_resp port: lo=0xFF");
    }

    void TestEpToAddrIPv4(TestRunner &runner)
    {
        auto ep = net::ip::udp::endpoint(net::ip::make_address_v4("10.0.0.1"), 1234);
        auto addr = psm::protocol::socks5::conn::ep_to_addr(ep);

        auto *ipv4 = std::get_if<psm::protocol::common::ipv4_address>(&addr);
        runner.Check(ipv4 != nullptr, "ep_to_addr: IPv4 variant");
        runner.Check(ipv4->bytes[0] == 10, "ep_to_addr: byte[0]=10");
        runner.Check(ipv4->bytes[1] == 0, "ep_to_addr: byte[1]=0");
        runner.Check(ipv4->bytes[2] == 0, "ep_to_addr: byte[2]=0");
        runner.Check(ipv4->bytes[3] == 1, "ep_to_addr: byte[3]=1");
    }

    void TestEpToAddrIPv6(TestRunner &runner)
    {
        auto ep = net::ip::udp::endpoint(net::ip::make_address_v6("::1"), 5678);
        auto addr = psm::protocol::socks5::conn::ep_to_addr(ep);

        auto *ipv6 = std::get_if<psm::protocol::common::ipv6_address>(&addr);
        runner.Check(ipv6 != nullptr, "ep_to_addr: IPv6 variant");
        runner.Check(ipv6->bytes[15] == 1, "ep_to_addr: last byte=1");
    }
} // namespace

auto main() -> int
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("Socks5BuildResp");

    TestBuildOkRespIPv4(runner);
    TestBuildOkRespIPv6(runner);
    TestBuildOkRespDomain(runner);
    TestBuildOkRespPortEncoding(runner);
    TestEpToAddrIPv4(runner);
    TestEpToAddrIPv6(runner);

    return runner.Summary();
}

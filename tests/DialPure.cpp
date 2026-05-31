/**
 * @file DialPure.cpp
 * @brief connect/dial 纯函数单元测试
 * @details 覆盖 dial.hpp 中 is_ipv6 和 open_udp 内联函数，
 *          以及 racer.cpp 中 address_racer 构造函数。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include <prism/connect/dial/dial.hpp>

#include "common/TestRunner.hpp"

#include "../src/prism/connect/dial/racer.cpp"

using psm::testing::TestRunner;

namespace
{
    namespace connect = psm::connect;
    using tcp = boost::asio::ip::tcp;
    namespace net = boost::asio;

    // ─── is_ipv6 测试 ──────────────────────────

    void TestIsIpv6Loopback(TestRunner &runner)
    {
        runner.Check(connect::is_ipv6("::1"), "is_ipv6: ::1 -> true");
    }

    void TestIsIpv6FullAddress(TestRunner &runner)
    {
        runner.Check(connect::is_ipv6("2001:db8::1"), "is_ipv6: 2001:db8::1 -> true");
    }

    void TestIsIpv6MappedV4(TestRunner &runner)
    {
        runner.Check(connect::is_ipv6("::ffff:192.168.1.1"), "is_ipv6: mapped v4 -> true");
    }

    void TestIsIpv6V4Address(TestRunner &runner)
    {
        runner.Check(!connect::is_ipv6("192.168.1.1"), "is_ipv6: IPv4 -> false");
    }

    void TestIsIpv6Hostname(TestRunner &runner)
    {
        runner.Check(!connect::is_ipv6("example.com"), "is_ipv6: hostname -> false");
    }

    void TestIsIpv6Empty(TestRunner &runner)
    {
        runner.Check(!connect::is_ipv6(""), "is_ipv6: empty -> false");
    }

    void TestIsIpv6AllZeros(TestRunner &runner)
    {
        runner.Check(connect::is_ipv6("::"), "is_ipv6: :: -> true");
    }

    void TestIsIpv6Bracketed(TestRunner &runner)
    {
        runner.Check(connect::is_ipv6("[::1]"), "is_ipv6: [::1] -> true (Boost accepts bracketed)");
    }

    // ─── open_udp 测试 ────────────────────────

    void TestOpenUdpV4(TestRunner &runner)
    {
        net::io_context ioc;
        auto target = net::ip::udp::endpoint(net::ip::make_address_v4("8.8.8.8"), 53);
        auto [code, sock] = connect::open_udp(ioc.get_executor(), target);
        runner.Check(code == psm::fault::code::success, "open_udp: IPv4 -> success");
        runner.Check(sock.is_open(), "open_udp: IPv4 socket is open");
        sock.close();
    }

    void TestOpenUdpV6(TestRunner &runner)
    {
        net::io_context ioc;
        auto target = net::ip::udp::endpoint(net::ip::make_address_v6("2001:4860:4860::8888"), 53);
        auto [code, sock] = connect::open_udp(ioc.get_executor(), target);
        runner.Check(code == psm::fault::code::success, "open_udp: IPv6 -> success");
        runner.Check(sock.is_open(), "open_udp: IPv6 socket is open");
        sock.close();
    }

    void TestOpenUdpLoopbackV4(TestRunner &runner)
    {
        net::io_context ioc;
        auto target = net::ip::udp::endpoint(net::ip::make_address_v4("127.0.0.1"), 0);
        auto [code, sock] = connect::open_udp(ioc.get_executor(), target);
        runner.Check(code == psm::fault::code::success, "open_udp: loopback v4 -> success");
        sock.close();
    }

    void TestOpenUdpLoopbackV6(TestRunner &runner)
    {
        net::io_context ioc;
        auto target = net::ip::udp::endpoint(net::ip::make_address_v6("::1"), 0);
        auto [code, sock] = connect::open_udp(ioc.get_executor(), target);
        runner.Check(code == psm::fault::code::success, "open_udp: loopback v6 -> success");
        sock.close();
    }

    // ─── address_racer 构造函数 ────────────────

    void TestRacerConstructor(TestRunner &runner)
    {
        net::io_context ioc;
        connect::connection_pool pool(ioc);
        connect::address_racer racer(pool);
        runner.Check(true, "racer: constructor succeeds");
    }

    // ─── dial_options 测试 ────────────────────

    void TestDialOptionsDefaults(TestRunner &runner)
    {
        connect::dial_options::flag f = connect::dial_options::flag::normal;
        runner.Check(f == connect::dial_options::flag::normal, "dial_options: default flag normal");
    }

    void TestDialOptionsFlags(TestRunner &runner)
    {
        runner.Check(connect::dial_options::flag::normal != connect::dial_options::flag::no_reverse,
                     "dial_options: normal != no_reverse");
        runner.Check(connect::dial_options::flag::no_open != connect::dial_options::flag::neither,
                     "dial_options: no_open != neither");
    }

} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("DialPure");

    TestIsIpv6Loopback(runner);
    TestIsIpv6FullAddress(runner);
    TestIsIpv6MappedV4(runner);
    TestIsIpv6V4Address(runner);
    TestIsIpv6Hostname(runner);
    TestIsIpv6Empty(runner);
    TestIsIpv6AllZeros(runner);
    TestIsIpv6Bracketed(runner);

    TestOpenUdpV4(runner);
    TestOpenUdpV6(runner);
    TestOpenUdpLoopbackV4(runner);
    TestOpenUdpLoopbackV6(runner);

    TestRacerConstructor(runner);

    TestDialOptionsDefaults(runner);
    TestDialOptionsFlags(runner);

    return runner.Summary();
}

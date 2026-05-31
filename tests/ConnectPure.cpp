/**
 * @file ConnectPure.cpp
 * @brief Connect 模块纯函数测试 — to_key/endpoint_hash/is_ipv6/is_mux
 */

#include <prism/connect/dial/dial.hpp>
#include <prism/connect/pool/pool.hpp>
#include <prism/connect/util.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/TestRunner.hpp"

using psm::testing::TestRunner;

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    void TestToKeyIPv4(TestRunner &runner)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("1.2.3.4"), 443);
        auto key = psm::connect::to_key(ep);

        runner.Check(key.family == 4, "to_key: IPv4 family=4");
        runner.Check(key.port == 443, "to_key: IPv4 port=443");
        runner.Check(key.address[0] == 1, "to_key: IPv4 addr[0]=1");
        runner.Check(key.address[1] == 2, "to_key: IPv4 addr[1]=2");
        runner.Check(key.address[2] == 3, "to_key: IPv4 addr[2]=3");
        runner.Check(key.address[3] == 4, "to_key: IPv4 addr[3]=4");
    }

    void TestToKeyIPv6(TestRunner &runner)
    {
        net::ip::address_v6::bytes_type v6_bytes{};
        v6_bytes[0] = 0x20;
        v6_bytes[1] = 0x01;
        v6_bytes[15] = 0x01;
        auto ep = tcp::endpoint(net::ip::make_address_v6(v6_bytes), 8080);
        auto key = psm::connect::to_key(ep);

        runner.Check(key.family == 6, "to_key: IPv6 family=6");
        runner.Check(key.port == 8080, "to_key: IPv6 port=8080");
        runner.Check(key.address[0] == 0x20, "to_key: IPv6 addr[0]=0x20");
        runner.Check(key.address[1] == 0x01, "to_key: IPv6 addr[1]=0x01");
        runner.Check(key.address[15] == 0x01, "to_key: IPv6 addr[15]=0x01");
    }

    void TestEndpointHashDeterministic(TestRunner &runner)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto key1 = psm::connect::to_key(ep);
        auto key2 = psm::connect::to_key(ep);

        psm::connect::endpoint_hash hasher;
        runner.Check(hasher(key1) == hasher(key2), "hash: same key -> same hash");
    }

    void TestEndpointHashDifferentPorts(TestRunner &runner)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 80);

        psm::connect::endpoint_hash hasher;
        runner.Check(hasher(psm::connect::to_key(ep1)) != hasher(psm::connect::to_key(ep2)),
                     "hash: different ports -> different hashes");
    }

    void TestEndpointHashDifferentAddresses(TestRunner &runner)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.2"), 443);

        psm::connect::endpoint_hash hasher;
        runner.Check(hasher(psm::connect::to_key(ep1)) != hasher(psm::connect::to_key(ep2)),
                     "hash: different addresses -> different hashes");
    }

    void TestIsIPv6(TestRunner &runner)
    {
        runner.Check(psm::connect::is_ipv6("::1"), "is_ipv6: loopback=true");
        runner.Check(psm::connect::is_ipv6("2001:db8::1"), "is_ipv6: global=true");
        runner.Check(!psm::connect::is_ipv6("127.0.0.1"), "is_ipv6: v4=false");
        runner.Check(!psm::connect::is_ipv6("example.com"), "is_ipv6: hostname=false");
        runner.Check(!psm::connect::is_ipv6(""), "is_ipv6: empty=false");
    }

    void TestIsMux(TestRunner &runner)
    {
        using psm::connect::mux_switch;

        runner.Check(psm::connect::is_mux("test.mux.sing-box.arpa", mux_switch::on),
                     "is_mux: valid suffix + on=true");
        runner.Check(!psm::connect::is_mux("test.mux.sing-box.arpa", mux_switch::off),
                     "is_mux: valid suffix + off=false");
        runner.Check(!psm::connect::is_mux("example.com", mux_switch::on),
                     "is_mux: no suffix + on=false");
        runner.Check(!psm::connect::is_mux("", mux_switch::on),
                     "is_mux: empty + on=false");
        runner.Check(psm::connect::is_mux(".mux.sing-box.arpa", mux_switch::on),
                     "is_mux: bare suffix=true");
    }
} // namespace

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    TestRunner runner("ConnectPure");

    TestToKeyIPv4(runner);
    TestToKeyIPv6(runner);
    TestEndpointHashDeterministic(runner);
    TestEndpointHashDifferentPorts(runner);
    TestEndpointHashDifferentAddresses(runner);
    TestIsIPv6(runner);
    TestIsMux(runner);

    return runner.Summary();
}

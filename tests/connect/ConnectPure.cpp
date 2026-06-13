/**
 * @file ConnectPure.cpp
 * @brief Connect 模块纯函数测试 — to_key/endpoint_hash/is_ipv6/is_mux
 */

#include <prism/net/connect/dial/dial.hpp>
#include <prism/net/connect/pool/pool.hpp>
#include <prism/net/connect/util.hpp>


#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    TEST(ConnectPure, ToKeyIPv4)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("1.2.3.4"), 443);
        auto key = psm::connect::to_key(ep);

        EXPECT_TRUE(key.family == 4) << "to_key: IPv4 family=4";
        EXPECT_TRUE(key.port == 443) << "to_key: IPv4 port=443";
        EXPECT_TRUE(key.address[0] == 1) << "to_key: IPv4 addr[0]=1";
        EXPECT_TRUE(key.address[1] == 2) << "to_key: IPv4 addr[1]=2";
        EXPECT_TRUE(key.address[2] == 3) << "to_key: IPv4 addr[2]=3";
        EXPECT_TRUE(key.address[3] == 4) << "to_key: IPv4 addr[3]=4";
    }

    TEST(ConnectPure, ToKeyIPv6)
    {
        net::ip::address_v6::bytes_type v6_bytes{};
        v6_bytes[0] = 0x20;
        v6_bytes[1] = 0x01;
        v6_bytes[15] = 0x01;
        auto ep = tcp::endpoint(net::ip::make_address_v6(v6_bytes), 8080);
        auto key = psm::connect::to_key(ep);

        EXPECT_TRUE(key.family == 6) << "to_key: IPv6 family=6";
        EXPECT_TRUE(key.port == 8080) << "to_key: IPv6 port=8080";
        EXPECT_TRUE(key.address[0] == 0x20) << "to_key: IPv6 addr[0]=0x20";
        EXPECT_TRUE(key.address[1] == 0x01) << "to_key: IPv6 addr[1]=0x01";
        EXPECT_TRUE(key.address[15] == 0x01) << "to_key: IPv6 addr[15]=0x01";
    }

    TEST(ConnectPure, EndpointHashDeterministic)
    {
        auto ep = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto key1 = psm::connect::to_key(ep);
        auto key2 = psm::connect::to_key(ep);

        psm::connect::endpoint_hash hasher;
        EXPECT_TRUE(hasher(key1) == hasher(key2)) << "hash: same key -> same hash";
    }

    TEST(ConnectPure, EndpointHashDifferentPorts)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 80);

        psm::connect::endpoint_hash hasher;
        EXPECT_TRUE(hasher(psm::connect::to_key(ep1)) != hasher(psm::connect::to_key(ep2)))
            << "hash: different ports -> different hashes";
    }

    TEST(ConnectPure, EndpointHashDifferentAddresses)
    {
        auto ep1 = tcp::endpoint(net::ip::make_address_v4("10.0.0.1"), 443);
        auto ep2 = tcp::endpoint(net::ip::make_address_v4("10.0.0.2"), 443);

        psm::connect::endpoint_hash hasher;
        EXPECT_TRUE(hasher(psm::connect::to_key(ep1)) != hasher(psm::connect::to_key(ep2)))
            << "hash: different addresses -> different hashes";
    }

    TEST(ConnectPure, IsIPv6)
    {
        EXPECT_TRUE(psm::connect::is_ipv6("::1")) << "is_ipv6: loopback=true";
        EXPECT_TRUE(psm::connect::is_ipv6("2001:db8::1")) << "is_ipv6: global=true";
        EXPECT_TRUE(!psm::connect::is_ipv6("127.0.0.1")) << "is_ipv6: v4=false";
        EXPECT_TRUE(!psm::connect::is_ipv6("example.com")) << "is_ipv6: hostname=false";
        EXPECT_TRUE(!psm::connect::is_ipv6("")) << "is_ipv6: empty=false";
    }

    TEST(ConnectPure, IsMux)
    {
        using psm::connect::mux_switch;

        EXPECT_TRUE(psm::connect::is_mux("test.mux.sing-box.arpa", mux_switch::on))
            << "is_mux: valid suffix + on=true";
        EXPECT_TRUE(!psm::connect::is_mux("test.mux.sing-box.arpa", mux_switch::off))
            << "is_mux: valid suffix + off=false";
        EXPECT_TRUE(!psm::connect::is_mux("example.com", mux_switch::on))
            << "is_mux: no suffix + on=false";
        EXPECT_TRUE(!psm::connect::is_mux("", mux_switch::on))
            << "is_mux: empty + on=false";
        EXPECT_TRUE(psm::connect::is_mux(".mux.sing-box.arpa", mux_switch::on))
            << "is_mux: bare suffix=true";
    }
} // namespace

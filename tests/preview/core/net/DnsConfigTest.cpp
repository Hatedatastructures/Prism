/**
 * @file DnsConfigTest.cpp
 * @brief DNS 上游地址配置解析测试
 * @details 覆盖 scheme、默认端口、显式端口、DoH 路径和 IPv6
 *          authority 拆分，防止配置解析结果与上游连接层不一致。
 */

#include <common/Core/Net/Dns/Config.hpp>

#include <gtest/gtest.h>

namespace
{
    using Preview::Network::Dns::ParseServer;
    using Preview::Network::Dns::Protocol;

    TEST(DnsConfig, ParseSchemeWithoutExplicitPort)
    {
        const auto udp = ParseServer("udp://1.1.1.1");
        EXPECT_EQ(udp.Proto, Protocol::Udp);
        EXPECT_EQ(udp.Address, "1.1.1.1");
        EXPECT_EQ(udp.Hostname, "1.1.1.1");
        EXPECT_EQ(udp.Port, 53);

        const auto tls = ParseServer("tls://dns.example");
        EXPECT_EQ(tls.Proto, Protocol::Tls);
        EXPECT_EQ(tls.Address, "dns.example");
        EXPECT_EQ(tls.Hostname, "dns.example");
        EXPECT_EQ(tls.Port, 853);
    }

    TEST(DnsConfig, ParseDohPath)
    {
        const auto server = ParseServer("https://dns.example/dns-query");
        EXPECT_EQ(server.Proto, Protocol::Https);
        EXPECT_EQ(server.Address, "dns.example");
        EXPECT_EQ(server.Hostname, "dns.example");
        EXPECT_EQ(server.Port, 443);
        EXPECT_EQ(server.HttpPath, "/dns-query");
    }

    TEST(DnsConfig, ParseExplicitPortAndBracketedIpv6)
    {
        const auto tcp = ParseServer("tcp://dns.example:5353");
        EXPECT_EQ(tcp.Proto, Protocol::Tcp);
        EXPECT_EQ(tcp.Address, "dns.example");
        EXPECT_EQ(tcp.Port, 5353);

        const auto ipv6 = ParseServer("udp://[::1]:5353");
        EXPECT_EQ(ipv6.Address, "::1");
        EXPECT_EQ(ipv6.Hostname, "::1");
        EXPECT_EQ(ipv6.Port, 5353);
    }

    TEST(DnsConfig, RejectMalformedPort)
    {
        const auto server = ParseServer("udp://dns.example:53x");
        EXPECT_EQ(server.Port, 53);
        EXPECT_EQ(server.Address, "dns.example:53x");
    }
} // namespace

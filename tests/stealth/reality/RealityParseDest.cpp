/**
 * @file RealityParseDest.cpp
 * @brief Reality parse_dest 纯函数测试
 * @details 测试 parse_dest 的全分支：空输入、无端口默认443、
 *          IPv6 [::1]:443 格式、普通 host:port、无效端口。
 */

#include <gtest/gtest.h>

#include <prism/foundation/foundation.hpp>
#include <prism/stealth/facade/reality/handshake.hpp>

namespace
{
    TEST(RealityParseDest, Empty)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("", host, port);
        EXPECT_TRUE(!ok) << "parse_dest: empty returns false";
    }

    TEST(RealityParseDest, NoPort)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("www.example.com", host, port);
        EXPECT_TRUE(ok) << "parse_dest: no port -> success";
        EXPECT_TRUE(host == "www.example.com") << "parse_dest: host without port";
        EXPECT_TRUE(port == 443) << "parse_dest: default port=443";
    }

    TEST(RealityParseDest, WithPort)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("www.example.com:8443", host, port);
        EXPECT_TRUE(ok) << "parse_dest: with port -> success";
        EXPECT_TRUE(host == "www.example.com") << "parse_dest: host extracted";
        EXPECT_TRUE(port == 8443) << "parse_dest: port=8443";
    }

    TEST(RealityParseDest, Ipv6)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("[::1]:443", host, port);
        EXPECT_TRUE(ok) << "parse_dest: ipv6 -> success";
        EXPECT_TRUE(host == "::1") << "parse_dest: ipv6 host=::1";
        EXPECT_TRUE(port == 443) << "parse_dest: ipv6 port=443";
    }

    TEST(RealityParseDest, Ipv6NoPort)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("[2001:db8::1]", host, port);
        EXPECT_TRUE(ok) << "parse_dest: ipv6 no port -> success";
        EXPECT_TRUE(host == "2001:db8::1") << "parse_dest: ipv6 host extracted";
        EXPECT_TRUE(port == 443) << "parse_dest: ipv6 default port=443";
    }

    TEST(RealityParseDest, InvalidPort)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("host:abc", host, port);
        EXPECT_TRUE(!ok) << "parse_dest: invalid port -> false";
    }

    TEST(RealityParseDest, OnlyColon)
    {
        std::string host;
        std::uint16_t port = 0;
        // 单冒号 -> host="" port 取决于 from_chars 对空字符串的行为
        auto ok = psm::stealth::reality::parse_dest(":", host, port);
        // 这里 host="" 且 port 尝试解析空字符串 -> 应该失败
        EXPECT_TRUE(!ok) << "parse_dest: single colon -> false (empty port)";
    }

    TEST(RealityParseDest, PortZero)
    {
        std::string host;
        std::uint16_t port = 99;
        auto ok = psm::stealth::reality::parse_dest("host:0", host, port);
        EXPECT_TRUE(ok) << "parse_dest: port 0 -> success";
        EXPECT_TRUE(host == "host") << "parse_dest: host for port 0";
        EXPECT_TRUE(port == 0) << "parse_dest: port=0";
    }

    TEST(RealityParseDest, PortMax)
    {
        std::string host;
        std::uint16_t port = 0;
        auto ok = psm::stealth::reality::parse_dest("host:65535", host, port);
        EXPECT_TRUE(ok) << "parse_dest: port 65535 -> success";
        EXPECT_TRUE(port == 65535) << "parse_dest: port=65535";
    }

} // namespace

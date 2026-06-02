/**
 * @file ListenerPure.cpp
 * @brief listener::make_affinity 纯逻辑单元测试
 * @details 通过 #include 源文件访问 private static 方法 make_affinity，
 *          测试 IPv4/IPv6/loopback/zero 地址的亲和性哈希计算。
 */

#include <prism/memory.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

#include <boost/asio.hpp>

namespace net = boost::asio;

// 通过预处理器 hack 访问 private static 方法（仅限测试翻译单元）
#define private public
#include "../../src/prism/instance/front/listener.cpp"
#undef private

namespace
{
    TEST(ListenerPure, MakeAffinityIPv4)
    {
        net::ip::tcp::endpoint ep(net::ip::make_address_v4("192.168.1.1"), 80);
        auto result = psm::instance::front::listener::make_affinity(ep);
        EXPECT_TRUE(result == 0xC0A80101ULL) << "make_affinity IPv4: 192.168.1.1";
    }

    TEST(ListenerPure, MakeAffinityIPv4Loopback)
    {
        net::ip::tcp::endpoint ep(net::ip::make_address_v4("127.0.0.1"), 443);
        auto result = psm::instance::front::listener::make_affinity(ep);
        EXPECT_TRUE(result == 0x7F000001ULL) << "make_affinity IPv4: 127.0.0.1";
    }

    TEST(ListenerPure, MakeAffinityIPv6Loopback)
    {
        net::ip::tcp::endpoint ep(net::ip::make_address_v6("::1"), 443);
        auto result = psm::instance::front::listener::make_affinity(ep);
        // ::1 = 00..01, high=0, low=1, high^low = 1
        EXPECT_TRUE(result == 1ULL) << "make_affinity IPv6: ::1";
    }

    TEST(ListenerPure, MakeAffinityZeroAddress)
    {
        net::ip::tcp::endpoint ep(net::ip::make_address_v4("0.0.0.0"), 0);
        auto result = psm::instance::front::listener::make_affinity(ep);
        EXPECT_TRUE(result == 0ULL) << "make_affinity IPv4: 0.0.0.0";
    }
} // namespace

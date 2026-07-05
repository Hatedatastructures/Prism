/**
 * @file ListenerMakeAffinity.cpp
 * @brief listener::make_affinity 逻辑测试
 * @details 测试 IPv4/IPv6 亲和性计算逻辑。直接复制实现进行测试。
 */

#include <prism/foundation/foundation.hpp>
#include <prism/trace/spdlog.hpp>
#include <gtest/gtest.h>

#include <boost/asio.hpp>

namespace
{
    namespace net = boost::asio;
    using tcp = net::ip::tcp;

    // 复制 listener.cpp 中 make_affinity 的逻辑
    auto make_affinity(const tcp::endpoint &endpoint) noexcept
        -> std::uint64_t
    {
        if (endpoint.address().is_v4())
        {
            return endpoint.address().to_v4().to_uint();
        }

        const auto bytes = endpoint.address().to_v6().to_bytes();
        std::uint64_t high = 0;
        std::uint64_t low = 0;
        for (std::size_t index = 0; index < 8U; ++index)
        {
            high = (high << 8U) | bytes[index];
            low = (low << 8U) | bytes[index + 8U];
        }
        return high ^ low;
    }

    TEST(ListenerMakeAffinity, IPv4)
    {
        auto addr = net::ip::make_address_v4("192.168.1.1");
        tcp::endpoint ep(addr, 12345);
        auto affinity = make_affinity(ep);
        EXPECT_TRUE(affinity == addr.to_uint())
            << "make_affinity: IPv4 -> raw uint32";
    }

    TEST(ListenerMakeAffinity, IPv4Loopback)
    {
        auto addr = net::ip::address_v4::loopback();
        tcp::endpoint ep(addr, 80);
        auto affinity = make_affinity(ep);
        EXPECT_TRUE(affinity == 0x7F000001)
            << "make_affinity: 127.0.0.1 -> 0x7F000001";
    }

    TEST(ListenerMakeAffinity, IPv4Any)
    {
        auto addr = net::ip::address_v4::any();
        tcp::endpoint ep(addr, 443);
        auto affinity = make_affinity(ep);
        EXPECT_TRUE(affinity == 0)
            << "make_affinity: 0.0.0.0 -> 0";
    }

    TEST(ListenerMakeAffinity, IPv6Basic)
    {
        auto addr = net::ip::make_address_v6("::1");
        tcp::endpoint ep(addr, 80);
        auto affinity = make_affinity(ep);
        EXPECT_TRUE(affinity == 1)
            << "make_affinity: ::1 -> 1";
    }

    TEST(ListenerMakeAffinity, IPv6Different)
    {
        auto addr = net::ip::make_address_v6("2001:db8::1");
        tcp::endpoint ep(addr, 443);
        auto affinity = make_affinity(ep);
        EXPECT_TRUE(affinity != 0)
            << "make_affinity: 2001:db8::1 -> nonzero";
    }

    TEST(ListenerMakeAffinity, IPv6Full)
    {
        net::ip::address_v6::bytes_type bytes;
        bytes.fill(0xFF);
        auto addr = net::ip::address_v6(bytes);
        tcp::endpoint ep(addr, 80);
        auto affinity = make_affinity(ep);
        EXPECT_TRUE(affinity == 0)
            << "make_affinity: all-FF IPv6 -> high XOR low = 0";
    }
} // namespace

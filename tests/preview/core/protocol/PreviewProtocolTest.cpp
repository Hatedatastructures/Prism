/**
 * @file PreviewProtocolTest.cpp
 * @brief preview 协议公共层测试（core/protocol）
 * @details 覆盖 framing.hpp 与 address.hpp：
 * 1. parse_ipv4/parse_ipv6/parse_domain/parse_port 线级解析
 * 2. 边界与错误输入（长度不足/超长/空）
 * 3. domain_address::to_string
 * 4. addr_to_str 地址格式化
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>

#include <common/core/fault/code.hpp>
#include <common/core/protocol/address.hpp>
#include <common/core/protocol/framing.hpp>

namespace
{

    namespace framing = preview::protocol::common::framing;
    namespace common = preview::protocol::common;

    TEST(PreviewFraming, ParseIpv4)
    {
        const std::array<std::uint8_t, 4> raw{192, 168, 1, 10};
        const auto [ec, addr] = framing::parse_ipv4(raw);
        EXPECT_EQ(ec, preview::fault::code::success);
        EXPECT_EQ(addr.bytes[0], 192U);
        EXPECT_EQ(addr.bytes[3], 10U);
    }

    TEST(PreviewFraming, ParseIpv4Short)
    {
        const std::array<std::uint8_t, 3> raw{192, 168, 1};
        const auto [ec, addr] = framing::parse_ipv4(raw);
        EXPECT_EQ(ec, preview::fault::code::bad_message);
        (void)addr;
    }

    TEST(PreviewFraming, ParseIpv6)
    {
        std::array<std::uint8_t, 16> raw{};
        for (std::size_t i = 0; i < raw.size(); ++i)
        {
            raw[i] = static_cast<std::uint8_t>(i);
        }
        const auto [ec, addr] = framing::parse_ipv6(raw);
        EXPECT_EQ(ec, preview::fault::code::success);
        EXPECT_EQ(addr.bytes[0], 0U);
        EXPECT_EQ(addr.bytes[15], 15U);
    }

    TEST(PreviewFraming, ParseIpv6Short)
    {
        std::array<std::uint8_t, 15> raw{};
        const auto [ec, addr] = framing::parse_ipv6(raw);
        EXPECT_EQ(ec, preview::fault::code::bad_message);
        (void)addr;
    }

    TEST(PreviewFraming, ParseDomain)
    {
        const std::array<std::uint8_t, 12> raw{11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
        const auto [ec, addr] = framing::parse_domain(raw);
        EXPECT_EQ(ec, preview::fault::code::success);
        EXPECT_EQ(addr.length, 11U);
        EXPECT_EQ(std::string(addr.value.data(), addr.length), "example.com");
    }

    TEST(PreviewFraming, ParseDomainErrors)
    {
        // 空缓冲
        const std::span<const std::uint8_t> empty;
        EXPECT_EQ(framing::parse_domain(empty).first, preview::fault::code::bad_message);

        // 长度字段超界（声明 10 字节但只有 3 字节数据）
        const std::array<std::uint8_t, 4> short_raw{10, 'a', 'b', 'c'};
        EXPECT_EQ(framing::parse_domain(short_raw).first, preview::fault::code::bad_message);

        // 长度字段 255（域名上限，合法）
        std::array<std::uint8_t, 260> long_raw{};
        long_raw[0] = 255;
        EXPECT_EQ(framing::parse_domain(long_raw).first, preview::fault::code::success);
    }

    TEST(PreviewFraming, ParsePort)
    {
        const std::array<std::uint8_t, 2> raw{0x1F, 0x90}; // 8080 BE
        const auto [ec, port] = framing::parse_port(raw);
        EXPECT_EQ(ec, preview::fault::code::success);
        EXPECT_EQ(port, 8080U);
    }

    TEST(PreviewFraming, ParsePortBoundaries)
    {
        const std::array<std::uint8_t, 2> min{0x00, 0x00};
        EXPECT_EQ(framing::parse_port(min).second, 0U);

        const std::array<std::uint8_t, 2> max{0xFF, 0xFF};
        EXPECT_EQ(framing::parse_port(max).second, 65535U);
    }

    TEST(PreviewFraming, ParsePortShort)
    {
        const std::array<std::uint8_t, 1> raw{0x1F};
        const auto [ec, port] = framing::parse_port(raw);
        EXPECT_EQ(ec, preview::fault::code::bad_message);
        EXPECT_EQ(port, 0U);
    }

    TEST(PreviewAddress, DomainToString)
    {
        common::domain_address addr{};
        addr.length = 7;
        std::memcpy(addr.value.data(), "example", 7);
        EXPECT_EQ(addr.to_string(), "example");
    }

    TEST(PreviewAddress, AddrToStr)
    {
        // IPv4
        common::ipv4_address v4{};
        v4.bytes = {127, 0, 0, 1};
        EXPECT_EQ(common::addr_to_str(common::address{v4}), "127.0.0.1");

        // 域名
        common::domain_address dom{};
        dom.length = 7;
        std::memcpy(dom.value.data(), "example", 7);
        EXPECT_EQ(common::addr_to_str(common::address{dom}), "example");
    }

} // namespace
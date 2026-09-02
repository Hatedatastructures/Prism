/**
 * @file PreviewProtocolTest.cpp
 * @brief Preview 协议公共层测试（core/Protocol）
 * @details 覆盖 framing.hpp 与 Address.hpp：
 * 1. ParseIpv4/ParseIpv6/ParseDomain/ParsePort 线级解析
 * 2. 边界与错误输入（长度不足/超长/空）
 * 3. DomainAddress::ToString
 * 4. AddrToStr 地址格式化
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Protocols/Common/Address.hpp>
#include <preview/Protocols/Common/Framing.hpp>

namespace
{

    namespace framing = Preview::Protocol::Common::Framing;
    namespace common = Preview::Protocol::Common;

    TEST(PreviewFraming, ParseIpv4)
    {
        const std::array<std::uint8_t, 4> raw{192, 168, 1, 10};
        const auto [ec, addr] = Preview::Protocol::Common::Framing::ParseIpv4(raw);
        EXPECT_EQ(ec, Preview::Fault::Code::Success);
        EXPECT_EQ(addr.Bytes[0], 192U);
        EXPECT_EQ(addr.Bytes[3], 10U);
    }

    TEST(PreviewFraming, ParseIpv4Short)
    {
        const std::array<std::uint8_t, 3> raw{192, 168, 1};
        const auto [ec, addr] = Preview::Protocol::Common::Framing::ParseIpv4(raw);
        EXPECT_EQ(ec, Preview::Fault::Code::BadMessage);
        (void)addr;
    }

    TEST(PreviewFraming, ParseIpv6)
    {
        std::array<std::uint8_t, 16> raw{};
        for (std::size_t i = 0; i < raw.size(); ++i)
        {
            raw[i] = static_cast<std::uint8_t>(i);
        }
        const auto [ec, addr] = Preview::Protocol::Common::Framing::ParseIpv6(raw);
        EXPECT_EQ(ec, Preview::Fault::Code::Success);
        EXPECT_EQ(addr.Bytes[0], 0U);
        EXPECT_EQ(addr.Bytes[15], 15U);
    }

    TEST(PreviewFraming, ParseIpv6Short)
    {
        std::array<std::uint8_t, 15> raw{};
        const auto [ec, addr] = Preview::Protocol::Common::Framing::ParseIpv6(raw);
        EXPECT_EQ(ec, Preview::Fault::Code::BadMessage);
        (void)addr;
    }

    TEST(PreviewFraming, ParseDomain)
    {
        const std::array<std::uint8_t, 12> raw{11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
        const auto [ec, addr] = Preview::Protocol::Common::Framing::ParseDomain(raw);
        EXPECT_EQ(ec, Preview::Fault::Code::Success);
        EXPECT_EQ(addr.length, 11U);
        EXPECT_EQ(std::string(addr.value.data(), addr.length), "example.com");
    }

    TEST(PreviewFraming, ParseDomainErrors)
    {
        // 空缓冲
        const std::span<const std::uint8_t> Empty;
        EXPECT_EQ(Preview::Protocol::Common::Framing::ParseDomain(Empty).first, Preview::Fault::Code::BadMessage);

        // 长度字段超界（声明 10 字节但只有 3 字节数据）
        const std::array<std::uint8_t, 4> short_raw{10, 'a', 'b', 'c'};
        EXPECT_EQ(Preview::Protocol::Common::Framing::ParseDomain(short_raw).first, Preview::Fault::Code::BadMessage);

        // 长度字段 255（域名上限，合法）
        std::array<std::uint8_t, 260> long_raw{};
        long_raw[0] = 255;
        EXPECT_EQ(Preview::Protocol::Common::Framing::ParseDomain(long_raw).first, Preview::Fault::Code::Success);
    }

    TEST(PreviewFraming, ParsePort)
    {
        const std::array<std::uint8_t, 2> raw{0x1F, 0x90}; // 8080 BE
        const auto [ec, port] = Preview::Protocol::Common::Framing::ParsePort(raw);
        EXPECT_EQ(ec, Preview::Fault::Code::Success);
        EXPECT_EQ(port, 8080U);
    }

    TEST(PreviewFraming, ParsePortBoundaries)
    {
        const std::array<std::uint8_t, 2> min{0x00, 0x00};
        EXPECT_EQ(Preview::Protocol::Common::Framing::ParsePort(min).second, 0U);

        const std::array<std::uint8_t, 2> max{0xFF, 0xFF};
        EXPECT_EQ(Preview::Protocol::Common::Framing::ParsePort(max).second, 65535U);
    }

    TEST(PreviewFraming, ParsePortShort)
    {
        const std::array<std::uint8_t, 1> raw{0x1F};
        const auto [ec, port] = Preview::Protocol::Common::Framing::ParsePort(raw);
        EXPECT_EQ(ec, Preview::Fault::Code::BadMessage);
        EXPECT_EQ(port, 0U);
    }

    TEST(PreviewAddress, DomainToString)
    {
        common::DomainAddress addr{};
        addr.length = 7;
        std::memcpy(addr.value.data(), "example", 7);
        EXPECT_EQ(addr.ToString(), "example");
    }

    TEST(PreviewAddress, AddrToStr)
    {
        // IPv4
        common::Ipv4Address v4{};
        v4.Bytes = {127, 0, 0, 1};
        EXPECT_EQ(common::AddrToStr(common::Address{v4}), "127.0.0.1");

        // 域名
        common::DomainAddress dom{};
        dom.length = 7;
        std::memcpy(dom.value.data(), "example", 7);
        EXPECT_EQ(common::AddrToStr(common::Address{dom}), "example");
    }

} // namespace

/**
 * @file Hysteria2CodecDeepTest.cpp
 * @brief Hysteria2 地址和解析器边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Hysteria2/Codec.hpp>

namespace
{
    namespace Hysteria2 = Preview::Hysteria2;
    using Preview::Error;

auto MakeBytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }
} // namespace

TEST(Hysteria2CodecDeep, ParseAddressBranches)
    {
        Hysteria2::Address addr{};
        std::size_t consumed = 0;

        // ipv4 数据不足
        EXPECT_EQ(Hysteria2::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x01, 8, 8})), addr,
                                           consumed),
                  Error::NeedMore);
        // ipv6 数据不足
        EXPECT_EQ(Hysteria2::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x03, 1})), addr,
                                           consumed),
                  Error::NeedMore);
        // ipv6 成功
        std::vector<std::uint8_t> v6{0x03};
        v6.insert(v6.end(), 16, 0x42);
        v6.push_back(0x00);
        v6.push_back(0x50);
        EXPECT_EQ(Hysteria2::ParseAddress(v6, addr, consumed), Error::None);
        EXPECT_EQ(addr.Type, Hysteria2::AddressType::Ipv6);
        EXPECT_EQ(addr.Host, std::string(16, '\x42'));
        EXPECT_EQ(addr.Port, 80u);
    }

TEST(Hysteria2CodecDeep, BuildUdpNullDst)
    {
        Hysteria2::UdpFrameInput in{};
        in.payload = std::span<const std::uint8_t>{};
        EXPECT_TRUE(Hysteria2::BuildUdp(in).empty());
    }

TEST(Hysteria2CodecDeep, RejectsUnknownMessageKind)
    {
        Hysteria2::Message Message{};
        std::size_t Consumed = 0;
        const std::vector<std::uint8_t> Wire{0x09, 0x01, 8, 8, 8, 8, 0x00, 0x35};

        EXPECT_EQ(Hysteria2::Parse(Wire, Message, Consumed), Error::BadMessage);
        EXPECT_EQ(Consumed, 0U);
    }

TEST(Hysteria2CodecDeep, ParserNeedMore)
    {
        Hysteria2::Parser p;
        std::error_code ec;
        EXPECT_EQ(p.Put(boost::asio::buffer(MakeBytes({0x01, 0x01, 8})), ec), 0u);
        EXPECT_EQ(ec, make_error_code(Error::NeedMore));
        p.Reset();
        // 成功解析（ipv4）
        std::vector<std::uint8_t> Ok{0x01, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'x'};
        EXPECT_EQ(p.Put(boost::asio::buffer(Ok), ec), 9u);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().dst.Host, "8.8.8.8");
    }


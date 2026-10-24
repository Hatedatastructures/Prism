/**
 * @file Ss2022GoldenVectorTest.cpp
 * @brief Shadowsocks 2022 golden vector 解析和构造测试。
 */

#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestState.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestWire.hpp>
#include <Prism/Protocols/Shadowsocks2022/ResponseCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/Types.hpp>

namespace
{
    namespace Shadowsocks2022 = Prism::Shadowsocks2022;
    using Prism::Error;
    using Prism::make_error_code;

} // namespace

TEST(GoldenVector, SS2022FixedHeaderRoundtrip)
{
    const auto wire = Shadowsocks2022::ParseFixedHeader(
        Shadowsocks2022::HeaderTypeClient, 1700000000ULL, 32u);
    ASSERT_EQ(wire.size(), 11u);
    Shadowsocks2022::FixedHeader h{};
    EXPECT_EQ(Shadowsocks2022::ParseFixedHeader(wire, h), Error::None);
    EXPECT_EQ(h.Type, Shadowsocks2022::HeaderTypeClient);
    EXPECT_EQ(h.TimeSec, 1700000000ULL);
    EXPECT_EQ(h.VarLen, 32u);
}

TEST(GoldenVector, SS2022AddressRoundtrip)
{
    const Shadowsocks2022::Address Target{
        Shadowsocks2022::AddressType::Domain, "example.com", 443};
    const auto wire = Shadowsocks2022::EncodeAddress(Target);
    ASSERT_FALSE(wire.empty());
    Shadowsocks2022::Address Parsed;
    std::size_t off = 0;
    EXPECT_EQ(Shadowsocks2022::ParseAddress(wire, Parsed, off), Error::None);
    EXPECT_EQ(Parsed.Type, Shadowsocks2022::AddressType::Domain);
    EXPECT_EQ(Parsed.Host, "example.com");
    EXPECT_EQ(Parsed.Port, 443u);
    EXPECT_EQ(off, wire.size());
}

TEST(GoldenVector, SS2022BoundaryPacketRoundtrip)
{
    const std::array<std::uint8_t, 16> psk = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
    const std::array<std::uint8_t, 16> salt = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
    const auto key = Shadowsocks2022::SessionKey(psk, salt, 16);
    const Shadowsocks2022::Address dst{Shadowsocks2022::AddressType::Ipv4, "8.8.8.8", 53};
    const std::vector<std::uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    const auto packet = Shadowsocks2022::BuildUdpPacket(
        {key, 1, &dst, payload});
    ASSERT_FALSE(packet.empty());
    Shadowsocks2022::Address parsed_dst;
    std::vector<std::uint8_t> Parsed;
    EXPECT_EQ(Shadowsocks2022::ParseUdpPacket({key, packet, &parsed_dst, &Parsed}),
              Error::None);
    EXPECT_EQ(parsed_dst.Type, Shadowsocks2022::AddressType::Ipv4);
    EXPECT_EQ(parsed_dst.Host, "8.8.8.8");
    EXPECT_EQ(parsed_dst.Port, 53u);
    ASSERT_EQ(Parsed.size(), payload.size());
    EXPECT_TRUE(std::equal(Parsed.begin(), Parsed.end(), payload.begin()));
}


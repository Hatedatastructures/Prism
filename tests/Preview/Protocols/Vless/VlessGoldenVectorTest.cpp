/**
 * @file VlessGoldenVectorTest.cpp
 * @brief VLESS golden vector 解析和构造测试。
 */

#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vless/Types.hpp>

namespace
{
    namespace Vless = Preview::Vless;
    using Preview::Error;
    using Preview::make_error_code;

    /** @brief VLESS TCP 域名请求 golden vector。 */
    inline const std::vector<std::uint8_t> VlessTcpRequest = {
    0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x00, 0x01, 0x01, 0xBB, 0x02, 0x0b,
    'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
} // namespace

TEST(GoldenVector, VlessTcpRequestParse)
{
    std::size_t Consumed = 0;
    Vless::RequestHeader Header;
    const auto ErrorValue = Vless::ParseRequest(
        std::span<const std::uint8_t>(VlessTcpRequest), Header, Consumed);
    EXPECT_EQ(ErrorValue, Error::None);
    EXPECT_EQ(Header.Version, 0x00);
    EXPECT_EQ(Header.Cmd, Vless::Command::Tcp);
    EXPECT_EQ(Header.Target.Host, "example.com");
    EXPECT_EQ(Header.Target.Port, 443u);
}

TEST(GoldenVector, VlessTcpRoundtrip)
{
    Vless::RequestHeader Header;
    Header.Version = Vless::ProtocolVersion;
    std::array<std::uint8_t, Vless::UuidLen> Uuid = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    Header.Uuid = Uuid;
    Header.Cmd = Vless::Command::Tcp;
    Header.Target.Type = Vless::AddressType::Domain;
    Header.Target.Host = "example.com";
    Header.Target.Port = 443;
    const auto Wire = Vless::BuildRequest(Header);
    ASSERT_FALSE(Wire.empty());
    std::size_t Consumed = 0;
    Vless::RequestHeader Parsed;
    const auto ErrorValue = Vless::ParseRequest(
        std::span<const std::uint8_t>(Wire), Parsed, Consumed);
    EXPECT_EQ(ErrorValue, Error::None);
    EXPECT_EQ(Parsed.Target.Host, "example.com");
    EXPECT_EQ(Parsed.Target.Port, 443u);
    EXPECT_EQ(Parsed.Uuid, Uuid);
}

TEST(GoldenVector, VlessBoundaryPacketRoundtrip)
{
    Vless::Address Target;
    Target.Type = Vless::AddressType::Domain;
    Target.Host = "example.com";
    Target.Port = 53;
    std::vector<std::uint8_t> Payload = {0xCA, 0xFE};
    const auto Wire = Vless::BuildUdpPkt(
        Target, std::span<const std::uint8_t>(Payload));
    ASSERT_FALSE(Wire.empty());
    Vless::Address ParsedTarget;
    std::span<const std::uint8_t> ParsedPayload;
    const auto ErrorValue = Vless::ParseUdpPkt(
        std::span<const std::uint8_t>(Wire), ParsedTarget, ParsedPayload);
    EXPECT_EQ(ErrorValue, Error::None);
    EXPECT_EQ(ParsedTarget.Host, "example.com");
    EXPECT_EQ(ParsedTarget.Port, 53u);
    ASSERT_EQ(ParsedPayload.size(), Payload.size());
    EXPECT_TRUE(std::equal(ParsedPayload.begin(), ParsedPayload.end(), Payload.begin()));
}

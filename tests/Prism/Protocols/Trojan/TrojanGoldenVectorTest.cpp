/**
 * @file TrojanGoldenVectorTest.cpp
 * @brief Trojan golden vector 解析和构造测试。
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
#include <Prism/Protocols/Trojan/Codec.hpp>
#include <Prism/Protocols/Trojan/Types.hpp>

namespace
{
    namespace Trojan = Prism::Trojan;
    using Prism::Error;
    using Prism::make_error_code;

} // namespace

TEST(GoldenVector, TrojanConnectRoundtrip)
{
    const auto Credential = Trojan::Credential("Secret");
    Trojan::Address Target{Trojan::AddressType::Domain, "example.com", 443};
    const auto Wire = Trojan::BuildRequest(Credential, Trojan::Command::Connect, Target);
    ASSERT_FALSE(Wire.empty());
    Trojan::RequestHeader Parsed;
    std::size_t Consumed = 0;
    const auto ErrorCode = Trojan::ParseRequest(std::span<const std::uint8_t>(Wire), Parsed, Consumed);
    EXPECT_EQ(ErrorCode, Error::None);
    EXPECT_EQ(Parsed.Cmd, Trojan::Command::Connect);
    EXPECT_EQ(Parsed.Target.Host, "example.com");
    EXPECT_EQ(Parsed.Target.Port, 443u);
}

TEST(GoldenVector, TrojanBoundaryPacketRoundtrip)
{
    Trojan::Address Target{Trojan::AddressType::Ipv4, "8.8.8.8", 53};
    std::vector<std::uint8_t> Payload = {0x01, 0x02, 0x03};
    const auto Wire = Trojan::BuildUdpPkt(Target, std::span<const std::uint8_t>(Payload));
    ASSERT_FALSE(Wire.empty());
    Trojan::Address ParsedTarget;
    std::span<const std::uint8_t> ParsedPayload;
    const auto ErrorCode = Trojan::ParseUdpPkt(std::span<const std::uint8_t>(Wire), ParsedTarget, ParsedPayload);
    EXPECT_EQ(ErrorCode, Error::None);
    EXPECT_EQ(ParsedTarget.Host, "8.8.8.8");
    EXPECT_EQ(ParsedTarget.Port, 53u);
    ASSERT_EQ(ParsedPayload.size(), Payload.size());
    EXPECT_TRUE(std::equal(ParsedPayload.begin(), ParsedPayload.end(), Payload.begin()));
}

TEST(GoldenVector, TrojanCredentialLength)
{
    const auto Credential = Trojan::Credential("Secret");
    EXPECT_EQ(Credential.size(), Trojan::CredentialLen);
    // hex length 56, All hex chars
    for (char c : Credential) { EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')); }
}


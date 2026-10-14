/**
 * @file Socks5GoldenVectorTest.cpp
 * @brief Socks5 golden vector 解析和构造测试。
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
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Socks5/Types.hpp>

namespace
{
    namespace Socks5 = Preview::Socks5;
    using Preview::Error;
    using Preview::make_error_code;

inline constexpr std::array<std::uint8_t, 3> socks5_greeting = {
    0x05, 0x01, 0x00};

inline constexpr std::array<std::uint8_t, 10> socks5_connect_req = {
    0x05, 0x01, 0x00, 0x01,
    0x7f, 0x00, 0x00, 0x01,
    0x00, 0x50};

inline constexpr std::array<std::uint8_t, 4 + 1 + 11 + 2> socks5_connect_domain = {
    0x05, 0x01, 0x00, 0x03,
    0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
    0x01, 0xBB};
} // namespace

TEST(GoldenVector, Socks5GreetingParse)
{
    // SOCKS5 握手帧：05 01 00 → ParseGreeting 真实解析
    Socks5::Greeting Greeting;
    std::size_t Consumed = 0;
    const auto ErrorCode = Socks5::ParseGreeting(
        std::span<const std::uint8_t>(socks5_greeting), Greeting, Consumed);
    ASSERT_EQ(ErrorCode, Error::None);
    EXPECT_EQ(Greeting.Ver, 5);
    EXPECT_EQ(Consumed, socks5_greeting.size());
    ASSERT_EQ(Greeting.Methods.size(), 1u);
    EXPECT_EQ(Greeting.Methods[0], static_cast<std::uint8_t>(Socks5::AuthMethod::NoAuth));
}

TEST(GoldenVector, Socks5ConnectReqParse)
{
    std::size_t Consumed = 0;
    Socks5::Request Request;
    const auto ErrorCode = Socks5::ParseRequest(
        std::span<const std::uint8_t>(socks5_connect_req), Request, Consumed);
    EXPECT_EQ(ErrorCode, Error::None);
    EXPECT_EQ(Request.Cmd, Socks5::Command::Connect);
    EXPECT_EQ(Request.Target.Type, Socks5::AddressType::Ipv4);
    EXPECT_EQ(Request.Target.Host, "127.0.0.1");
    EXPECT_EQ(Request.Target.Port, 80u);
}

TEST(GoldenVector, Socks5ConnectDomainParse)
{
    std::size_t Consumed = 0;
    Socks5::Request Request;
    const auto ErrorCode = Socks5::ParseRequest(
        std::span<const std::uint8_t>(socks5_connect_domain), Request, Consumed);
    EXPECT_EQ(ErrorCode, Error::None);
    EXPECT_EQ(Request.Cmd, Socks5::Command::Connect);
    EXPECT_EQ(Request.Target.Type, Socks5::AddressType::Domain);
    EXPECT_EQ(Request.Target.Host, "example.com");
    EXPECT_EQ(Request.Target.Port, 443u);
}

TEST(GoldenVector, Socks5SuccessReplyBuild)
{
    Socks5::Reply Reply;
    Reply.Ver = Socks5::Version;
    Reply.Code = Socks5::ReplyCode::Success;
    Reply.Bind.Type = Socks5::AddressType::Ipv4;
    Reply.Bind.Host = "0.0.0.0";
    Reply.Bind.Port = 0;
    const auto Wire = Socks5::BuildReply(Reply);
    ASSERT_FALSE(Wire.empty());
    EXPECT_EQ(Wire[0], 0x05);
    EXPECT_EQ(Wire[1], 0x00);
}

TEST(GoldenVector, Socks5ConnectRoundtrip)
{
    // Build Request → Parse Request
    Socks5::Request Request;
    Request.Cmd = Socks5::Command::Connect;
    Request.Target.Type = Socks5::AddressType::Domain;
    Request.Target.Host = "example.com";
    Request.Target.Port = 443;
    const auto Wire = Socks5::BuildRequest(Request);
    ASSERT_FALSE(Wire.empty());
    std::size_t Consumed = 0;
    Socks5::Request Parsed;
    const auto ErrorCode = Socks5::ParseRequest(
        std::span<const std::uint8_t>(Wire), Parsed, Consumed);
    EXPECT_EQ(ErrorCode, Error::None);
    EXPECT_EQ(Parsed.Cmd, Socks5::Command::Connect);
    EXPECT_EQ(Parsed.Target.Host, "example.com");
    EXPECT_EQ(Parsed.Target.Port, 443u);
}

TEST(GoldenVector, DomainTooLongFailsClosed)
{
    Socks5::Address AddressValue{Socks5::AddressType::Domain, std::string(300, 'a'), 443};
    const auto Wire = Socks5::EncodeAddress(AddressValue);
    // 地址无法用单字节长度表达时必须拒绝，不能生成空域名替代目标。
    EXPECT_TRUE(Wire.empty());
}

TEST(GoldenVector, Socks5UdpDatagramRoundtrip)
{
    Socks5::Address Target;
    Target.Type = Socks5::AddressType::Ipv4;
    Target.Host = "8.8.8.8";
    Target.Port = 53;
    std::vector<std::uint8_t> Payload = {0xDE, 0xAD, 0xBE, 0xEF};
    const auto Wire = Socks5::BuildUdpDatagram(
        Target, std::span<const std::uint8_t>(Payload));
    ASSERT_FALSE(Wire.empty());
    Socks5::Address ParsedTarget;
    std::span<const std::uint8_t> ParsedPayload;
    const auto ErrorCode = Socks5::ParseUdpDatagram(
        std::span<const std::uint8_t>(Wire), ParsedTarget, ParsedPayload);
    EXPECT_EQ(ErrorCode, Error::None);
    EXPECT_EQ(ParsedTarget.Host, "8.8.8.8");
    EXPECT_EQ(ParsedTarget.Port, 53u);
    ASSERT_EQ(ParsedPayload.size(), Payload.size());
    EXPECT_TRUE(std::equal(ParsedPayload.begin(), ParsedPayload.end(), Payload.begin()));
}


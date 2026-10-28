/**
 * @file OwnerTest.cpp
 * @brief SOCKS5 拆分编解码 owner 的直接包含测试
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <system_error>

#include <Prism/Protocols/Socks5/AddressCodec.hpp>
#include <Prism/Protocols/Socks5/AuthCodec.hpp>
#include <Prism/Protocols/Socks5/BeastCodec.hpp>
#include <Prism/Protocols/Socks5/MessageCodec.hpp>
#include <Prism/Protocols/Socks5/TransportCodec.hpp>

namespace
{
    namespace Socks5 = Prism::Socks5;

    TEST(Socks5CodecOwner, DirectHeadersKeepWireOwnersUsable)
    {
        Socks5::Address Target;
        Target.Type = Socks5::AddressType::Ipv4;
        Target.Host = "127.0.0.1";
        Target.Port = 8080;

        const auto AddressWire = Socks5::EncodeAddress(Target);
        ASSERT_EQ(AddressWire.size(), 7U);
        EXPECT_EQ(AddressWire[0], 0x01U);

        Socks5::Request Request;
        Request.Target = Target;
        const auto RequestWire = Socks5::BuildRequest(Request);
        ASSERT_EQ(RequestWire.size(), 10U);
        EXPECT_EQ(RequestWire[1], 0x01U);

        const auto UserpassWire = Socks5::BuildUserpass("alice", "secret");
        ASSERT_EQ(UserpassWire.size(), 14U);
        const std::array<std::uint8_t, 2> UserpassReply{0x01, 0x00};
        EXPECT_EQ(Socks5::ParseUserpassReply(UserpassReply), Prism::Error::None);
    }

    TEST(Socks5CodecOwner, StatefulOwnerRetainsPartialFrameSemantics)
    {
        Socks5::Serializer Serializer;
        Socks5::Message Message;
        Message.Type = Socks5::Message::Kind::Greeting;
        Message.Methods = {static_cast<std::uint8_t>(Socks5::AuthMethod::NoAuth)};
        Serializer.Reset(Message);

        std::error_code ErrorCode;
        std::array<std::uint8_t, 3> Wire{};
        ASSERT_EQ(Serializer.Get(
                      boost::asio::mutable_buffer(Wire.data(), Wire.size()), ErrorCode),
                  3U);
        ASSERT_FALSE(ErrorCode);

        Socks5::Parser Parser;
        Parser.Expect(Socks5::Message::Kind::Greeting);
        const std::array<std::uint8_t, 2> Prefix{Wire[0], Wire[1]};
        EXPECT_EQ(Parser.Put(
                      boost::asio::const_buffer(Prefix.data(), Prefix.size()), ErrorCode),
                  0U);
        EXPECT_FALSE(Parser.IsDone());
        EXPECT_EQ(Parser.Put(
                      boost::asio::const_buffer(Wire.data() + 2, 1), ErrorCode),
                  1U);
        EXPECT_TRUE(Parser.IsDone());
    }
} // namespace

/**
 * @file RoundtripTest.cpp
 * @brief Hysteria2 TCP/UDP 帧与认证请求编解码测试。
 */

#include <Prism/Protocols/Hysteria2/Hysteria2.hpp>
#include <gtest/gtest.h>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstdint>
#include <system_error>

namespace Net = boost::asio;

namespace
{
    using Hysteria2AddressType = Prism::Hysteria2::AddressType;
    using Hysteria2Message = Prism::Hysteria2::Message;
    using Hysteria2Parser = Prism::Hysteria2::Parser;
    using Hysteria2Serializer = Prism::Hysteria2::Serializer;

    TEST(Hysteria2Beast, TcpFrameRoundtrip)
    {
        Hysteria2Message Message;
        Message.Type = Hysteria2Message::Kind::Tcp;
        Message.dst.Type = Hysteria2AddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;
        Message.payload = "hello hysteria2";

        Hysteria2Serializer Serializer;
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 256> Wire{};
        const auto OutputBuffer = Net::mutable_buffer(
            Wire.data(), Wire.size());
        const auto Total = Serializer.Get(OutputBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);

        Hysteria2Parser Parser;
        const auto InputBuffer = Net::const_buffer(Wire.data(), Total);
        const auto Parsed = Parser.Put(InputBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Parsed, Total);
        ASSERT_TRUE(Parser.IsDone());
        const auto &Result = Parser.Get();
        EXPECT_EQ(Result.Type, Hysteria2Message::Kind::Tcp);
        EXPECT_EQ(Result.dst.Host, "127.0.0.1");
        EXPECT_EQ(Result.dst.Port, 8080);
        EXPECT_EQ(Result.payload, "hello hysteria2");
    }

    TEST(Hysteria2Beast, UdpFrameRoundtrip)
    {
        Hysteria2Message Message;
        Message.Type = Hysteria2Message::Kind::Udp;
        Message.SessionId = 0x11223344;
        Message.PacketId = 7;
        Message.dst.Type = Hysteria2AddressType::Domain;
        Message.dst.Host = "example.com";
        Message.dst.Port = 53;
        Message.payload = "dns";

        Hysteria2Serializer Serializer;
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 256> Wire{};
        const auto OutputBuffer = Net::mutable_buffer(
            Wire.data(), Wire.size());
        const auto Total = Serializer.Get(OutputBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);

        Hysteria2Parser Parser;
        const auto InputBuffer = Net::const_buffer(Wire.data(), Total);
        const auto Parsed = Parser.Put(InputBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Parsed, Total);
        ASSERT_TRUE(Parser.IsDone());
        const auto &Result = Parser.Get();
        EXPECT_EQ(Result.Type, Hysteria2Message::Kind::Udp);
        EXPECT_EQ(Result.SessionId, 0x11223344U);
        EXPECT_EQ(Result.dst.Host, "example.com");
        EXPECT_EQ(Result.payload, "dns");
    }

    TEST(Hysteria2Beast, AuthRequest)
    {
        const auto Auth =
            Prism::Hysteria2::MakeAuthRequest("hysteria2_password");
        EXPECT_FALSE(Auth.empty());
        EXPECT_EQ(static_cast<std::uint8_t>(Auth[0]), 0x01);
    }
} // namespace

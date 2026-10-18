/**
 * @file TrojanBeastTest.cpp
 * @brief Trojan 序列化器和解析器行为测试。
 */

#include <boost/asio/buffer.hpp>
#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <string>
#include <system_error>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Trojan = Prism::Trojan;
    using Prism::Error;
} // namespace

TEST(TrojanBeast, SerializerParserRoundtrip)
    {
        const std::string Password = "prism";
        Trojan::Message Message;
        Message.Target.Type = Trojan::AddressType::Ipv4;
        Message.Target.Host = "127.0.0.1";
        Message.Target.Port = 8080;
        Message.Udp = false;

        Trojan::Serializer Serializer(Password);
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 128> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);
        EXPECT_FALSE(ErrorCode);

        Trojan::Parser Parser(Password);
        const auto BytesRead = Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_TRUE(Parser.Get().Valid);
        EXPECT_FALSE(Parser.Get().Udp);
        EXPECT_EQ(Parser.Get().Target.Host, "127.0.0.1");
        EXPECT_EQ(Parser.Get().Target.Port, 8080);
    }

TEST(TrojanBeast, WrongPasswordRejected)
    {
        const std::string Password = "prism";
        Trojan::Message Message;
        Message.Target.Type = Trojan::AddressType::Ipv4;
        Message.Target.Host = "127.0.0.1";
        Message.Target.Port = 8080;

        Trojan::Serializer Serializer("wrong");
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 128> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);

        Trojan::Parser Parser(Password);
        Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_EQ(ErrorCode, Error::BadAuth);
    }

TEST(TrojanBeast, UdpHeader)
    {
        const std::string Password = "prism";
        Trojan::Message Message;
        Message.Target.Type = Trojan::AddressType::Domain;
        Message.Target.Host = "example.com";
        Message.Target.Port = 53;
        Message.Udp = true;

        Trojan::Serializer Serializer(Password);
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 128> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);

        Trojan::Parser Parser(Password);
        Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_TRUE(Parser.Get().Udp);
        EXPECT_EQ(Parser.Get().Target.Host, "example.com");
        EXPECT_EQ(Parser.Get().Target.Port, 53);
    }

    // ---------- VLESS ----------


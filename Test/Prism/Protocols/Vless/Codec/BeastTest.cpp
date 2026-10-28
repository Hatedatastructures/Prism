/**
 * @file BeastTest.cpp
 * @brief VLESS 序列化器和解析器行为测试。
 */

#include <boost/asio/buffer.hpp>
#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <string>
#include <system_error>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Vless/Vless.hpp>

namespace
{
    namespace Net = boost::asio;
    namespace Vless = Prism::Vless;
    using Prism::Error;
} // namespace

TEST(VlessBeast, SerializerParserRoundtrip)
    {
        const auto Uuid = std::array<std::uint8_t, 16>{0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                                                       0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        Vless::Message Message;
        Message.uuid = Uuid;
        Message.cmd = Vless::CmdTcp;
        Message.dst.Type = Vless::AddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;

        Vless::Serializer Serializer(Uuid);
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 128> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);
        EXPECT_FALSE(ErrorCode);

        Vless::Parser Parser(Uuid);
        const auto BytesRead = Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_TRUE(Parser.Get().valid);
        EXPECT_EQ(Parser.Get().cmd, Vless::CmdTcp);
        EXPECT_EQ(Parser.Get().dst.Host, "127.0.0.1");
        EXPECT_EQ(Parser.Get().dst.Port, 8080);
    }

TEST(VlessBeast, WrongUuidRejected)
    {
        const auto GoodUuid = std::array<std::uint8_t, 16>{0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                                                           0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        const auto BadUuid = std::array<std::uint8_t, 16>{0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
                                                          0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44};
        Vless::Message Message;
        Message.uuid = BadUuid;
        Message.cmd = Vless::CmdTcp;
        Message.dst.Type = Vless::AddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;

        Vless::Serializer Serializer(BadUuid);
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 128> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);

        Vless::Parser Parser(GoodUuid);
        Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_EQ(ErrorCode, Error::BadAuth);
    }

TEST(VlessBeast, MuxCommand)
    {
        const auto Uuid = std::array<std::uint8_t, 16>{0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                                                       0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        Vless::Message Message;
        Message.uuid = Uuid;
        Message.cmd = Vless::CmdMux;
        Vless::Serializer Serializer(Uuid);
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 64> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);
        Vless::Parser Parser(Uuid);
        Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().cmd, Vless::CmdMux);
    }


/**
 * @file HttpTrojanVlessBeastTest.cpp
 * @brief Trojan/VLESS Beast 风格组件测试
 */

#include <cstring>

#include <preview/Protocols/Http1/Parser.hpp>
#include <preview/Protocols/Trojan/Trojan.hpp>
#include <preview/Protocols/Vless/Vless.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Http = Preview::Http11;
    namespace Trojan = Preview::Trojan;
    namespace Vless = Preview::Vless;
    namespace Net = boost::asio;
    using Preview::Error;

    // ---------- Trojan ----------

    TEST(TrojanBeast, SerializerParserRoundtrip)
    {
        const std::string Password = "prism";
        Trojan::Message Message;
        Message.dst.Type = Trojan::AddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;
        Message.udp = false;

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
        EXPECT_TRUE(Parser.Get().valid);
        EXPECT_FALSE(Parser.Get().udp);
        EXPECT_EQ(Parser.Get().dst.Host, "127.0.0.1");
        EXPECT_EQ(Parser.Get().dst.Port, 8080);
    }

    TEST(TrojanBeast, WrongPasswordRejected)
    {
        const std::string Password = "prism";
        Trojan::Message Message;
        Message.dst.Type = Trojan::AddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;

        Trojan::Serializer Serializer("wrong");
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 128> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);

        Trojan::Parser Parser(Password);
        Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_EQ(ErrorCode, Error::AuthFailed);
    }

    TEST(TrojanBeast, UdpHeader)
    {
        const std::string Password = "prism";
        Trojan::Message Message;
        Message.dst.Type = Trojan::AddressType::Domain;
        Message.dst.Host = "example.com";
        Message.dst.Port = 53;
        Message.udp = true;

        Trojan::Serializer Serializer(Password);
        Serializer.Reset(Message);
        std::error_code ErrorCode;
        std::array<std::uint8_t, 128> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);

        Trojan::Parser Parser(Password);
        Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_TRUE(Parser.Get().udp);
        EXPECT_EQ(Parser.Get().dst.Host, "example.com");
        EXPECT_EQ(Parser.Get().dst.Port, 53);
    }

    // ---------- VLESS ----------

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
        EXPECT_EQ(ErrorCode, Error::AuthFailed);
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

} // namespace

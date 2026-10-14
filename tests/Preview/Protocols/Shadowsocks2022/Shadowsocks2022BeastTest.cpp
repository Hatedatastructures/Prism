/**
 * @file Shadowsocks2022BeastTest.cpp
 * @brief SS2022 Beast 风格组件测试
 */

#include <ctime>

#include <boost/asio/buffer.hpp>

#include <cstdint>
#include <string>

#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Shadowsocks2022 = Preview::Shadowsocks2022;
    using Preview::Error;
    using Preview::make_error_code;

    constexpr std::array<std::uint8_t, 16> Psk{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    TEST(Shadow2022Beast, HandshakeRoundtrip)
    {
        Shadowsocks2022::Message Message;
        Message.dst.Type = Shadowsocks2022::AddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;
        Message.InitialPayload = "hello ss2022";

        Shadowsocks2022::Serializer Serializer(Psk);
        Serializer.Reset(Message, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ErrorCode;
        std::array<std::uint8_t, 256> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(Serializer.IsDone());

        Shadowsocks2022::Parser Parser(Psk);
        const auto BytesRead = Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(BytesRead, Total);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().dst.Host, "127.0.0.1");
        EXPECT_EQ(Parser.Get().dst.Port, 8080);
        EXPECT_EQ(Parser.Get().InitialPayload, "hello ss2022");
    }

    TEST(Shadow2022Beast, WrongPskRejected)
    {
        constexpr std::array<std::uint8_t, 16> WrongPsk{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                                                        0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
        Shadowsocks2022::Message Message;
        Message.dst.Type = Shadowsocks2022::AddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;

        Shadowsocks2022::Serializer Serializer(WrongPsk);
        Serializer.Reset(Message, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ErrorCode;
        std::array<std::uint8_t, 256> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);

        Shadowsocks2022::Parser Parser(Psk);
        Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_EQ(ErrorCode, Error::AuthFailed);
    }

    TEST(Shadow2022Beast, SerializerReportsRandomSourceFailure)
    {
        Shadowsocks2022::Message Message;
        Message.dst.Type = Shadowsocks2022::AddressType::Ipv4;
        Message.dst.Host = "127.0.0.1";
        Message.dst.Port = 8080;
        Shadowsocks2022::Serializer Serializer(Psk, [](std::uint8_t *, int) { return 0; });
        Serializer.Reset(Message, static_cast<std::uint64_t>(std::time(nullptr)));
        std::array<std::uint8_t, 256> Wire{};
        std::error_code ErrorCode;
        EXPECT_EQ(Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode), 0U);
        EXPECT_EQ(ErrorCode, make_error_code(Error::IoError));
        EXPECT_FALSE(Serializer.IsDone());
    }

    TEST(Shadow2022Beast, DomainAddress)
    {
        Shadowsocks2022::Message Message;
        Message.dst.Type = Shadowsocks2022::AddressType::Domain;
        Message.dst.Host = "example.com";
        Message.dst.Port = 443;

        Shadowsocks2022::Serializer Serializer(Psk);
        Serializer.Reset(Message, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ErrorCode;
        std::array<std::uint8_t, 256> Wire{};
        const auto Total = Serializer.Get(Net::mutable_buffer(Wire.data(), Wire.size()), ErrorCode);

        Shadowsocks2022::Parser Parser(Psk);
        Parser.Put(Net::const_buffer(Wire.data(), Total), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().dst.Host, "example.com");
        EXPECT_EQ(Parser.Get().dst.Port, 443);
    }

} // namespace

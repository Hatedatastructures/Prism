/**
 * @file Shadowsocks2022BeastTest.cpp
 * @brief SS2022 Beast 风格组件测试
 */

#include <ctime>

#include <preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;

    constexpr std::array<std::uint8_t, 16> kPsk{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    TEST(Shadow2022Beast, HandshakeRoundtrip)
    {
        Shadowsocks2022::Message msg;
        msg.dst.Type = Shadowsocks2022::AddressType::Ipv4;
        msg.dst.Host = "127.0.0.1";
        msg.dst.Port = 8080;
        msg.InitialPayload = "hello ss2022";

        Shadowsocks2022::Serializer s(kPsk);
        s.Reset(msg, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto Total = s.Get(net::mutable_buffer(wire.data(), wire.size()), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(s.IsDone());

        Shadowsocks2022::Parser p(kPsk);
        const auto n = p.Put(net::const_buffer(wire.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n, Total);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().dst.Host, "127.0.0.1");
        EXPECT_EQ(p.Get().dst.Port, 8080);
        EXPECT_EQ(p.Get().InitialPayload, "hello ss2022");
    }

    TEST(Shadow2022Beast, WrongPskRejected)
    {
        constexpr std::array<std::uint8_t, 16> wrong{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                                                     0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
        Shadowsocks2022::Message msg;
        msg.dst.Type = Shadowsocks2022::AddressType::Ipv4;
        msg.dst.Host = "127.0.0.1";
        msg.dst.Port = 8080;

        Shadowsocks2022::Serializer s(wrong);
        s.Reset(msg, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto Total = s.Get(net::mutable_buffer(wire.data(), wire.size()), ec);

        Shadowsocks2022::Parser p(kPsk);
        p.Put(net::const_buffer(wire.data(), Total), ec);
        EXPECT_EQ(ec, Error::AuthFailed);
    }

    TEST(Shadow2022Beast, DomainAddress)
    {
        Shadowsocks2022::Message msg;
        msg.dst.Type = Shadowsocks2022::AddressType::Domain;
        msg.dst.Host = "example.com";
        msg.dst.Port = 443;

        Shadowsocks2022::Serializer s(kPsk);
        s.Reset(msg, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto Total = s.Get(net::mutable_buffer(wire.data(), wire.size()), ec);

        Shadowsocks2022::Parser p(kPsk);
        p.Put(net::const_buffer(wire.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().dst.Host, "example.com");
        EXPECT_EQ(p.Get().dst.Port, 443);
    }

} // namespace

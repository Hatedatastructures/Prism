/**
 * @file Shadowsocks2022BeastTest.cpp
 * @brief SS2022 Beast 风格组件测试
 */

#include <ctime>

#include <common/proxy/shadowsocks2022/shadowsocks2022.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace psmtest;

    constexpr std::array<std::uint8_t, 16> kPsk{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    TEST(Shadow2022Beast, HandshakeRoundtrip)
    {
        shadowsocks2022::message msg;
        msg.dst.type = shadowsocks2022::address_type::ipv4;
        msg.dst.host = "127.0.0.1";
        msg.dst.port = 8080;
        msg.initial_payload = "hello ss2022";

        shadowsocks2022::serializer s(kPsk);
        s.reset(msg, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto total = s.get(net::mutable_buffer(wire.data(), wire.size()), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(s.is_done());

        shadowsocks2022::parser p(kPsk);
        const auto n = p.put(net::const_buffer(wire.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_EQ(n, total);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().dst.host, "127.0.0.1");
        EXPECT_EQ(p.get().dst.port, 8080);
        EXPECT_EQ(p.get().initial_payload, "hello ss2022");
    }

    TEST(Shadow2022Beast, WrongPskRejected)
    {
        constexpr std::array<std::uint8_t, 16> wrong{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                                                     0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
        shadowsocks2022::message msg;
        msg.dst.type = shadowsocks2022::address_type::ipv4;
        msg.dst.host = "127.0.0.1";
        msg.dst.port = 8080;

        shadowsocks2022::serializer s(wrong);
        s.reset(msg, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto total = s.get(net::mutable_buffer(wire.data(), wire.size()), ec);

        shadowsocks2022::parser p(kPsk);
        p.put(net::const_buffer(wire.data(), total), ec);
        EXPECT_EQ(ec, error::auth_failed);
    }

    TEST(Shadow2022Beast, DomainAddress)
    {
        shadowsocks2022::message msg;
        msg.dst.type = shadowsocks2022::address_type::domain;
        msg.dst.host = "example.com";
        msg.dst.port = 443;

        shadowsocks2022::serializer s(kPsk);
        s.reset(msg, static_cast<std::uint64_t>(std::time(nullptr)));
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto total = s.get(net::mutable_buffer(wire.data(), wire.size()), ec);

        shadowsocks2022::parser p(kPsk);
        p.put(net::const_buffer(wire.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().dst.host, "example.com");
        EXPECT_EQ(p.get().dst.port, 443);
    }

} // namespace

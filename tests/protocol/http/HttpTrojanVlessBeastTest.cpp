/**
 * @file HttpTrojanVlessBeastTest.cpp
 * @brief Trojan/VLESS Beast 风格组件测试
 */

#include <common/trojan/trojan.hpp>
#include <common/vless/vless.hpp>

#include <gtest/gtest.h>

#include <cstring>

namespace
{
    using namespace psmtest;

    // ---------- Trojan ----------

    TEST(TrojanBeast, SerializerParserRoundtrip)
    {
        const std::string password = "prism";
        trojan::message msg;
        msg.dst.type = trojan::address_type::ipv4;
        msg.dst.host = "127.0.0.1";
        msg.dst.port = 8080;
        msg.udp = false;

        trojan::serializer s(password);
        s.reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> out{};
        const auto total = s.get(net::mutable_buffer(out.data(), out.size()), ec);
        EXPECT_FALSE(ec);

        trojan::parser p(password);
        const auto n = p.put(net::const_buffer(out.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.is_done());
        EXPECT_TRUE(p.get().valid);
        EXPECT_FALSE(p.get().udp);
        EXPECT_EQ(p.get().dst.host, "127.0.0.1");
        EXPECT_EQ(p.get().dst.port, 8080);
    }

    TEST(TrojanBeast, WrongPasswordRejected)
    {
        const std::string password = "prism";
        trojan::message msg;
        msg.dst.type = trojan::address_type::ipv4;
        msg.dst.host = "127.0.0.1";
        msg.dst.port = 8080;

        trojan::serializer s("wrong");
        s.reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> out{};
        const auto total = s.get(net::mutable_buffer(out.data(), out.size()), ec);

        trojan::parser p(password);
        p.put(net::const_buffer(out.data(), total), ec);
        EXPECT_EQ(ec, error::auth_failed);
    }

    TEST(TrojanBeast, UdpHeader)
    {
        const std::string password = "prism";
        trojan::message msg;
        msg.dst.type = trojan::address_type::domain;
        msg.dst.host = "example.com";
        msg.dst.port = 53;
        msg.udp = true;

        trojan::serializer s(password);
        s.reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> out{};
        const auto total = s.get(net::mutable_buffer(out.data(), out.size()), ec);

        trojan::parser p(password);
        p.put(net::const_buffer(out.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.is_done());
        EXPECT_TRUE(p.get().udp);
        EXPECT_EQ(p.get().dst.host, "example.com");
        EXPECT_EQ(p.get().dst.port, 53);
    }

    // ---------- VLESS ----------

    TEST(VlessBeast, SerializerParserRoundtrip)
    {
        const auto uuid = std::array<std::uint8_t, 16>{
            0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
            0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        vless::message msg;
        msg.uuid = uuid;
        msg.cmd = vless::cmd_tcp;
        msg.dst.type = vless::address_type::ipv4;
        msg.dst.host = "127.0.0.1";
        msg.dst.port = 8080;

        vless::serializer s(uuid);
        s.reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> out{};
        const auto total = s.get(net::mutable_buffer(out.data(), out.size()), ec);
        EXPECT_FALSE(ec);

        vless::parser p(uuid);
        const auto n = p.put(net::const_buffer(out.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.is_done());
        EXPECT_TRUE(p.get().valid);
        EXPECT_EQ(p.get().cmd, vless::cmd_tcp);
        EXPECT_EQ(p.get().dst.host, "127.0.0.1");
        EXPECT_EQ(p.get().dst.port, 8080);
    }

    TEST(VlessBeast, WrongUuidRejected)
    {
        const auto good = std::array<std::uint8_t, 16>{
            0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
            0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        const auto bad = std::array<std::uint8_t, 16>{
            0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
            0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44};
        vless::message msg;
        msg.uuid = bad;
        msg.cmd = vless::cmd_tcp;
        msg.dst.type = vless::address_type::ipv4;
        msg.dst.host = "127.0.0.1";
        msg.dst.port = 8080;

        vless::serializer s(bad);
        s.reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> out{};
        const auto total = s.get(net::mutable_buffer(out.data(), out.size()), ec);

        vless::parser p(good);
        p.put(net::const_buffer(out.data(), total), ec);
        EXPECT_EQ(ec, error::auth_failed);
    }

    TEST(VlessBeast, MuxCommand)
    {
        const auto uuid = std::array<std::uint8_t, 16>{
            0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
            0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        vless::message msg;
        msg.uuid = uuid;
        msg.cmd = vless::cmd_mux;
        vless::serializer s(uuid);
        s.reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 64> out{};
        const auto total = s.get(net::mutable_buffer(out.data(), out.size()), ec);
        vless::parser p(uuid);
        p.put(net::const_buffer(out.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().cmd, vless::cmd_mux);
    }

} // namespace

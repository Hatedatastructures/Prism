/**
 * @file HttpTrojanVlessBeastTest.cpp
 * @brief Trojan/VLESS Beast 风格组件测试
 */

#include <cstring>

#include <common/Protocols/Trojan/Trojan.hpp>
#include <common/Protocols/Vless/Vless.hpp>
#include <gtest/gtest.h>

namespace
{
    using namespace Preview;

    // ---------- Trojan ----------

    TEST(TrojanBeast, SerializerParserRoundtrip)
    {
        const std::string password = "prism";
        Trojan::Message msg;
        msg.dst.Type = Trojan::AddressType::Ipv4;
        msg.dst.Host = "127.0.0.1";
        msg.dst.Port = 8080;
        msg.udp = false;

        Trojan::Serializer s(password);
        s.Reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> out{};
        const auto Total = s.Get(net::mutable_buffer(out.data(), out.size()), ec);
        EXPECT_FALSE(ec);

        Trojan::Parser p(password);
        const auto n = p.Put(net::const_buffer(out.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.IsDone());
        EXPECT_TRUE(p.Get().valid);
        EXPECT_FALSE(p.Get().udp);
        EXPECT_EQ(p.Get().dst.Host, "127.0.0.1");
        EXPECT_EQ(p.Get().dst.Port, 8080);
    }

    TEST(TrojanBeast, WrongPasswordRejected)
    {
        const std::string password = "prism";
        Trojan::Message msg;
        msg.dst.Type = Trojan::AddressType::Ipv4;
        msg.dst.Host = "127.0.0.1";
        msg.dst.Port = 8080;

        Trojan::Serializer s("wrong");
        s.Reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> out{};
        const auto Total = s.Get(net::mutable_buffer(out.data(), out.size()), ec);

        Trojan::Parser p(password);
        p.Put(net::const_buffer(out.data(), Total), ec);
        EXPECT_EQ(ec, Error::AuthFailed);
    }

    TEST(TrojanBeast, UdpHeader)
    {
        const std::string password = "prism";
        Trojan::Message msg;
        msg.dst.Type = Trojan::AddressType::Domain;
        msg.dst.Host = "example.com";
        msg.dst.Port = 53;
        msg.udp = true;

        Trojan::Serializer s(password);
        s.Reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> out{};
        const auto Total = s.Get(net::mutable_buffer(out.data(), out.size()), ec);

        Trojan::Parser p(password);
        p.Put(net::const_buffer(out.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.IsDone());
        EXPECT_TRUE(p.Get().udp);
        EXPECT_EQ(p.Get().dst.Host, "example.com");
        EXPECT_EQ(p.Get().dst.Port, 53);
    }

    // ---------- VLESS ----------

    TEST(VlessBeast, SerializerParserRoundtrip)
    {
        const auto uuid = std::array<std::uint8_t, 16>{0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                                                       0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        Vless::Message msg;
        msg.uuid = uuid;
        msg.cmd = Vless::CmdTcp;
        msg.dst.Type = Vless::AddressType::Ipv4;
        msg.dst.Host = "127.0.0.1";
        msg.dst.Port = 8080;

        Vless::Serializer s(uuid);
        s.Reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> out{};
        const auto Total = s.Get(net::mutable_buffer(out.data(), out.size()), ec);
        EXPECT_FALSE(ec);

        Vless::Parser p(uuid);
        const auto n = p.Put(net::const_buffer(out.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.IsDone());
        EXPECT_TRUE(p.Get().valid);
        EXPECT_EQ(p.Get().cmd, Vless::CmdTcp);
        EXPECT_EQ(p.Get().dst.Host, "127.0.0.1");
        EXPECT_EQ(p.Get().dst.Port, 8080);
    }

    TEST(VlessBeast, WrongUuidRejected)
    {
        const auto good = std::array<std::uint8_t, 16>{0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                                                       0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        const auto bad = std::array<std::uint8_t, 16>{0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22,
                                                      0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44};
        Vless::Message msg;
        msg.uuid = bad;
        msg.cmd = Vless::CmdTcp;
        msg.dst.Type = Vless::AddressType::Ipv4;
        msg.dst.Host = "127.0.0.1";
        msg.dst.Port = 8080;

        Vless::Serializer s(bad);
        s.Reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> out{};
        const auto Total = s.Get(net::mutable_buffer(out.data(), out.size()), ec);

        Vless::Parser p(good);
        p.Put(net::const_buffer(out.data(), Total), ec);
        EXPECT_EQ(ec, Error::AuthFailed);
    }

    TEST(VlessBeast, MuxCommand)
    {
        const auto uuid = std::array<std::uint8_t, 16>{0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
                                                       0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        Vless::Message msg;
        msg.uuid = uuid;
        msg.cmd = Vless::CmdMux;
        Vless::Serializer s(uuid);
        s.Reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 64> out{};
        const auto Total = s.Get(net::mutable_buffer(out.data(), out.size()), ec);
        Vless::Parser p(uuid);
        p.Put(net::const_buffer(out.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().cmd, Vless::CmdMux);
    }

} // namespace

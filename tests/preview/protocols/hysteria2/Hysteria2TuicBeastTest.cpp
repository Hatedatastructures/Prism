/**
 * @file Hysteria2TuicBeastTest.cpp
 * @brief Hysteria2/TUIC Beast 风格组件测试
 */

#include <common/Protocols/Hysteria2/Hysteria2.hpp>
#include <common/Protocols/Tuic/Tuic.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace Preview;

    TEST(Hysteria2Beast, TcpFrameRoundtrip)
    {
        Hysteria2::Message msg;
        msg.Type = Hysteria2::Message::Kind::Tcp;
        msg.dst.Type = Hysteria2::AddressType::Ipv4;
        msg.dst.Host = "127.0.0.1";
        msg.dst.Port = 8080;
        msg.payload = "hello hysteria2";

        Hysteria2::Serializer s;
        s.Reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto Total = s.Get(net::mutable_buffer(wire.data(), wire.size()), ec);
        EXPECT_FALSE(ec);

        Hysteria2::Parser p;
        const auto n = p.Put(net::const_buffer(wire.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Type, Hysteria2::Message::Kind::Tcp);
        EXPECT_EQ(p.Get().dst.Host, "127.0.0.1");
        EXPECT_EQ(p.Get().dst.Port, 8080);
        EXPECT_EQ(p.Get().payload, "hello hysteria2");
    }

    TEST(Hysteria2Beast, UdpFrameRoundtrip)
    {
        Hysteria2::Message msg;
        msg.Type = Hysteria2::Message::Kind::Udp;
        msg.SessionId = 0x11223344;
        msg.PacketId = 7;
        msg.dst.Type = Hysteria2::AddressType::Domain;
        msg.dst.Host = "example.com";
        msg.dst.Port = 53;
        msg.payload = "dns";

        Hysteria2::Serializer s;
        s.Reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto Total = s.Get(net::mutable_buffer(wire.data(), wire.size()), ec);

        Hysteria2::Parser p;
        p.Put(net::const_buffer(wire.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Type, Hysteria2::Message::Kind::Udp);
        EXPECT_EQ(p.Get().SessionId, 0x11223344U);
        EXPECT_EQ(p.Get().dst.Host, "example.com");
        EXPECT_EQ(p.Get().payload, "dns");
    }

    TEST(Hysteria2Beast, AuthRequest)
    {
        const auto Auth = Hysteria2::MakeAuthRequest("hysteria2_password");
        EXPECT_FALSE(Auth.empty());
        EXPECT_EQ(static_cast<std::uint8_t>(Auth[0]), 0x01); // HEADERS
    }

    TEST(TuicBeast, ConnectRoundtrip)
    {
        Tuic::Message msg;
        msg.Cmd = Tuic::CmdConnect;
        msg.dst.Type = Tuic::AddressType::Ipv4;
        msg.dst.Host = "127.0.0.1";
        msg.dst.Port = 8080;

        Tuic::Serializer s;
        s.Reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> wire{};
        const auto Total = s.Get(net::mutable_buffer(wire.data(), wire.size()), ec);

        Tuic::Parser p;
        p.Put(net::const_buffer(wire.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Cmd, Tuic::CmdConnect);
        EXPECT_EQ(p.Get().dst.Host, "127.0.0.1");
        EXPECT_EQ(p.Get().dst.Port, 8080);
    }

    TEST(TuicBeast, PacketRoundtrip)
    {
        Tuic::Message msg;
        msg.Cmd = Tuic::CmdPacket;
        msg.AssocId = 3;
        msg.PktId = 9;
        msg.dst.Type = Tuic::AddressType::Ipv4;
        msg.dst.Host = "8.8.8.8";
        msg.dst.Port = 53;
        msg.payload = "dns payload";

        Tuic::Serializer s;
        s.Reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto Total = s.Get(net::mutable_buffer(wire.data(), wire.size()), ec);

        Tuic::Parser p;
        p.Put(net::const_buffer(wire.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Cmd, Tuic::CmdPacket);
        EXPECT_EQ(p.Get().AssocId, 3);
        EXPECT_EQ(p.Get().PktId, 9);
        EXPECT_EQ(p.Get().dst.Host, "8.8.8.8");
        EXPECT_EQ(p.Get().payload, "dns payload");
    }

    TEST(TuicBeast, Heartbeat)
    {
        Tuic::Message msg;
        msg.Cmd = Tuic::CmdHeartbeat;
        Tuic::Serializer s;
        s.Reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 8> wire{};
        const auto Total = s.Get(net::mutable_buffer(wire.data(), wire.size()), ec);

        Tuic::Parser p;
        p.Put(net::const_buffer(wire.data(), Total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.IsDone());
        EXPECT_EQ(p.Get().Cmd, Tuic::CmdHeartbeat);
    }

} // namespace

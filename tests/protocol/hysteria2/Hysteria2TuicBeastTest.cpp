/**
 * @file Hysteria2TuicBeastTest.cpp
 * @brief Hysteria2/TUIC Beast 风格组件测试
 */

#include <common/proxy/hysteria2/hysteria2.hpp>
#include <common/proxy/tuic/tuic.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    using namespace psmtest;

    TEST(Hysteria2Beast, TcpFrameRoundtrip)
    {
        hysteria2::message msg;
        msg.type = hysteria2::message::kind::tcp;
        msg.dst.type = hysteria2::address_type::ipv4;
        msg.dst.host = "127.0.0.1";
        msg.dst.port = 8080;
        msg.payload = "hello hysteria2";

        hysteria2::serializer s;
        s.reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto total = s.get(net::mutable_buffer(wire.data(), wire.size()), ec);
        EXPECT_FALSE(ec);

        hysteria2::parser p;
        const auto n = p.put(net::const_buffer(wire.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().type, hysteria2::message::kind::tcp);
        EXPECT_EQ(p.get().dst.host, "127.0.0.1");
        EXPECT_EQ(p.get().dst.port, 8080);
        EXPECT_EQ(p.get().payload, "hello hysteria2");
    }

    TEST(Hysteria2Beast, UdpFrameRoundtrip)
    {
        hysteria2::message msg;
        msg.type = hysteria2::message::kind::udp;
        msg.session_id = 0x11223344;
        msg.packet_id = 7;
        msg.dst.type = hysteria2::address_type::domain;
        msg.dst.host = "example.com";
        msg.dst.port = 53;
        msg.payload = "dns";

        hysteria2::serializer s;
        s.reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto total = s.get(net::mutable_buffer(wire.data(), wire.size()), ec);

        hysteria2::parser p;
        p.put(net::const_buffer(wire.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().type, hysteria2::message::kind::udp);
        EXPECT_EQ(p.get().session_id, 0x11223344U);
        EXPECT_EQ(p.get().dst.host, "example.com");
        EXPECT_EQ(p.get().payload, "dns");
    }

    TEST(Hysteria2Beast, AuthRequest)
    {
        const auto auth = hysteria2::make_auth_request("hysteria2_password");
        EXPECT_FALSE(auth.empty());
        EXPECT_EQ(static_cast<std::uint8_t>(auth[0]), 0x01); // HEADERS
    }

    TEST(TuicBeast, ConnectRoundtrip)
    {
        tuic::message msg;
        msg.cmd = tuic::cmd_connect;
        msg.dst.type = tuic::address_type::ipv4;
        msg.dst.host = "127.0.0.1";
        msg.dst.port = 8080;

        tuic::serializer s;
        s.reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 128> wire{};
        const auto total = s.get(net::mutable_buffer(wire.data(), wire.size()), ec);

        tuic::parser p;
        p.put(net::const_buffer(wire.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().cmd, tuic::cmd_connect);
        EXPECT_EQ(p.get().dst.host, "127.0.0.1");
        EXPECT_EQ(p.get().dst.port, 8080);
    }

    TEST(TuicBeast, PacketRoundtrip)
    {
        tuic::message msg;
        msg.cmd = tuic::cmd_packet;
        msg.assoc_id = 3;
        msg.pkt_id = 9;
        msg.dst.type = tuic::address_type::ipv4;
        msg.dst.host = "8.8.8.8";
        msg.dst.port = 53;
        msg.payload = "dns payload";

        tuic::serializer s;
        s.reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 256> wire{};
        const auto total = s.get(net::mutable_buffer(wire.data(), wire.size()), ec);

        tuic::parser p;
        p.put(net::const_buffer(wire.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().cmd, tuic::cmd_packet);
        EXPECT_EQ(p.get().assoc_id, 3);
        EXPECT_EQ(p.get().pkt_id, 9);
        EXPECT_EQ(p.get().dst.host, "8.8.8.8");
        EXPECT_EQ(p.get().payload, "dns payload");
    }

    TEST(TuicBeast, Heartbeat)
    {
        tuic::message msg;
        msg.cmd = tuic::cmd_heartbeat;
        tuic::serializer s;
        s.reset(msg);
        std::error_code ec;
        std::array<std::uint8_t, 8> wire{};
        const auto total = s.get(net::mutable_buffer(wire.data(), wire.size()), ec);

        tuic::parser p;
        p.put(net::const_buffer(wire.data(), total), ec);
        EXPECT_FALSE(ec);
        EXPECT_TRUE(p.is_done());
        EXPECT_EQ(p.get().cmd, tuic::cmd_heartbeat);
    }

} // namespace

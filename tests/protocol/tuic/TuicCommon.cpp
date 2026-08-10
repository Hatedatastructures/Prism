/**
 * @file TuicCommon.cpp
 * @brief TUIC v5 协议 common 模块测试（认证/Connect/Packet/Heartbeat 帧编解码）
 */

#include <common/tuic/tuic.hpp>

#include <gtest/gtest.h>

using namespace psm_test;

namespace
{
    constexpr std::string_view uuid_hex = "123e4567-e89b-12d3-a456-426614174000";
} // namespace

TEST(TuicCommon, AuthenticateRoundTrip)
{
    const auto uuid = parse_uuid(uuid_hex);
    std::array<std::uint8_t, 32> token{};
    for (std::size_t i = 0; i < token.size(); ++i)
        token[i] = static_cast<std::uint8_t>(i);

    const auto frame = tuic::build_authenticate(uuid, token);
    ASSERT_EQ(frame.size(), 2 + 16 + 32);

    const auto auth = tuic::parse_authenticate(frame);
    ASSERT_TRUE(auth.valid);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(auth.uuid.data()), 16),
              std::string_view(reinterpret_cast<const char *>(uuid.data()), 16));
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(auth.token.data()), 32),
              std::string_view(reinterpret_cast<const char *>(token.data()), 32));
}

TEST(TuicCommon, AuthenticateRejectBadVersion)
{
    const auto uuid = parse_uuid(uuid_hex);
    std::array<std::uint8_t, 32> token{};
    const auto frame = tuic::build_authenticate(uuid, token);
    std::vector<std::uint8_t> bad = frame;
    bad[0] = 0x04;
    EXPECT_FALSE(tuic::parse_authenticate(bad).valid);
}

TEST(TuicCommon, ConnectRoundTrip)
{
    tuic::address dst;
    dst.type = atyp::domain;
    dst.host = "example.com";
    dst.port = 443;

    const auto frame = tuic::build_connect(dst);
    const auto req = tuic::parse_connect(frame);
    ASSERT_TRUE(req.valid);
    EXPECT_EQ(req.dst.host, "example.com");
    EXPECT_EQ(req.dst.port, 443);
}

TEST(TuicCommon, PacketRoundTrip)
{
    tuic::address dst;
    dst.type = atyp::ipv4;
    dst.host = "127.0.0.1";
    dst.port = 5353;

    const std::string payload = "hello tuic udp";
    const auto frame = tuic::build_packet(0x1122, 0x3344, dst, view(
        reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));

    const auto pkt = tuic::parse_packet(frame);
    ASSERT_TRUE(pkt.valid);
    EXPECT_EQ(pkt.assoc_id, 0x1122);
    EXPECT_EQ(pkt.pkt_id, 0x3344);
    EXPECT_EQ(pkt.dst.host, "127.0.0.1");
    EXPECT_EQ(pkt.dst.port, 5353);
    EXPECT_EQ(frame.size() - pkt.payload_offset, payload.size());
}

TEST(TuicCommon, HeartbeatAndHead)
{
    const auto hb = tuic::build_heartbeat();
    ASSERT_EQ(hb.size(), 2);
    std::uint8_t type = 0;
    ASSERT_TRUE(tuic::parse_head(hb, type));
    EXPECT_EQ(type, tuic::cmd_heartbeat);
}

/**
 * @file TuicCodec.cpp
 * @brief TUIC v5 帧编解码测试
 */

#include <prism/protocol/tuic/codec.hpp>

#include <gtest/gtest.h>

#include <cstring>

namespace
{
    using psm::protocol::tuic::authenticate_frame;
    using psm::protocol::tuic::connect_frame;
    using psm::protocol::tuic::decode_varint;
    using psm::protocol::tuic::encode_varint;
    using psm::protocol::tuic::packet_frame;
    using psm::protocol::tuic::parse_authenticate;
    using psm::protocol::tuic::parse_connect;
    using psm::protocol::tuic::parse_dissociate;
    using psm::protocol::tuic::parse_heartbeat;
    using psm::protocol::tuic::parse_packet;

    auto make_bytes(std::initializer_list<std::uint8_t> list) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(list);
    }
}

TEST(TuicCodec, VarintKnownValues)
{
    std::array<std::uint8_t, 8> out{};
    EXPECT_EQ(encode_varint(0, out), 1);
    EXPECT_EQ(encode_varint(300, out), 2);
    EXPECT_EQ(out[0], 0xAC);
    EXPECT_EQ(out[1], 0x02);

    std::uint32_t value = 0;
    const std::array<std::uint8_t, 2> enc{0xAC, 0x02};
    EXPECT_EQ(decode_varint(enc, value), 2);
    EXPECT_EQ(value, 300);
}

TEST(TuicCodec, ParseAuthenticate)
{
    std::vector<std::uint8_t> buf;
    buf.push_back(0x05);
    buf.push_back(0x00);
    buf.insert(buf.end(), 16, 0x11);
    buf.insert(buf.end(), 32, 0x22);

    authenticate_frame frame;
    ASSERT_TRUE(parse_authenticate(buf, frame));
    EXPECT_EQ(frame.uuid[0], 0x11);
    EXPECT_EQ(frame.uuid[15], 0x11);
    EXPECT_EQ(frame.token[0], 0x22);
    EXPECT_EQ(frame.token[31], 0x22);

    // 截断
    buf.pop_back();
    EXPECT_FALSE(parse_authenticate(buf, frame));
}

TEST(TuicCodec, ParseConnectDomain)
{
    // VER TYPE ATYP(0) LEN(11) "example.com" PORT(443)
    std::vector<std::uint8_t> buf{0x05, 0x01, 0x00, 11};
    const std::string_view domain = "example.com";
    for (const auto c : domain)
        buf.push_back(static_cast<std::uint8_t>(c));
    buf.push_back(0x01);
    buf.push_back(0xBB);

    connect_frame frame;
    std::size_t frame_len = 0;
    ASSERT_TRUE(parse_connect(buf, frame, frame_len));
    EXPECT_EQ(frame.port, 443);
    // 帧头 = VER(1) + TYPE(1) + ATYP(1) + LEN(1) + 域名(11) + PORT(2) = 17
    EXPECT_EQ(frame_len, 17);
    const auto *dom = std::get_if<psm::protocol::common::domain_address>(&frame.destination);
    ASSERT_NE(dom, nullptr);
    EXPECT_EQ(std::string_view(dom->value.data(), dom->length), "example.com");
}

TEST(TuicCodec, ParseConnectIpv4)
{
    std::vector<std::uint8_t> buf{0x05, 0x01, 0x01, 8, 8, 8, 8, 0x00, 0x35};
    connect_frame frame;
    std::size_t frame_len = 0;
    ASSERT_TRUE(parse_connect(buf, frame, frame_len));
    EXPECT_EQ(frame.port, 53);
    // 帧头 = VER + TYPE + ATYP + IPv4(4) + PORT(2) = 9
    EXPECT_EQ(frame_len, 9);
    const auto *ip = std::get_if<psm::protocol::common::ipv4_address>(&frame.destination);
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->bytes[0], 8);
}

TEST(TuicCodec, ParsePacketWithAddress)
{
    // VER TYPE ASSOC(2) PKT(2) TOTAL(1) ID(1) SIZE(2) ATYP(1) ADDR(4) PORT(2) DATA
    std::vector<std::uint8_t> buf{0x05, 0x02, 0x00, 0x01, 0x00, 0x02, 0x01, 0x00, 0x00, 0x03,
                                  0x01, 10, 0, 0, 1, 0x00, 0x35, 'a', 'b', 'c'};
    packet_frame frame;
    ASSERT_TRUE(parse_packet(buf, frame));
    EXPECT_EQ(frame.assoc_id, 1);
    EXPECT_EQ(frame.pkt_id, 2);
    EXPECT_EQ(frame.frag_total, 1);
    EXPECT_EQ(frame.frag_id, 0);
    EXPECT_EQ(frame.port, 53);
    EXPECT_EQ(frame.data_len, 3);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data() + frame.data_offset), 3), "abc");
}

TEST(TuicCodec, ParsePacketNoAddress)
{
    // 非首片：ATYP=0xFF，无地址
    std::vector<std::uint8_t> buf{0x05, 0x02, 0x00, 0x01, 0x00, 0x02, 0x02, 0x01, 0x00, 0x02,
                                  0xFF, 'x', 'y'};
    packet_frame frame;
    ASSERT_TRUE(parse_packet(buf, frame));
    EXPECT_EQ(frame.frag_total, 2);
    EXPECT_EQ(frame.frag_id, 1);
    EXPECT_EQ(frame.data_len, 2);
    const auto *none = std::get_if<psm::protocol::common::domain_address>(&frame.destination);
    EXPECT_EQ(none, nullptr);
}

TEST(TuicCodec, ParseDissociate)
{
    std::vector<std::uint8_t> buf{0x05, 0x03, 0x00, 0x07};
    std::uint16_t assoc = 0;
    ASSERT_TRUE(parse_dissociate(buf, assoc));
    EXPECT_EQ(assoc, 7);
}

TEST(TuicCodec, ParseHeartbeat)
{
    EXPECT_TRUE(parse_heartbeat(std::array<std::uint8_t, 2>{0x05, 0x04}));
    EXPECT_FALSE(parse_heartbeat(std::array<std::uint8_t, 2>{0x04, 0x04}));
    EXPECT_FALSE(parse_heartbeat(std::array<std::uint8_t, 1>{0x05}));
}

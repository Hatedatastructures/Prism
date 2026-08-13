/**
 * @file Hysteria2Codec.cpp
 * @brief Hysteria2 协议帧编解码测试
 */

#include <prism/protocol/hysteria2/codec.hpp>

#include <gtest/gtest.h>

namespace
{
    using psm::protocol::hysteria2::decode_varint;
    using psm::protocol::hysteria2::encode_varint;
    using psm::protocol::hysteria2::parse_tcp_request;
    using psm::protocol::hysteria2::parse_udp_message;
    using psm::protocol::hysteria2::tcp_request;
    using psm::protocol::hysteria2::udp_message;
} // namespace

TEST(Hysteria2Codec, VarintKnownValues)
{
    std::array<std::uint8_t, 8> out{};
    // 63 → 1 字节
    EXPECT_EQ(encode_varint(63, out), 1);
    EXPECT_EQ(out[0], 63);
    // 16383 → 2 字节
    EXPECT_EQ(encode_varint(16383, out), 2);
    EXPECT_EQ(out[0], 0x7F);
    EXPECT_EQ(out[1], 0xFF);
    // 16384 → 4 字节
    EXPECT_EQ(encode_varint(16384, out), 4);
    EXPECT_EQ(out[0], 0x80 | 0x00);
    EXPECT_EQ(out[1], 0x00);
    EXPECT_EQ(out[2], 0x40);
    EXPECT_EQ(out[3], 0x00);

    std::uint64_t value = 0;
    const std::array<std::uint8_t, 1> one{63};
    EXPECT_EQ(decode_varint(one, value), 1);
    EXPECT_EQ(value, 63);
    const std::array<std::uint8_t, 2> two{0x7F, 0xFF};
    EXPECT_EQ(decode_varint(two, value), 2);
    EXPECT_EQ(value, 16383);
    const std::array<std::uint8_t, 4> four{0x80, 0x00, 0x40, 0x00};
    EXPECT_EQ(decode_varint(four, value), 4);
    EXPECT_EQ(value, 16384);
}

TEST(Hysteria2Codec, ParseTcpRequest)
{
    // 0x401 (2B varint: 0x5C01? 0x401=1025 ≥64 → 2B: 0x44 0x01)
    // AddrLen(2B: 13) "example.com:443" PaddingLen(1B: 0)
    std::vector<std::uint8_t> buf{0x44, 0x01, 0x0F};
    const std::string_view addr = "example.com:443";
    for (const auto c : addr)
    {
        buf.push_back(static_cast<std::uint8_t>(c));
    }
    buf.push_back(0x00);

    tcp_request req;
    std::size_t payload_offset = 0;
    ASSERT_TRUE(parse_tcp_request(buf, req, payload_offset));
    EXPECT_EQ(req.address, "example.com:443");
    // 帧头 = 类型 varint(2) + 地址长 varint(1) + 地址(15) + padding 长(1) = 19
    EXPECT_EQ(payload_offset, 19);
    // 无载荷：偏移应等于输入长度
    EXPECT_EQ(payload_offset, buf.size());
}

TEST(Hysteria2Codec, ParseUdpMessage)
{
    // SessionID(4)=0x00000001 PacketID(2)=0x0002 FragID=0 FragCount=1
    // AddrLen(1)=7 "8.8.8.8:53" Data "hello"
    std::vector<std::uint8_t> buf{0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x0A};
    const std::string_view addr = "8.8.8.8:53";
    for (const auto c : addr)
    {
        buf.push_back(static_cast<std::uint8_t>(c));
    }
    for (const auto c : std::string_view("hello"))
    {
        buf.push_back(static_cast<std::uint8_t>(c));
    }

    udp_message msg;
    ASSERT_TRUE(parse_udp_message(buf, msg));
    EXPECT_EQ(msg.session_id, 1);
    EXPECT_EQ(msg.packet_id, 2);
    EXPECT_EQ(msg.frag_count, 1);
    EXPECT_EQ(msg.frag_id, 0);
    EXPECT_EQ(msg.address, "8.8.8.8:53");
    EXPECT_EQ(msg.data_len, 5);
    EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(buf.data() + msg.data_offset), 5), "hello");
}

TEST(Hysteria2Codec, ParseUdpFragmented)
{
    // 分片 2/2（FragID=1 FragCount=2）
    std::vector<std::uint8_t> buf{0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x01, 0x02, 0x0A};
    const std::string_view addr = "8.8.8.8:53";
    for (const auto c : addr)
    {
        buf.push_back(static_cast<std::uint8_t>(c));
    }
    buf.push_back('x');

    udp_message msg;
    ASSERT_TRUE(parse_udp_message(buf, msg));
    EXPECT_EQ(msg.frag_id, 1);
    EXPECT_EQ(msg.frag_count, 2);
    EXPECT_EQ(msg.data_len, 1);
}

TEST(Hysteria2Codec, InvalidInputs)
{
    tcp_request req;
    std::size_t payload_offset = 0;
    // 空
    EXPECT_FALSE(parse_tcp_request({}, req, payload_offset));
    // 错误帧类型
    std::array<std::uint8_t, 3> wrong_type{0x00, 0x01, 0x00};
    EXPECT_FALSE(parse_tcp_request(wrong_type, req, payload_offset));
    // 地址过长
    std::vector<std::uint8_t> long_addr{0x44, 0x01, 0xFF, 0xFF, 0x00, 0x00};
    EXPECT_FALSE(parse_tcp_request(long_addr, req, payload_offset));

    udp_message msg;
    // 过短
    EXPECT_FALSE(parse_udp_message(std::array<std::uint8_t, 4>{0, 0, 0, 1}, msg));
    // frag_id >= frag_count
    std::vector<std::uint8_t> bad_frag{0, 0, 0, 1, 0, 0, 2, 1, 0};
    EXPECT_FALSE(parse_udp_message(bad_frag, msg));
}

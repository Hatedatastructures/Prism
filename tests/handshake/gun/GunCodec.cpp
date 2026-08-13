/**
 * @file GunCodec.cpp
 * @brief gRPC (gun) 帧编解码测试
 * @details 验证 varint、帧封装/解析往返与非法输入。
 */

#include <prism/handshake/gun/codec.hpp>

#include <cstring>

#include <gtest/gtest.h>

namespace
{
    using psm::handshake::gun::codec::decode_varint;
    using psm::handshake::gun::codec::encode_frame;
    using psm::handshake::gun::codec::encode_varint;
    using psm::handshake::gun::codec::frame_header;
    using psm::handshake::gun::codec::parse_frame_header;
} // namespace

TEST(GunCodec, VarintKnownValues)
{
    std::array<std::uint8_t, 8> out{};
    // 0 -> [0x00]
    EXPECT_EQ(encode_varint(0, out), 1);
    EXPECT_EQ(out[0], 0x00);
    // 1 -> [0x01]
    EXPECT_EQ(encode_varint(1, out), 1);
    EXPECT_EQ(out[0], 0x01);
    // 300 -> [0xAC, 0x02]
    EXPECT_EQ(encode_varint(300, out), 2);
    EXPECT_EQ(out[0], 0xAC);
    EXPECT_EQ(out[1], 0x02);
}

TEST(GunCodec, VarintDecode)
{
    const std::array<std::uint8_t, 4> enc{0xAC, 0x02, 0x00, 0x00};
    std::uint32_t value = 0;
    EXPECT_EQ(decode_varint(enc, value), 2);
    EXPECT_EQ(value, 300);

    // 数据不足
    const std::array<std::uint8_t, 1> short_{0x80};
    EXPECT_EQ(decode_varint(short_, value), 0);
}

TEST(GunCodec, EncodeParseRoundtrip)
{
    const std::string payload = "gun frame payload";
    std::array<std::uint8_t, 512> buf{};
    const auto n = encode_frame(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()),
        buf);
    ASSERT_GT(n, 0);
    // 头 6 字节
    EXPECT_EQ(buf[0], 0x00);
    EXPECT_EQ(buf[5], 0x0A);

    frame_header header;
    ASSERT_TRUE(parse_frame_header(std::span<const std::uint8_t>(buf.data(), n), header));
    EXPECT_EQ(header.payload_len, payload.size());
    EXPECT_EQ(header.header_len, 6 + 1); // 11 字节 payload varint 1 字节

    // payload 内容一致
    EXPECT_EQ(std::memcmp(buf.data() + header.header_len, payload.data(), payload.size()), 0);
}

TEST(GunCodec, EncodeLargePayloadVarint)
{
    // 300 字节 payload：varint 2 字节
    std::vector<std::uint8_t> payload(300, 0xAB);
    std::vector<std::uint8_t> buf(512);
    const auto n = encode_frame(payload, buf);
    ASSERT_GT(n, 0);

    frame_header header;
    ASSERT_TRUE(parse_frame_header(std::span<const std::uint8_t>(buf.data(), n), header));
    EXPECT_EQ(header.payload_len, 300);
    EXPECT_EQ(header.header_len, 8);
}

TEST(GunCodec, InvalidInputs)
{
    frame_header header;
    // 数据不足
    const std::array<std::uint8_t, 3> short_{0, 0, 0};
    EXPECT_FALSE(parse_frame_header(short_, header));
    // 压缩标志非零
    const std::array<std::uint8_t, 6> compressed{1, 0, 0, 0, 0, 0x0A};
    EXPECT_FALSE(parse_frame_header(compressed, header));
    // protobuf 标记错误
    const std::array<std::uint8_t, 6> wrong_tag{0, 0, 0, 0, 0, 0x12};
    EXPECT_FALSE(parse_frame_header(wrong_tag, header));
    // 长度字段但 varint 截断
    const std::array<std::uint8_t, 7> trunc{0, 0, 0, 0, 0x10, 0x0A, 0x80};
    EXPECT_FALSE(parse_frame_header(trunc, header));
}

TEST(GunCodec, InsufficientBuffer)
{
    const std::string payload = "x";
    std::array<std::uint8_t, 4> tiny{};
    const auto n = encode_frame(
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()),
        tiny);
    EXPECT_EQ(n, 0);
}

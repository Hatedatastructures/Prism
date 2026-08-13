/**
 * @file WsCodec.cpp
 * @brief WebSocket 帧编解码测试
 * @details 验证 accept key 计算、帧头解析（含掩码/扩展长度）、
 *          服务端帧编码。
 */

#include <prism/handshake/ws/codec.hpp>

#include <cstring>

#include <gtest/gtest.h>

namespace
{
    using psm::handshake::ws::codec::compute_accept;
    using psm::handshake::ws::codec::encode_frame;
    using psm::handshake::ws::codec::frame_header;
    using psm::handshake::ws::codec::opcode;
    using psm::handshake::ws::codec::parse_frame_header;

    auto make_bytes(std::initializer_list<std::uint8_t> list) -> std::vector<std::byte>
    {
        std::vector<std::byte> out;
        for (const auto b : list)
        {
            out.push_back(static_cast<std::byte>(b));
        }
        return out;
    }
} // namespace

TEST(WsCodec, AcceptKeyKnownVector)
{
    // RFC 6455 示例：key "dGhlIHNhbXBsZSBub25jZQ==" → "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    std::array<char, 29> accept{};
    ASSERT_TRUE(compute_accept("dGhlIHNhbXBsZSBub25jZQ==", std::span<char, 28>(accept.data(), 28)));
    EXPECT_EQ(std::string_view(accept.data(), 28), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

TEST(WsCodec, ParseShortFrame)
{
    // FIN + binary，len=5
    auto data = make_bytes({0x82, 0x05, 'h', 'e', 'l', 'l', 'o'});
    frame_header header;
    ASSERT_TRUE(parse_frame_header(data, header));
    EXPECT_TRUE(header.fin);
    EXPECT_EQ(header.opcode, 0x02);
    EXPECT_FALSE(header.masked);
    EXPECT_EQ(header.payload_len, 5);
    EXPECT_EQ(header.header_len, 2);
}

TEST(WsCodec, ParseMaskedFrame)
{
    // FIN + binary，MASK，len=2 + 4B mask + payload
    auto data = make_bytes({0x82, 0x82, 0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB});
    frame_header header;
    ASSERT_TRUE(parse_frame_header(data, header));
    EXPECT_TRUE(header.masked);
    EXPECT_EQ(header.payload_len, 2);
    EXPECT_EQ(header.header_len, 6); // 2 头 + 4 mask key
    EXPECT_EQ(header.mask[0], 0x01);
    EXPECT_EQ(header.mask[3], 0x04);
}

TEST(WsCodec, ParseExtendedLength16)
{
    // FIN + binary，len=126 → 2B 长度
    auto data = make_bytes({0x82, 0x7E, 0x01, 0x00});
    frame_header header;
    ASSERT_TRUE(parse_frame_header(data, header));
    EXPECT_EQ(header.payload_len, 256);
    EXPECT_EQ(header.header_len, 4);
}

TEST(WsCodec, ParseExtendedLength64)
{
    // FIN + binary，len=127 → 8B 长度
    std::vector<std::byte> data = make_bytes({0x82, 0x7F, 0, 0, 0, 0, 0, 0, 0x01, 0x00});
    frame_header header;
    ASSERT_TRUE(parse_frame_header(data, header));
    EXPECT_EQ(header.payload_len, 256);
    EXPECT_EQ(header.header_len, 10);
}

TEST(WsCodec, ParseTruncated)
{
    // 只有 1 字节
    auto data = make_bytes({0x82});
    frame_header header;
    EXPECT_FALSE(parse_frame_header(data, header));
    // 126 但缺长度字节
    auto data2 = make_bytes({0x82, 0x7E, 0x01});
    EXPECT_FALSE(parse_frame_header(data2, header));
}

TEST(WsCodec, EncodeServerFrame)
{
    const std::string payload = "ws data";
    std::array<std::byte, 64> buf{};
    const auto n = encode_frame(
        opcode::binary, true,
        std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()), payload.size()), buf);
    ASSERT_GT(n, 0);
    // 服务端帧不掩码：byte0 = 0x82，byte1 = len
    EXPECT_EQ(static_cast<std::uint8_t>(buf[0]), 0x82);
    EXPECT_EQ(static_cast<std::uint8_t>(buf[1]), payload.size());
    EXPECT_EQ(std::memcmp(buf.data() + 2, payload.data(), payload.size()), 0);
}

TEST(WsCodec, EncodeExtendedLength)
{
    std::vector<std::byte> payload(300, std::byte{0xAB});
    std::vector<std::byte> buf(512);
    const auto n = encode_frame(opcode::binary, true, payload, buf);
    ASSERT_GT(n, 0);
    EXPECT_EQ(static_cast<std::uint8_t>(buf[1]), 126);
    EXPECT_EQ(static_cast<std::uint8_t>(buf[2]), 0x01);
    EXPECT_EQ(static_cast<std::uint8_t>(buf[3]), 0x2C);
}

/**
 * @file WsAcceptFrameTest.cpp
 * @brief WebSocket Accept 值与帧头编解码测试。
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <Prism/Protocols/Ws/Detail/Codec.hpp>
#include <gtest/gtest.h>

namespace
{

    namespace Ws = Prism::Ws;

TEST(WsBeast, AcceptAndFrame)
    {
        // Sec-WebSocket-Accept 标准测试向量（RFC 6455 示例）
        const auto Accept = Ws::Detail::ComputeAccept("dGhlIHNhbXBsZSBub25jZQ==");
        EXPECT_EQ(Accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

        // 帧编解码往返
        const std::string payload = "hello websocket";
        std::array<std::byte, 128> out{};
        const auto n = Ws::Detail::EncodeFrame(
            Ws::Detail::FrameInput{Ws::Detail::Opcode::Binary, true,
                            std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                       payload.size())},
            out);
        EXPECT_GT(n, 0u);

        Ws::Detail::FrameHeader hdr{};
        EXPECT_TRUE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(out).first(n), hdr));
        EXPECT_TRUE(hdr.Fin);
        EXPECT_EQ(hdr.Opcode, static_cast<std::uint8_t>(Ws::Detail::Opcode::Binary));
        EXPECT_FALSE(hdr.Masked);
        EXPECT_EQ(hdr.PayloadLen, payload.size());
        EXPECT_EQ(hdr.HeaderLen, 2u);
    }

} // namespace

/**
 * @file WsCodecDeepTest.cpp
 * @brief WebSocket 帧长度和控制帧边界测试。
 */

#include <boost/asio/buffer.hpp>
#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Ws/Detail/Codec.hpp>

namespace
{
    namespace Ws = Prism::Ws;
    using Prism::As;
    using Prism::AsBytes;
    using Prism::AsBytesSpan;
    using Prism::AsStrView;
    using Prism::AsU8;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::make_error_code;

auto MakeBytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }
} // namespace

TEST(WsCodec, FrameHeaderExtendedLengths)
    {
        Ws::Detail::FrameHeader Header{};
        std::array<std::byte, 64> Buffer{};

        // 16 位长度（126）+ 掩码
        Buffer[0] = std::byte{0x82};
        Buffer[1] = std::byte{0x80 | 126};
        Buffer[2] = std::byte{0x01};
        Buffer[3] = std::byte{0x00};
        Buffer[4] = std::byte{0xAA};
        Buffer[5] = std::byte{0xBB};
        Buffer[6] = std::byte{0xCC};
        Buffer[7] = std::byte{0xDD};
        EXPECT_TRUE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer.data(), 8), Header));
        EXPECT_TRUE(Header.Fin);
        EXPECT_EQ(Header.Opcode, 0x02u);
        EXPECT_TRUE(Header.Masked);
        EXPECT_EQ(Header.PayloadLen, 256u);
        EXPECT_EQ(Header.HeaderLen, 8u);
        EXPECT_EQ(static_cast<std::uint8_t>(Header.MaskKey[0]), 0xAA);

        // 16 位长度：数据不足（需 4 字节，只有 3）
        EXPECT_FALSE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer.data(), 3), Header));

        // 64 位长度（127）
        Buffer[1] = std::byte{0x7F};
        for (std::size_t i = 0; i < 8; ++i)
        {
            Buffer[2 + i] = std::byte{0};
        }
        Buffer[7] = std::byte{0x01};
        EXPECT_TRUE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer.data(), 10), Header));
        EXPECT_EQ(Header.PayloadLen, 65536u);
        EXPECT_EQ(Header.HeaderLen, 10u);

        // 64 位长度：数据不足（需 10 字节，只有 9）
        EXPECT_FALSE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer.data(), 9), Header));

        // 掩码 key 不足
        Buffer[1] = std::byte{0x80 | 5};
        EXPECT_FALSE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer.data(), 3), Header));
    }

TEST(WsCodec, RejectsInvalidFrameHeaderShape)
    {
        Ws::Detail::FrameHeader Header{};
        std::array<std::byte, 14> Buffer{};

        // RSV bits and reserved opcodes are rejected before any Payload allocation.
        Buffer[0] = std::byte{0xC2};
        Buffer[1] = std::byte{0x00};
        EXPECT_FALSE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));

        Buffer[0] = std::byte{0x8B};
        EXPECT_FALSE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));

        // Control frames must be final and use the Short length form.
        Buffer[0] = std::byte{0x09};
        EXPECT_FALSE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));
        Buffer[0] = std::byte{0x89};
        Buffer[1] = std::byte{126};
        EXPECT_FALSE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));

        // Extended lengths must be canonical and the 64-bit form cannot set bit 63.
        Buffer[0] = std::byte{0x82};
        Buffer[1] = std::byte{126};
        Buffer[2] = std::byte{0x00};
        Buffer[3] = std::byte{0x7D};
        EXPECT_FALSE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));

        Buffer[1] = std::byte{127};
        Buffer[2] = std::byte{0x80};
        EXPECT_FALSE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));

        for (std::size_t I = 2; I < 10; ++I)
        {
            Buffer[I] = std::byte{0x00};
        }
        Buffer[9] = std::byte{0x01};
        EXPECT_FALSE(Ws::Detail::ParseFrameHeader(std::span<const std::byte>(Buffer), Header));
    }

TEST(WsCodec, EncodeExtendedLengths)
    {
        std::array<std::byte, 80000> Output{};

        // 16 位长度（126）
        std::vector<std::byte> Payload126(300, std::byte{0x11});
        Ws::Detail::FrameInput Input126{Ws::Detail::Opcode::Binary, true, std::span<const std::byte>(Payload126)};
        const auto Bytes126 = Ws::Detail::EncodeFrame(Input126, Output);
        EXPECT_EQ(Bytes126, 304u);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[1]), 126u);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[2]), 0x01);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[3]), 0x2C);

        // 64 位长度（127）
        std::vector<std::byte> Payload127(70000, std::byte{0x22});
        Ws::Detail::FrameInput Input127{Ws::Detail::Opcode::Binary, true, std::span<const std::byte>(Payload127)};
        const auto Bytes127 = Ws::Detail::EncodeFrame(Input127, Output);
        EXPECT_EQ(Bytes127, 70010u);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[1]), 127u);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[2]), 0x00);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[7]), 0x01);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[8]), 0x11);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[9]), 0x70);
        EXPECT_EQ(static_cast<std::uint8_t>(Output[10]), 0x22);

        // 缓冲区不足 → 0
        std::array<std::byte, 16> SmallOutput{};
        EXPECT_EQ(Ws::Detail::EncodeFrame(Input127, SmallOutput), 0u);
    }

TEST(WsCodec, EncodeRejectsInvalidControlFrames)
    {
        std::array<std::byte, 256> Output{};
        std::array<std::byte, 126> Payload{};

        const Ws::Detail::FrameInput FragmentedPing{Ws::Detail::Opcode::Ping, false,
                                            std::span<const std::byte>(Payload).first(1)};
        EXPECT_EQ(Ws::Detail::EncodeFrame(FragmentedPing, Output), 0U);

        const Ws::Detail::FrameInput OversizedPing{Ws::Detail::Opcode::Ping, true,
                                           std::span<const std::byte>(Payload)};
        EXPECT_EQ(Ws::Detail::EncodeFrame(OversizedPing, Output), 0U);

        const Ws::Detail::FrameInput ShortClose{Ws::Detail::Opcode::Close, true,
                                        std::span<const std::byte>(Payload).first(1)};
        EXPECT_EQ(Ws::Detail::EncodeFrame(ShortClose, Output), 0U);
    }

    // ───────────────────────── socks5 Codec ─────────────────────────


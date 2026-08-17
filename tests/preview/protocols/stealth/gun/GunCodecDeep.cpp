/**
 * @file GunCodecDeep.cpp
 * @brief gun（gRPC 帧）codec 字节级深测（纯函数）
 * @details 覆盖：varint 编解码往返/边界、帧编码往返、
 *          帧头解析（定长头校验/长度一致性/截断）。
 */

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include <common/protocols/gun/codec.hpp>

namespace
{
    using namespace preview;

    TEST(GunCodecDeep, VarintRoundtrip)
    {
        for (const auto v : {0u, 1u, 127u, 128u, 16383u, 16384u, 0xFFFFFFFFu})
        {
            std::array<std::uint8_t, 8> buf{};
            const auto n = gun::encode_varint(v, buf);
            EXPECT_GT(n, 0u);
            std::uint32_t out = 0;
            const auto dn = gun::decode_varint(std::span<const std::uint8_t>(buf).first(n), out);
            EXPECT_GT(dn, 0u);
            EXPECT_EQ(out, v);
        }
    }

    TEST(GunCodecDeep, VarintBoundaries)
    {
        // 1 字节边界 127 / 128
        std::array<std::uint8_t, 8> buf{};
        EXPECT_EQ(gun::encode_varint(127, buf), 1u);
        EXPECT_EQ(gun::encode_varint(128, buf), 2u);
        // 截断输入 → 解码失败
        std::uint32_t out = 0;
        EXPECT_EQ(gun::decode_varint(std::span<const std::uint8_t>(), out), 0u);
    }

    TEST(GunCodecDeep, FrameEncodeRoundtrip)
    {
        const std::vector<std::uint8_t> payload = {1, 2, 3, 4, 5};
        const auto frame = gun::encode_frame(payload);
        EXPECT_GT(frame.size(), payload.size());

        gun::frame_header hdr{};
        EXPECT_TRUE(gun::parse_frame_header(frame, hdr));
        EXPECT_EQ(hdr.payload_len, payload.size());
        // 数据完整性：帧尾 == payload
        EXPECT_EQ(std::vector<std::uint8_t>(frame.end() - static_cast<std::ptrdiff_t>(payload.size()),
                                            frame.end()),
                  payload);
    }

    TEST(GunCodecDeep, ParseFrameHeaderErrors)
    {
        gun::frame_header hdr{};
        // 空 / 截断
        EXPECT_FALSE(gun::parse_frame_header(std::span<const std::uint8_t>{}, hdr));
        const std::array<std::uint8_t, 3> short_buf{0x00, 0x00, 0x00};
        EXPECT_FALSE(gun::parse_frame_header(short_buf, hdr));
        // 坏魔数
        const std::array<std::uint8_t, 8> bad_magic{0xFF, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00};
        EXPECT_FALSE(gun::parse_frame_header(bad_magic, hdr));
        // 长度不一致（total 与 varint+payload 不匹配）
        const std::array<std::uint8_t, 8> bad_len{0x00, 0x00, 0x00, 0x00, 0x64, 0x0A, 0x00, 0x00};
        EXPECT_FALSE(gun::parse_frame_header(bad_len, hdr));
    }

} // namespace

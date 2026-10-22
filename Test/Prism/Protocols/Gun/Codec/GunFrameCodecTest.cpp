/**
 * @file GunFrameCodecTest.cpp
 * @brief Gun gRPC 帧与 varint 编解码值测试。
 */

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <Prism/Protocols/Gun/Codec.hpp>
#include <gtest/gtest.h>

namespace
{

    namespace Gun = Prism::Gun;

TEST(GunBeast, FrameRoundtrip)
    {
        const std::string payload = "hello gun grpc";
        const auto Frame = Gun::EncodeFrame(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(payload.data()), payload.size()));

        Gun::FrameHeader hdr{};
        EXPECT_TRUE(Gun::ParseFrameHeader(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Frame.data()), Frame.size()),
            hdr));
        EXPECT_EQ(hdr.PayloadLen, payload.size());
        EXPECT_EQ(hdr.HeaderLen + hdr.PayloadLen, Frame.size());

        // varint 编解码
        std::array<std::uint8_t, 5> vb{};
        const auto vn = Gun::EncodeVarint(300, vb);
        std::uint32_t val = 0;
        EXPECT_EQ(Gun::DecodeVarint(std::span<const std::uint8_t>(vb).first(vn), val), vn);
        EXPECT_EQ(val, 300u);
    }

} // namespace

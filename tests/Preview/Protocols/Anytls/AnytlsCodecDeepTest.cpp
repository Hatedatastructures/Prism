/**
 * @file AnytlsCodecDeepTest.cpp
 * @brief AnyTLS 编解码器认证帧边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Anytls/Codec.hpp>

namespace
{
    namespace Anytls = Preview::Anytls;
    using Preview::Error;

auto MakeBytes(std::initializer_list<std::uint8_t> List) -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }
} // namespace

TEST(AnyTlsCodecDeep, ParseAuthFrameShort)
    {
        std::array<std::uint8_t, 32> Hash{};
        std::uint16_t PadLen = 0;
        // 帧头不足
        EXPECT_EQ(Anytls::ParseAuthFrame(std::span<const std::uint8_t>(MakeBytes({0x01})), Hash, PadLen),
                  Error::BadLength);
        // 头长足够但 padding 不足
        std::vector<std::uint8_t> short_pad(34, 0);
        short_pad[32] = 0x01; // PadLen = 256
        EXPECT_EQ(Anytls::ParseAuthFrame(short_pad, Hash, PadLen), Error::BadLength);
        // 成功
        std::vector<std::uint8_t> Ok(34 + 5, 0);
        EXPECT_EQ(Anytls::ParseAuthFrame(Ok, Hash, PadLen), Error::None);
    }


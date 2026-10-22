/**
 * @file Ss2022CodecFuzzTest.cpp
 * @brief Shadowsocks 2022 编解码器 fuzz 及边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <vector>
#include <Prism/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestState.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestWire.hpp>
#include <Prism/Protocols/Shadowsocks2022/ResponseCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/Types.hpp>

namespace
{
    namespace Shadowsocks2022 = Prism::Shadowsocks2022;
    using Prism::Error;

auto MakeRng(std::uint32_t Seed) -> std::mt19937
    {
        return std::mt19937(Seed);
    }

auto RandomBytes(std::mt19937 &RandomGenerator) -> std::vector<std::uint8_t>
    {
        std::uniform_int_distribution<int> LengthDistribution(0, 256);
        std::uniform_int_distribution<int> ByteDistribution(0, 255);
        std::vector<std::uint8_t> Output(LengthDistribution(RandomGenerator));
        for (auto &Byte : Output)
        {
            Byte = static_cast<std::uint8_t>(ByteDistribution(RandomGenerator));
        }
        return Output;
    }
} // namespace

TEST(CodecFuzz, Ss2022ParseNeverCrashes)
    {
        auto RandomGenerator = MakeRng(46);
        const auto Key = std::array<std::uint8_t, 16>{};
        for (int Index = 0; Index < 500; ++Index)
        {
            const auto Data = RandomBytes(RandomGenerator);
            Shadowsocks2022::ChunkCodec Codec(Key);
            std::vector<std::uint8_t> Output;
            (void)Codec.OpenPayload(Data, Output);
            EXPECT_LE(Output.size(), Data.size()); // AEAD 解密不膨胀

            if (Data.size() >= 18)
            {
                (void)Codec.OpenLen(std::span<const std::uint8_t>(Data).first(18));
            }
        }
        SUCCEED();
    }


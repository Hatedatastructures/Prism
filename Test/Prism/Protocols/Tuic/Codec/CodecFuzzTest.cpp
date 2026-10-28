/**
 * @file CodecFuzzTest.cpp
 * @brief TUIC 编解码器 fuzz 及边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <vector>
#include <Prism/Protocols/Tuic/Codec.hpp>

namespace
{
    namespace Tuic = Prism::Tuic;
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

TEST(CodecFuzz, TuicParseNeverCrashes)
    {
        auto RandomGenerator = MakeRng(48);
        for (int Index = 0; Index < 500; ++Index)
        {
            const auto Data = RandomBytes(RandomGenerator);
            Tuic::Message Message;
            std::size_t Consumed = 0;
            (void)Tuic::Parse(Data, Message, Consumed);
            EXPECT_LE(Consumed, Data.size());
        }
    }


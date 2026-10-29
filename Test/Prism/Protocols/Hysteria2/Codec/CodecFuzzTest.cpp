/**
 * @file CodecFuzzTest.cpp
 * @brief Hysteria2 编解码器 fuzz 及边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <vector>
#include <Prism/Protocols/Hysteria2/Codec.hpp>

namespace
{
    namespace Hysteria2 = Prism::Hysteria2;
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

TEST(CodecFuzz, Hysteria2ParseNeverCrashes)
    {
        auto RandomGenerator = MakeRng(47);
        for (int Index = 0; Index < 500; ++Index)
        {
            const auto Data = RandomBytes(RandomGenerator);
            Hysteria2::Message Message;
            std::size_t Consumed = 0;
            (void)Hysteria2::Parse(Data, Message, Consumed);
            EXPECT_LE(Consumed, Data.size());
        }
    }


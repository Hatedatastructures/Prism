/**
 * @file TrojanCodecFuzzTest.cpp
 * @brief Trojan 编解码器 fuzz 及边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <vector>
#include <Preview/Protocols/Trojan/Codec.hpp>

namespace
{
    namespace Trojan = Preview::Trojan;
    using Preview::Error;

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

TEST(CodecFuzz, TrojanParseNeverCrashes)
    {
        auto RandomGenerator = MakeRng(43);
        for (int Index = 0; Index < 500; ++Index)
        {
            const auto Data = RandomBytes(RandomGenerator);
            Trojan::RequestHeader Header;
            std::size_t Consumed = 0;
            (void)Trojan::ParseRequest(Data, Header, Consumed);
            EXPECT_LE(Consumed, Data.size());

            Trojan::Address Address;
            Consumed = 0;
            (void)Trojan::ParseAddress(Data, Address, Consumed);
            EXPECT_LE(Consumed, Data.size());

            Trojan::Address Destination;
            std::span<const std::uint8_t> Payload;
            (void)Trojan::ParseUdpPkt(Data, Destination, Payload);
            EXPECT_LE(Payload.size(), Data.size()); // 载荷视图不得超出输入
        }
        SUCCEED();
    }


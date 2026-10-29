/**
 * @file CodecFuzzTest.cpp
 * @brief VLESS 编解码器 fuzz 及边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <vector>
#include <Prism/Protocols/Vless/AddressCodec.hpp>
#include <Prism/Protocols/Vless/BeastCodec.hpp>
#include <Prism/Protocols/Vless/RequestCodec.hpp>
#include <Prism/Protocols/Vless/Types.hpp>
#include <Prism/Protocols/Vless/UdpCodec.hpp>

namespace
{
    namespace Vless = Prism::Vless;
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

TEST(CodecFuzz, VlessParseNeverCrashes)
    {
        auto RandomGenerator = MakeRng(44);
        for (int Index = 0; Index < 500; ++Index)
        {
            const auto Data = RandomBytes(RandomGenerator);
            Vless::RequestHeader Header;
            std::size_t Consumed = 0;
            (void)Vless::ParseRequest(Data, Header, Consumed);
            EXPECT_LE(Consumed, Data.size());

            Vless::Address Address;
            Consumed = 0;
            (void)Vless::ParseAddress(Data, Address, Consumed);
            EXPECT_LE(Consumed, Data.size());

            std::span<const std::uint8_t> Payload;
            (void)Vless::ParseUdpPkt(Data, Payload);
            EXPECT_LE(Payload.size(), Data.size());
        }
    }


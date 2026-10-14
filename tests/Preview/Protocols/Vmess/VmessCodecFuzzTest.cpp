/**
 * @file VmessCodecFuzzTest.cpp
 * @brief VMess 编解码器 fuzz 及边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <vector>
#include <Preview/Protocols/Vmess/Codec.hpp>

namespace
{
    namespace Vmess = Preview::Vmess;
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

TEST(CodecFuzz, VmessParseNeverCrashes)
    {
        auto RandomGenerator = MakeRng(45);
        const auto Key = std::array<std::uint8_t, 16>{};
        for (int Index = 0; Index < 500; ++Index)
        {
            const auto Data = RandomBytes(RandomGenerator);
            // 解码器状态机：随机输入不应崩溃
            const auto Nonce = std::array<std::uint8_t, 12>{};
            Vmess::ChunkDecryptor Decryptor(Key, Nonce);
            std::vector<std::uint8_t> Plaintext;
            (void)Decryptor.OpenPayload(Data, Plaintext);
            EXPECT_LE(Plaintext.size(), Data.size()); // AEAD 解密不膨胀
        }
        SUCCEED();
    }


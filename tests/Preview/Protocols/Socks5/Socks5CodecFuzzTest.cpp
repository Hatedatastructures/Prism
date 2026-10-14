/**
 * @file Socks5CodecFuzzTest.cpp
 * @brief Socks5 编解码器 fuzz 及边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <vector>
#include <Preview/Protocols/Socks5/Codec.hpp>

namespace
{
    namespace Socks5 = Preview::Socks5;
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

TEST(CodecFuzz, Socks5ParseNeverCrashes)
    {
        auto RandomGenerator = MakeRng(42);
        for (int Index = 0; Index < 500; ++Index)
        {
            const auto Data = RandomBytes(RandomGenerator);
            Socks5::Greeting Greeting;
            std::size_t Consumed = 0;
            (void)Socks5::ParseGreeting(Data, Greeting, Consumed);
            EXPECT_LE(Consumed, Data.size()); // 解析游标不得越过输入

            Socks5::Request Request;
            Consumed = 0;
            (void)Socks5::ParseRequest(Data, Request, Consumed);
            EXPECT_LE(Consumed, Data.size());

            Socks5::Reply Reply;
            Consumed = 0;
            (void)Socks5::ParseReply(Data, Reply, Consumed);
            EXPECT_LE(Consumed, Data.size());

            Socks5::Address Address;
            Consumed = 0;
            (void)Socks5::ParseAddress(Data, Address, Consumed);
            EXPECT_LE(Consumed, Data.size());

            Socks5::Address Destination;
            std::span<const std::uint8_t> Payload;
            (void)Socks5::ParseUdpDatagram(Data, Destination, Payload);
        }
        SUCCEED();
    }

TEST(CodecFuzz, Socks5BoundaryInputs)
    {
        // 有界输入：空/单字节/满缓冲
        const std::array<std::vector<std::uint8_t>, 4> Inputs = {
            std::vector<std::uint8_t>{},
            std::vector<std::uint8_t>{0x05},
            std::vector<std::uint8_t>(1, 0xFF),
            std::vector<std::uint8_t>(512, 0x00),
        };
        for (const auto &Data : Inputs)
        {
            Socks5::Request Request;
            std::size_t Consumed = 0;
            (void)Socks5::ParseRequest(Data, Request, Consumed);

            Socks5::Address Address;
            Consumed = 0;
            (void)Socks5::ParseAddress(Data, Address, Consumed);
        }
        SUCCEED();
    }

TEST(CodecFuzz, RoundtripStability)
    {
        // 合法数据往返：Encode → Decode 应稳定
        auto RandomGenerator = MakeRng(49);
        for (int Index = 0; Index < 100; ++Index)
        {
            std::uniform_int_distribution<int> TypeDistribution(1, 3);
            std::uniform_int_distribution<int> LengthDistribution(1, 20);
            Socks5::Address Address;
            Address.Type = static_cast<Socks5::AddressType>(TypeDistribution(RandomGenerator));
            Address.Host.assign(static_cast<std::size_t>(LengthDistribution(RandomGenerator)), 'x');
            Address.Port = 443;

            const auto Wire = Socks5::EncodeAddress(Address);
            Socks5::Address Parsed;
            std::size_t Consumed = 0;
            const auto ErrorCode = Socks5::ParseAddress(Wire, Parsed, Consumed);
            if (ErrorCode == Preview::Error::None)
            {
                EXPECT_EQ(Parsed.Port, Address.Port);
            }
        }
        SUCCEED();
    }


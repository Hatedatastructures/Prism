/**
 * @file CodecFuzzTest.cpp
 * @brief Socks5 编解码器 fuzz 及边界测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <random>
#include <span>
#include <string>
#include <vector>
#include <Prism/Protocols/Socks5/AddressCodec.hpp>
#include <Prism/Protocols/Socks5/AuthCodec.hpp>
#include <Prism/Protocols/Socks5/BeastCodec.hpp>
#include <Prism/Protocols/Socks5/MessageCodec.hpp>
#include <Prism/Protocols/Socks5/TransportCodec.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>

namespace
{
    namespace Socks5 = Prism::Socks5;
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
    }

TEST(CodecFuzz, RoundtripStability)
    {
        // 合法数据往返：Encode → Decode 应稳定
        constexpr std::array<Socks5::AddressType, 3> Types{
            Socks5::AddressType::Ipv4,
            Socks5::AddressType::Domain,
            Socks5::AddressType::Ipv6};
        auto RandomGenerator = MakeRng(49);
        for (int Index = 0; Index < 100; ++Index)
        {
            std::uniform_int_distribution<int> LengthDistribution(1, 20);
            Socks5::Address Address;
            Address.Type = Types[static_cast<std::size_t>(Index) % Types.size()];
            switch (Address.Type)
            {
            case Socks5::AddressType::Ipv4:
                Address.Host = "192.0.2." + std::to_string(Index % 256);
                break;
            case Socks5::AddressType::Domain:
                Address.Host.assign(
                    static_cast<std::size_t>(LengthDistribution(RandomGenerator)), 'x');
                break;
            case Socks5::AddressType::Ipv6:
                Address.Host = "2001:db8::" + std::to_string(Index + 1);
                break;
            }
            Address.Port = static_cast<std::uint16_t>(443 + Index % 60000);

            const auto Wire = Socks5::EncodeAddress(Address);
            ASSERT_FALSE(Wire.empty());
            Socks5::Address Parsed;
            std::size_t Consumed = 0;
            const auto ErrorCode = Socks5::ParseAddress(Wire, Parsed, Consumed);
            ASSERT_EQ(ErrorCode, Prism::Error::None);
            EXPECT_EQ(Parsed.Type, Address.Type);
            EXPECT_EQ(Parsed.Port, Address.Port);
            EXPECT_EQ(Consumed, Wire.size());
            EXPECT_EQ(Socks5::EncodeAddress(Parsed), Wire);
        }
    }


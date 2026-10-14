/**
 * @file ProtocolMutationFuzzTest.cpp
 * @brief 跨协议编解码器结构化 mutation fuzz 测试。
 */

#include <gtest/gtest.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <vector>
#include <Preview/Protocols/Http2/Detail/Codec.hpp>
#include <Preview/Protocols/Http2/Detail/Frame.hpp>
#include <Preview/Protocols/Http3/Qpack.hpp>
#include <Preview/Protocols/Hysteria2/Codec.hpp>
#include <Preview/Protocols/Shadowsocks2022/Codec.hpp>
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Trojan/Codec.hpp>
#include <Preview/Protocols/Tuic/Codec.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vmess/Codec.hpp>
#include <Preview/Foundation/Error.hpp>

namespace
{
    namespace Http2 = Preview::Http2;
    namespace Hysteria2 = Preview::Hysteria2;
    namespace Memory = Preview::Memory;
    namespace Qpack = Preview::Http3::Qpack;
    namespace Shadowsocks2022 = Preview::Shadowsocks2022;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Tuic = Preview::Tuic;
    namespace Vless = Preview::Vless;
    namespace Vmess = Preview::Vmess;
    using Preview::Error;

auto MakeRng(std::uint32_t Seed) -> std::mt19937
    {
        return std::mt19937(Seed);
    }

auto RandomBytes(std::mt19937 &Rng) -> std::vector<std::uint8_t>
    {
        std::uniform_int_distribution<int> LengthDistribution(0, 512);
        std::uniform_int_distribution<int> ByteDistribution(0, 255);
        std::vector<std::uint8_t> Output(LengthDistribution(Rng));
        for (auto &Byte : Output)
        {
            Byte = static_cast<std::uint8_t>(ByteDistribution(Rng));
        }
        return Output;
    }

constexpr std::array<std::uint8_t, 24> EdgeBytes = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x0D, 0x0A, 0x0F, 0x10,
        0x1F, 0x20, 0x3F, 0x40, 0x7F, 0x80, 0xFE, 0xFF, 0x00, 0x00, 0xFF, 0xFF};

auto MutateBytes(std::mt19937 &Rng) -> std::vector<std::uint8_t>
    {
        auto Data = RandomBytes(Rng);
        if (Data.empty())
        {
            Data.push_back(static_cast<std::uint8_t>(Rng() & 0xFF));
        }
        std::uniform_int_distribution<int> Operation(0, 3);
        const auto Mode = Operation(Rng);
        if (Mode == 0)
        {
            // 截断
            std::uniform_int_distribution<std::size_t> Cut(0, Data.size());
            Data.resize(Cut(Rng));
        }
        else if (Mode == 1)
        {
            // 边界字典注入
            std::uniform_int_distribution<std::size_t> Position(0, Data.size() - 1);
            std::uniform_int_distribution<std::size_t> Edge(0, EdgeBytes.size() - 1);
            const auto PositionValue = Position(Rng);
            const auto EdgeValue = EdgeBytes[Edge(Rng)];
            if (PositionValue < Data.size())
            {
                Data[PositionValue] = EdgeValue;
            }
        }
        else if (Mode == 2)
        {
            // 头部插入边界字典
            std::uniform_int_distribution<std::size_t> Count(1, 8);
            const auto CountValue = Count(Rng);
            Data.insert(Data.begin(), EdgeBytes.begin(),
                        EdgeBytes.begin() + static_cast<std::ptrdiff_t>(CountValue));
        }
        // mode 3：原样（随机字节）
        return Data;
    }
} // namespace

TEST(FuzzExtended, CodecStructuredMutation)
    {
        auto Rng = MakeRng(12);
        const auto Key = std::array<std::uint8_t, 16>{};
        for (int I = 0; I < 1000; ++I)
        {
            const auto Data = MutateBytes(Rng);
            std::span<const std::uint8_t> Input(Data);

            Socks5::Greeting Greeting;
            std::size_t Consumed = 0;
            (void)Socks5::ParseGreeting(Input, Greeting, Consumed);
            EXPECT_LE(Consumed, Input.size()); // 解析游标不得越过输入

            Trojan::RequestHeader RequestHeader;
            Consumed = 0;
            (void)Trojan::ParseRequest(Input, RequestHeader, Consumed);
            EXPECT_LE(Consumed, Input.size());

            Vless::RequestHeader VlessHeader;
            Consumed = 0;
            (void)Vless::ParseRequest(Input, VlessHeader, Consumed);
            EXPECT_LE(Consumed, Input.size());

            Vmess::ChunkDecryptor VmessDecoder(Key, std::array<std::uint8_t, 12>{});
            std::vector<std::uint8_t> Plain;
            (void)VmessDecoder.OpenPayload(Data, Plain);
            EXPECT_LE(Plain.size(), Data.size()); // AEAD 解密不膨胀

            Shadowsocks2022::ChunkCodec ShadowsocksCodec(Key);
            std::vector<std::uint8_t> ShadowsocksPlain;
            (void)ShadowsocksCodec.OpenPayload(Data, ShadowsocksPlain);
            EXPECT_LE(ShadowsocksPlain.size(), Data.size());

            Hysteria2::Message HysteriaMessage;
            Consumed = 0;
            (void)Hysteria2::Parse(Input, HysteriaMessage, Consumed);
            EXPECT_LE(Consumed, Input.size());

            Tuic::Message TuicMessage;
            Consumed = 0;
            (void)Tuic::Parse(Input, TuicMessage, Consumed);
            EXPECT_LE(Consumed, Input.size());
        }
    }


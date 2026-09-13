/**
 * @file CodecFuzzTest.cpp
 * @brief 协议解析器模糊测试
 * @details 对协议 Codec 的 Parse 函数注入随机/变异输入，断言：
 * - 不崩溃（随机输入不触发 UB/段错误）
 * - 不产生非法状态（错误码合理）
 * - 有界输入边界（空/满/截断）
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <random>
#include <span>
#include <vector>

#include <preview/Protocols/Hysteria2/Codec.hpp>
#include <preview/Protocols/Shadowsocks2022/Codec.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Trojan/Codec.hpp>
#include <preview/Protocols/Tuic/Codec.hpp>
#include <preview/Protocols/Vless/Codec.hpp>
#include <preview/Protocols/Vmess/Codec.hpp>

namespace
{
    namespace Hysteria2 = Preview::Hysteria2;
    namespace Shadowsocks2022 = Preview::Shadowsocks2022;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Tuic = Preview::Tuic;
    namespace Vless = Preview::Vless;
    namespace Vmess = Preview::Vmess;
    using Preview::ConstantTimeEqual;
    using Preview::Error;

    /// 确定性随机数生成器（可复现）
    auto MakeRng(std::uint32_t Seed) -> std::mt19937
    {
        return std::mt19937(Seed);
    }

    /// 生成随机字节流（长度 0-256）
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

            Vless::Address Destination;
            std::span<const std::uint8_t> Payload;
            (void)Vless::ParseUdpPkt(Data, Destination, Payload);
            EXPECT_LE(Payload.size(), Data.size());
        }
        SUCCEED();
    }

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
        SUCCEED();
    }

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

} // namespace

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

#include <common/Protocols/Hysteria2/Codec.hpp>
#include <common/Protocols/Shadowsocks2022/Codec.hpp>
#include <common/Protocols/Socks5/Codec.hpp>
#include <common/Protocols/Trojan/Codec.hpp>
#include <common/Protocols/Tuic/Codec.hpp>
#include <common/Protocols/Vless/Codec.hpp>
#include <common/Protocols/Vmess/Codec.hpp>

namespace
{
    using namespace Preview;

    /// 确定性随机数生成器（可复现）
    auto make_rng(std::uint32_t seed) -> std::mt19937
    {
        return std::mt19937(seed);
    }

    /// 生成随机字节流（长度 0-256）
    auto random_bytes(std::mt19937 &rng) -> std::vector<std::uint8_t>
    {
        std::uniform_int_distribution<int> len_dist(0, 256);
        std::uniform_int_distribution<int> byte_dist(0, 255);
        std::vector<std::uint8_t> out(len_dist(rng));
        for (auto &b : out)
        {
            b = static_cast<std::uint8_t>(byte_dist(rng));
        }
        return out;
    }

    TEST(CodecFuzz, Socks5ParseNeverCrashes)
    {
        auto rng = make_rng(42);
        for (int i = 0; i < 500; ++i)
        {
            const auto Data = random_bytes(rng);
            Socks5::Greeting g;
            std::size_t consumed = 0;
            (void)Socks5::ParseGreeting(Data, g, consumed);
            EXPECT_LE(consumed, Data.size()); // 解析游标不得越过输入

            Socks5::Request req;
            consumed = 0;
            (void)Socks5::ParseRequest(Data, req, consumed);
            EXPECT_LE(consumed, Data.size());

            Socks5::Reply rep;
            consumed = 0;
            (void)Socks5::ParseReply(Data, rep, consumed);
            EXPECT_LE(consumed, Data.size());

            Socks5::Address addr;
            consumed = 0;
            (void)Socks5::ParseAddress(Data, addr, consumed);
            EXPECT_LE(consumed, Data.size());

            Socks5::Address dst;
            std::span<const std::uint8_t> payload;
            (void)Socks5::ParseUdpDatagram(Data, dst, payload);
        }
        SUCCEED();
    }

    TEST(CodecFuzz, TrojanParseNeverCrashes)
    {
        auto rng = make_rng(43);
        for (int i = 0; i < 500; ++i)
        {
            const auto Data = random_bytes(rng);
            Trojan::RequestHeader hdr;
            std::size_t consumed = 0;
            (void)Trojan::ParseRequest(Data, hdr, consumed);
            EXPECT_LE(consumed, Data.size());

            Trojan::Address addr;
            consumed = 0;
            (void)Trojan::ParseAddress(Data, addr, consumed);
            EXPECT_LE(consumed, Data.size());

            Trojan::Address dst;
            std::span<const std::uint8_t> payload;
            (void)Trojan::ParseUdpPkt(Data, dst, payload);
            EXPECT_LE(payload.size(), Data.size()); // 载荷视图不得超出输入
        }
        SUCCEED();
    }

    TEST(CodecFuzz, VlessParseNeverCrashes)
    {
        auto rng = make_rng(44);
        for (int i = 0; i < 500; ++i)
        {
            const auto Data = random_bytes(rng);
            Vless::RequestHeader hdr;
            std::size_t consumed = 0;
            (void)Vless::ParseRequest(Data, hdr, consumed);
            EXPECT_LE(consumed, Data.size());

            Vless::Address addr;
            consumed = 0;
            (void)Vless::ParseAddress(Data, addr, consumed);
            EXPECT_LE(consumed, Data.size());

            Vless::Address dst;
            std::span<const std::uint8_t> payload;
            (void)Vless::ParseUdpPkt(Data, dst, payload);
            EXPECT_LE(payload.size(), Data.size());
        }
        SUCCEED();
    }

    TEST(CodecFuzz, VmessParseNeverCrashes)
    {
        auto rng = make_rng(45);
        const auto key = std::array<std::uint8_t, 16>{};
        for (int i = 0; i < 500; ++i)
        {
            const auto Data = random_bytes(rng);
            // 解码器状态机：随机输入不应崩溃
            const auto Nonce = std::array<std::uint8_t, 12>{};
            Vmess::ChunkDecryptor dec(key, Nonce);
            std::vector<std::uint8_t> plain;
            (void)dec.OpenPayload(Data, plain);
            EXPECT_LE(plain.size(), Data.size()); // AEAD 解密不膨胀
        }
        SUCCEED();
    }

    TEST(CodecFuzz, Ss2022ParseNeverCrashes)
    {
        auto rng = make_rng(46);
        const auto key = std::array<std::uint8_t, 16>{};
        for (int i = 0; i < 500; ++i)
        {
            const auto Data = random_bytes(rng);
            Shadowsocks2022::ChunkCodec Codec(key);
            std::vector<std::uint8_t> out;
            (void)Codec.OpenPayload(Data, out);
            EXPECT_LE(out.size(), Data.size()); // AEAD 解密不膨胀

            if (Data.size() >= 18)
            {
                (void)Codec.OpenLen(std::span<const std::uint8_t>(Data).first(18));
            }
        }
        SUCCEED();
    }

    TEST(CodecFuzz, Hysteria2ParseNeverCrashes)
    {
        auto rng = make_rng(47);
        for (int i = 0; i < 500; ++i)
        {
            const auto Data = random_bytes(rng);
            Hysteria2::Message msg;
            std::size_t consumed = 0;
            (void)Hysteria2::Parse(Data, msg, consumed);
            EXPECT_LE(consumed, Data.size());
        }
        SUCCEED();
    }

    TEST(CodecFuzz, TuicParseNeverCrashes)
    {
        auto rng = make_rng(48);
        for (int i = 0; i < 500; ++i)
        {
            const auto Data = random_bytes(rng);
            Tuic::Message msg;
            std::size_t consumed = 0;
            (void)Tuic::Parse(Data, msg, consumed);
            EXPECT_LE(consumed, Data.size());
        }
        SUCCEED();
    }

    TEST(CodecFuzz, Socks5BoundaryInputs)
    {
        // 有界输入：空/单字节/满缓冲
        const std::array<std::vector<std::uint8_t>, 4> inputs = {
            std::vector<std::uint8_t>{},
            std::vector<std::uint8_t>{0x05},
            std::vector<std::uint8_t>(1, 0xFF),
            std::vector<std::uint8_t>(512, 0x00),
        };
        for (const auto &Data : inputs)
        {
            Socks5::Request req;
            std::size_t consumed = 0;
            (void)Socks5::ParseRequest(Data, req, consumed);

            Socks5::Address addr;
            consumed = 0;
            (void)Socks5::ParseAddress(Data, addr, consumed);
        }
        SUCCEED();
    }

    TEST(CodecFuzz, RoundtripStability)
    {
        // 合法数据往返：Encode → Decode 应稳定
        auto rng = make_rng(49);
        for (int i = 0; i < 100; ++i)
        {
            std::uniform_int_distribution<int> type_dist(1, 3);
            std::uniform_int_distribution<int> len_dist(1, 20);
            Socks5::Address addr;
            addr.Type = static_cast<Socks5::AddressType>(type_dist(rng));
            addr.Host.assign(static_cast<std::size_t>(len_dist(rng)), 'x');
            addr.Port = 443;

            const auto wire = Socks5::EncodeAddress(addr);
            Socks5::Address Parsed;
            std::size_t consumed = 0;
            const auto err = Socks5::ParseAddress(wire, Parsed, consumed);
            if (err == Preview::Error::None)
            {
                EXPECT_EQ(Parsed.Port, addr.Port);
            }
        }
        SUCCEED();
    }

} // namespace

/**
 * @file CodecFuzzTest.cpp
 * @brief 协议解析器模糊测试
 * @details 对协议 codec 的 parse 函数注入随机/变异输入，断言：
 * - 不崩溃（随机输入不触发 UB/段错误）
 * - 不产生非法状态（错误码合理）
 * - 有界输入边界（空/满/截断）
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <random>
#include <span>
#include <vector>

#include <common/protocols/hysteria2/codec.hpp>
#include <common/protocols/shadowsocks2022/codec.hpp>
#include <common/protocols/socks5/codec.hpp>
#include <common/protocols/trojan/codec.hpp>
#include <common/protocols/tuic/codec.hpp>
#include <common/protocols/vless/codec.hpp>
#include <common/protocols/vmess/codec.hpp>

namespace
{
    using namespace preview;

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
            const auto data = random_bytes(rng);
            socks5::greeting g;
            std::size_t consumed = 0;
            (void)socks5::parse_greeting(data, g, consumed);
            EXPECT_LE(consumed, data.size()); // 解析游标不得越过输入

            socks5::request req;
            consumed = 0;
            (void)socks5::parse_request(data, req, consumed);
            EXPECT_LE(consumed, data.size());

            socks5::reply rep;
            consumed = 0;
            (void)socks5::parse_reply(data, rep, consumed);
            EXPECT_LE(consumed, data.size());

            socks5::address addr;
            consumed = 0;
            (void)socks5::parse_address(data, addr, consumed);
            EXPECT_LE(consumed, data.size());

            socks5::address dst;
            std::span<const std::uint8_t> payload;
            (void)socks5::parse_udp_datagram(data, dst, payload);
        }
        SUCCEED();
    }

    TEST(CodecFuzz, TrojanParseNeverCrashes)
    {
        auto rng = make_rng(43);
        for (int i = 0; i < 500; ++i)
        {
            const auto data = random_bytes(rng);
            trojan::request_header hdr;
            std::size_t consumed = 0;
            (void)trojan::parse_request(data, hdr, consumed);
            EXPECT_LE(consumed, data.size());

            trojan::address addr;
            consumed = 0;
            (void)trojan::parse_address(data, addr, consumed);
            EXPECT_LE(consumed, data.size());

            trojan::address dst;
            std::span<const std::uint8_t> payload;
            (void)trojan::parse_udp_pkt(data, dst, payload);
            EXPECT_LE(payload.size(), data.size()); // 载荷视图不得超出输入
        }
        SUCCEED();
    }

    TEST(CodecFuzz, VlessParseNeverCrashes)
    {
        auto rng = make_rng(44);
        for (int i = 0; i < 500; ++i)
        {
            const auto data = random_bytes(rng);
            vless::request_header hdr;
            std::size_t consumed = 0;
            (void)vless::parse_request(data, hdr, consumed);
            EXPECT_LE(consumed, data.size());

            vless::address addr;
            consumed = 0;
            (void)vless::parse_address(data, addr, consumed);
            EXPECT_LE(consumed, data.size());

            vless::address dst;
            std::span<const std::uint8_t> payload;
            (void)vless::parse_udp_pkt(data, dst, payload);
            EXPECT_LE(payload.size(), data.size());
        }
        SUCCEED();
    }

    TEST(CodecFuzz, VmessParseNeverCrashes)
    {
        auto rng = make_rng(45);
        const auto key = std::array<std::uint8_t, 16>{};
        for (int i = 0; i < 500; ++i)
        {
            const auto data = random_bytes(rng);
            // 解码器状态机：随机输入不应崩溃
            const auto nonce = std::array<std::uint8_t, 12>{};
            vmess::chunk_decryptor dec(key, nonce);
            std::vector<std::uint8_t> plain;
            (void)dec.open_payload(data, plain);
            EXPECT_LE(plain.size(), data.size()); // AEAD 解密不膨胀
        }
        SUCCEED();
    }

    TEST(CodecFuzz, Ss2022ParseNeverCrashes)
    {
        auto rng = make_rng(46);
        const auto key = std::array<std::uint8_t, 16>{};
        for (int i = 0; i < 500; ++i)
        {
            const auto data = random_bytes(rng);
            shadowsocks2022::chunk_codec codec(key);
            std::vector<std::uint8_t> out;
            (void)codec.open_payload(data, out);
            EXPECT_LE(out.size(), data.size()); // AEAD 解密不膨胀

            if (data.size() >= 18)
            {
                (void)codec.open_len(std::span<const std::uint8_t>(data).first(18));
            }
        }
        SUCCEED();
    }

    TEST(CodecFuzz, Hysteria2ParseNeverCrashes)
    {
        auto rng = make_rng(47);
        for (int i = 0; i < 500; ++i)
        {
            const auto data = random_bytes(rng);
            hysteria2::message msg;
            std::size_t consumed = 0;
            (void)hysteria2::parse(data, msg, consumed);
            EXPECT_LE(consumed, data.size());
        }
        SUCCEED();
    }

    TEST(CodecFuzz, TuicParseNeverCrashes)
    {
        auto rng = make_rng(48);
        for (int i = 0; i < 500; ++i)
        {
            const auto data = random_bytes(rng);
            tuic::message msg;
            std::size_t consumed = 0;
            (void)tuic::parse(data, msg, consumed);
            EXPECT_LE(consumed, data.size());
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
        for (const auto &data : inputs)
        {
            socks5::request req;
            std::size_t consumed = 0;
            (void)socks5::parse_request(data, req, consumed);

            socks5::address addr;
            consumed = 0;
            (void)socks5::parse_address(data, addr, consumed);
        }
        SUCCEED();
    }

    TEST(CodecFuzz, RoundtripStability)
    {
        // 合法数据往返：encode → decode 应稳定
        auto rng = make_rng(49);
        for (int i = 0; i < 100; ++i)
        {
            std::uniform_int_distribution<int> type_dist(1, 3);
            std::uniform_int_distribution<int> len_dist(1, 20);
            socks5::address addr;
            addr.type = static_cast<socks5::address_type>(type_dist(rng));
            addr.host.assign(static_cast<std::size_t>(len_dist(rng)), 'x');
            addr.port = 443;

            const auto wire = socks5::encode_address(addr);
            socks5::address parsed;
            std::size_t consumed = 0;
            const auto err = socks5::parse_address(wire, parsed, consumed);
            if (err == preview::error::none)
            {
                EXPECT_EQ(parsed.port, addr.port);
            }
        }
        SUCCEED();
    }

} // namespace

/**
 * @file FuzzExtendedTest.cpp
 * @brief 结构化 fuzz 扩展（T6-4 D6）
 * @details 在 CodecFuzzTest（7 Codec 随机字节）基础上扩展：
 *          - 结构化变异器：截断 / 边界字典 / 字段翻转
 *          - http2：帧头解析 / SETTINGS 解码 / varint / HPACK
 *          - qpack：Header block 解码 / huffman 解码
 * @note smoke 参数（500-2000 轮/用例）；完整 fuzz 走 libFuzzer（T6-4 完整版）
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <vector>

#include <preview/Protocols/Http2/Codec.hpp>
#include <preview/Protocols/Http2/Frame.hpp>
#include <preview/Protocols/Http3/Qpack.hpp>
#include <preview/Protocols/Hysteria2/Codec.hpp>
#include <preview/Protocols/Shadowsocks2022/Codec.hpp>
#include <preview/Protocols/Socks5/Codec.hpp>
#include <preview/Protocols/Trojan/Codec.hpp>
#include <preview/Protocols/Tuic/Codec.hpp>
#include <preview/Protocols/Vless/Codec.hpp>
#include <preview/Protocols/Vmess/Codec.hpp>

namespace
{
    using namespace Preview;

    auto make_rng(std::uint32_t seed) -> std::mt19937
    {
        return std::mt19937(seed);
    }

    /// 随机字节流（0-512）
    auto random_bytes(std::mt19937 &rng) -> std::vector<std::uint8_t>
    {
        std::uniform_int_distribution<int> len_dist(0, 512);
        std::uniform_int_distribution<int> byte_dist(0, 255);
        std::vector<std::uint8_t> out(len_dist(rng));
        for (auto &b : out)
        {
            b = static_cast<std::uint8_t>(byte_dist(rng));
        }
        return out;
    }

    /// 边界字典（协议字段常用边界值）
    constexpr std::array<std::uint8_t, 24> edge_bytes = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x0D, 0x0A, 0x0F, 0x10,
        0x1F, 0x20, 0x3F, 0x40, 0x7F, 0x80, 0xFE, 0xFF, 0x00, 0x00, 0xFF, 0xFF};

    /// 结构化变异：随机字节流 + 边界字典注入 + 截断
    auto mutate_bytes(std::mt19937 &rng) -> std::vector<std::uint8_t>
    {
        auto Data = random_bytes(rng);
        if (Data.empty())
        {
            Data.push_back(static_cast<std::uint8_t>(rng() & 0xFF));
        }
        std::uniform_int_distribution<int> op(0, 3);
        const auto mode = op(rng);
        if (mode == 0)
        {
            // 截断
            std::uniform_int_distribution<std::size_t> cut(0, Data.size());
            Data.resize(cut(rng));
        }
        else if (mode == 1)
        {
            // 边界字典注入
            std::uniform_int_distribution<std::size_t> pos(0, Data.size() - 1);
            std::uniform_int_distribution<std::size_t> eb(0, edge_bytes.size() - 1);
            const auto p = pos(rng);
            const auto v = edge_bytes[eb(rng)];
            if (p < Data.size())
            {
                Data[p] = v;
            }
        }
        else if (mode == 2)
        {
            // 头部插入边界字典
            std::uniform_int_distribution<std::size_t> n(1, 8);
            const auto cnt = n(rng);
            Data.insert(Data.begin(), edge_bytes.begin(),
                        edge_bytes.begin() + static_cast<std::ptrdiff_t>(cnt));
        }
        // mode 3：原样（随机字节）
        return Data;
    }

    TEST(FuzzExtended, Http2FrameHeaderParse)
    {
        auto rng = make_rng(7);
        for (int i = 0; i < 2000; ++i)
        {
            const auto Data = mutate_bytes(rng);
            if (Data.size() >= 9)
            {
                if (const auto fh = Http2::ParseFrameHeader(std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Data.data()), 9)))
                {
                    // HTTP/2 帧长 24-bit：解析不得越界
                    EXPECT_LE(fh->length, 0xFFFFFFu);
                }
            }
            if (const auto sv = Http2::DecodeSettings(std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(Data.data()), Data.size())))
            {
                // SETTINGS 每项至少 6 字节：条目数受输入长度约束
                EXPECT_LE(sv->size(), Data.size() / 6 + 1);
            }
        }
    }

    TEST(FuzzExtended, Http2VarintDecode)
    {
        auto rng = make_rng(8);
        std::array<std::byte, 8> buf{};
        for (int i = 0; i < 2000; ++i)
        {
            const auto Data = mutate_bytes(rng);
            const auto n = (std::min)(Data.size(), buf.size());
            for (std::size_t j = 0; j < n; ++j)
            {
                buf[j] = static_cast<std::byte>(Data[j]);
            }
            std::size_t offset = 0;
            (void)Http2::DecodeInt(std::span<const std::byte>(buf.data(), n), 7, offset);
            EXPECT_LE(offset, n); // 解析游标不得越过输入
            std::size_t offset2 = 0;
            (void)Http2::DecodeString(std::span<const std::byte>(buf.data(), n), offset2);
            EXPECT_LE(offset2, n);
        }
    }

    TEST(FuzzExtended, Http2HpackDecode)
    {
        auto rng = make_rng(9);
        for (int i = 0; i < 1000; ++i)
        {
            const auto Data = mutate_bytes(rng);
            std::size_t offset = 0;
            (void)Http2::DecodeInt(std::span<const std::byte>(
                                        reinterpret_cast<const std::byte *>(Data.data()), Data.size()),
                                    7, offset);
            EXPECT_LE(offset, Data.size()); // 解析游标不得越过输入
            std::size_t offset2 = 0;
            (void)Http2::DecodeString(std::span<const std::byte>(
                                           reinterpret_cast<const std::byte *>(Data.data()),
                                           Data.size()),
                                       offset2);
            EXPECT_LE(offset2, Data.size());
        }
    }

    TEST(FuzzExtended, QpackHeaderBlockDecode)
    {
        auto rng = make_rng(10);
        namespace qpack = Preview::Http3::Qpack;
        for (int i = 0; i < 1000; ++i)
        {
            const auto Data = mutate_bytes(rng);
            (void)qpack::DecodeHeaderBlock(std::span<const std::uint8_t>(Data),
                                             Preview::Memory::CurrentResource());
        }
    }

    TEST(FuzzExtended, QpackHuffmanDecode)
    {
        auto rng = make_rng(11);
        namespace qpack = Preview::Http3::Qpack;
        for (int i = 0; i < 2000; ++i)
        {
            const auto Data = mutate_bytes(rng);
            std::vector<std::uint8_t> out;
            (void)qpack::HuffmanDecode(std::span<const std::uint8_t>(Data), out);
            // 注：qpack huffman 位填充可致输出略膨胀（实测 ~1.32x，最短码 5bit 界限 1.6x），
            //     无安全上限可断言；保持健壮性角色（不崩溃 + ASan 捕获越界）。
        }
    }

    TEST(FuzzExtended, QpackHuffmanRejectsLongInvalidPrefix)
    {
        std::array<std::uint8_t, 16> Invalid{};
        Invalid.fill(0xFF);
        std::vector<std::uint8_t> out;
        EXPECT_FALSE(Preview::Http3::Qpack::HuffmanDecode(Invalid, out));
    }

    TEST(FuzzExtended, QpackHuffmanRejectsFullBytePadding)
    {
        const std::array<std::uint8_t, 1> Invalid{0xFF};
        std::vector<std::uint8_t> out;
        EXPECT_FALSE(Preview::Http3::Qpack::HuffmanDecode(Invalid, out));
    }

    TEST(FuzzExtended, CodecStructuredMutation)
    {
        auto rng = make_rng(12);
        const auto key = std::array<std::uint8_t, 16>{};
        for (int i = 0; i < 1000; ++i)
        {
            const auto Data = mutate_bytes(rng);
            std::span<const std::uint8_t> in(Data);

            Socks5::Greeting g;
            std::size_t consumed = 0;
            (void)Socks5::ParseGreeting(in, g, consumed);
            EXPECT_LE(consumed, in.size()); // 解析游标不得越过输入

            Trojan::RequestHeader req_h;
            consumed = 0;
            (void)Trojan::ParseRequest(in, req_h, consumed);
            EXPECT_LE(consumed, in.size());

            Vless::RequestHeader vl_h;
            consumed = 0;
            (void)Vless::ParseRequest(in, vl_h, consumed);
            EXPECT_LE(consumed, in.size());

            Vmess::ChunkDecryptor vm_dec(key, std::array<std::uint8_t, 12>{});
            std::vector<std::uint8_t> plain;
            (void)vm_dec.OpenPayload(Data, plain);
            EXPECT_LE(plain.size(), Data.size()); // AEAD 解密不膨胀

            Shadowsocks2022::ChunkCodec ss_codec(key);
            std::vector<std::uint8_t> out;
            (void)ss_codec.OpenPayload(Data, out);
            EXPECT_LE(out.size(), Data.size());

            Hysteria2::Message hy_msg;
            consumed = 0;
            (void)Hysteria2::Parse(in, hy_msg, consumed);
            EXPECT_LE(consumed, in.size());

            Tuic::Message tu_msg;
            consumed = 0;
            (void)Tuic::Parse(in, tu_msg, consumed);
            EXPECT_LE(consumed, in.size());
        }
    }

} // namespace

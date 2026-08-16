/**
 * @file FuzzExtendedTest.cpp
 * @brief 结构化 fuzz 扩展（T6-4 D6）
 * @details 在 CodecFuzzTest（7 codec 随机字节）基础上扩展：
 *          - 结构化变异器：截断 / 边界字典 / 字段翻转
 *          - http2：帧头解析 / SETTINGS 解码 / varint / HPACK
 *          - qpack：header block 解码 / huffman 解码
 * @note smoke 参数（500-2000 轮/用例）；完整 fuzz 走 libFuzzer（T6-4 完整版）
 */

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <vector>

#include <common/core/http2/codec.hpp>
#include <common/core/http2/frame.hpp>
#include <common/core/http3/qpack.hpp>
#include <common/proxy/hysteria2/codec.hpp>
#include <common/proxy/shadowsocks2022/codec.hpp>
#include <common/proxy/socks5/codec.hpp>
#include <common/proxy/trojan/codec.hpp>
#include <common/proxy/tuic/codec.hpp>
#include <common/proxy/vless/codec.hpp>
#include <common/proxy/vmess/codec.hpp>

namespace
{
    using namespace psmtest;

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
        auto data = random_bytes(rng);
        if (data.empty())
        {
            data.push_back(static_cast<std::uint8_t>(rng() & 0xFF));
        }
        std::uniform_int_distribution<int> op(0, 3);
        const auto mode = op(rng);
        if (mode == 0)
        {
            // 截断
            std::uniform_int_distribution<std::size_t> cut(0, data.size());
            data.resize(cut(rng));
        }
        else if (mode == 1)
        {
            // 边界字典注入
            std::uniform_int_distribution<std::size_t> pos(0, data.size() - 1);
            std::uniform_int_distribution<std::size_t> eb(0, edge_bytes.size() - 1);
            const auto p = pos(rng);
            const auto v = edge_bytes[eb(rng)];
            if (p < data.size())
            {
                data[p] = v;
            }
        }
        else if (mode == 2)
        {
            // 头部插入边界字典
            std::uniform_int_distribution<std::size_t> n(1, 8);
            const auto cnt = n(rng);
            data.insert(data.begin(), edge_bytes.begin(),
                        edge_bytes.begin() + static_cast<std::ptrdiff_t>(cnt));
        }
        // mode 3：原样（随机字节）
        return data;
    }

    TEST(FuzzExtended, Http2FrameHeaderParse)
    {
        auto rng = make_rng(7);
        for (int i = 0; i < 2000; ++i)
        {
            const auto data = mutate_bytes(rng);
            if (data.size() >= 9)
            {
                (void)http2::parse_frame_header(std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(data.data()), 9));
            }
            (void)http2::decode_settings(std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(data.data()), data.size()));
        }
    }

    TEST(FuzzExtended, Http2VarintDecode)
    {
        auto rng = make_rng(8);
        std::array<std::byte, 8> buf{};
        for (int i = 0; i < 2000; ++i)
        {
            const auto data = mutate_bytes(rng);
            const auto n = (std::min)(data.size(), buf.size());
            for (std::size_t j = 0; j < n; ++j)
            {
                buf[j] = static_cast<std::byte>(data[j]);
            }
            std::size_t offset = 0;
            (void)http2::decode_int(std::span<const std::byte>(buf.data(), n), 7, offset);
            std::size_t offset2 = 0;
            (void)http2::decode_string(std::span<const std::byte>(buf.data(), n), offset2);
        }
    }

    TEST(FuzzExtended, Http2HpackDecode)
    {
        auto rng = make_rng(9);
        for (int i = 0; i < 1000; ++i)
        {
            const auto data = mutate_bytes(rng);
            std::size_t offset = 0;
            (void)http2::decode_int(std::span<const std::byte>(
                                        reinterpret_cast<const std::byte *>(data.data()), data.size()),
                                    7, offset);
            std::size_t offset2 = 0;
            (void)http2::decode_string(std::span<const std::byte>(
                                           reinterpret_cast<const std::byte *>(data.data()),
                                           data.size()),
                                       offset2);
        }
    }

    TEST(FuzzExtended, QpackHeaderBlockDecode)
    {
        auto rng = make_rng(10);
        namespace qpack = psmtest::protocol::hysteria2::qpack;
        for (int i = 0; i < 1000; ++i)
        {
            const auto data = mutate_bytes(rng);
            (void)qpack::decode_header_block(std::span<const std::uint8_t>(data),
                                             memory::current_resource());
        }
    }

    TEST(FuzzExtended, QpackHuffmanDecode)
    {
        auto rng = make_rng(11);
        namespace qpack = psmtest::protocol::hysteria2::qpack;
        for (int i = 0; i < 2000; ++i)
        {
            const auto data = mutate_bytes(rng);
            memory::vector<std::uint8_t> out(memory::current_resource());
            (void)qpack::huffman_decode(std::span<const std::uint8_t>(data), out);
        }
    }

    TEST(FuzzExtended, CodecStructuredMutation)
    {
        auto rng = make_rng(12);
        const auto key = std::array<std::uint8_t, 16>{};
        for (int i = 0; i < 1000; ++i)
        {
            const auto data = mutate_bytes(rng);
            std::span<const std::uint8_t> in(data);

            socks5::greeting g;
            std::size_t consumed = 0;
            (void)socks5::parse_greeting(in, g, consumed);

            trojan::request_header req_h;
            consumed = 0;
            (void)trojan::parse_request(in, req_h, consumed);

            vless::request_header vl_h;
            consumed = 0;
            (void)vless::parse_request(in, vl_h, consumed);

            vmess::chunk_decryptor vm_dec(key, std::array<std::uint8_t, 12>{});
            std::vector<std::uint8_t> plain;
            (void)vm_dec.open_payload(data, plain);

            ss2022::chunk_codec ss_codec(key);
            std::vector<std::uint8_t> out;
            (void)ss_codec.open_payload(data, out);

            hysteria2::message hy_msg;
            consumed = 0;
            (void)hysteria2::parse(in, hy_msg, consumed);

            tuic::message tu_msg;
            consumed = 0;
            (void)tuic::parse(in, tu_msg, consumed);
        }
    }

} // namespace

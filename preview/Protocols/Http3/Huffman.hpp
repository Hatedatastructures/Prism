/**
 * @file Huffman.hpp
 * @brief HTTP/3 QPACK 的 RFC 7541 Huffman 表与编解码辅助
 * @details 只负责静态 Huffman 编码、解码和定长缓冲路径；QPACK
 *          静态表、字段解析和字段编码仍由 Qpack.hpp 负责。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace Preview::Http3::Qpack::Detail
{

    /// HPACK huffman 编码表（RFC 7541 附录 B）
    constexpr std::array<std::uint32_t, 256> HuffmanCodes = {
        0x1ff8,    0x7fffd8,  0xfffffe2,  0xfffffe3, 0xfffffe4, 0xfffffe5,  0xfffffe6,  0xfffffe7,
        0xfffffe8, 0xffffea,  0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb,  0xfffffec,
        0xfffffed, 0xfffffee, 0xfffffef,  0xffffff0, 0xffffff1, 0xffffff2,  0x3ffffffe, 0xffffff3,
        0xffffff4, 0xffffff5, 0xffffff6,  0xffffff7, 0xffffff8, 0xffffff9,  0xffffffa,  0xffffffb,
        0x14,      0x3f8,     0x3f9,      0xffa,     0x1ff9,    0x15,       0xf8,       0x7fa,
        0x3fa,     0x3fb,     0xf9,       0x7fb,     0xfa,      0x16,       0x17,       0x18,
        0x0,       0x1,       0x2,        0x19,      0x1a,      0x1b,       0x1c,       0x1d,
        0x1e,      0x1f,      0x5c,       0xfb,      0x7ffc,    0x20,       0xffb,      0x3fc,
        0x1ffa,    0x21,      0x5d,       0x5e,      0x5f,      0x60,       0x61,       0x62,
        0x63,      0x64,      0x65,       0x66,      0x67,      0x68,       0x69,       0x6a,
        0x6b,      0x6c,      0x6d,       0x6e,      0x6f,      0x70,       0x71,       0x72,
        0xfc,      0x73,      0xfd,       0x1ffb,    0x7fff0,   0x1ffc,     0x3ffc,     0x22,
        0x7ffd,    0x3,       0x23,       0x4,       0x24,      0x5,        0x25,       0x26,
        0x27,      0x6,       0x74,       0x75,      0x28,      0x29,       0x2a,       0x7,
        0x2b,      0x76,      0x2c,       0x8,       0x9,       0x2d,       0x77,       0x78,
        0x79,      0x7a,      0x7b,       0x7ffe,    0x7fc,     0x3ffd,     0x1ffd,     0xffffffc,
        0xfffe6,   0x3fffd2,  0xfffe7,    0xfffe8,   0x3fffd3,  0x3fffd4,   0x3fffd5,   0x7fffd9,
        0x3fffd6,  0x7fffda,  0x7fffdb,   0x7fffdc,  0x7fffdd,  0x7fffde,   0xffffeb,   0x7fffdf,
        0xffffec,  0xffffed,  0x3fffd7,   0x7fffe0,  0xffffee,  0x7fffe1,   0x7fffe2,   0x7fffe3,
        0x7fffe4,  0x1fffdc,  0x3fffd8,   0x7fffe5,  0x3fffd9,  0x7fffe6,   0x7fffe7,   0xffffef,
        0x3fffda,  0x1fffdd,  0xfffe9,    0x3fffdb,  0x3fffdc,  0x7fffe8,   0x7fffe9,   0x1fffde,
        0x7fffea,  0x3fffdd,  0x3fffde,   0xfffff0,  0x1fffdf,  0x3fffdf,   0x7fffeb,   0x7fffec,
        0x1fffe0,  0x1fffe1,  0x3fffe0,   0x1fffe2,  0x7fffed,  0x3fffe1,   0x7fffee,   0x7fffef,
        0xfffea,   0x3fffe2,  0x3fffe3,   0x3fffe4,  0x7ffff0,  0x3fffe5,   0x3fffe6,   0x7ffff1,
        0x3ffffe0, 0x3ffffe1, 0xfffeb,    0x7fff1,   0x3fffe7,  0x7ffff2,   0x3fffe8,   0x1ffffec,
        0x3ffffe2, 0x3ffffe3, 0x3ffffe4,  0x7ffffde, 0x7ffffdf, 0x3ffffe5,  0xfffff1,   0x1ffffed,
        0x7fff2,   0x1fffe3,  0x3ffffe6,  0x7ffffe0, 0x7ffffe1, 0x3ffffe7,  0x7ffffe2,  0xfffff2,
        0x1fffe4,  0x1fffe5,  0x3ffffe8,  0x3ffffe9, 0xffffffd, 0x7ffffe3,  0x7ffffe4,  0x7ffffe5,
        0xfffec,   0xfffff3,  0xfffed,    0x1fffe6,  0x3fffe9,  0x1fffe7,   0x1fffe8,   0x7ffff3,
        0x3fffea,  0x3fffeb,  0x1ffffee,  0x1ffffef, 0xfffff4,  0xfffff5,   0x3ffffea,  0x7ffff4,
        0x3ffffeb, 0x7ffffe6, 0x3ffffec,  0x3ffffed, 0x7ffffe7, 0x7ffffe8,  0x7ffffe9,  0x7ffffea,
        0x7ffffeb, 0xffffffe, 0x7ffffec,  0x7ffffed, 0x7ffffee, 0x7ffffef,  0x7fffff0,  0x3ffffee};

    /// HPACK huffman 码长表（RFC 7541 附录 B）
    constexpr std::array<std::uint8_t, 256> HuffmanLens = {
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
        28, 28, 28, 28, 28, 28, 28, 28, 6,  10, 10, 12, 13, 6,  8,  11, 10, 10, 8,  11, 8,  6,  6,  6,
        5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8,  15, 6,  12, 10, 13, 6,  7,  7,  7,  7,  7,  7,
        7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8,  13, 19, 13, 14, 6,
        15, 5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,  6,  7,  6,  5,  5,  6,  7,  7,
        7,  7,  7,  15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23, 21,
        23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24,
        21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
         26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26};

    /// HPACK huffman 快速查表：len ≤ 8 的符号按 (len, Code) 直接命中，O(1) 解码
    /// 构建方式：对每个符号（len ≤ 8），在对应 len 表中 Code 位置写入符号索引
    constexpr auto BuildHuffmanLookup() -> std::array<std::array<std::int16_t, 256>, 9>
    {
        std::array<std::array<std::int16_t, 256>, 9> tbl{};
        for (auto &row : tbl)
        {
            row.fill(-1);
        }
        for (std::uint16_t Sym = 0; Sym < 256; ++Sym)
        {
            const auto Len = HuffmanLens[Sym];
            if (Len <= 8)
            {
                tbl[Len][static_cast<std::size_t>(HuffmanCodes[Sym])] = static_cast<std::int16_t>(Sym);
            }
        }
        return tbl;
    }
    constexpr auto HuffmanLookup = BuildHuffmanLookup();

    /// 快速 huffman 符号解码：len ≤ 8 查表，否则线性扫描
    [[nodiscard]] inline auto HuffmanFindSym(const std::uint32_t Code, const std::uint16_t Len)
        -> std::int16_t
    {
        if (Len <= 8)
        {
            return HuffmanLookup[Len][Code & 0xFF];
        }
        for (std::uint16_t Sym = 0; Sym < 256; ++Sym)
        {
            if (HuffmanLens[Sym] == Len && HuffmanCodes[Sym] == Code)
            {
                return static_cast<std::int16_t>(Sym);
            }
        }
        return -1;
    }


    /**
     * @brief huffman 解码：位累积式查表（RFC 7541 附录 B，MSB 优先）
     * @param in 编码后的字节序列
     * @param out 解码结果
     * @return 是否解码成功
     */
    [[nodiscard]] auto HuffmanDecodeImpl(std::span<const std::uint8_t> in,
                                           std::vector<std::uint8_t> &out) -> bool
    {
        std::uint64_t Acc = 0;
        std::uint32_t AccBits = 0;
        for (const auto B : in)
        {
            Acc = (Acc << 8) | B;
            AccBits += 8;
            // 每读入一字节即尝试从高位匹配最短符号
            while (AccBits > 0)
            {
                bool Matched = false;
                for (std::uint16_t Len = 1; Len <= AccBits && Len <= 30; ++Len)
                {
                    const std::uint64_t Mask = (1ULL << Len) - 1;
                    const auto Code = static_cast<std::uint32_t>((Acc >> (AccBits - Len)) & Mask);
                    const auto Sym = HuffmanFindSym(Code, Len);
                    if (Sym >= 0)
                    {
                        out.push_back(static_cast<std::uint8_t>(Sym));
                        AccBits -= Len;
                        Matched = true;
                        break;
                    }
                }
                if (!Matched)
                {
                    if (AccBits > 30)
                    {
                        return false;
                    }
                    break; // 数据不足，等待更多字节
                }
            }
        }
        // 剩余位数：RFC 7541 5.2 要求以 1 填充（EOS 前缀），0 位时无需校验
        if (AccBits > 0)
        {
            if (AccBits > 7)
            {
                return false;
            }
            std::uint64_t Mask = 0;
            if (AccBits >= 64)
            {
                Mask = ~0ULL;
            }
            else
            {
                Mask = ((1ULL << AccBits) - 1);
            }
            if ((Acc & Mask) != Mask)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief huffman 解码到定长缓冲（热路径零分配版本）
     * @param in 编码字节
     * @param out 栈缓冲
     * @param OutN 输出字节数
     * @return 是否解码成功
     * @note 与 HuffmanDecodeImpl 逻辑一致，但写入固定 span 避免堆分配
     */
    [[nodiscard]] auto HuffmanDecodeTo(std::span<const std::uint8_t> in,
                                         const std::span<std::uint8_t> out,
                                         std::size_t &OutN) -> bool
    {
        std::uint64_t Acc = 0;
        std::uint32_t AccBits = 0;
        OutN = 0;
        for (const auto B : in)
        {
            Acc = (Acc << 8) | B;
            AccBits += 8;
            while (AccBits > 0)
            {
                bool Matched = false;
                for (std::uint16_t Len = 1; Len <= AccBits && Len <= 30; ++Len)
                {
                    const std::uint64_t Mask = (1ULL << Len) - 1;
                    const auto Code = static_cast<std::uint32_t>((Acc >> (AccBits - Len)) & Mask);
                    const auto Sym = HuffmanFindSym(Code, Len);
                    if (Sym >= 0)
                    {
                        if (OutN >= out.size())
                        {
                            return false;
                        }
                        out[OutN++] = static_cast<std::uint8_t>(Sym);
                        AccBits -= Len;
                        Matched = true;
                        break;
                    }
                }
                if (!Matched)
                {
                    if (AccBits > 30)
                    {
                        return false;
                    }
                    break;
                }
            }
        }
        if (AccBits > 0)
        {
            if (AccBits > 7)
            {
                return false;
            }
            std::uint64_t Mask = 0;
            if (AccBits >= 64)
            {
                Mask = ~0ULL;
            }
            else
            {
                Mask = ((1ULL << AccBits) - 1);
            }
            if ((Acc & Mask) != Mask)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @brief huffman 编码到定长缓冲（MSB 优先，RFC 7541 附录 B）
     * @param in 待编码的字符串
     * @param out 输出缓冲
     * @return 编码字节数；缓冲不足返回 0
     * @note 最坏膨胀 30 bit/符号 ≈ 4 B/字符，调用方预留 in.size()*4
     *       字节即可保证不失败（热路径栈缓冲零分配）
     */
    [[nodiscard]] auto HuffmanEncodeTo(std::string_view in, std::span<std::uint8_t> out)
        -> std::size_t
    {
        std::uint64_t Acc = 0;
        std::uint32_t AccBits = 0;
        std::size_t N = 0;
        for (const auto c : in)
        {
            const auto Sym = static_cast<std::uint8_t>(c);
            const auto Len = HuffmanLens[Sym];
            Acc = (Acc << Len) | HuffmanCodes[Sym];
            AccBits += Len;
            // 防止 64 位溢出：累积超 32 位即冲刷整字节
            while (AccBits >= 8)
            {
                if (N >= out.size())
                {
                    return 0;
                }
                out[N++] = static_cast<std::uint8_t>(Acc >> (AccBits - 8));
                AccBits -= 8;
            }
        }
        // 尾部不足 8 位：高位补 1 填充（RFC 7541 5.2 EOS 前缀）
        if (AccBits > 0)
        {
            if (N >= out.size())
            {
                return 0;
            }
            const auto Pad = 8 - AccBits;
            out[N++] = static_cast<std::uint8_t>((Acc << Pad) | (0xFFU >> AccBits));
        }
        return N;
    }

    /**
     * @brief huffman 编码：按符号输出码字（MSB 优先，RFC 7541 附录 B）
     * @param in 待编码的字符串
     * @param out 编码结果
     * @return 是否编码成功
     */
    [[nodiscard]] auto HuffmanEncodeImpl(std::string_view in, std::vector<std::uint8_t> &out) -> bool
    {
        std::uint64_t Acc = 0;
        std::uint32_t AccBits = 0;
        for (const auto c : in)
        {
            const auto Sym = static_cast<std::uint8_t>(c);
            const auto Len = HuffmanLens[Sym];
            Acc = (Acc << Len) | HuffmanCodes[Sym];
            AccBits += Len;
            // 防止 64 位溢出：累积超 32 位即冲刷整字节
            while (AccBits >= 8)
            {
                out.push_back(static_cast<std::uint8_t>(Acc >> (AccBits - 8)));
                AccBits -= 8;
            }
        }
        // 尾部不足 8 位：高位补 1 填充（RFC 7541 5.2 EOS 前缀）
        if (AccBits > 0)
        {
            const auto Over = AccBits;
            const auto Pad = 8 - Over;
            const std::uint8_t EosPadByte = 0xFF; // EOS 0x3fffffff 的最高 8 位
            Acc = (Acc << Pad) | (EosPadByte >> Over);
            out.push_back(static_cast<std::uint8_t>(Acc));
        }
        return true;
    }


} // namespace Preview::Http3::Qpack::Detail

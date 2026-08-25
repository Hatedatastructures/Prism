/**
 * @file qpack.hpp
 * @brief QPACK 头压缩编解码（RFC 9204 静态表 + HPACK huffman）
 * @details 实现 Hysteria2 HTTP/3 认证所需的 QPACK 解码/编码：
 *          1. 静态表 99 项（RFC 9204 附录 A）
 *          2. HPACK huffman 编解码（RFC 7541 附录 B，257 符号）
 *          3. 无动态表（mihomo 客户端 qpack 实现同样无动态表）
 *          4. 编码器静态表查找（对照 Go metacubex/qpack encoderMap）：
 *             值命中走索引字段，名称命中走名称引用，未命中走字面量；
 *             热路径栈缓冲零堆分配
 *          仅支持认证请求的 HEADERS 帧解析，不做通用 HTTP/3 处理。
 *          Header-only：所有实现 inline，测试库独立链接不依赖主库。
 */

#pragma once

#include <common/Core/Memory/Container.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace Preview::Http3::Qpack
{

    /**
     * @struct HeaderField
     * @brief 解码出的头字段
     */
    struct HeaderField
    {
        // std::string 带 SSO（小字符串内联，≤15 字节零堆分配）：
        // QPACK 头字段名/值多为短字符串，热路径避免 PMR 分配
        std::string Name;
        std::string value;
    };

    /**
     * @brief 解码一个 QPACK 头块
     * @param Data 编码数据（不含 HTTP/3 帧头，仅 QPACK 块）
     * @param mr 内存资源
     * @return 解码出的头字段列表；失败返回空（无法区分空与失败，
     *         调用方应结合编码格式校验）
     * @details 仅支持静态表索引与字面量（无动态表），与 mihomo
     *          metacubex/qpack 客户端编码器对应。
     */
    [[nodiscard]] auto DecodeHeaderBlock(std::span<const std::uint8_t> Data, Preview::Memory::ResourcePointer mr)
        -> std::vector<HeaderField>;

    /**
     * @brief 编码一个头字段为 QPACK 字段表示
     * @param Name 字段名
     * @param value 字段值
     * @param out 输出缓冲区
     * @return 写入字节数；失败返回 0
     * @details 三分支编码（对照 Go metacubex/qpack 编码器）：
     *          1. 静态表值命中 → 索引字段（1Txxxxxx，1 字节）
     *          2. 静态表名称命中、值不同 → 名称引用字面量（01Nxxxxx，免名称 huffman）
     *          3. 未命中 → 字面量无名称引用（001xxxxx，huffman 编码）
     *          热路径零堆分配：≤63 字符走栈缓冲，超长回退堆。
     */
    [[nodiscard]] auto EncodeLiteral(std::string_view Name, std::string_view value,
                                      std::span<std::uint8_t> out) -> std::size_t;

    /**
     * @brief 编码 QPACK 头块前缀（Required Insert Count=0, Delta Base=0）
     * @param out 输出缓冲区
     * @return 写入字节数
     */
    [[nodiscard]] auto EncodePrefix(std::span<std::uint8_t> out) -> std::size_t;

    /**
     * @brief HPACK huffman 解码
     * @param in 编码数据
     * @param out 解码输出
     * @return 是否成功
     */
    [[nodiscard]] auto HuffmanDecode(std::span<const std::uint8_t> in, std::vector<std::uint8_t> &out)
        -> bool;

    /**
     * @brief HPACK huffman 编码
     * @param in 明文数据
     * @param out 编码输出
     * @return 是否成功
     */
    [[nodiscard]] auto HuffmanEncode(std::string_view in, std::vector<std::uint8_t> &out) -> bool;

    namespace
    {
        /**
         * @brief varint 解码（HPACK/QPACK 通用格式）
         * @param in 输入字节序列
         * @param prefix_bits 前缀位宽
         * @param value 解码结果
         * @param consumed 消耗的字节数
         * @return 是否解码成功
         */
        [[nodiscard]] auto ReadVarint(std::span<const std::uint8_t> in, std::uint8_t prefix_bits,
                                       std::uint64_t &value, std::size_t &consumed) -> bool
        {
            if (in.empty())
            {
                return false;
            }
            const std::uint64_t PrefixMask = (1ULL << prefix_bits) - 1;
            std::uint64_t v = in[0] & PrefixMask;
            std::size_t offset = 1;
            if (v < PrefixMask)
            {
                value = v;
                consumed = offset;
                return true;
            }
            std::uint64_t shift = 0;
            while (offset < in.size())
            {
                const auto b = in[offset++];
                v += static_cast<std::uint64_t>(b & 0x7F) << shift;
                if ((b & 0x80) == 0)
                {
                    value = v;
                    consumed = offset;
                    return true;
                }
                shift += 7;
                if (shift >= 63)
                {
                    return false;
                }
            }
            return false;
        }

        /**
         * @brief varint 编码（前缀位保留）
         * @param out 输出缓冲区
         * @param prefix_bits 前缀位宽
         * @param value 待编码的值
         * @param prefix_pattern 前缀模式
         * @return 写入的字节数，失败返回 0
         */
        [[nodiscard]] auto WriteVarint(std::span<std::uint8_t> out, std::uint8_t prefix_bits,
                                        const std::uint64_t value, std::uint8_t prefix_pattern)
            -> std::size_t
        {
            const std::uint64_t PrefixMask = (1ULL << prefix_bits) - 1;
            std::size_t n = 0;
            if (value < PrefixMask)
            {
                if (out.size() < 1)
                {
                    return 0;
                }
                out[0] = static_cast<std::uint8_t>(prefix_pattern | value);
                return 1;
            }
            if (out.size() < 1)
            {
                return 0;
            }
            out[0] = static_cast<std::uint8_t>(prefix_pattern | PrefixMask);
            n = 1;
            auto rest = value - PrefixMask;
            while (rest >= 128)
            {
                if (out.size() <= n)
                {
                    return 0;
                }
                out[n++] = static_cast<std::uint8_t>((rest & 0x7F) | 0x80);
                rest >>= 7;
            }
            if (out.size() <= n)
            {
                return 0;
            }
            out[n++] = static_cast<std::uint8_t>(rest);
            return n;
        }

        /// HPACK huffman 编码表（RFC 7541 附录 B）
        constexpr std::array<std::uint32_t, 256> huffman_codes = {
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
        constexpr std::array<std::uint8_t, 256> huffman_lens = {
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
            for (std::uint16_t sym = 0; sym < 256; ++sym)
            {
                const auto len = huffman_lens[sym];
                if (len <= 8)
                {
                    tbl[len][static_cast<std::size_t>(huffman_codes[sym])] = static_cast<std::int16_t>(sym);
                }
            }
            return tbl;
        }
        constexpr auto HuffmanLookup = BuildHuffmanLookup();

        /// 快速 huffman 符号解码：len ≤ 8 查表，否则线性扫描
        [[nodiscard]] inline auto HuffmanFindSym(const std::uint32_t Code, const std::uint16_t len)
            -> std::int16_t
        {
            if (len <= 8)
            {
                return HuffmanLookup[len][Code & 0xFF];
            }
            for (std::uint16_t sym = 0; sym < 256; ++sym)
            {
                if (huffman_lens[sym] == len && huffman_codes[sym] == Code)
                {
                    return static_cast<std::int16_t>(sym);
                }
            }
            return -1;
        }

        /// QPACK 静态表（RFC 9204 附录 A，99 项）
        struct StaticEntry
        {
            std::string_view Name;
            std::string_view value;
        };

        constexpr std::array<StaticEntry, 99> static_table = {
            StaticEntry{":authority", ""},
            StaticEntry{":Path", "/"},
            StaticEntry{"age", "0"},
            StaticEntry{"content-disposition", ""},
            StaticEntry{"content-length", "0"},
            StaticEntry{"cookie", ""},
            StaticEntry{"date", ""},
            StaticEntry{"etag", ""},
            StaticEntry{"if-modified-since", ""},
            StaticEntry{"if-none-match", ""},
            StaticEntry{"last-modified", ""},
            StaticEntry{"link", ""},
            StaticEntry{"Location", ""},
            StaticEntry{"referer", ""},
            StaticEntry{"set-cookie", ""},
            StaticEntry{":Method", "CONNECT"},
            StaticEntry{":Method", "DELETE"},
            StaticEntry{":Method", "GET"},
            StaticEntry{":Method", "HEAD"},
            StaticEntry{":Method", "OPTIONS"},
            StaticEntry{":Method", "POST"},
            StaticEntry{":Method", "PUT"},
            StaticEntry{":scheme", "http"},
            StaticEntry{":scheme", "https"},
            StaticEntry{":status", "103"},
            StaticEntry{":status", "200"},
            StaticEntry{":status", "304"},
            StaticEntry{":status", "404"},
            StaticEntry{":status", "503"},
            StaticEntry{"Accept", "*/*"},
            StaticEntry{"Accept", "application/dns-Message"},
            StaticEntry{"Accept-encoding", "gzip, deflate, br"},
            StaticEntry{"Accept-ranges", "Bytes"},
            StaticEntry{"Access-control-allow-headers", "cache-control"},
            StaticEntry{"Access-control-allow-headers", "content-Type"},
            StaticEntry{"Access-control-allow-origin", "*"},
            StaticEntry{"cache-control", "max-age=0"},
            StaticEntry{"cache-control", "max-age=2592000"},
            StaticEntry{"cache-control", "max-age=604800"},
            StaticEntry{"cache-control", "no-cache"},
            StaticEntry{"cache-control", "no-store"},
            StaticEntry{"cache-control", "public, max-age=31536000"},
            StaticEntry{"content-encoding", "br"},
            StaticEntry{"content-encoding", "gzip"},
            StaticEntry{"content-Type", "application/dns-Message"},
            StaticEntry{"content-Type", "application/javascript"},
            StaticEntry{"content-Type", "application/json"},
            StaticEntry{"content-Type", "application/x-www-Form-urlencoded"},
            StaticEntry{"content-Type", "image/gif"},
            StaticEntry{"content-Type", "image/jpeg"},
            StaticEntry{"content-Type", "image/png"},
            StaticEntry{"content-Type", "text/css"},
            StaticEntry{"content-Type", "text/html; charset=utf-8"},
            StaticEntry{"content-Type", "text/plain"},
            StaticEntry{"content-Type", "text/plain;charset=utf-8"},
            StaticEntry{"range", "Bytes=0-"},
            StaticEntry{"strict-transport-Security", "max-age=31536000"},
            StaticEntry{"strict-transport-Security", "max-age=31536000; includesubdomains"},
            StaticEntry{"strict-transport-Security", "max-age=31536000; includesubdomains; preload"},
            StaticEntry{"vary", "Accept-encoding"},
            StaticEntry{"vary", "origin"},
            StaticEntry{"x-content-Type-Options", "nosniff"},
            StaticEntry{"x-xss-protection", "1; mode=block"},
            StaticEntry{":status", "100"},
            StaticEntry{":status", "204"},
            StaticEntry{":status", "206"},
            StaticEntry{":status", "302"},
            StaticEntry{":status", "400"},
            StaticEntry{":status", "403"},
            StaticEntry{":status", "421"},
            StaticEntry{":status", "425"},
            StaticEntry{":status", "500"},
            StaticEntry{"Accept-language", ""},
            StaticEntry{"Access-control-allow-credentials", "FALSE"},
            StaticEntry{"Access-control-allow-credentials", "TRUE"},
            StaticEntry{"Access-control-allow-headers", "*"},
            StaticEntry{"Access-control-allow-methods", "Get"},
            StaticEntry{"Access-control-allow-methods", "Get, post, Options"},
            StaticEntry{"Access-control-allow-methods", "Options"},
            StaticEntry{"Access-control-expose-headers", "content-length"},
            StaticEntry{"Access-control-Request-headers", "content-Type"},
            StaticEntry{"Access-control-Request-Method", "Get"},
            StaticEntry{"Access-control-Request-Method", "post"},
            StaticEntry{"alt-svc", "Clear"},
            StaticEntry{"authorization", ""},
            StaticEntry{"content-Security-Policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
            StaticEntry{"early-Data", "1"},
            StaticEntry{"Expect-ct", ""},
            StaticEntry{"forwarded", ""},
            StaticEntry{"if-range", ""},
            StaticEntry{"origin", ""},
            StaticEntry{"purpose", "prefetch"},
            StaticEntry{"Server", ""},
            StaticEntry{"timing-allow-origin", "*"},
            StaticEntry{"upgrade-insecure-requests", "1"},
            StaticEntry{"user-agent", ""},
            StaticEntry{"x-forwarded-for", ""},
            StaticEntry{"x-Frame-Options", "deny"},
            StaticEntry{"x-Frame-Options", "sameorigin"},
        };

        /// 编码器值条目（名称 → 值 → 静态表索引）
        struct EncoderValueEntry
        {
            std::string_view value;
            std::uint8_t index;
        };

        /// 编码器名称条目（对应 Go metacubex/qpack 的 encoderMap）
        struct EncoderNameEntry
        {
            std::string_view Name;
            std::uint8_t FirstIndex;   // 名称引用编码的基准索引（该名称首个静态表条目）
            std::uint16_t ValueOffset; // 值条目在 encoder_values 中的偏移
            std::uint8_t ValueCount;   // 值条目数量（0 = 该名称仅有空值条目）
        };

        /// 编码器值条目表（按 encoder_names 同名顺序排列）
        constexpr std::array<EncoderValueEntry, 78> encoder_values = {
            // :Method（索引 15-21）
            EncoderValueEntry{"CONNECT", 15},
            EncoderValueEntry{"DELETE", 16},
            EncoderValueEntry{"GET", 17},
            EncoderValueEntry{"HEAD", 18},
            EncoderValueEntry{"OPTIONS", 19},
            EncoderValueEntry{"POST", 20},
            EncoderValueEntry{"PUT", 21},
            // :Path（索引 1）
            EncoderValueEntry{"/", 1},
            // :status（索引 24-28 与 63-71，非连续）
            EncoderValueEntry{"103", 24},
            EncoderValueEntry{"200", 25},
            EncoderValueEntry{"304", 26},
            EncoderValueEntry{"404", 27},
            EncoderValueEntry{"503", 28},
            EncoderValueEntry{"100", 63},
            EncoderValueEntry{"204", 64},
            EncoderValueEntry{"206", 65},
            EncoderValueEntry{"302", 66},
            EncoderValueEntry{"400", 67},
            EncoderValueEntry{"403", 68},
            EncoderValueEntry{"421", 69},
            EncoderValueEntry{"425", 70},
            EncoderValueEntry{"500", 71},
            // :scheme（索引 22-23）
            EncoderValueEntry{"http", 22},
            EncoderValueEntry{"https", 23},
            // age（索引 2）
            EncoderValueEntry{"0", 2},
            // content-length（索引 4）
            EncoderValueEntry{"0", 4},
            // Accept（索引 29-30）
            EncoderValueEntry{"*/*", 29},
            EncoderValueEntry{"application/dns-Message", 30},
            // Accept-encoding（索引 31）
            EncoderValueEntry{"gzip, deflate, br", 31},
            // Accept-ranges（索引 32）
            EncoderValueEntry{"Bytes", 32},
            // Access-control-allow-headers（索引 33-34 与 75）
            EncoderValueEntry{"cache-control", 33},
            EncoderValueEntry{"content-Type", 34},
            EncoderValueEntry{"*", 75},
            // Access-control-allow-origin（索引 35）
            EncoderValueEntry{"*", 35},
            // cache-control（索引 36-41）
            EncoderValueEntry{"max-age=0", 36},
            EncoderValueEntry{"max-age=2592000", 37},
            EncoderValueEntry{"max-age=604800", 38},
            EncoderValueEntry{"no-cache", 39},
            EncoderValueEntry{"no-store", 40},
            EncoderValueEntry{"public, max-age=31536000", 41},
            // content-encoding（索引 42-43）
            EncoderValueEntry{"br", 42},
            EncoderValueEntry{"gzip", 43},
            // content-Type（索引 44-54）
            EncoderValueEntry{"application/dns-Message", 44},
            EncoderValueEntry{"application/javascript", 45},
            EncoderValueEntry{"application/json", 46},
            EncoderValueEntry{"application/x-www-Form-urlencoded", 47},
            EncoderValueEntry{"image/gif", 48},
            EncoderValueEntry{"image/jpeg", 49},
            EncoderValueEntry{"image/png", 50},
            EncoderValueEntry{"text/css", 51},
            EncoderValueEntry{"text/html; charset=utf-8", 52},
            EncoderValueEntry{"text/plain", 53},
            EncoderValueEntry{"text/plain;charset=utf-8", 54},
            // range（索引 55）
            EncoderValueEntry{"Bytes=0-", 55},
            // strict-transport-Security（索引 56-58）
            EncoderValueEntry{"max-age=31536000", 56},
            EncoderValueEntry{"max-age=31536000; includesubdomains", 57},
            EncoderValueEntry{"max-age=31536000; includesubdomains; preload", 58},
            // vary（索引 59-60）
            EncoderValueEntry{"Accept-encoding", 59},
            EncoderValueEntry{"origin", 60},
            // x-content-Type-Options（索引 61）
            EncoderValueEntry{"nosniff", 61},
            // x-xss-protection（索引 62）
            EncoderValueEntry{"1; mode=block", 62},
            // Access-control-allow-credentials（索引 73-74）
            EncoderValueEntry{"FALSE", 73},
            EncoderValueEntry{"TRUE", 74},
            // Access-control-allow-methods（索引 76-78）
            EncoderValueEntry{"Get", 76},
            EncoderValueEntry{"Get, post, Options", 77},
            EncoderValueEntry{"Options", 78},
            // Access-control-expose-headers（索引 79）
            EncoderValueEntry{"content-length", 79},
            // Access-control-Request-headers（索引 80）
            EncoderValueEntry{"content-Type", 80},
            // Access-control-Request-Method（索引 81-82）
            EncoderValueEntry{"Get", 81},
            EncoderValueEntry{"post", 82},
            // alt-svc（索引 83）
            EncoderValueEntry{"Clear", 83},
            // content-Security-Policy（索引 85）
            EncoderValueEntry{"script-src 'none'; object-src 'none'; base-uri 'none'", 85},
            // early-Data（索引 86）
            EncoderValueEntry{"1", 86},
            // purpose（索引 91）
            EncoderValueEntry{"prefetch", 91},
            // timing-allow-origin（索引 93）
            EncoderValueEntry{"*", 93},
            // upgrade-insecure-requests（索引 94）
            EncoderValueEntry{"1", 94},
            // x-Frame-Options（索引 97-98）
            EncoderValueEntry{"deny", 97},
            EncoderValueEntry{"sameorigin", 98},
        };

        /// 编码器名称表（热路径名称靠前，线性扫描命中快）
        constexpr std::array<EncoderNameEntry, 52> encoder_names = {
            EncoderNameEntry{":Method", 15, 0, 7},
            EncoderNameEntry{":Path", 1, 7, 1},
            EncoderNameEntry{":status", 24, 8, 14},
            EncoderNameEntry{":scheme", 22, 22, 2},
            EncoderNameEntry{":authority", 0, 24, 0},
            EncoderNameEntry{"age", 2, 24, 1},
            EncoderNameEntry{"content-disposition", 3, 25, 0},
            EncoderNameEntry{"content-length", 4, 25, 1},
            EncoderNameEntry{"cookie", 5, 26, 0},
            EncoderNameEntry{"date", 6, 26, 0},
            EncoderNameEntry{"etag", 7, 26, 0},
            EncoderNameEntry{"if-modified-since", 8, 26, 0},
            EncoderNameEntry{"if-none-match", 9, 26, 0},
            EncoderNameEntry{"last-modified", 10, 26, 0},
            EncoderNameEntry{"link", 11, 26, 0},
            EncoderNameEntry{"Location", 12, 26, 0},
            EncoderNameEntry{"referer", 13, 26, 0},
            EncoderNameEntry{"set-cookie", 14, 26, 0},
            EncoderNameEntry{"Accept", 29, 26, 2},
            EncoderNameEntry{"Accept-encoding", 31, 28, 1},
            EncoderNameEntry{"Accept-ranges", 32, 29, 1},
            EncoderNameEntry{"Access-control-allow-headers", 33, 30, 3},
            EncoderNameEntry{"Access-control-allow-origin", 35, 33, 1},
            EncoderNameEntry{"cache-control", 36, 34, 6},
            EncoderNameEntry{"content-encoding", 42, 40, 2},
            EncoderNameEntry{"content-Type", 44, 42, 11},
            EncoderNameEntry{"range", 55, 53, 1},
            EncoderNameEntry{"strict-transport-Security", 56, 54, 3},
            EncoderNameEntry{"vary", 59, 57, 2},
            EncoderNameEntry{"x-content-Type-Options", 61, 59, 1},
            EncoderNameEntry{"x-xss-protection", 62, 60, 1},
            EncoderNameEntry{"Accept-language", 72, 61, 0},
            EncoderNameEntry{"Access-control-allow-credentials", 73, 61, 2},
            EncoderNameEntry{"Access-control-allow-methods", 76, 63, 3},
            EncoderNameEntry{"Access-control-expose-headers", 79, 66, 1},
            EncoderNameEntry{"Access-control-Request-headers", 80, 67, 1},
            EncoderNameEntry{"Access-control-Request-Method", 81, 68, 2},
            EncoderNameEntry{"alt-svc", 83, 70, 1},
            EncoderNameEntry{"authorization", 84, 71, 0},
            EncoderNameEntry{"content-Security-Policy", 85, 71, 1},
            EncoderNameEntry{"early-Data", 86, 72, 1},
            EncoderNameEntry{"Expect-ct", 87, 73, 0},
            EncoderNameEntry{"forwarded", 88, 73, 0},
            EncoderNameEntry{"if-range", 89, 73, 0},
            EncoderNameEntry{"origin", 90, 73, 0},
            EncoderNameEntry{"purpose", 91, 73, 1},
            EncoderNameEntry{"Server", 92, 74, 0},
            EncoderNameEntry{"timing-allow-origin", 93, 74, 1},
            EncoderNameEntry{"upgrade-insecure-requests", 94, 75, 1},
            EncoderNameEntry{"user-agent", 95, 76, 0},
            EncoderNameEntry{"x-forwarded-for", 96, 76, 0},
            EncoderNameEntry{"x-Frame-Options", 97, 76, 2},
        };

        /// 编译期校验：encoder 表与 static_table 语义一致（索引/名称/值对齐）
        constexpr auto ValidateEncoderTables() -> bool
        {
            for (const auto &Entry : encoder_names)
            {
                if (static_table[Entry.FirstIndex].Name != Entry.Name)
                {
                    return false;
                }
                for (std::size_t i = 0; i < Entry.ValueCount; ++i)
                {
                    const auto &ve = encoder_values[Entry.ValueOffset + i];
                    if (static_table[ve.index].Name != Entry.Name || static_table[ve.index].value != ve.value)
                    {
                        return false;
                    }
                }
            }
            return true;
        }
        static_assert(ValidateEncoderTables(), "encoder 表与静态表不一致");

        /**
         * @brief 静态表名称查找（编码器用）
         * @param Name 字段名
         * @return 名称条目指针；未命中返回 nullptr
         * @note 线性扫描：长度不等快速拒绝，热路径命中通常 ≤5 次迭代
         */
        [[nodiscard]] auto LookupEncoderName(std::string_view Name) -> const EncoderNameEntry *
        {
            for (const auto &Entry : encoder_names)
            {
                if (Entry.Name == Name)
                {
                    return &Entry;
                }
            }
            return nullptr;
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
            std::uint64_t acc = 0;
            std::uint32_t AccBits = 0;
            for (const auto b : in)
            {
                acc = (acc << 8) | b;
                AccBits += 8;
                // 每读入一字节即尝试从高位匹配最短符号
                while (AccBits > 0)
                {
                    bool matched = false;
                    for (std::uint16_t len = 1; len <= AccBits && len <= 30; ++len)
                    {
                        const std::uint64_t mask = (1ULL << len) - 1;
                        const auto Code = static_cast<std::uint32_t>((acc >> (AccBits - len)) & mask);
                        const auto sym = HuffmanFindSym(Code, len);
                        if (sym >= 0)
                        {
                            out.push_back(static_cast<std::uint8_t>(sym));
                            AccBits -= len;
                            matched = true;
                            break;
                        }
                    }
                    if (!matched)
                    {
                        break; // 数据不足，等待更多字节
                    }
                }
            }
            // 剩余位数：RFC 7541 5.2 要求以 1 填充（EOS 前缀），0 位时无需校验
            if (AccBits > 0)
            {
                std::uint64_t mask = 0;
                if (AccBits >= 64)
                {
                    mask = ~0ULL;
                }
                else
                {
                    mask = ((1ULL << AccBits) - 1);
                }
                if ((acc & mask) != mask)
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
            std::uint64_t acc = 0;
            std::uint32_t AccBits = 0;
            OutN = 0;
            for (const auto b : in)
            {
                acc = (acc << 8) | b;
                AccBits += 8;
                while (AccBits > 0)
                {
                    bool matched = false;
                    for (std::uint16_t len = 1; len <= AccBits && len <= 30; ++len)
                    {
                        const std::uint64_t mask = (1ULL << len) - 1;
                        const auto Code = static_cast<std::uint32_t>((acc >> (AccBits - len)) & mask);
                        const auto sym = HuffmanFindSym(Code, len);
                        if (sym >= 0)
                        {
                            if (OutN >= out.size())
                            {
                                return false;
                            }
                            out[OutN++] = static_cast<std::uint8_t>(sym);
                            AccBits -= len;
                            matched = true;
                            break;
                        }
                    }
                    if (!matched)
                    {
                        break;
                    }
                }
            }
            if (AccBits > 0)
            {
                std::uint64_t mask = 0;
                if (AccBits >= 64)
                {
                    mask = ~0ULL;
                }
                else
                {
                    mask = ((1ULL << AccBits) - 1);
                }
                if ((acc & mask) != mask)
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
            std::uint64_t acc = 0;
            std::uint32_t AccBits = 0;
            std::size_t n = 0;
            for (const auto c : in)
            {
                const auto sym = static_cast<std::uint8_t>(c);
                const auto len = huffman_lens[sym];
                acc = (acc << len) | huffman_codes[sym];
                AccBits += len;
                // 防止 64 位溢出：累积超 32 位即冲刷整字节
                while (AccBits >= 8)
                {
                    if (n >= out.size())
                    {
                        return 0;
                    }
                    out[n++] = static_cast<std::uint8_t>(acc >> (AccBits - 8));
                    AccBits -= 8;
                }
            }
            // 尾部不足 8 位：高位补 1 填充（RFC 7541 5.2 EOS 前缀）
            if (AccBits > 0)
            {
                if (n >= out.size())
                {
                    return 0;
                }
                const auto pad = 8 - AccBits;
                out[n++] = static_cast<std::uint8_t>((acc << pad) | (0xFFU >> AccBits));
            }
            return n;
        }

        /**
         * @brief huffman 编码：按符号输出码字（MSB 优先，RFC 7541 附录 B）
         * @param in 待编码的字符串
         * @param out 编码结果
         * @return 是否编码成功
         */
        [[nodiscard]] auto HuffmanEncodeImpl(std::string_view in, std::vector<std::uint8_t> &out) -> bool
        {
            std::uint64_t acc = 0;
            std::uint32_t AccBits = 0;
            for (const auto c : in)
            {
                const auto sym = static_cast<std::uint8_t>(c);
                const auto len = huffman_lens[sym];
                acc = (acc << len) | huffman_codes[sym];
                AccBits += len;
                // 防止 64 位溢出：累积超 32 位即冲刷整字节
                while (AccBits >= 8)
                {
                    out.push_back(static_cast<std::uint8_t>(acc >> (AccBits - 8)));
                    AccBits -= 8;
                }
            }
            // 尾部不足 8 位：高位补 1 填充（RFC 7541 5.2 EOS 前缀）
            if (AccBits > 0)
            {
                const auto over = AccBits;
                const auto pad = 8 - over;
                const std::uint8_t EosPadByte = 0xFF; // EOS 0x3fffffff 的最高 8 位
                acc = (acc << pad) | (EosPadByte >> over);
                out.push_back(static_cast<std::uint8_t>(acc));
            }
            return true;
        }

        /**
         * @brief 解析字面量名称（3 位前缀 + H 位 0x08，RFC 9204 4.5.2）
         * @param in 输入字节序列
         * @param offset 当前解析偏移（退出时已前进）
         * @param out 解析出的名称
         * @param mr 内存资源
         * @return 是否解析成功
         */
        [[nodiscard]] auto ParseName(std::span<const std::uint8_t> in, std::size_t &offset,
                                      std::string &out) -> bool
        {
            if (offset >= in.size())
            {
                return false;
            }
            const bool huffman = (in[offset] & 0x08) != 0;
            std::uint64_t len = 0;
            std::size_t consumed = 0;
            if (!ReadVarint(in.subspan(offset), 3, len, consumed))
            {
                return false;
            }
            offset += consumed;
            if (len > in.size() - offset)
            {
                return false;
            }
            // 热路径零分配：短值走栈缓冲，超长才回退堆
            std::array<std::uint8_t, 255> stack{};
            std::vector<std::uint8_t> heap(Preview::Memory::CurrentResource());
            if (huffman)
            {
                const auto est = static_cast<std::size_t>(len) * 2;
                if (est <= stack.size())
                {
                    std::size_t OutN = 0;
                    if (!HuffmanDecodeTo(in.subspan(offset, static_cast<std::size_t>(len)),
                                           stack, OutN))
                    {
                        return false;
                    }
                    offset += static_cast<std::size_t>(len);
                    out.assign(reinterpret_cast<const char *>(stack.data()), OutN);
                    return true;
                }
                if (!HuffmanDecodeImpl(in.subspan(offset, static_cast<std::size_t>(len)), heap))
                {
                    return false;
                }
                offset += static_cast<std::size_t>(len);
                out.assign(reinterpret_cast<const char *>(heap.data()), heap.size());
                return true;
            }
            offset += static_cast<std::size_t>(len);
            out.assign(reinterpret_cast<const char *>(in.data() + offset - static_cast<std::ptrdiff_t>(len)),
                       static_cast<std::size_t>(len));
            return true;
        }

        /**
         * @brief 解析一个字面量值（7 位前缀 + H 位 0x80，RFC 9204 4.5.1/4.5.2）
         * @param in 输入字节序列
         * @param offset 当前解析偏移（退出时已前进）
         * @param out 解析出的值
         * @param mr 内存资源
         * @return 是否解析成功
         */
        [[nodiscard]] auto ParseValue(std::span<const std::uint8_t> in, std::size_t &offset, std::string &out) -> bool
        {
            if (offset >= in.size())
            {
                return false;
            }
            const bool huffman = (in[offset] & 0x80) != 0;
            std::uint64_t len = 0;
            std::size_t consumed = 0;
            if (!ReadVarint(in.subspan(offset), 7, len, consumed))
            {
                return false;
            }
            offset += consumed;
            if (len > in.size() - offset)
            {
                return false;
            }
            // 热路径零分配：短值走栈缓冲，超长才回退堆
            std::array<std::uint8_t, 255> stack{};
            std::vector<std::uint8_t> heap(Preview::Memory::CurrentResource());
            if (huffman)
            {
                const auto est = static_cast<std::size_t>(len) * 2;
                if (est <= stack.size())
                {
                    std::size_t OutN = 0;
                    if (!HuffmanDecodeTo(in.subspan(offset, static_cast<std::size_t>(len)),
                                           stack, OutN))
                    {
                        return false;
                    }
                    offset += static_cast<std::size_t>(len);
                    out.assign(reinterpret_cast<const char *>(stack.data()), OutN);
                    return true;
                }
                if (!HuffmanDecodeImpl(in.subspan(offset, static_cast<std::size_t>(len)), heap))
                {
                    return false;
                }
                offset += static_cast<std::size_t>(len);
                out.assign(reinterpret_cast<const char *>(heap.data()), heap.size());
                return true;
            }
            offset += static_cast<std::size_t>(len);
            out.assign(reinterpret_cast<const char *>(in.data() + offset - static_cast<std::ptrdiff_t>(len)),
                       static_cast<std::size_t>(len));
            return true;
        }

        /**
         * @brief 写一个 huffman 字符串（长度前缀 + 编码字节）
         * @param out 输出缓冲区
         * @param offset 当前写入偏移（写入后自动前进）
         * @param value 待写入的字符串
         * @param prefix_bits 长度前缀位宽（3 或 7）
         * @param huff_flag 长度前缀的模式位（含 H 位）
         * @return 是否写入成功
         * @note 热路径零分配：≤63 字符走栈缓冲（255 B），超长回退堆
         */
        [[nodiscard]] auto WriteStringPrefixed(std::span<std::uint8_t> out, std::size_t &offset,
                                                 const std::string_view value, std::uint8_t prefix_bits,
                                                 const std::uint8_t huff_flag) -> bool
        {
            std::array<std::uint8_t, 255> stack;
            std::array<std::uint8_t, 16> len_buf;
            std::vector<std::uint8_t> heap; // 仅超长回退时分配
            // 最坏膨胀 30 bit/符号 ≈ 4 B/字符；255 B 栈缓冲可容纳 ≤63 字符
            std::size_t EncN = 0;
            const std::uint8_t *enc_data = nullptr;
            if (value.size() * 4 <= stack.size())
            {
                EncN = HuffmanEncodeTo(value, stack);
                if (EncN == 0 && !value.empty())
                {
                    return false;
                }
                enc_data = stack.data();
            }
            else
            {
                if (!HuffmanEncodeImpl(value, heap))
                {
                    return false;
                }
                EncN = heap.size();
                enc_data = heap.data();
            }
            const auto LenN = WriteVarint(len_buf, prefix_bits, EncN, huff_flag);
            if (LenN == 0 || out.size() < offset + LenN + EncN)
            {
                return false;
            }
            std::memcpy(out.data() + offset, len_buf.data(), LenN);
            offset += LenN;
            if (EncN > 0)
            {
                std::memcpy(out.data() + offset, enc_data, EncN);
                offset += EncN;
            }
            return true;
        }
    } // namespace

    inline auto DecodeHeaderBlock(std::span<const std::uint8_t> Data, const Preview::Memory::ResourcePointer mr)
        -> std::vector<HeaderField>
    {
        std::vector<HeaderField> fields(mr);
        fields.reserve(8); // 常见认证头 5-8 个字段，预防扩容分配
        std::size_t offset = 0;

        // Header Block Prefix：Required Insert Count（8 位前缀）+ Delta Base（7 位前缀）
        std::uint64_t RequiredCount = 0;
        std::size_t consumed = 0;
        if (!ReadVarint(Data.subspan(offset), 8, RequiredCount, consumed))
        {
            return fields;
        }
        offset += consumed;
        if (RequiredCount != 0)
        {
            return fields;
        }

        std::uint64_t base = 0;
        if (!ReadVarint(Data.subspan(offset), 7, base, consumed))
        {
            return fields;
        }
        offset += consumed;
        if (base != 0)
        {
            return fields;
        }

        while (offset < Data.size())
        {
            const auto first = Data[offset];
            if ((first & 0x80) != 0)
            {
                // 1Txxxxxx：索引字段（T=1 静态表）
                if ((first & 0x40) == 0)
                {
                    return fields; // 动态表索引不支持
                }
                std::uint64_t index = 0;
                if (!ReadVarint(Data.subspan(offset), 6, index, consumed))
                {
                    return fields;
                }
                offset += consumed;
                if (index >= static_table.size())
                {
                    return fields;
                }
                HeaderField hf{};
                hf.Name.assign(static_table[index].Name);
                hf.value.assign(static_table[index].value);
                fields.push_back(std::move(hf));
            }
            else if ((first & 0xC0) == 0x40)
            {
                // 01Nxxxxx：字面量，名称引用静态表
                std::uint64_t index = 0;
                if (!ReadVarint(Data.subspan(offset), 4, index, consumed))
                {
                    return fields;
                }
                offset += consumed;
                if (index >= static_table.size())
                {
                    return fields;
                }
                HeaderField hf{};
                hf.Name.assign(static_table[index].Name);
                if (!ParseValue(Data, offset, hf.value))
                {
                    return fields;
                }
                fields.push_back(std::move(hf));
            }
            else if ((first & 0xE0) == 0x20)
            {
                // 001xxxxx：字面量，字面名称（3 位前缀 + H 位 0x08）
                HeaderField hf{};
                if (!ParseName(Data, offset, hf.Name))
                {
                    return fields;
                }
                if (!ParseValue(Data, offset, hf.value))
                {
                    return fields;
                }
                fields.push_back(std::move(hf));
            }
            else if ((first & 0xE0) == 0x00)
            {
                // 000xxxxx：动态表指令（本实现不支持，直接失败）
                return fields;
            }
            else
            {
                return fields;
            }
        }
        return fields;
    }

    inline auto EncodePrefix(std::span<std::uint8_t> out) -> std::size_t
    {
        if (out.size() < 2)
        {
            return 0;
        }
        // Required Insert Count = 0（8 位前缀，值 0）
        out[0] = 0x00;
        // Delta Base = 0（7 位前缀，值 0）
        out[1] = 0x00;
        return 2;
    }

    inline auto EncodeLiteral(std::string_view Name, std::string_view value,
                               const std::span<std::uint8_t> out) -> std::size_t
    {
        // 1) 静态表命中（对照 Go metacubex/qpack 编码器）
        if (const auto *Entry = LookupEncoderName(Name))
        {
            // 值全匹配 → 索引字段（1Txxxxxx，T=1）：1 字节完成，免 huffman
            for (std::size_t i = 0; i < Entry->ValueCount; ++i)
            {
                const auto &ve = encoder_values[Entry->ValueOffset + i];
                if (ve.value == value)
                {
                    return WriteVarint(out, 6, ve.index, 0xC0);
                }
            }
            // 名称仅有空值条目且值为空 → 索引字段
            if (Entry->ValueCount == 0 && value.empty())
            {
                return WriteVarint(out, 6, Entry->FirstIndex, 0xC0);
            }
            // 值不匹配 → 名称引用字面量（01Nxxxxx，N=0，T=1）：免名称 huffman
            std::size_t offset = WriteVarint(out, 4, Entry->FirstIndex, 0x50);
            if (offset == 0)
            {
                return 0;
            }
            if (!WriteStringPrefixed(out, offset, value, 7, 0x80))
            {
                return 0;
            }
            return offset;
        }
        // 2) 未命中 → 字面量无名称引用（001xxxxx，H=1，huffman 编码）
        std::size_t offset = 0;
        if (!WriteStringPrefixed(out, offset, Name, 3, 0x20 | 0x08))
        {
            return 0;
        }
        if (!WriteStringPrefixed(out, offset, value, 7, 0x80))
        {
            return 0;
        }
        return offset;
    }

    inline auto HuffmanDecode(std::span<const std::uint8_t> in, std::vector<std::uint8_t> &out) -> bool
    {
        return HuffmanDecodeImpl(in, out);
    }

    inline auto HuffmanEncode(std::string_view in, std::vector<std::uint8_t> &out) -> bool
    {
        return HuffmanEncodeImpl(in, out);
    }

} // namespace Preview::Http3::Qpack

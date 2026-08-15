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
 *          header-only：所有实现 inline，测试库独立链接不依赖主库。
 */

#pragma once

#include <common/core/memory/container.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace psm::protocol::hysteria2::qpack
{

    /**
     * @struct header_field
     * @brief 解码出的头字段
     */
    struct header_field
    {
        // std::string 带 SSO（小字符串内联，≤15 字节零堆分配）：
        // QPACK 头字段名/值多为短字符串，热路径避免 PMR 分配
        std::string name;
        std::string value;
    };

    /**
     * @brief 解码一个 QPACK 头块
     * @param data 编码数据（不含 HTTP/3 帧头，仅 QPACK 块）
     * @param mr 内存资源
     * @return 解码出的头字段列表；失败返回空（无法区分空与失败，
     *         调用方应结合编码格式校验）
     * @details 仅支持静态表索引与字面量（无动态表），与 mihomo
     *          metacubex/qpack 客户端编码器对应。
     */
    [[nodiscard]] auto decode_header_block(std::span<const std::uint8_t> data, memory::resource_pointer mr)
        -> memory::vector<header_field>;

    /**
     * @brief 编码一个头字段为 QPACK 字段表示
     * @param name 字段名
     * @param value 字段值
     * @param out 输出缓冲区
     * @return 写入字节数；失败返回 0
     * @details 三分支编码（对照 Go metacubex/qpack 编码器）：
     *          1. 静态表值命中 → 索引字段（1Txxxxxx，1 字节）
     *          2. 静态表名称命中、值不同 → 名称引用字面量（01Nxxxxx，免名称 huffman）
     *          3. 未命中 → 字面量无名称引用（001xxxxx，huffman 编码）
     *          热路径零堆分配：≤63 字符走栈缓冲，超长回退堆。
     */
    [[nodiscard]] auto encode_literal(std::string_view name, std::string_view value,
                                      std::span<std::uint8_t> out) -> std::size_t;

    /**
     * @brief 编码 QPACK 头块前缀（Required Insert Count=0, Delta Base=0）
     * @param out 输出缓冲区
     * @return 写入字节数
     */
    [[nodiscard]] auto encode_prefix(std::span<std::uint8_t> out) -> std::size_t;

    /**
     * @brief HPACK huffman 解码
     * @param in 编码数据
     * @param out 解码输出
     * @return 是否成功
     */
    [[nodiscard]] auto huffman_decode(std::span<const std::uint8_t> in, memory::vector<std::uint8_t> &out)
        -> bool;

    /**
     * @brief HPACK huffman 编码
     * @param in 明文数据
     * @param out 编码输出
     * @return 是否成功
     */
    [[nodiscard]] auto huffman_encode(std::string_view in, memory::vector<std::uint8_t> &out) -> bool;

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
        [[nodiscard]] auto read_varint(const std::span<const std::uint8_t> in, const std::uint8_t prefix_bits,
                                       std::uint64_t &value, std::size_t &consumed) -> bool
        {
            if (in.empty())
            {
                return false;
            }
            const std::uint64_t prefix_mask = (1ULL << prefix_bits) - 1;
            std::uint64_t v = in[0] & prefix_mask;
            std::size_t offset = 1;
            if (v < prefix_mask)
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
        [[nodiscard]] auto write_varint(const std::span<std::uint8_t> out, const std::uint8_t prefix_bits,
                                        const std::uint64_t value, const std::uint8_t prefix_pattern)
            -> std::size_t
        {
            const std::uint64_t prefix_mask = (1ULL << prefix_bits) - 1;
            std::size_t n = 0;
            if (value < prefix_mask)
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
            out[0] = static_cast<std::uint8_t>(prefix_pattern | prefix_mask);
            n = 1;
            auto rest = value - prefix_mask;
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

        /// HPACK huffman 快速查表：len ≤ 8 的符号按 (len, code) 直接命中，O(1) 解码
        /// 构建方式：对每个符号（len ≤ 8），在对应 len 表中 code 位置写入符号索引
        constexpr auto build_huffman_lookup() -> std::array<std::array<std::int16_t, 256>, 9>
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
        constexpr auto huffman_lookup = build_huffman_lookup();

        /// 快速 huffman 符号解码：len ≤ 8 查表，否则线性扫描
        [[nodiscard]] inline auto huffman_find_sym(const std::uint32_t code, const std::uint16_t len)
            -> std::int16_t
        {
            if (len <= 8)
            {
                return huffman_lookup[len][code & 0xFF];
            }
            for (std::uint16_t sym = 0; sym < 256; ++sym)
            {
                if (huffman_lens[sym] == len && huffman_codes[sym] == code)
                {
                    return static_cast<std::int16_t>(sym);
                }
            }
            return -1;
        }

        /// QPACK 静态表（RFC 9204 附录 A，99 项）
        struct static_entry
        {
            std::string_view name;
            std::string_view value;
        };

        constexpr std::array<static_entry, 99> static_table = {
            static_entry{":authority", ""},
            static_entry{":path", "/"},
            static_entry{"age", "0"},
            static_entry{"content-disposition", ""},
            static_entry{"content-length", "0"},
            static_entry{"cookie", ""},
            static_entry{"date", ""},
            static_entry{"etag", ""},
            static_entry{"if-modified-since", ""},
            static_entry{"if-none-match", ""},
            static_entry{"last-modified", ""},
            static_entry{"link", ""},
            static_entry{"location", ""},
            static_entry{"referer", ""},
            static_entry{"set-cookie", ""},
            static_entry{":method", "CONNECT"},
            static_entry{":method", "DELETE"},
            static_entry{":method", "GET"},
            static_entry{":method", "HEAD"},
            static_entry{":method", "OPTIONS"},
            static_entry{":method", "POST"},
            static_entry{":method", "PUT"},
            static_entry{":scheme", "http"},
            static_entry{":scheme", "https"},
            static_entry{":status", "103"},
            static_entry{":status", "200"},
            static_entry{":status", "304"},
            static_entry{":status", "404"},
            static_entry{":status", "503"},
            static_entry{"accept", "*/*"},
            static_entry{"accept", "application/dns-message"},
            static_entry{"accept-encoding", "gzip, deflate, br"},
            static_entry{"accept-ranges", "bytes"},
            static_entry{"access-control-allow-headers", "cache-control"},
            static_entry{"access-control-allow-headers", "content-type"},
            static_entry{"access-control-allow-origin", "*"},
            static_entry{"cache-control", "max-age=0"},
            static_entry{"cache-control", "max-age=2592000"},
            static_entry{"cache-control", "max-age=604800"},
            static_entry{"cache-control", "no-cache"},
            static_entry{"cache-control", "no-store"},
            static_entry{"cache-control", "public, max-age=31536000"},
            static_entry{"content-encoding", "br"},
            static_entry{"content-encoding", "gzip"},
            static_entry{"content-type", "application/dns-message"},
            static_entry{"content-type", "application/javascript"},
            static_entry{"content-type", "application/json"},
            static_entry{"content-type", "application/x-www-form-urlencoded"},
            static_entry{"content-type", "image/gif"},
            static_entry{"content-type", "image/jpeg"},
            static_entry{"content-type", "image/png"},
            static_entry{"content-type", "text/css"},
            static_entry{"content-type", "text/html; charset=utf-8"},
            static_entry{"content-type", "text/plain"},
            static_entry{"content-type", "text/plain;charset=utf-8"},
            static_entry{"range", "bytes=0-"},
            static_entry{"strict-transport-security", "max-age=31536000"},
            static_entry{"strict-transport-security", "max-age=31536000; includesubdomains"},
            static_entry{"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
            static_entry{"vary", "accept-encoding"},
            static_entry{"vary", "origin"},
            static_entry{"x-content-type-options", "nosniff"},
            static_entry{"x-xss-protection", "1; mode=block"},
            static_entry{":status", "100"},
            static_entry{":status", "204"},
            static_entry{":status", "206"},
            static_entry{":status", "302"},
            static_entry{":status", "400"},
            static_entry{":status", "403"},
            static_entry{":status", "421"},
            static_entry{":status", "425"},
            static_entry{":status", "500"},
            static_entry{"accept-language", ""},
            static_entry{"access-control-allow-credentials", "FALSE"},
            static_entry{"access-control-allow-credentials", "TRUE"},
            static_entry{"access-control-allow-headers", "*"},
            static_entry{"access-control-allow-methods", "get"},
            static_entry{"access-control-allow-methods", "get, post, options"},
            static_entry{"access-control-allow-methods", "options"},
            static_entry{"access-control-expose-headers", "content-length"},
            static_entry{"access-control-request-headers", "content-type"},
            static_entry{"access-control-request-method", "get"},
            static_entry{"access-control-request-method", "post"},
            static_entry{"alt-svc", "clear"},
            static_entry{"authorization", ""},
            static_entry{"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
            static_entry{"early-data", "1"},
            static_entry{"expect-ct", ""},
            static_entry{"forwarded", ""},
            static_entry{"if-range", ""},
            static_entry{"origin", ""},
            static_entry{"purpose", "prefetch"},
            static_entry{"server", ""},
            static_entry{"timing-allow-origin", "*"},
            static_entry{"upgrade-insecure-requests", "1"},
            static_entry{"user-agent", ""},
            static_entry{"x-forwarded-for", ""},
            static_entry{"x-frame-options", "deny"},
            static_entry{"x-frame-options", "sameorigin"},
        };

        /// 编码器值条目（名称 → 值 → 静态表索引）
        struct encoder_value_entry
        {
            std::string_view value;
            std::uint8_t index;
        };

        /// 编码器名称条目（对应 Go metacubex/qpack 的 encoderMap）
        struct encoder_name_entry
        {
            std::string_view name;
            std::uint8_t first_index;   // 名称引用编码的基准索引（该名称首个静态表条目）
            std::uint16_t value_offset; // 值条目在 encoder_values 中的偏移
            std::uint8_t value_count;   // 值条目数量（0 = 该名称仅有空值条目）
        };

        /// 编码器值条目表（按 encoder_names 同名顺序排列）
        constexpr std::array<encoder_value_entry, 78> encoder_values = {
            // :method（索引 15-21）
            encoder_value_entry{"CONNECT", 15},
            encoder_value_entry{"DELETE", 16},
            encoder_value_entry{"GET", 17},
            encoder_value_entry{"HEAD", 18},
            encoder_value_entry{"OPTIONS", 19},
            encoder_value_entry{"POST", 20},
            encoder_value_entry{"PUT", 21},
            // :path（索引 1）
            encoder_value_entry{"/", 1},
            // :status（索引 24-28 与 63-71，非连续）
            encoder_value_entry{"103", 24},
            encoder_value_entry{"200", 25},
            encoder_value_entry{"304", 26},
            encoder_value_entry{"404", 27},
            encoder_value_entry{"503", 28},
            encoder_value_entry{"100", 63},
            encoder_value_entry{"204", 64},
            encoder_value_entry{"206", 65},
            encoder_value_entry{"302", 66},
            encoder_value_entry{"400", 67},
            encoder_value_entry{"403", 68},
            encoder_value_entry{"421", 69},
            encoder_value_entry{"425", 70},
            encoder_value_entry{"500", 71},
            // :scheme（索引 22-23）
            encoder_value_entry{"http", 22},
            encoder_value_entry{"https", 23},
            // age（索引 2）
            encoder_value_entry{"0", 2},
            // content-length（索引 4）
            encoder_value_entry{"0", 4},
            // accept（索引 29-30）
            encoder_value_entry{"*/*", 29},
            encoder_value_entry{"application/dns-message", 30},
            // accept-encoding（索引 31）
            encoder_value_entry{"gzip, deflate, br", 31},
            // accept-ranges（索引 32）
            encoder_value_entry{"bytes", 32},
            // access-control-allow-headers（索引 33-34 与 75）
            encoder_value_entry{"cache-control", 33},
            encoder_value_entry{"content-type", 34},
            encoder_value_entry{"*", 75},
            // access-control-allow-origin（索引 35）
            encoder_value_entry{"*", 35},
            // cache-control（索引 36-41）
            encoder_value_entry{"max-age=0", 36},
            encoder_value_entry{"max-age=2592000", 37},
            encoder_value_entry{"max-age=604800", 38},
            encoder_value_entry{"no-cache", 39},
            encoder_value_entry{"no-store", 40},
            encoder_value_entry{"public, max-age=31536000", 41},
            // content-encoding（索引 42-43）
            encoder_value_entry{"br", 42},
            encoder_value_entry{"gzip", 43},
            // content-type（索引 44-54）
            encoder_value_entry{"application/dns-message", 44},
            encoder_value_entry{"application/javascript", 45},
            encoder_value_entry{"application/json", 46},
            encoder_value_entry{"application/x-www-form-urlencoded", 47},
            encoder_value_entry{"image/gif", 48},
            encoder_value_entry{"image/jpeg", 49},
            encoder_value_entry{"image/png", 50},
            encoder_value_entry{"text/css", 51},
            encoder_value_entry{"text/html; charset=utf-8", 52},
            encoder_value_entry{"text/plain", 53},
            encoder_value_entry{"text/plain;charset=utf-8", 54},
            // range（索引 55）
            encoder_value_entry{"bytes=0-", 55},
            // strict-transport-security（索引 56-58）
            encoder_value_entry{"max-age=31536000", 56},
            encoder_value_entry{"max-age=31536000; includesubdomains", 57},
            encoder_value_entry{"max-age=31536000; includesubdomains; preload", 58},
            // vary（索引 59-60）
            encoder_value_entry{"accept-encoding", 59},
            encoder_value_entry{"origin", 60},
            // x-content-type-options（索引 61）
            encoder_value_entry{"nosniff", 61},
            // x-xss-protection（索引 62）
            encoder_value_entry{"1; mode=block", 62},
            // access-control-allow-credentials（索引 73-74）
            encoder_value_entry{"FALSE", 73},
            encoder_value_entry{"TRUE", 74},
            // access-control-allow-methods（索引 76-78）
            encoder_value_entry{"get", 76},
            encoder_value_entry{"get, post, options", 77},
            encoder_value_entry{"options", 78},
            // access-control-expose-headers（索引 79）
            encoder_value_entry{"content-length", 79},
            // access-control-request-headers（索引 80）
            encoder_value_entry{"content-type", 80},
            // access-control-request-method（索引 81-82）
            encoder_value_entry{"get", 81},
            encoder_value_entry{"post", 82},
            // alt-svc（索引 83）
            encoder_value_entry{"clear", 83},
            // content-security-policy（索引 85）
            encoder_value_entry{"script-src 'none'; object-src 'none'; base-uri 'none'", 85},
            // early-data（索引 86）
            encoder_value_entry{"1", 86},
            // purpose（索引 91）
            encoder_value_entry{"prefetch", 91},
            // timing-allow-origin（索引 93）
            encoder_value_entry{"*", 93},
            // upgrade-insecure-requests（索引 94）
            encoder_value_entry{"1", 94},
            // x-frame-options（索引 97-98）
            encoder_value_entry{"deny", 97},
            encoder_value_entry{"sameorigin", 98},
        };

        /// 编码器名称表（热路径名称靠前，线性扫描命中快）
        constexpr std::array<encoder_name_entry, 52> encoder_names = {
            encoder_name_entry{":method", 15, 0, 7},
            encoder_name_entry{":path", 1, 7, 1},
            encoder_name_entry{":status", 24, 8, 14},
            encoder_name_entry{":scheme", 22, 22, 2},
            encoder_name_entry{":authority", 0, 24, 0},
            encoder_name_entry{"age", 2, 24, 1},
            encoder_name_entry{"content-disposition", 3, 25, 0},
            encoder_name_entry{"content-length", 4, 25, 1},
            encoder_name_entry{"cookie", 5, 26, 0},
            encoder_name_entry{"date", 6, 26, 0},
            encoder_name_entry{"etag", 7, 26, 0},
            encoder_name_entry{"if-modified-since", 8, 26, 0},
            encoder_name_entry{"if-none-match", 9, 26, 0},
            encoder_name_entry{"last-modified", 10, 26, 0},
            encoder_name_entry{"link", 11, 26, 0},
            encoder_name_entry{"location", 12, 26, 0},
            encoder_name_entry{"referer", 13, 26, 0},
            encoder_name_entry{"set-cookie", 14, 26, 0},
            encoder_name_entry{"accept", 29, 26, 2},
            encoder_name_entry{"accept-encoding", 31, 28, 1},
            encoder_name_entry{"accept-ranges", 32, 29, 1},
            encoder_name_entry{"access-control-allow-headers", 33, 30, 3},
            encoder_name_entry{"access-control-allow-origin", 35, 33, 1},
            encoder_name_entry{"cache-control", 36, 34, 6},
            encoder_name_entry{"content-encoding", 42, 40, 2},
            encoder_name_entry{"content-type", 44, 42, 11},
            encoder_name_entry{"range", 55, 53, 1},
            encoder_name_entry{"strict-transport-security", 56, 54, 3},
            encoder_name_entry{"vary", 59, 57, 2},
            encoder_name_entry{"x-content-type-options", 61, 59, 1},
            encoder_name_entry{"x-xss-protection", 62, 60, 1},
            encoder_name_entry{"accept-language", 72, 61, 0},
            encoder_name_entry{"access-control-allow-credentials", 73, 61, 2},
            encoder_name_entry{"access-control-allow-methods", 76, 63, 3},
            encoder_name_entry{"access-control-expose-headers", 79, 66, 1},
            encoder_name_entry{"access-control-request-headers", 80, 67, 1},
            encoder_name_entry{"access-control-request-method", 81, 68, 2},
            encoder_name_entry{"alt-svc", 83, 70, 1},
            encoder_name_entry{"authorization", 84, 71, 0},
            encoder_name_entry{"content-security-policy", 85, 71, 1},
            encoder_name_entry{"early-data", 86, 72, 1},
            encoder_name_entry{"expect-ct", 87, 73, 0},
            encoder_name_entry{"forwarded", 88, 73, 0},
            encoder_name_entry{"if-range", 89, 73, 0},
            encoder_name_entry{"origin", 90, 73, 0},
            encoder_name_entry{"purpose", 91, 73, 1},
            encoder_name_entry{"server", 92, 74, 0},
            encoder_name_entry{"timing-allow-origin", 93, 74, 1},
            encoder_name_entry{"upgrade-insecure-requests", 94, 75, 1},
            encoder_name_entry{"user-agent", 95, 76, 0},
            encoder_name_entry{"x-forwarded-for", 96, 76, 0},
            encoder_name_entry{"x-frame-options", 97, 76, 2},
        };

        /// 编译期校验：encoder 表与 static_table 语义一致（索引/名称/值对齐）
        constexpr auto validate_encoder_tables() -> bool
        {
            for (const auto &entry : encoder_names)
            {
                if (static_table[entry.first_index].name != entry.name)
                {
                    return false;
                }
                for (std::size_t i = 0; i < entry.value_count; ++i)
                {
                    const auto &ve = encoder_values[entry.value_offset + i];
                    if (static_table[ve.index].name != entry.name || static_table[ve.index].value != ve.value)
                    {
                        return false;
                    }
                }
            }
            return true;
        }
        static_assert(validate_encoder_tables(), "encoder 表与静态表不一致");

        /**
         * @brief 静态表名称查找（编码器用）
         * @param name 字段名
         * @return 名称条目指针；未命中返回 nullptr
         * @note 线性扫描：长度不等快速拒绝，热路径命中通常 ≤5 次迭代
         */
        [[nodiscard]] auto lookup_encoder_name(const std::string_view name) -> const encoder_name_entry *
        {
            for (const auto &entry : encoder_names)
            {
                if (entry.name == name)
                {
                    return &entry;
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
        [[nodiscard]] auto huffman_decode_impl(std::span<const std::uint8_t> in,
                                               memory::vector<std::uint8_t> &out) -> bool
        {
            std::uint64_t acc = 0;
            std::uint32_t acc_bits = 0;
            for (const auto b : in)
            {
                acc = (acc << 8) | b;
                acc_bits += 8;
                // 每读入一字节即尝试从高位匹配最短符号
                while (acc_bits > 0)
                {
                    bool matched = false;
                    for (std::uint16_t len = 1; len <= acc_bits && len <= 30; ++len)
                    {
                        const std::uint64_t mask = (1ULL << len) - 1;
                        const auto code = static_cast<std::uint32_t>((acc >> (acc_bits - len)) & mask);
                        const auto sym = huffman_find_sym(code, len);
                        if (sym >= 0)
                        {
                            out.push_back(static_cast<std::uint8_t>(sym));
                            acc_bits -= len;
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
            if (acc_bits > 0)
            {
                const std::uint64_t mask = (acc_bits >= 64) ? ~0ULL : ((1ULL << acc_bits) - 1);
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
         * @param out_n 输出字节数
         * @return 是否解码成功
         * @note 与 huffman_decode_impl 逻辑一致，但写入固定 span 避免堆分配
         */
        [[nodiscard]] auto huffman_decode_to(const std::span<const std::uint8_t> in,
                                             const std::span<std::uint8_t> out,
                                             std::size_t &out_n) -> bool
        {
            std::uint64_t acc = 0;
            std::uint32_t acc_bits = 0;
            out_n = 0;
            for (const auto b : in)
            {
                acc = (acc << 8) | b;
                acc_bits += 8;
                while (acc_bits > 0)
                {
                    bool matched = false;
                    for (std::uint16_t len = 1; len <= acc_bits && len <= 30; ++len)
                    {
                        const std::uint64_t mask = (1ULL << len) - 1;
                        const auto code = static_cast<std::uint32_t>((acc >> (acc_bits - len)) & mask);
                        const auto sym = huffman_find_sym(code, len);
                        if (sym >= 0)
                        {
                            if (out_n >= out.size())
                            {
                                return false;
                            }
                            out[out_n++] = static_cast<std::uint8_t>(sym);
                            acc_bits -= len;
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
            if (acc_bits > 0)
            {
                const std::uint64_t mask = (acc_bits >= 64) ? ~0ULL : ((1ULL << acc_bits) - 1);
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
        [[nodiscard]] auto huffman_encode_to(const std::string_view in, const std::span<std::uint8_t> out)
            -> std::size_t
        {
            std::uint64_t acc = 0;
            std::uint32_t acc_bits = 0;
            std::size_t n = 0;
            for (const auto c : in)
            {
                const auto sym = static_cast<std::uint8_t>(c);
                const auto len = huffman_lens[sym];
                acc = (acc << len) | huffman_codes[sym];
                acc_bits += len;
                // 防止 64 位溢出：累积超 32 位即冲刷整字节
                while (acc_bits >= 8)
                {
                    if (n >= out.size())
                    {
                        return 0;
                    }
                    out[n++] = static_cast<std::uint8_t>(acc >> (acc_bits - 8));
                    acc_bits -= 8;
                }
            }
            // 尾部不足 8 位：高位补 1 填充（RFC 7541 5.2 EOS 前缀）
            if (acc_bits > 0)
            {
                if (n >= out.size())
                {
                    return 0;
                }
                const auto pad = 8 - acc_bits;
                out[n++] = static_cast<std::uint8_t>((acc << pad) | (0xFFU >> acc_bits));
            }
            return n;
        }

        /**
         * @brief huffman 编码：按符号输出码字（MSB 优先，RFC 7541 附录 B）
         * @param in 待编码的字符串
         * @param out 编码结果
         * @return 是否编码成功
         */
        [[nodiscard]] auto huffman_encode_impl(std::string_view in, memory::vector<std::uint8_t> &out) -> bool
        {
            std::uint64_t acc = 0;
            std::uint32_t acc_bits = 0;
            for (const auto c : in)
            {
                const auto sym = static_cast<std::uint8_t>(c);
                const auto len = huffman_lens[sym];
                acc = (acc << len) | huffman_codes[sym];
                acc_bits += len;
                // 防止 64 位溢出：累积超 32 位即冲刷整字节
                while (acc_bits >= 8)
                {
                    out.push_back(static_cast<std::uint8_t>(acc >> (acc_bits - 8)));
                    acc_bits -= 8;
                }
            }
            // 尾部不足 8 位：高位补 1 填充（RFC 7541 5.2 EOS 前缀）
            if (acc_bits > 0)
            {
                const auto over = acc_bits;
                const auto pad = 8 - over;
                const std::uint8_t eos_pad_byte = 0xFF; // EOS 0x3fffffff 的最高 8 位
                acc = (acc << pad) | (eos_pad_byte >> over);
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
        [[nodiscard]] auto parse_name(std::span<const std::uint8_t> in, std::size_t &offset,
                                      std::string &out) -> bool
        {
            if (offset >= in.size())
            {
                return false;
            }
            const bool huffman = (in[offset] & 0x08) != 0;
            std::uint64_t len = 0;
            std::size_t consumed = 0;
            if (!read_varint(in.subspan(offset), 3, len, consumed))
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
            memory::vector<std::uint8_t> heap(psm::memory::current_resource());
            if (huffman)
            {
                const auto est = static_cast<std::size_t>(len) * 2;
                if (est <= stack.size())
                {
                    std::size_t out_n = 0;
                    if (!huffman_decode_to(in.subspan(offset, static_cast<std::size_t>(len)),
                                           stack, out_n))
                    {
                        return false;
                    }
                    offset += static_cast<std::size_t>(len);
                    out.assign(reinterpret_cast<const char *>(stack.data()), out_n);
                    return true;
                }
                if (!huffman_decode_impl(in.subspan(offset, static_cast<std::size_t>(len)), heap))
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
        [[nodiscard]] auto parse_value(std::span<const std::uint8_t> in, std::size_t &offset, std::string &out) -> bool
        {
            if (offset >= in.size())
            {
                return false;
            }
            const bool huffman = (in[offset] & 0x80) != 0;
            std::uint64_t len = 0;
            std::size_t consumed = 0;
            if (!read_varint(in.subspan(offset), 7, len, consumed))
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
            memory::vector<std::uint8_t> heap(psm::memory::current_resource());
            if (huffman)
            {
                const auto est = static_cast<std::size_t>(len) * 2;
                if (est <= stack.size())
                {
                    std::size_t out_n = 0;
                    if (!huffman_decode_to(in.subspan(offset, static_cast<std::size_t>(len)),
                                           stack, out_n))
                    {
                        return false;
                    }
                    offset += static_cast<std::size_t>(len);
                    out.assign(reinterpret_cast<const char *>(stack.data()), out_n);
                    return true;
                }
                if (!huffman_decode_impl(in.subspan(offset, static_cast<std::size_t>(len)), heap))
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
        [[nodiscard]] auto write_string_prefixed(const std::span<std::uint8_t> out, std::size_t &offset,
                                                 const std::string_view value, const std::uint8_t prefix_bits,
                                                 const std::uint8_t huff_flag) -> bool
        {
            std::array<std::uint8_t, 255> stack;
            std::array<std::uint8_t, 16> len_buf;
            memory::vector<std::uint8_t> heap; // 仅超长回退时分配
            // 最坏膨胀 30 bit/符号 ≈ 4 B/字符；255 B 栈缓冲可容纳 ≤63 字符
            std::size_t enc_n = 0;
            const std::uint8_t *enc_data = nullptr;
            if (value.size() * 4 <= stack.size())
            {
                enc_n = huffman_encode_to(value, stack);
                if (enc_n == 0 && !value.empty())
                {
                    return false;
                }
                enc_data = stack.data();
            }
            else
            {
                if (!huffman_encode_impl(value, heap))
                {
                    return false;
                }
                enc_n = heap.size();
                enc_data = heap.data();
            }
            const auto len_n = write_varint(len_buf, prefix_bits, enc_n, huff_flag);
            if (len_n == 0 || out.size() < offset + len_n + enc_n)
            {
                return false;
            }
            std::memcpy(out.data() + offset, len_buf.data(), len_n);
            offset += len_n;
            if (enc_n > 0)
            {
                std::memcpy(out.data() + offset, enc_data, enc_n);
                offset += enc_n;
            }
            return true;
        }
    } // namespace

    inline auto decode_header_block(const std::span<const std::uint8_t> data, const memory::resource_pointer mr)
        -> memory::vector<header_field>
    {
        memory::vector<header_field> fields(mr);
        fields.reserve(8); // 常见认证头 5-8 个字段，预防扩容分配
        std::size_t offset = 0;

        // Header Block Prefix：Required Insert Count（8 位前缀）+ Delta Base（7 位前缀）
        std::uint64_t required_count = 0;
        std::size_t consumed = 0;
        if (!read_varint(data.subspan(offset), 8, required_count, consumed))
        {
            return fields;
        }
        offset += consumed;
        if (required_count != 0)
        {
            return fields;
        }

        std::uint64_t base = 0;
        if (!read_varint(data.subspan(offset), 7, base, consumed))
        {
            return fields;
        }
        offset += consumed;
        if (base != 0)
        {
            return fields;
        }

        while (offset < data.size())
        {
            const auto first = data[offset];
            if ((first & 0x80) != 0)
            {
                // 1Txxxxxx：索引字段（T=1 静态表）
                if ((first & 0x40) == 0)
                {
                    return fields; // 动态表索引不支持
                }
                std::uint64_t index = 0;
                if (!read_varint(data.subspan(offset), 6, index, consumed))
                {
                    return fields;
                }
                offset += consumed;
                if (index >= static_table.size())
                {
                    return fields;
                }
                header_field hf{};
                hf.name.assign(static_table[index].name);
                hf.value.assign(static_table[index].value);
                fields.push_back(std::move(hf));
            }
            else if ((first & 0xC0) == 0x40)
            {
                // 01Nxxxxx：字面量，名称引用静态表
                std::uint64_t index = 0;
                if (!read_varint(data.subspan(offset), 4, index, consumed))
                {
                    return fields;
                }
                offset += consumed;
                if (index >= static_table.size())
                {
                    return fields;
                }
                header_field hf{};
                hf.name.assign(static_table[index].name);
                if (!parse_value(data, offset, hf.value))
                {
                    return fields;
                }
                fields.push_back(std::move(hf));
            }
            else if ((first & 0xE0) == 0x20)
            {
                // 001xxxxx：字面量，字面名称（3 位前缀 + H 位 0x08）
                header_field hf{};
                if (!parse_name(data, offset, hf.name))
                {
                    return fields;
                }
                if (!parse_value(data, offset, hf.value))
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

    inline auto encode_prefix(const std::span<std::uint8_t> out) -> std::size_t
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

    inline auto encode_literal(const std::string_view name, const std::string_view value,
                               const std::span<std::uint8_t> out) -> std::size_t
    {
        // 1) 静态表命中（对照 Go metacubex/qpack 编码器）
        if (const auto *entry = lookup_encoder_name(name))
        {
            // 值全匹配 → 索引字段（1Txxxxxx，T=1）：1 字节完成，免 huffman
            for (std::size_t i = 0; i < entry->value_count; ++i)
            {
                const auto &ve = encoder_values[entry->value_offset + i];
                if (ve.value == value)
                {
                    return write_varint(out, 6, ve.index, 0xC0);
                }
            }
            // 名称仅有空值条目且值为空 → 索引字段
            if (entry->value_count == 0 && value.empty())
            {
                return write_varint(out, 6, entry->first_index, 0xC0);
            }
            // 值不匹配 → 名称引用字面量（01Nxxxxx，N=0，T=1）：免名称 huffman
            std::size_t offset = write_varint(out, 4, entry->first_index, 0x50);
            if (offset == 0)
            {
                return 0;
            }
            if (!write_string_prefixed(out, offset, value, 7, 0x80))
            {
                return 0;
            }
            return offset;
        }
        // 2) 未命中 → 字面量无名称引用（001xxxxx，H=1，huffman 编码）
        std::size_t offset = 0;
        if (!write_string_prefixed(out, offset, name, 3, 0x20 | 0x08))
        {
            return 0;
        }
        if (!write_string_prefixed(out, offset, value, 7, 0x80))
        {
            return 0;
        }
        return offset;
    }

    inline auto huffman_decode(const std::span<const std::uint8_t> in, memory::vector<std::uint8_t> &out) -> bool
    {
        return huffman_decode_impl(in, out);
    }

    inline auto huffman_encode(const std::string_view in, memory::vector<std::uint8_t> &out) -> bool
    {
        return huffman_encode_impl(in, out);
    }

} // namespace psm::protocol::hysteria2::qpack

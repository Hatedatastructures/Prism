/**
 * @file qpack.cpp
 * @brief QPACK 头压缩编解码实现（RFC 9204 静态表 + HPACK huffman）
 */

#include <prism/protocol/hysteria2/qpack.hpp>

#include <array>
#include <cstring>

namespace psm::protocol::hysteria2::qpack
{

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
                        for (std::uint16_t sym = 0; sym < 256; ++sym)
                        {
                            if (huffman_lens[sym] == len && huffman_codes[sym] == code)
                            {
                                out.push_back(static_cast<std::uint8_t>(sym));
                                acc_bits -= len;
                                matched = true;
                                break;
                            }
                        }
                        if (matched)
                        {
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
                                      memory::string &out, memory::resource_pointer mr) -> bool
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
            memory::vector<std::uint8_t> raw(mr);
            if (huffman)
            {
                if (!huffman_decode_impl(in.subspan(offset, static_cast<std::size_t>(len)), raw))
                {
                    return false;
                }
            }
            else
            {
                raw.assign(in.begin() + static_cast<std::ptrdiff_t>(offset),
                           in.begin() + static_cast<std::ptrdiff_t>(offset + len));
            }
            offset += static_cast<std::size_t>(len);
            out.assign(reinterpret_cast<const char *>(raw.data()), raw.size());
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
        [[nodiscard]] auto parse_value(std::span<const std::uint8_t> in, std::size_t &offset,
                                       memory::string &out, memory::resource_pointer mr) -> bool
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
            memory::vector<std::uint8_t> raw(mr);
            if (huffman)
            {
                if (!huffman_decode_impl(in.subspan(offset, static_cast<std::size_t>(len)), raw))
                {
                    return false;
                }
            }
            else
            {
                raw.assign(in.begin() + static_cast<std::ptrdiff_t>(offset),
                           in.begin() + static_cast<std::ptrdiff_t>(offset + len));
            }
            offset += static_cast<std::size_t>(len);
            out.assign(reinterpret_cast<const char *>(raw.data()), raw.size());
            return true;
        }

        /**
         * @brief 写一个字符串（huffman 编码，带长度前缀）
         * @param out 输出缓冲区
         * @param offset 当前写入偏移（写入后自动前进）
         * @param value 待写入的字符串
         * @return 是否写入成功
         */
        [[nodiscard]] auto write_string(std::span<std::uint8_t> out, std::size_t &offset,
                                        std::string_view value) -> bool
        {
            memory::vector<std::uint8_t> encoded;
            if (!huffman_encode_impl(value, encoded))
            {
                return false;
            }
            std::array<std::uint8_t, 16> len_buf{};
            const auto len_n = write_varint(len_buf, 7, encoded.size(), 0x80);
            if (len_n == 0 || out.size() < offset + len_n + encoded.size())
            {
                return false;
            }
            std::memcpy(out.data() + offset, len_buf.data(), len_n);
            offset += len_n;
            std::memcpy(out.data() + offset, encoded.data(), encoded.size());
            offset += encoded.size();
            return true;
        }
    } // namespace

    auto decode_header_block(const std::span<const std::uint8_t> data, const memory::resource_pointer mr)
        -> memory::vector<header_field>
    {
        memory::vector<header_field> fields(mr);
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
                header_field hf{memory::string(mr), memory::string(mr)};
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
                header_field hf{memory::string(mr), memory::string(mr)};
                hf.name.assign(static_table[index].name);
                if (!parse_value(data, offset, hf.value, mr))
                {
                    return fields;
                }
                fields.push_back(std::move(hf));
            }
            else if ((first & 0xE0) == 0x20)
            {
                // 001xxxxx：字面量，字面名称（3 位前缀 + H 位 0x08）
                header_field hf{memory::string(mr), memory::string(mr)};
                if (!parse_name(data, offset, hf.name, mr))
                {
                    return fields;
                }
                if (!parse_value(data, offset, hf.value, mr))
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

    auto encode_prefix(const std::span<std::uint8_t> out) -> std::size_t
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

    auto encode_literal(const std::string_view name, const std::string_view value,
                        const std::span<std::uint8_t> out) -> std::size_t
    {
        // 字面量无名称引用：001xxxxx，H=1（huffman），名称长度 3 位前缀
        std::size_t offset = 0;
        memory::vector<std::uint8_t> name_enc;
        if (!huffman_encode_impl(name, name_enc))
        {
            return 0;
        }
        std::array<std::uint8_t, 16> name_len{};
        const auto name_n = write_varint(name_len, 3, name_enc.size(), 0x20 | 0x08);
        if (name_n == 0 || out.size() < offset + name_n + name_enc.size())
        {
            return 0;
        }
        std::memcpy(out.data() + offset, name_len.data(), name_n);
        offset += name_n;
        std::memcpy(out.data() + offset, name_enc.data(), name_enc.size());
        offset += name_enc.size();

        if (!write_string(out, offset, value))
        {
            return 0;
        }
        return offset;
    }

    auto huffman_decode(const std::span<const std::uint8_t> in, memory::vector<std::uint8_t> &out) -> bool
    {
        return huffman_decode_impl(in, out);
    }

    auto huffman_encode(const std::string_view in, memory::vector<std::uint8_t> &out) -> bool
    {
        return huffman_encode_impl(in, out);
    }

} // namespace psm::protocol::hysteria2::qpack

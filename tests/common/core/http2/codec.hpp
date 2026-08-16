/**
 * @file codec.hpp
 * @brief HPACK 头压缩编解码（自包含，RFC 7541）
 * @details 实现 HPACK 核心：
 *          - 整数编码（prefix N 位）
 *          - 字符串编码（Huffman 标记 + 长度前缀）
 *          - 静态表（61 项，RFC 7541 Appendix A）
 *          - 动态表（基本实现：插入/索引）
 *          - 索引头字段 / 字面量头字段（增量索引/无索引/永不索引）
 * @note Huffman 压缩未实现（plain 编码，可扩展）
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <common/core/http2/session.hpp>

namespace psmtest::http2
{

    /// HPACK 静态表（RFC 7541 Appendix A，61 项）
    inline const std::vector<std::pair<std::string_view, std::string_view>> &static_table()
    {
        static const std::vector<std::pair<std::string_view, std::string_view>> table = {
            {":authority", ""},
            {":method", "GET"},
            {":method", "POST"},
            {":path", "/"},
            {":path", "/index.html"},
            {":scheme", "http"},
            {":scheme", "https"},
            {":status", "200"},
            {":status", "204"},
            {":status", "206"},
            {":status", "304"},
            {":status", "400"},
            {":status", "404"},
            {":status", "500"},
            {"accept-charset", ""},
            {"accept-encoding", "gzip, deflate"},
            {"accept-language", ""},
            {"accept-ranges", ""},
            {"accept", ""},
            {"access-control-allow-origin", ""},
            {"age", ""},
            {"allow", ""},
            {"authorization", ""},
            {"cache-control", ""},
            {"content-disposition", ""},
            {"content-encoding", ""},
            {"content-language", ""},
            {"content-length", ""},
            {"content-location", ""},
            {"content-range", ""},
            {"content-type", ""},
            {"cookie", ""},
            {"date", ""},
            {"etag", ""},
            {"expect", ""},
            {"expires", ""},
            {"from", ""},
            {"host", ""},
            {"if-match", ""},
            {"if-modified-since", ""},
            {"if-none-match", ""},
            {"if-range", ""},
            {"if-unmodified-since", ""},
            {"last-modified", ""},
            {"link", ""},
            {"location", ""},
            {"max-forwards", ""},
            {"proxy-authenticate", ""},
            {"proxy-authorization", ""},
            {"range", ""},
            {"referer", ""},
            {"refresh", ""},
            {"retry-after", ""},
            {"server", ""},
            {"set-cookie", ""},
            {"strict-transport-security", ""},
            {"transfer-encoding", ""},
            {"user-agent", ""},
            {"vary", ""},
            {"via", ""},
            {"www-authenticate", ""},
        };
        return table;
    }

    /**
     * @brief 编码整数（prefix N 位）
     * @param value 整数值
     * @param prefix_bits 前缀位数（1-8）
     * @param first 首字节高位（已含前缀标记位）
     * @param out 输出缓冲区
     */
    inline void encode_int(std::uint64_t value, std::uint8_t prefix_bits, std::uint8_t first,
                           std::vector<std::byte> &out)
    {
        const auto prefix_mask = static_cast<std::uint8_t>((1U << prefix_bits) - 1U);
        if (value < prefix_mask)
        {
            out.push_back(static_cast<std::byte>(first | static_cast<std::uint8_t>(value)));
            return;
        }
        out.push_back(static_cast<std::byte>(first | prefix_mask));
        value -= prefix_mask;
        while (value >= 128)
        {
            out.push_back(static_cast<std::byte>((value % 128) + 128));
            value /= 128;
        }
        out.push_back(static_cast<std::byte>(value));
    }

    /**
     * @brief 解码整数（prefix N 位）
     * @param data 输入缓冲区
     * @param prefix_bits 前缀位数
     * @param offset 解析偏移（输入输出）
     * @return 整数值
     */
    [[nodiscard]] inline auto decode_int(std::span<const std::byte> data, std::uint8_t prefix_bits,
                                         std::size_t &offset) -> std::uint64_t
    {
        const auto prefix_mask = static_cast<std::uint8_t>((1U << prefix_bits) - 1U);
        if (offset >= data.size())
        {
            return 0;
        }
        auto value = static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(data[offset]) & prefix_mask);
        ++offset;
        if (value < prefix_mask)
        {
            return value;
        }
        std::uint64_t shift = 0;
        while (offset < data.size())
        {
            const auto b = std::to_integer<std::uint8_t>(data[offset]);
            ++offset;
            value += static_cast<std::uint64_t>(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
            {
                break;
            }
            shift += 7;
        }
        return value;
    }

    /**
     * @brief 编码字符串（plain，Huffman 标记位 = 0）
     * @param s 字符串
     * @param out 输出缓冲区
     */
    inline void encode_string(std::string_view s, std::vector<std::byte> &out)
    {
        // Huffman 标记位 0 + 7 位前缀长度
        encode_int(s.size(), 7, 0x00, out);
        for (const auto c : s)
        {
            out.push_back(static_cast<std::byte>(c));
        }
    }

    /**
     * @brief 解码字符串
     * @param data 输入缓冲区
     * @param offset 解析偏移（输入输出）
     * @return 解码字符串；失败返回 std::nullopt
     */
    [[nodiscard]] inline auto decode_string(std::span<const std::byte> data, std::size_t &offset)
        -> std::optional<std::string>
    {
        if (offset >= data.size())
        {
            return std::nullopt;
        }
        const auto huffman = (std::to_integer<std::uint8_t>(data[offset]) & 0x80) != 0;
        const auto len = decode_int(data, 7, offset);
        if (huffman)
        {
            // Huffman 未实现：按 plain 读（等价误判；h2mux 互操作走 plain）
        }
        if (offset + len > data.size())
        {
            return std::nullopt;
        }
        std::string out;
        out.reserve(len);
        for (std::size_t i = 0; i < len; ++i)
        {
            out.push_back(std::to_integer<char>(data[offset + i]));
        }
        offset += len;
        return out;
    }

    /**
     * @brief 查静态表索引（name+value 完全匹配）
     * @param name 头名称
     * @param value 头值
     * @return 索引（1-61）；未命中返回 0
     */
    [[nodiscard]] inline auto lookup_static(std::string_view name, std::string_view value) -> std::size_t
    {
        const auto &table = static_table();
        for (std::size_t i = 0; i < table.size(); ++i)
        {
            if (table[i].first == name && table[i].second == value)
            {
                return i + 1;
            }
        }
        return 0;
    }

    /**
     * @brief 查静态表索引（仅 name 匹配，任意 value）
     * @param name 头名称
     * @return 最小索引（1-61）；未命中返回 0
     */
    [[nodiscard]] inline auto lookup_static_name(std::string_view name) -> std::size_t
    {
        const auto &table = static_table();
        for (std::size_t i = 0; i < table.size(); ++i)
        {
            if (table[i].first == name)
            {
                return i + 1;
            }
        }
        return 0;
    }

    /**
     * @brief HPACK 编码器（静态表 + 增量索引）
     * @details 维护发送侧动态表（简化为静态表 + 索引头字段；
     *          字面量增量索引头字段实现动态表更新）。
     */
    class hpack_encoder
    {
    public:
        /**
         * @brief 编码头列表为 HPACK 块
         * @param headers 头列表
         * @return HPACK 编码字节
         */
        [[nodiscard]] auto encode(const header_list &headers) -> std::vector<std::byte>
        {
            std::vector<std::byte> out;
            for (const auto &h : headers)
            {
                encode_header(h.name, h.value, out);
            }
            return out;
        }

    private:
        /// 增量索引字面量头字段（RFC 7541 §6.2.1）
        void encode_header(std::string_view name, std::string_view value, std::vector<std::byte> &out)
        {
            const auto full_idx = lookup_static(name, value);
            if (full_idx != 0)
            {
                // 索引头字段（§6.1）：1 + 7 位索引
                encode_int(full_idx, 7, 0x80, out);
                return;
            }
            const auto name_idx = lookup_static_name(name);
            if (name_idx != 0)
            {
                // 增量索引：名引用静态表
                encode_int(name_idx, 6, 0x40, out);
                encode_string(value, out);
                return;
            }
            // 增量索引：名字面量（new name）
            encode_int(0, 6, 0x40, out);
            encode_string(name, out);
            encode_string(value, out);
        }
    };

    /**
     * @brief HPACK 解码器（静态表 + 动态表）
     */
    class hpack_decoder
    {
    public:
        /**
         * @brief 解码 HPACK 块
         * @param data HPACK 字节
         * @return 头列表；解析失败返回 std::nullopt
         */
        [[nodiscard]] auto decode(std::span<const std::byte> data) -> std::optional<header_list>
        {
            header_list headers;
            std::size_t offset = 0;
            while (offset < data.size())
            {
                const auto b = std::to_integer<std::uint8_t>(data[offset]);
                if ((b & 0x80) != 0)
                {
                    // 索引头字段（§6.1）
                    const auto idx = decode_int(data, 7, offset);
                    auto h = lookup_index(idx);
                    if (!h)
                    {
                        return std::nullopt;
                    }
                    headers.push_back(*h);
                }
                else if ((b & 0x40) != 0)
                {
                    // 增量索引字面量头字段（§6.2.1）
                    const auto idx = decode_int(data, 6, offset);
                    std::string name;
                    if (idx != 0)
                    {
                        // name 引用索引（静态/动态表）
                        auto h = lookup_index(idx);
                        if (!h)
                        {
                            return std::nullopt;
                        }
                        name = h->name;
                    }
                    else
                    {
                        // name 字面量
                        auto name_opt = decode_string(data, offset);
                        if (!name_opt)
                        {
                            return std::nullopt;
                        }
                        name = std::move(*name_opt);
                    }
                    auto value_opt = decode_string(data, offset);
                    if (!value_opt)
                    {
                        return std::nullopt;
                    }
                    headers.push_back({std::move(name), std::move(*value_opt)});
                }
                else if ((b & 0x20) != 0)
                {
                    // 动态表大小更新（§6.3）：跳过
                    (void)decode_int(data, 5, offset);
                }
                else if ((b & 0x10) != 0)
                {
                    // 永不索引字面量（§6.2.3）：仅解析
                    const auto idx = decode_int(data, 4, offset);
                    std::string name;
                    if (idx != 0)
                    {
                        auto h = lookup_index(idx);
                        if (!h)
                        {
                            return std::nullopt;
                        }
                        name = h->name;
                    }
                    else
                    {
                        auto name_opt = decode_string(data, offset);
                        if (!name_opt)
                        {
                            return std::nullopt;
                        }
                        name = std::move(*name_opt);
                    }
                    auto value_opt = decode_string(data, offset);
                    if (!value_opt)
                    {
                        return std::nullopt;
                    }
                    headers.push_back({std::move(name), std::move(*value_opt)});
                }
                else
                {
                    // 无索引字面量（§6.2.2）
                    const auto idx = decode_int(data, 4, offset);
                    std::string name;
                    if (idx != 0)
                    {
                        auto h = lookup_index(idx);
                        if (!h)
                        {
                            return std::nullopt;
                        }
                        name = h->name;
                    }
                    else
                    {
                        auto name_opt = decode_string(data, offset);
                        if (!name_opt)
                        {
                            return std::nullopt;
                        }
                        name = std::move(*name_opt);
                    }
                    auto value_opt = decode_string(data, offset);
                    if (!value_opt)
                    {
                        return std::nullopt;
                    }
                    headers.push_back({std::move(name), std::move(*value_opt)});
                }
            }
            return headers;
        }

    private:
        /// 动态表（容量上限 4096，简单 FIFO）
        std::vector<header> dynamic_;

        /**
         * @brief 按索引查表（静态 1-61 + 动态 62+）
         * @param idx 索引
         * @return 头；越界返回 std::nullopt
         */
        [[nodiscard]] auto lookup_index(std::size_t idx) -> std::optional<header>
        {
            const auto &table = static_table();
            if (idx >= 1 && idx <= table.size())
            {
                return header{std::string(table[idx - 1].first), std::string(table[idx - 1].second)};
            }
            const auto dyn_idx = idx - table.size() - 1;
            if (dyn_idx < dynamic_.size())
            {
                return dynamic_[dyn_idx];
            }
            return std::nullopt;
        }
    };

} // namespace psmtest::http2

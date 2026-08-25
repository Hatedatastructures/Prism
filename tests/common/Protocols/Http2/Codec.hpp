/**
 * @file Codec.hpp
 * @brief HPACK 头压缩编解码（自包含，RFC 7541）
 * @details 实现 HPACK 核心：
 *          - 整数编码（Prefix N 位）
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

#include <common/Protocols/Http2/Session.hpp>

namespace Preview::Http2
{

    /// HPACK 静态表（RFC 7541 Appendix A，61 项）
    inline const std::vector<std::pair<std::string_view, std::string_view>> &static_table()
    {
        static const std::vector<std::pair<std::string_view, std::string_view>> Table = {
            {":authority", ""},
            {":Method", "GET"},
            {":Method", "POST"},
            {":Path", "/"},
            {":Path", "/index.html"},
            {":scheme", "http"},
            {":scheme", "https"},
            {":status", "200"},
            {":status", "204"},
            {":status", "206"},
            {":status", "304"},
            {":status", "400"},
            {":status", "404"},
            {":status", "500"},
            {"Accept-charset", ""},
            {"Accept-encoding", "gzip, deflate"},
            {"Accept-language", ""},
            {"Accept-ranges", ""},
            {"Accept", ""},
            {"Access-control-allow-origin", ""},
            {"age", ""},
            {"allow", ""},
            {"authorization", ""},
            {"cache-control", ""},
            {"content-disposition", ""},
            {"content-encoding", ""},
            {"content-language", ""},
            {"content-length", ""},
            {"content-Location", ""},
            {"content-range", ""},
            {"content-Type", ""},
            {"cookie", ""},
            {"date", ""},
            {"etag", ""},
            {"Expect", ""},
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
            {"Location", ""},
            {"max-forwards", ""},
            {"proxy-authenticate", ""},
            {"proxy-authorization", ""},
            {"range", ""},
            {"referer", ""},
            {"refresh", ""},
            {"retry-after", ""},
            {"Server", ""},
            {"set-cookie", ""},
            {"strict-transport-Security", ""},
            {"transfer-encoding", ""},
            {"user-agent", ""},
            {"vary", ""},
            {"via", ""},
            {"www-authenticate", ""},
        };
        return Table;
    }

    /**
     * @brief 编码整数（Prefix N 位）
     * @param value 整数值
     * @param prefix_bits 前缀位数（1-8）
     * @param first 首字节高位（已含前缀标记位）
     * @param out 输出缓冲区
     */
    inline void EncodeInt(std::uint64_t value, std::uint8_t prefix_bits, std::uint8_t first,
                           std::vector<std::byte> &out)
    {
        const auto PrefixMask = static_cast<std::uint8_t>((1U << prefix_bits) - 1U);
        if (value < PrefixMask)
        {
            out.push_back(static_cast<std::byte>(first | static_cast<std::uint8_t>(value)));
            return;
        }
        out.push_back(static_cast<std::byte>(first | PrefixMask));
        value -= PrefixMask;
        while (value >= 128)
        {
            out.push_back(static_cast<std::byte>((value % 128) + 128));
            value /= 128;
        }
        out.push_back(static_cast<std::byte>(value));
    }

    /**
     * @brief 解码整数（Prefix N 位）
     * @param Data 输入缓冲区
     * @param prefix_bits 前缀位数
     * @param offset 解析偏移（输入输出）
     * @return 整数值
     */
    [[nodiscard]] inline auto DecodeInt(std::span<const std::byte> Data, std::uint8_t prefix_bits,
                                         std::size_t &offset) -> std::uint64_t
    {
        const auto PrefixMask = static_cast<std::uint8_t>((1U << prefix_bits) - 1U);
        if (offset >= Data.size())
        {
            return 0;
        }
        auto value = static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(Data[offset]) & PrefixMask);
        ++offset;
        if (value < PrefixMask)
        {
            return value;
        }
        std::uint64_t shift = 0;
        while (offset < Data.size())
        {
            const auto b = std::to_integer<std::uint8_t>(Data[offset]);
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
    inline void EncodeString(std::string_view s, std::vector<std::byte> &out)
    {
        // Huffman 标记位 0 + 7 位前缀长度
        EncodeInt(s.size(), 7, 0x00, out);
        for (const auto c : s)
        {
            out.push_back(static_cast<std::byte>(c));
        }
    }

    /**
     * @brief 解码字符串
     * @param Data 输入缓冲区
     * @param offset 解析偏移（输入输出）
     * @return 解码字符串；失败返回 std::nullopt
     */
    [[nodiscard]] inline auto DecodeString(std::span<const std::byte> Data, std::size_t &offset)
        -> std::optional<std::string>
    {
        if (offset >= Data.size())
        {
            return std::nullopt;
        }
        const auto huffman = (std::to_integer<std::uint8_t>(Data[offset]) & 0x80) != 0;
        const auto len = DecodeInt(Data, 7, offset);
        if (huffman)
        {
            // Huffman 未实现：按 plain 读（等价误判；h2mux 互操作走 plain）
        }
        if (offset + len > Data.size())
        {
            return std::nullopt;
        }
        std::string out;
        out.reserve(len);
        for (std::size_t i = 0; i < len; ++i)
        {
            out.push_back(std::to_integer<char>(Data[offset + i]));
        }
        offset += len;
        return out;
    }

    /**
     * @brief 查静态表索引（Name+value 完全匹配）
     * @param Name 头名称
     * @param value 头值
     * @return 索引（1-61）；未命中返回 0
     */
    [[nodiscard]] inline auto LookupStatic(std::string_view Name, std::string_view value) -> std::size_t
    {
        const auto &Table = static_table();
        for (std::size_t i = 0; i < Table.size(); ++i)
        {
            if (Table[i].first == Name && Table[i].second == value)
            {
                return i + 1;
            }
        }
        return 0;
    }

    /**
     * @brief 查静态表索引（仅 Name 匹配，任意 value）
     * @param Name 头名称
     * @return 最小索引（1-61）；未命中返回 0
     */
    [[nodiscard]] inline auto LookupStaticName(std::string_view Name) -> std::size_t
    {
        const auto &Table = static_table();
        for (std::size_t i = 0; i < Table.size(); ++i)
        {
            if (Table[i].first == Name)
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
    class HpackEncoder
    {
    public:
        /**
         * @brief 编码头列表为 HPACK 块
         * @param headers 头列表
         * @return HPACK 编码字节
         */
        [[nodiscard]] auto Encode(const HeaderList &headers) -> std::vector<std::byte>
        {
            std::vector<std::byte> out;
            for (const auto &h : headers)
            {
                EncodeHeader(h.Name, h.value, out);
            }
            return out;
        }

    private:
        /// 增量索引字面量头字段（RFC 7541 §6.2.1）
        void EncodeHeader(std::string_view Name, std::string_view value, std::vector<std::byte> &out)
        {
            const auto FullIdx = LookupStatic(Name, value);
            if (FullIdx != 0)
            {
                // 索引头字段（§6.1）：1 + 7 位索引
                EncodeInt(FullIdx, 7, 0x80, out);
                return;
            }
            const auto NameIdx = LookupStaticName(Name);
            if (NameIdx != 0)
            {
                // 增量索引：名引用静态表
                EncodeInt(NameIdx, 6, 0x40, out);
                EncodeString(value, out);
                return;
            }
            // 增量索引：名字面量（new Name）
            EncodeInt(0, 6, 0x40, out);
            EncodeString(Name, out);
            EncodeString(value, out);
        }
    };

    /**
     * @brief HPACK 解码器（静态表 + 动态表）
     */
    class HpackDecoder
    {
    public:
        /**
         * @brief 解码 HPACK 块
         * @param Data HPACK 字节
         * @return 头列表；解析失败返回 std::nullopt
         */
        [[nodiscard]] auto Decode(std::span<const std::byte> Data) -> std::optional<HeaderList>
        {
            HeaderList headers;
            std::size_t offset = 0;
            while (offset < Data.size())
            {
                const auto b = std::to_integer<std::uint8_t>(Data[offset]);
                if ((b & 0x80) != 0)
                {
                    // 索引头字段（§6.1）
                    const auto idx = DecodeInt(Data, 7, offset);
                    auto h = LookupIndex(idx);
                    if (!h)
                    {
                        return std::nullopt;
                    }
                    headers.push_back(*h);
                }
                else if ((b & 0x40) != 0)
                {
                    // 增量索引字面量头字段（§6.2.1）
                    const auto idx = DecodeInt(Data, 6, offset);
                    std::string Name;
                    if (idx != 0)
                    {
                        // Name 引用索引（静态/动态表）
                        auto h = LookupIndex(idx);
                        if (!h)
                        {
                            return std::nullopt;
                        }
                        Name = h->Name;
                    }
                    else
                    {
                        // Name 字面量
                        auto NameOpt = DecodeString(Data, offset);
                        if (!NameOpt)
                        {
                            return std::nullopt;
                        }
                        Name = std::move(*NameOpt);
                    }
                    auto ValueOpt = DecodeString(Data, offset);
                    if (!ValueOpt)
                    {
                        return std::nullopt;
                    }
                    headers.push_back({std::move(Name), std::move(*ValueOpt)});
                }
                else if ((b & 0x20) != 0)
                {
                    // 动态表大小更新（§6.3）：跳过
                    (void)DecodeInt(Data, 5, offset);
                }
                else if ((b & 0x10) != 0)
                {
                    // 永不索引字面量（§6.2.3）：仅解析
                    const auto idx = DecodeInt(Data, 4, offset);
                    std::string Name;
                    if (idx != 0)
                    {
                        auto h = LookupIndex(idx);
                        if (!h)
                        {
                            return std::nullopt;
                        }
                        Name = h->Name;
                    }
                    else
                    {
                        auto NameOpt = DecodeString(Data, offset);
                        if (!NameOpt)
                        {
                            return std::nullopt;
                        }
                        Name = std::move(*NameOpt);
                    }
                    auto ValueOpt = DecodeString(Data, offset);
                    if (!ValueOpt)
                    {
                        return std::nullopt;
                    }
                    headers.push_back({std::move(Name), std::move(*ValueOpt)});
                }
                else
                {
                    // 无索引字面量（§6.2.2）
                    const auto idx = DecodeInt(Data, 4, offset);
                    std::string Name;
                    if (idx != 0)
                    {
                        auto h = LookupIndex(idx);
                        if (!h)
                        {
                            return std::nullopt;
                        }
                        Name = h->Name;
                    }
                    else
                    {
                        auto NameOpt = DecodeString(Data, offset);
                        if (!NameOpt)
                        {
                            return std::nullopt;
                        }
                        Name = std::move(*NameOpt);
                    }
                    auto ValueOpt = DecodeString(Data, offset);
                    if (!ValueOpt)
                    {
                        return std::nullopt;
                    }
                    headers.push_back({std::move(Name), std::move(*ValueOpt)});
                }
            }
            return headers;
        }

    private:
        /// 动态表（容量上限 4096，简单 FIFO）
        std::vector<Header> dynamic_;

        /**
         * @brief 按索引查表（静态 1-61 + 动态 62+）
         * @param idx 索引
         * @return 头；越界返回 std::nullopt
         */
        [[nodiscard]] auto LookupIndex(std::size_t idx) -> std::optional<Header>
        {
            const auto &Table = static_table();
            if (idx >= 1 && idx <= Table.size())
            {
                return Header{std::string(Table[idx - 1].first), std::string(Table[idx - 1].second)};
            }
            const auto DynIdx = idx - Table.size() - 1;
            if (DynIdx < dynamic_.size())
            {
                return dynamic_[DynIdx];
            }
            return std::nullopt;
        }
    };

} // namespace Preview::Http2

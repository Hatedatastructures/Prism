/**
 * @file Codec.hpp
 * @brief HPACK 头压缩编解码（自包含，RFC 7541）
 * @details 实现 HPACK 核心：
 *          - 整数编码（Prefix N 位）
 *          - 字符串编码（Huffman 标记 + 长度前缀）
 *          - 静态表（61 项，RFC 7541 Appendix A）
 *          - 动态表（基本实现：插入/索引）
 *          - 索引头字段 / 字面量头字段（增量索引/无索引/永不索引）
 * @note Huffman 字符串复用 HTTP/3 模块中的 RFC 7541 编解码实现。
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

#include <preview/Protocols/Http2/Session.hpp>
#include <preview/Protocols/Http3/Huffman.hpp>

namespace Preview::Http2
{

    /// HPACK 静态表（RFC 7541 Appendix A，61 项）
    inline const std::vector<std::pair<std::string_view, std::string_view>> &StaticTable()
    {
        static const std::vector<std::pair<std::string_view, std::string_view>> Table = {
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
        return Table;
    }

    /**
     * @brief 编码整数（Prefix N 位）
     * @param value 整数值
     * @param PrefixBits 前缀位数（1-8）
     * @param first 首字节高位（已含前缀标记位）
     * @param out 输出缓冲区
     */
    inline void EncodeInt(std::uint64_t value, std::uint8_t PrefixBits, std::uint8_t first,
                           std::vector<std::byte> &out)
    {
        const auto PrefixMask = static_cast<std::uint8_t>((1U << PrefixBits) - 1U);
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
     * @param PrefixBits 前缀位数
     * @param offset 解析偏移（输入输出）
     * @return 整数值
     */
    [[nodiscard]] inline auto DecodeInt(std::span<const std::byte> Data, std::uint8_t PrefixBits,
                                         std::size_t &Offset) -> std::uint64_t
    {
        const auto PrefixMask = static_cast<std::uint8_t>((1U << PrefixBits) - 1U);
        if (Offset >= Data.size())
        {
            return 0;
        }
        auto value = static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(Data[Offset]) & PrefixMask);
        ++Offset;
        if (value < PrefixMask)
        {
            return value;
        }
        std::uint64_t Shift = 0;
        while (Offset < Data.size())
        {
            const auto B = std::to_integer<std::uint8_t>(Data[Offset]);
            ++Offset;
            value += static_cast<std::uint64_t>(B & 0x7F) << Shift;
            if ((B & 0x80) == 0)
            {
                break;
            }
            Shift += 7;
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
    [[nodiscard]] inline auto DecodeString(std::span<const std::byte> Data, std::size_t &Offset)
        -> std::optional<std::string>
    {
        if (Offset >= Data.size())
        {
            return std::nullopt;
        }
        const auto Huffman = (std::to_integer<std::uint8_t>(Data[Offset]) & 0x80) != 0;
        const auto Len = DecodeInt(Data, 7, Offset);
        if (Offset > Data.size() || Len > Data.size() - Offset)
        {
            return std::nullopt;
        }
        if (Huffman)
        {
            std::vector<std::uint8_t> Decoded;
            const auto Encoded = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Data.data() + Offset),
                static_cast<std::size_t>(Len));
            if (!Preview::Http3::Qpack::Detail::HuffmanDecodeImpl(Encoded, Decoded))
            {
                return std::nullopt;
            }
            Offset += static_cast<std::size_t>(Len);
            return std::string(reinterpret_cast<const char *>(Decoded.data()), Decoded.size());
        }
        std::string out;
        out.reserve(static_cast<std::size_t>(Len));
        for (std::size_t I = 0; I < static_cast<std::size_t>(Len); ++I)
        {
            out.push_back(std::to_integer<char>(Data[Offset + I]));
        }
        Offset += static_cast<std::size_t>(Len);
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
        const auto &Table = StaticTable();
        for (std::size_t I = 0; I < Table.size(); ++I)
        {
            if (Table[I].first == Name && Table[I].second == value)
            {
                return I + 1;
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
        const auto &Table = StaticTable();
        for (std::size_t I = 0; I < Table.size(); ++I)
        {
            if (Table[I].first == Name)
            {
                return I + 1;
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
            for (const auto &H : headers)
            {
                EncodeHeader(H.Name, H.value, out);
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
            std::size_t Offset = 0;
            while (Offset < Data.size())
            {
                const auto B = std::to_integer<std::uint8_t>(Data[Offset]);
                if ((B & 0x80) != 0)
                {
                    // 索引头字段（§6.1）
                    const auto Idx = DecodeInt(Data, 7, Offset);
                    auto H = LookupIndex(Idx);
                    if (!H)
                    {
                        return std::nullopt;
                    }
                    headers.push_back(*H);
                }
                else if ((B & 0x40) != 0)
                {
                    // 增量索引字面量头字段（§6.2.1）
                    const auto Idx = DecodeInt(Data, 6, Offset);
                    std::string Name;
                    if (Idx != 0)
                    {
                        // Name 引用索引（静态/动态表）
                        auto H = LookupIndex(Idx);
                        if (!H)
                        {
                            return std::nullopt;
                        }
                        Name = H->Name;
                    }
                    else
                    {
                        // Name 字面量
                        auto NameOpt = DecodeString(Data, Offset);
                        if (!NameOpt)
                        {
                            return std::nullopt;
                        }
                        Name = std::move(*NameOpt);
                    }
                    auto ValueOpt = DecodeString(Data, Offset);
                    if (!ValueOpt)
                    {
                        return std::nullopt;
                    }
                    Header H{std::move(Name), std::move(*ValueOpt)};
                    InsertDynamic(H);
                    headers.push_back(std::move(H));
                }
                else if ((B & 0x20) != 0)
                {
                    // 动态表大小更新（§6.3）：按新上限驱逐超限条目
                    const auto NewCap = DecodeInt(Data, 5, Offset);
                    EvictDynamic(NewCap);
                }
                else if ((B & 0x10) != 0)
                {
                    // 永不索引字面量（§6.2.3）：仅解析
                    const auto Idx = DecodeInt(Data, 4, Offset);
                    std::string Name;
                    if (Idx != 0)
                    {
                        auto H = LookupIndex(Idx);
                        if (!H)
                        {
                            return std::nullopt;
                        }
                        Name = H->Name;
                    }
                    else
                    {
                        auto NameOpt = DecodeString(Data, Offset);
                        if (!NameOpt)
                        {
                            return std::nullopt;
                        }
                        Name = std::move(*NameOpt);
                    }
                    auto ValueOpt = DecodeString(Data, Offset);
                    if (!ValueOpt)
                    {
                        return std::nullopt;
                    }
                    headers.push_back({std::move(Name), std::move(*ValueOpt)});
                }
                else
                {
                    // 无索引字面量（§6.2.2）
                    const auto Idx = DecodeInt(Data, 4, Offset);
                    std::string Name;
                    if (Idx != 0)
                    {
                        auto H = LookupIndex(Idx);
                        if (!H)
                        {
                            return std::nullopt;
                        }
                        Name = H->Name;
                    }
                    else
                    {
                        auto NameOpt = DecodeString(Data, Offset);
                        if (!NameOpt)
                        {
                            return std::nullopt;
                        }
                        Name = std::move(*NameOpt);
                    }
                    auto ValueOpt = DecodeString(Data, Offset);
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
        /// 动态表容量上限（RFC 7541 §4.2 默认 4096 字节）
        static constexpr std::size_t DynCapacity = 4096;
        /// HPACK 条目开销（RFC 7541 §4.1：name + value + 32）
        static constexpr std::size_t EntryOverhead = 32;

        /// 动态表（Dynamic_[0] = 最新条目 = 索引 62，尾部为最旧）
        std::vector<Header> Dynamic_;
        /// 动态表当前字节数（含每条目 32 开销）
        std::size_t DynUsed_{0};

        /// 计算一个头的动态表占用
        [[nodiscard]] static auto EntrySizeOf(const Header &H) -> std::size_t
        {
            return H.Name.size() + H.value.size() + EntryOverhead;
        }

        /**
         * @brief 插入动态表（§6.2.1 增量索引）：最新条目置于头部，
         *        插入前从尾部（最旧）驱逐直至不超容量；单条超容量则清空
         */
        void InsertDynamic(const Header &H)
        {
            const auto Sz = EntrySizeOf(H);
            if (Sz > DynCapacity)
            {
                Dynamic_.clear();
                DynUsed_ = 0;
                return;
            }
            while (!Dynamic_.empty() && DynUsed_ + Sz > DynCapacity)
            {
                DynUsed_ -= EntrySizeOf(Dynamic_.back());
                Dynamic_.pop_back();
            }
            Dynamic_.insert(Dynamic_.begin(), H);
            DynUsed_ += Sz;
        }

        /**
         * @brief 按新容量上限驱逐最旧条目（§6.3 大小更新指令）
         */
        void EvictDynamic(std::size_t NewCap)
        {
            if (NewCap >= DynCapacity)
            {
                return;
            }
            while (!Dynamic_.empty() && DynUsed_ > NewCap)
            {
                DynUsed_ -= EntrySizeOf(Dynamic_.back());
                Dynamic_.pop_back();
            }
        }

        /**
         * @brief 按索引查表（静态 1-61 + 动态 62+）
         * @param idx 索引
         * @return 头；越界返回 std::nullopt
         */
        [[nodiscard]] auto LookupIndex(std::size_t Idx) -> std::optional<Header>
        {
            const auto &Table = StaticTable();
            if (Idx >= 1 && Idx <= Table.size())
            {
                return Header{std::string(Table[Idx - 1].first), std::string(Table[Idx - 1].second)};
            }
            const auto DynIdx = Idx - Table.size() - 1;
            if (DynIdx < Dynamic_.size())
            {
                return Dynamic_[DynIdx];
            }
            return std::nullopt;
        }
    };

} // namespace Preview::Http2

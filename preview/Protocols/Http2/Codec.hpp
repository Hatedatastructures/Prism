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
#include <limits>
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
    inline auto StaticTable()
        -> const std::vector<std::pair<std::string_view, std::string_view>> &
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
     * @param Value 整数值
     * @param PrefixBits 前缀位数（1-8）
     * @param First 首字节高位（已含前缀标记位）
     * @param Output 输出缓冲区
     */
    inline auto EncodeInt(
        std::uint64_t Value,
        std::uint8_t PrefixBits,
        std::uint8_t First,
        std::vector<std::byte> &Output) -> void
    {
        const auto PrefixMask = static_cast<std::uint8_t>((1U << PrefixBits) - 1U);
        if (Value < PrefixMask)
        {
            Output.push_back(static_cast<std::byte>(First | static_cast<std::uint8_t>(Value)));
            return;
        }
        Output.push_back(static_cast<std::byte>(First | PrefixMask));
        Value -= PrefixMask;
        while (Value >= 128)
        {
            Output.push_back(static_cast<std::byte>((Value % 128) + 128));
            Value /= 128;
        }
        Output.push_back(static_cast<std::byte>(Value));
    }

    /**
     * @brief 解码整数（Prefix N 位）
     * @param Data 输入缓冲区
     * @param PrefixBits 前缀位数
     * @param Offset 解析偏移（输入输出）
     * @return 整数值
     */
    [[nodiscard]] inline auto DecodeInt(
        std::span<const std::byte> Data,
        std::uint8_t PrefixBits,
        std::size_t &Offset) -> std::optional<std::uint64_t>
    {
        if (PrefixBits == 0 || PrefixBits > 8)
        {
            return std::nullopt;
        }
        const auto PrefixMask = static_cast<std::uint8_t>((1U << PrefixBits) - 1U);
        if (Offset >= Data.size())
        {
            return std::nullopt;
        }
        auto Value = static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(Data[Offset]) & PrefixMask);
        ++Offset;
        if (Value < PrefixMask)
        {
            return Value;
        }
        std::uint64_t Shift = 0;
        while (Offset < Data.size())
        {
            const auto Byte = std::to_integer<std::uint8_t>(Data[Offset]);
            ++Offset;
            const auto Payload = static_cast<std::uint64_t>(Byte & 0x7F);
            if (Shift >= 64 || Payload > (std::numeric_limits<std::uint64_t>::max() - Value) >> Shift)
            {
                return std::nullopt;
            }
            Value += Payload << Shift;
            if ((Byte & 0x80) == 0)
            {
                return Value;
            }
            if (Shift > 56)
            {
                return std::nullopt;
            }
            Shift += 7;
        }
        return std::nullopt;
    }

    /**
     * @brief 编码字符串（plain，Huffman 标记位 = 0）
     * @param Text 字符串
     * @param Output 输出缓冲区
     */
    inline auto EncodeString(
        std::string_view Text,
        std::vector<std::byte> &Output) -> void
    {
        // Huffman 标记位 0 + 7 位前缀长度
        EncodeInt(Text.size(), 7, 0x00, Output);
        for (const auto Character : Text)
        {
            Output.push_back(static_cast<std::byte>(Character));
        }
    }

    /**
     * @brief 解码字符串
     * @param Data 输入缓冲区
     * @param Offset 解析偏移（输入输出）
     * @return 解码字符串；失败返回 std::nullopt
     */
    [[nodiscard]] inline auto DecodeString(
        std::span<const std::byte> Data,
        std::size_t &Offset)
        -> std::optional<std::string>
    {
        if (Offset >= Data.size())
        {
            return std::nullopt;
        }
        const auto Huffman = (std::to_integer<std::uint8_t>(Data[Offset]) & 0x80) != 0;
        const auto Length = DecodeInt(Data, 7, Offset);
        if (!Length || Offset > Data.size() || *Length > Data.size() - Offset)
        {
            return std::nullopt;
        }
        if (Huffman)
        {
            std::vector<std::uint8_t> Decoded;
            const auto Encoded = std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Data.data() + Offset),
                static_cast<std::size_t>(*Length));
            if (!Preview::Http3::Qpack::Detail::HuffmanDecodeImpl(Encoded, Decoded))
            {
                return std::nullopt;
            }
            Offset += static_cast<std::size_t>(*Length);
            return std::string(reinterpret_cast<const char *>(Decoded.data()), Decoded.size());
        }
        std::string Output;
        Output.reserve(static_cast<std::size_t>(*Length));
        for (std::size_t Index = 0; Index < static_cast<std::size_t>(*Length); ++Index)
        {
            Output.push_back(std::to_integer<char>(Data[Offset + Index]));
        }
        Offset += static_cast<std::size_t>(*Length);
        return Output;
    }

    /**
     * @brief 查静态表索引（Name+Value 完全匹配）
     * @param Name 头名称
     * @param Value 头值
     * @return 索引（1-61）；未命中返回 0
     */
    [[nodiscard]] inline auto LookupStatic(
        std::string_view Name,
        std::string_view Value) -> std::size_t
    {
        const auto &Table = StaticTable();
        for (std::size_t Index = 0; Index < Table.size(); ++Index)
        {
            if (Table[Index].first == Name && Table[Index].second == Value)
            {
                return Index + 1;
            }
        }
        return 0;
    }

    /**
     * @brief 查静态表索引（仅 Name 匹配，任意 Value）
     * @param Name 头名称
     * @return 最小索引（1-61）；未命中返回 0
     */
    [[nodiscard]] inline auto LookupStaticName(std::string_view Name) -> std::size_t
    {
        const auto &Table = StaticTable();
        for (std::size_t Index = 0; Index < Table.size(); ++Index)
        {
            if (Table[Index].first == Name)
            {
                return Index + 1;
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
         * @param Headers 头列表
         * @return HPACK 编码字节
         */
        [[nodiscard]] auto Encode(
            const HeaderList &Headers) -> std::vector<std::byte>
        {
            std::vector<std::byte> Output;
            for (const auto &Field : Headers)
            {
                EncodeHeader(Field.Name, Field.value, Output);
            }
            return Output;
        }

    private:
        /// 增量索引字面量头字段（RFC 7541 §6.2.1）
        inline auto EncodeHeader(
            std::string_view Name,
            std::string_view Value,
            std::vector<std::byte> &Output) -> void
        {
            const auto FullIndex = LookupStatic(Name, Value);
            if (FullIndex != 0)
            {
                // 索引头字段（§6.1）：1 + 7 位索引
                EncodeInt(FullIndex, 7, 0x80, Output);
                return;
            }
            const auto NameIndex = LookupStaticName(Name);
            if (NameIndex != 0)
            {
                // 增量索引：名引用静态表
                EncodeInt(NameIndex, 6, 0x40, Output);
                EncodeString(Value, Output);
                return;
            }
            // 增量索引：名字面量（new Name）
            EncodeInt(0, 6, 0x40, Output);
            EncodeString(Name, Output);
            EncodeString(Value, Output);
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
        [[nodiscard]] auto Decode(
            std::span<const std::byte> Data) -> std::optional<HeaderList>
        {
            HeaderList Headers;
            std::size_t Offset = 0;
            while (Offset < Data.size())
            {
                const auto Byte = std::to_integer<std::uint8_t>(Data[Offset]);
                if ((Byte & 0x80) != 0)
                {
                    // 索引头字段（§6.1）
                    const auto Index = DecodeInt(Data, 7, Offset);
                    if (!Index)
                    {
                        return std::nullopt;
                    }
                    auto IndexedHeader = LookupIndex(*Index);
                    if (!IndexedHeader)
                    {
                        return std::nullopt;
                    }
                    Headers.push_back(*IndexedHeader);
                }
                else if ((Byte & 0x40) != 0)
                {
                    // 增量索引字面量头字段（§6.2.1）
                    const auto Index = DecodeInt(Data, 6, Offset);
                    if (!Index)
                    {
                        return std::nullopt;
                    }
                    std::string Name;
                    if (*Index != 0)
                    {
                        // Name 引用索引（静态/动态表）
                        auto IndexedHeader = LookupIndex(*Index);
                        if (!IndexedHeader)
                        {
                            return std::nullopt;
                        }
                        Name = IndexedHeader->Name;
                    }
                    else
                    {
                        // Name 字面量
                        auto NameOptional = DecodeString(Data, Offset);
                        if (!NameOptional)
                        {
                            return std::nullopt;
                        }
                        Name = std::move(*NameOptional);
                    }
                    auto ValueOptional = DecodeString(Data, Offset);
                    if (!ValueOptional)
                    {
                        return std::nullopt;
                    }
                    Header Field{std::move(Name), std::move(*ValueOptional)};
                    InsertDynamic(Field);
                    Headers.push_back(std::move(Field));
                }
                else if ((Byte & 0x20) != 0)
                {
                    // 动态表大小更新（§6.3）：按新上限驱逐超限条目
                    const auto NewCapacity = DecodeInt(Data, 5, Offset);
                    if (!NewCapacity)
                    {
                        return std::nullopt;
                    }
                    EvictDynamic(*NewCapacity);
                }
                else if ((Byte & 0x10) != 0)
                {
                    // 永不索引字面量（§6.2.3）：仅解析
                    const auto Index = DecodeInt(Data, 4, Offset);
                    if (!Index)
                    {
                        return std::nullopt;
                    }
                    std::string Name;
                    if (*Index != 0)
                    {
                        auto IndexedHeader = LookupIndex(*Index);
                        if (!IndexedHeader)
                        {
                            return std::nullopt;
                        }
                        Name = IndexedHeader->Name;
                    }
                    else
                    {
                        auto NameOptional = DecodeString(Data, Offset);
                        if (!NameOptional)
                        {
                            return std::nullopt;
                        }
                        Name = std::move(*NameOptional);
                    }
                    auto ValueOptional = DecodeString(Data, Offset);
                    if (!ValueOptional)
                    {
                        return std::nullopt;
                    }
                    Headers.push_back({std::move(Name), std::move(*ValueOptional)});
                }
                else
                {
                    // 无索引字面量（§6.2.2）
                    const auto Index = DecodeInt(Data, 4, Offset);
                    if (!Index)
                    {
                        return std::nullopt;
                    }
                    std::string Name;
                    if (*Index != 0)
                    {
                        auto IndexedHeader = LookupIndex(*Index);
                        if (!IndexedHeader)
                        {
                            return std::nullopt;
                        }
                        Name = IndexedHeader->Name;
                    }
                    else
                    {
                        auto NameOptional = DecodeString(Data, Offset);
                        if (!NameOptional)
                        {
                            return std::nullopt;
                        }
                        Name = std::move(*NameOptional);
                    }
                    auto ValueOptional = DecodeString(Data, Offset);
                    if (!ValueOptional)
                    {
                        return std::nullopt;
                    }
                    Headers.push_back({std::move(Name), std::move(*ValueOptional)});
                }
            }
            return Headers;
        }

    private:
        /// 动态表容量上限（RFC 7541 §4.2 默认 4096 字节）
        static constexpr std::size_t DynCapacity = 4096;
        /// HPACK 条目开销（RFC 7541 §4.1：Name + Value + 32）
        static constexpr std::size_t EntryOverhead = 32;

        /// 动态表（Dynamic_[0] = 最新条目 = 索引 62，尾部为最旧）
        std::vector<Header> Dynamic_;
        /// 动态表当前字节数（含每条目 32 开销）
        std::size_t DynUsed_{0};

        /// 计算一个头的动态表占用
        [[nodiscard]] static auto EntrySizeOf(const Header &Field) -> std::size_t
        {
            return Field.Name.size() + Field.value.size() + EntryOverhead;
        }

        /**
         * @brief 插入动态表（§6.2.1 增量索引）：最新条目置于头部，
         *        插入前从尾部（最旧）驱逐直至不超容量；单条超容量则清空
         */
        inline auto InsertDynamic(const Header &Field) -> void
        {
            const auto Size = EntrySizeOf(Field);
            if (Size > DynCapacity)
            {
                Dynamic_.clear();
                DynUsed_ = 0;
                return;
            }
            while (!Dynamic_.empty() && DynUsed_ + Size > DynCapacity)
            {
                DynUsed_ -= EntrySizeOf(Dynamic_.back());
                Dynamic_.pop_back();
            }
            Dynamic_.insert(Dynamic_.begin(), Field);
            DynUsed_ += Size;
        }

        /**
         * @brief 按新容量上限驱逐最旧条目（§6.3 大小更新指令）
         */
        inline auto EvictDynamic(std::size_t NewCapacity) -> void
        {
            if (NewCapacity >= DynCapacity)
            {
                return;
            }
            while (!Dynamic_.empty() && DynUsed_ > NewCapacity)
            {
                DynUsed_ -= EntrySizeOf(Dynamic_.back());
                Dynamic_.pop_back();
            }
        }

        /**
         * @brief 按索引查表（静态 1-61 + 动态 62+）
         * @param Index 索引
         * @return 头；越界返回 std::nullopt
         */
        [[nodiscard]] auto LookupIndex(std::size_t Index) -> std::optional<Header>
        {
            const auto &Table = StaticTable();
            if (Index >= 1 && Index <= Table.size())
            {
                return Header{std::string(Table[Index - 1].first), std::string(Table[Index - 1].second)};
            }
            const auto DynamicIndex = Index - Table.size() - 1;
            if (DynamicIndex < Dynamic_.size())
            {
                return Dynamic_[DynamicIndex];
            }
            return std::nullopt;
        }
    };

} // namespace Preview::Http2

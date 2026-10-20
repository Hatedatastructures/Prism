/**
 * @file Hpack.cpp
 * @brief HPACK 帧头编解码与动态表状态实现。
 */
#include <Prism/Protocols/Http2/Detail/Codec.hpp>
#include <Prism/Protocols/Http2/Detail/StaticTable.hpp>

#include <limits>
#include <string>
#include <utility>

#include <Prism/Protocols/HttpCompression/Huffman.hpp>

namespace Prism::Http2::Detail
{

    auto StaticTable()
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

    auto EncodeInt(const HpackInteger &Input, std::vector<std::byte> &Output) -> void
    {
        const auto PrefixMask = static_cast<std::uint8_t>((1U << Input.PrefixBits) - 1U);
        auto Value = Input.Value;
        if (Value < PrefixMask)
        {
            Output.push_back(static_cast<std::byte>(
                Input.FirstByte | static_cast<std::uint8_t>(Value)));
            return;
        }
        Output.push_back(static_cast<std::byte>(Input.FirstByte | PrefixMask));
        Value -= PrefixMask;
        while (Value >= 128)
        {
            Output.push_back(static_cast<std::byte>((Value % 128) + 128));
            Value /= 128;
        }
        Output.push_back(static_cast<std::byte>(Value));
    }

    auto DecodeInt(
        const std::span<const std::byte> Data,
        const std::uint8_t PrefixBits,
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

    auto EncodeString(
        const std::string_view Text,
        std::vector<std::byte> &Output) -> void
    {
        EncodeInt({Text.size(), 7, 0x00}, Output);
        for (const auto Character : Text)
        {
            Output.push_back(static_cast<std::byte>(Character));
        }
    }

    auto DecodeString(
        const std::span<const std::byte> Data,
        std::size_t &Offset) -> std::optional<std::string>
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
            if (!Prism::HttpCompression::HuffmanDecode(Encoded, Decoded))
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

    auto LookupStatic(
        const std::string_view Name,
        const std::string_view Value) -> std::size_t
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

    auto LookupStaticName(const std::string_view Name) -> std::size_t
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

    auto HpackEncoder::Encode(const HeaderList &Headers) -> std::vector<std::byte>
    {
        std::vector<std::byte> Output;
        for (const auto &Field : Headers)
        {
            EncodeHeader(Field.Name, Field.Value, Output);
        }
        return Output;
    }

    auto HpackEncoder::EncodeHeader(
        const std::string_view Name,
        const std::string_view Value,
        std::vector<std::byte> &Output) -> void
    {
        const auto FullIndex = LookupStatic(Name, Value);
        if (FullIndex != 0)
        {
            EncodeInt({FullIndex, 7, 0x80}, Output);
            return;
        }
        const auto NameIndex = LookupStaticName(Name);
        if (NameIndex != 0)
        {
            EncodeInt({NameIndex, 6, 0x40}, Output);
            EncodeString(Value, Output);
            return;
        }
        EncodeInt({0, 6, 0x40}, Output);
        EncodeString(Name, Output);
        EncodeString(Value, Output);
    }

    auto HpackDecoder::Decode(const std::span<const std::byte> Data)
        -> std::optional<HeaderList>
    {
        HeaderList Headers;
        std::size_t Offset = 0;
        bool HeaderFieldSeen = false;
        while (Offset < Data.size())
        {
            const auto Byte = std::to_integer<std::uint8_t>(Data[Offset]);
            if ((Byte & 0x80) != 0)
            {
                const auto Field = DecodeIndexed(Data, Offset);
                if (!Field)
                {
                    return std::nullopt;
                }
                Headers.push_back(*Field);
                HeaderFieldSeen = true;
            }
            else if ((Byte & 0x40) != 0)
            {
                auto Field = DecodeLiteral(Data, Offset, 6);
                if (!Field)
                {
                    return std::nullopt;
                }
                InsertDynamic(*Field);
                Headers.push_back(std::move(*Field));
                HeaderFieldSeen = true;
            }
            else if ((Byte & 0x20) != 0)
            {
                if (HeaderFieldSeen || !ApplyTableSizeUpdate(Data, Offset))
                {
                    return std::nullopt;
                }
            }
            else if ((Byte & 0x10) != 0)
            {
                auto Field = DecodeLiteral(Data, Offset, 4);
                if (!Field)
                {
                    return std::nullopt;
                }
                Headers.push_back(std::move(*Field));
                HeaderFieldSeen = true;
            }
            else
            {
                auto Field = DecodeLiteral(Data, Offset, 4);
                if (!Field)
                {
                    return std::nullopt;
                }
                Headers.push_back(std::move(*Field));
                HeaderFieldSeen = true;
            }
        }
        return Headers;
    }

    auto HpackDecoder::DecodeIndexed(
        const std::span<const std::byte> Data,
        std::size_t &Offset) -> std::optional<Header>
    {
        const auto Index = DecodeInt(Data, 7, Offset);
        if (!Index)
        {
            return std::nullopt;
        }
        return LookupIndex(*Index);
    }

    auto HpackDecoder::ApplyTableSizeUpdate(
        const std::span<const std::byte> Data,
        std::size_t &Offset) -> bool
    {
        const auto NewCapacity = DecodeInt(Data, 5, Offset);
        if (!NewCapacity || *NewCapacity > DynCapacity)
        {
            return false;
        }
        DynamicCapacity_ = *NewCapacity;
        EvictDynamic(DynamicCapacity_);
        return true;
    }

    auto HpackDecoder::DecodeLiteral(
        const std::span<const std::byte> Data,
        std::size_t &Offset,
        const std::uint8_t PrefixBits) -> std::optional<Header>
    {
        const auto Index = DecodeInt(Data, PrefixBits, Offset);
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
        return Header{std::move(Name), std::move(*ValueOptional)};
    }

    auto HpackDecoder::InsertDynamic(const Header &Field) -> void
    {
        const auto Size = EntrySizeOf(Field);
        if (Size > DynamicCapacity_)
        {
            Dynamic_.clear();
            DynUsed_ = 0;
            return;
        }
        while (!Dynamic_.empty() && DynUsed_ + Size > DynamicCapacity_)
        {
            DynUsed_ -= EntrySizeOf(Dynamic_.back());
            Dynamic_.pop_back();
        }
        Dynamic_.insert(Dynamic_.begin(), Field);
        DynUsed_ += Size;
    }

    auto HpackDecoder::EvictDynamic(const std::size_t NewCapacity) -> void
    {
        while (!Dynamic_.empty() && DynUsed_ > NewCapacity)
        {
            DynUsed_ -= EntrySizeOf(Dynamic_.back());
            Dynamic_.pop_back();
        }
    }

    auto HpackDecoder::LookupIndex(const std::size_t Index) -> std::optional<Header>
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

} // namespace Prism::Http2::Detail

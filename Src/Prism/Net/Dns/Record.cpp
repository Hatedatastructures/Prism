/** @file Record.cpp @brief DNS 大端字段与完整资源记录的有界解析实现。 */
#include <Prism/Net/Dns/Detail/Record.hpp>

#include <optional>

namespace Prism::Network::Dns::Detail
{
    namespace
    {
        [[nodiscard]] auto ReadU16(const std::span<const std::uint8_t> Data,
                                   std::size_t &Offset) noexcept
            -> std::optional<std::uint16_t>
        {
            if (Offset > Data.size() || Data.size() - Offset < 2)
            {
                return std::nullopt;
            }
            const auto Value = static_cast<std::uint16_t>(
                (Data[Offset] << 8) | Data[Offset + 1]);
            Offset += 2;
            return Value;
        }

        [[nodiscard]] auto ReadU32(const std::span<const std::uint8_t> Data,
                                   std::size_t &Offset) noexcept
            -> std::optional<std::uint32_t>
        {
            if (Offset > Data.size() || Data.size() - Offset < 4)
            {
                return std::nullopt;
            }
            const auto Value = (static_cast<std::uint32_t>(Data[Offset]) << 24) |
                               (static_cast<std::uint32_t>(Data[Offset + 1]) << 16) |
                               (static_cast<std::uint32_t>(Data[Offset + 2]) << 8) |
                               static_cast<std::uint32_t>(Data[Offset + 3]);
            Offset += 4;
            return Value;
        }
    }

    auto ReadHeader(const std::span<const std::uint8_t> Data) noexcept
        -> std::expected<ResponseHeader, Fault::Failure>
    {
        if (Data.size() < 12 || Data.size() > 65535)
        {
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        }
        std::size_t Offset = 0;
        ResponseHeader Header;
        Header.Id = *ReadU16(Data, Offset);
        Header.Flags = *ReadU16(Data, Offset);
        Header.Questions = *ReadU16(Data, Offset);
        Header.Answers = *ReadU16(Data, Offset);
        Header.Authority = *ReadU16(Data, Offset);
        Header.Additional = *ReadU16(Data, Offset);
        return Header;
    }

    auto ReadQuestion(NameCursor &Cursor) noexcept
        -> std::expected<QuestionView, Fault::Failure>
    {
        auto Name = ReadName(Cursor);
        if (!Name)
        {
            return std::unexpected(Name.error());
        }
        const auto Type = ReadU16(Cursor.Data, Cursor.Offset);
        const auto Class = ReadU16(Cursor.Data, Cursor.Offset);
        if (!Type || !Class)
        {
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        }
        return QuestionView{std::move(*Name), *Type, *Class};
    }

    auto ReadRecord(NameCursor &Cursor) noexcept
        -> std::expected<RecordView, Fault::Failure>
    {
        const auto NameOffset = Cursor.Offset;
        auto Name = ReadName(Cursor);
        if (!Name)
        {
            return std::unexpected(Name.error());
        }
        const auto Type = ReadU16(Cursor.Data, Cursor.Offset);
        const auto Class = ReadU16(Cursor.Data, Cursor.Offset);
        const auto Ttl = ReadU32(Cursor.Data, Cursor.Offset);
        const auto Length = ReadU16(Cursor.Data, Cursor.Offset);
        if (!Type || !Class || !Ttl || !Length || Cursor.Offset > Cursor.Data.size() ||
            *Length > Cursor.Data.size() - Cursor.Offset)
        {
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        }
        RecordView Result{std::move(*Name), *Type, *Class, *Ttl, NameOffset, Cursor.Offset,
                          Cursor.Data.subspan(Cursor.Offset, *Length)};
        Cursor.Offset += *Length;
        return Result;
    }

    auto ReadCname(const RecordView &Record,
                   const std::span<const std::uint8_t> Data) noexcept
        -> std::expected<DecodedName, Fault::Failure>
    {
        NameCursor Cursor{Data, Record.RdataOffset};
        auto Target = ReadName(Cursor);
        if (!Target)
        {
            return std::unexpected(Target.error());
        }
        if (Target->Size == 0 || Cursor.Offset != Record.RdataOffset + Record.Rdata.size())
        {
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        }
        return Target;
    }
}

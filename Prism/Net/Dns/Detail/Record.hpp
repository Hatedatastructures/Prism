/** @file Record.hpp @brief DNS 完整报文中的有界 header、question 和记录游标。 */
#pragma once

#include <Prism/Net/Dns/QueryType.hpp>
#include <Prism/Net/Dns/Detail/Name.hpp>
#include <Prism/Net/Dns/Detail/Wire.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <utility>

namespace Prism::Network::Dns::Detail
{
    /** @brief 同步读取的 header 值；各 section 数量只用于当前完整报文。 */
    struct ResponseHeader final
    {
        std::uint16_t Id{0};
        std::uint16_t Flags{0};
        std::uint16_t Questions{0};
        std::uint16_t Answers{0};
        std::uint16_t Authority{0};
        std::uint16_t Additional{0};
    };

    /** @brief 读取固定 header 并限制完整 DNS 报文大小，输入仅同步借用。 */
    [[nodiscard]] inline auto ReadHeader(const std::span<const std::uint8_t> Data) noexcept
        -> std::expected<ResponseHeader, Fault::Failure>
    {
        if (Data.size() < 12 || Data.size() > 65535)
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        std::size_t Offset = 0;
        ResponseHeader Header;
        Header.Id = *GetU16(Data, Offset);
        Header.Flags = *GetU16(Data, Offset);
        Header.Questions = *GetU16(Data, Offset);
        Header.Answers = *GetU16(Data, Offset);
        Header.Authority = *GetU16(Data, Offset);
        Header.Additional = *GetU16(Data, Offset);
        return Header;
    }

    /** @brief 解压后的完整问题值；名称拥有字节，不保存原始输入借用。 */
    struct QuestionView final
    {
        DecodedName Name;
        std::uint16_t Type{0};
        std::uint16_t Class{0};
    };

    [[nodiscard]] inline auto ReadQuestion(NameCursor &Cursor) noexcept
        -> std::expected<QuestionView, Fault::Failure>
    {
        auto Name = ReadName(Cursor);
        if (!Name) return std::unexpected(Name.error());
        const auto Type = GetU16(Cursor.Data, Cursor.Offset);
        const auto Class = GetU16(Cursor.Data, Cursor.Offset);
        if (!Type || !Class)
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        return QuestionView{std::move(*Name), *Type, *Class};
    }

    /** @brief 同步记录视图；Name 为拥有值，Rdata 只借用当前完整报文。 */
    struct RecordView final
    {
        DecodedName Name;
        std::uint16_t Type{0};
        std::uint16_t Class{0};
        std::uint32_t Ttl{0};
        std::size_t NameOffset{0};
        std::size_t RdataOffset{0};
        std::span<const std::uint8_t> Rdata;
    };

    /** @brief 有界读取记录；Rdata 借用不得逃离当前同步扫描，错误不抛异常。 */
    [[nodiscard]] inline auto ReadRecord(NameCursor &Cursor) noexcept
        -> std::expected<RecordView, Fault::Failure>
    {
        const auto NameOffset = Cursor.Offset;
        auto Name = ReadName(Cursor);
        if (!Name) return std::unexpected(Name.error());
        const auto Type = GetU16(Cursor.Data, Cursor.Offset);
        const auto Class = GetU16(Cursor.Data, Cursor.Offset);
        const auto Ttl = GetU32(Cursor.Data, Cursor.Offset);
        const auto Length = GetU16(Cursor.Data, Cursor.Offset);
        if (!Type || !Class || !Ttl || !Length || *Length > Cursor.Data.size() - Cursor.Offset)
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        RecordView Result{std::move(*Name), *Type, *Class, *Ttl, NameOffset, Cursor.Offset,
                          Cursor.Data.subspan(Cursor.Offset, *Length)};
        Cursor.Offset += *Length;
        return Result;
    }

    /** @brief CNAME RDATA 必须恰好编码一个完整名称，可以回指当前完整报文。 */
    [[nodiscard]] inline auto ReadCname(const RecordView &Record,
                                        const std::span<const std::uint8_t> Data) noexcept
        -> std::expected<DecodedName, Fault::Failure>
    {
        NameCursor Cursor{Data, Record.RdataOffset};
        auto Target = ReadName(Cursor);
        if (!Target) return std::unexpected(Target.error());
        if (Target->Size == 0 || Cursor.Offset != Record.RdataOffset + Record.Rdata.size())
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        return Target;
    }
}

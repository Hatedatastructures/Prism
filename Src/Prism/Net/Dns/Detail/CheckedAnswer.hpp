/** @file CheckedAnswer.hpp @brief 当前 DNS 问题与应答地址的正式关联校验。 */
#pragma once

#include <Prism/Net/Dns/Detail/Scan.hpp>
#include <expected>
#include <optional>
#include <utility>

namespace Prism::Network::Dns::Detail
{
    /**
     * @brief 沿 answer CNAME 索引解析最终 owner，不使用无界别名列表或逐层全表扫描。
     * @details 每层二分定位，至多索引数量加一步；循环和同 owner 冲突返回 ProtocolError。
     */
    [[nodiscard]] inline auto ResolveOwner(AliasIndex &Aliases, DecodedName Owner)
        -> std::expected<DecodedName, Fault::Failure>
    {
        const auto Sorted = Aliases.Sort();
        if (!Sorted) return std::unexpected(Sorted.error());
        for (std::size_t Depth = 0; Depth <= Aliases.Size(); ++Depth)
        {
            const auto Target = Aliases.Find(Owner);
            if (!Target) return std::unexpected(Target.error());
            if (!*Target) return Owner;
            Owner = **Target;
        }
        return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
    }

    /** @brief 一次扫描只发布最终 query/CNAME owner 的 A/AAAA，不接受旁路 additional 地址。 */
    [[nodiscard]] inline auto CollectRelated(AnswerScanState &State, const DecodedName &Owner,
                                             const ResponseHeader &Header)
        -> std::expected<void, Fault::Failure>
    {
        auto Cursor = State.Cursor;
        for (std::uint16_t Index = 0; Index < Header.Answers; ++Index)
        {
            const auto Record = ReadRecord(Cursor);
            if (!Record) return std::unexpected(Record.error());
            if (Record->Type != static_cast<std::uint16_t>(State.Type)) continue;
            const auto Address = AddressOf(*Record);
            if (!Address) continue;
            const auto Alias = State.Aliases.Find(Record->Name);
            if (!Alias) return std::unexpected(Alias.error());
            if (*Alias) return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
            if (Record->Name.View() != Owner.View()) continue;
            const auto Appended = State.Result.Ips.TryAppend(*Address, State.Pool);
            if (!Appended) return std::unexpected(Appended.error());
        }
        return {};
    }

    /** @brief ID、QR、opcode 和当前唯一 question 的同步正式校验。 */
    [[nodiscard]] inline auto CheckQuestion(AnswerScanState &State, const ResponseHeader &Header,
                                            const QueryIdentity &Query)
        -> std::expected<DecodedName, Fault::Failure>
    {
        const auto Opcode = static_cast<std::uint8_t>((Header.Flags >> 11) & 0x0Fu);
        if (Header.Id != Query.Parameters.Id || (Header.Flags & 0x8000u) == 0 ||
            (Header.Flags & 0x0040u) != 0 ||
            Opcode != Query.Parameters.Opcode || Query.Parameters.Opcode != 0 ||
            Query.Parameters.Class != 1 || Header.Questions != 1)
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        const auto Question = ReadQuestion(State.Cursor);
        if (!Question) return std::unexpected(Question.error());
        if (Question->Name.View() != Query.Name.View() ||
            Question->Type != static_cast<std::uint16_t>(Query.Parameters.Type) ||
            Question->Class != Query.Parameters.Class)
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        return Question->Name;
    }

    /**
     * @brief 生产校验入口：完整 query、记录结构、class、地址关联共用一份结果 owner。
     * @details TC 在完整 question 校验后返回，以便上层按同一 query 进行 TCP fallback。
     *          非截断应答必须消费完整报文；NXDOMAIN/NODATA 由 Rcode 与空地址分别表达。
     */
    [[nodiscard]] inline auto CheckResponse(const std::span<const std::uint8_t> Data,
                                             const CheckedAnswerRequest Request)
        -> std::expected<AnswerSet, Fault::Failure>
    {
        const auto Header = ReadHeader(Data);
        if (!Header) return std::unexpected(Header.error());
        AnswerScanState State{{Data, 12}, Request.Query.Parameters.Type, Request.Pool, {},
                              Request.Query.Parameters.Class, AliasIndex(Data), false};
        SetHeader(State.Result, *Header);
        const auto Question = CheckQuestion(State, *Header, Request.Query);
        if (!Question) return std::unexpected(Question.error());
        if (State.Result.Truncated) return std::move(State.Result);
        const auto AnswerOffset = State.Cursor.Offset;
        const auto Scanned = ScanRecords(State, *Header);
        if (!Scanned) return std::unexpected(Scanned.error());
        if (State.Cursor.Offset != Data.size())
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        const auto Owner = ResolveOwner(State.Aliases, *Question);
        if (!Owner) return std::unexpected(Owner.error());
        State.Cursor.Offset = AnswerOffset;
        const auto Collected = CollectRelated(State, *Owner, *Header);
        if (!Collected) return std::unexpected(Collected.error());
        if (State.Result.Rcode != 0 && !State.Result.Ips.Empty())
            return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
        return std::move(State.Result);
    }
}

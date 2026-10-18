/** @file Scan.hpp @brief DNS 记录扫描、TTL 观察与池地址提交的唯一实现。 */
#pragma once

#include <Prism/Net/Dns/AnswerSet.hpp>
#include <Prism/Net/Dns/Detail/Record.hpp>
#include <Prism/Net/Dns/Detail/AliasIndex.hpp>
#include <algorithm>
#include <array>
#include <expected>
#include <optional>

namespace Prism::Network::Dns::Detail
{
    /** @brief 地址及 CNAME 只从 answer 发布，其他 section 仅参与结构和 TTL 观察。 */
    enum class RecordSection : std::uint8_t { Answer, Authority, Additional };
    /** @brief 扫描 owner；Cursor 借用当前调用输入，Result 拥有所有发布地址。 */
    struct AnswerScanState final
    {
        NameCursor Cursor;
        QType Type;
        Memory::BytePool &Pool;
        AnswerSet Result;
        std::optional<std::uint16_t> RequiredClass;
        AliasIndex Aliases;
        bool CollectAll{false};
        bool HasOpt{false};
    };

    /** @brief 从已校验长度的 A/AAAA RDATA 构造值，不保留原报文借用。 */
    [[nodiscard]] inline auto AddressOf(const RecordView &Record) noexcept
        -> std::optional<boost::asio::ip::address>
    {
        if (Record.Type == static_cast<std::uint16_t>(QType::A) && Record.Rdata.size() == 4)
        {
            boost::asio::ip::address_v4::bytes_type Bytes{};
            std::copy(Record.Rdata.begin(), Record.Rdata.end(), Bytes.begin());
            return boost::asio::ip::address_v4(Bytes);
        }
        if (Record.Type == static_cast<std::uint16_t>(QType::Aaaa) && Record.Rdata.size() == 16)
        {
            boost::asio::ip::address_v6::bytes_type Bytes{};
            std::copy(Record.Rdata.begin(), Record.Rdata.end(), Bytes.begin());
            return boost::asio::ip::address_v6(Bytes);
        }
        return std::nullopt;
    }

    /** @brief 观察非 OPT 的真实 TTL；零值仍然是存在的 TTL。 */
    inline auto ObserveTtl(AnswerSet &Result, const RecordView &Record) noexcept -> void
    {
        if (Record.Type == static_cast<std::uint16_t>(QType::Opt)) return;
        if (!Result.HasTtl || Record.Ttl < Result.MinTtl) Result.MinTtl = Record.Ttl;
        Result.HasTtl = true;
    }

    /** @brief 同步扫描一个 section；预算在地址复制之前取得，失败保留 Failure。 */
    [[nodiscard]] inline auto ScanSection(AnswerScanState &State, const std::uint16_t Count,
                                          const RecordSection Section) -> std::expected<void, Fault::Failure>
    {
        for (std::uint16_t Index = 0; Index < Count; ++Index)
        {
            const auto Record = ReadRecord(State.Cursor);
            if (!Record) return std::unexpected(Record.error());
            if (Record->Type == static_cast<std::uint16_t>(QType::Opt))
            {
                if (State.RequiredClass &&
                    (Section != RecordSection::Additional || Record->Name.Size != 0 || State.HasOpt))
                    return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
                State.Result.Rcode = static_cast<std::uint16_t>(State.Result.Rcode |
                    ((Record->Ttl >> 24) << 4));
                State.HasOpt = true;
            }
            if (State.RequiredClass && Record->Type != static_cast<std::uint16_t>(QType::Opt) &&
                Record->Class != *State.RequiredClass)
                return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
            ObserveTtl(State.Result, *Record);
            if (State.RequiredClass && Section == RecordSection::Answer &&
                Record->Type == static_cast<std::uint16_t>(QType::Cname))
            {
                const auto Target = ReadCname(*Record, State.Cursor.Data);
                if (!Target) return std::unexpected(Target.error());
                const AliasEntry Entry{static_cast<std::uint16_t>(Record->NameOffset),
                    static_cast<std::uint16_t>(Record->RdataOffset),
                    static_cast<std::uint16_t>(Record->Rdata.size())};
                const auto Indexed = State.Aliases.TryAppend(Entry, State.Pool);
                if (!Indexed) return Indexed;
            }
            if (State.RequiredClass &&
                ((Record->Type == static_cast<std::uint16_t>(QType::A) && Record->Rdata.size() != 4) ||
                 (Record->Type == static_cast<std::uint16_t>(QType::Aaaa) && Record->Rdata.size() != 16)))
                return std::unexpected(Fault::Failure{Fault::Code::ProtocolError, {}});
            if (!State.CollectAll || Section != RecordSection::Answer ||
                Record->Type != static_cast<std::uint16_t>(State.Type) || Record->Class != 1)
                continue;
            const auto Address = AddressOf(*Record);
            if (!Address) continue;
            const auto Appended = State.Result.Ips.TryAppend(*Address, State.Pool);
            if (!Appended) return std::unexpected(Appended.error());
        }
        return {};
    }

    /** @brief 三段记录共用扫描事实；正式生产调用先校验当前问题，再单独关联地址。 */
    [[nodiscard]] inline auto ScanRecords(AnswerScanState &State, const ResponseHeader &Header)
        -> std::expected<void, Fault::Failure>
    {
        auto Scanned = ScanSection(State, Header.Answers, RecordSection::Answer);
        if (!Scanned) return Scanned;
        Scanned = ScanSection(State, Header.Authority, RecordSection::Authority);
        if (!Scanned) return Scanned;
        return ScanSection(State, Header.Additional, RecordSection::Additional);
    }

    inline auto SetHeader(AnswerSet &Result, const ResponseHeader &Header) noexcept -> void
    {
        Result.Id = Header.Id;
        Result.Truncated = (Header.Flags & 0x0200u) != 0;
        Result.Rcode = static_cast<std::uint16_t>(Header.Flags & 0x0Fu);
    }

    /** @brief 纯扫描：完整解析 question/record，不对调用者未提供的 query 作关联承诺。 */
    [[nodiscard]] inline auto ScanResponse(const std::span<const std::uint8_t> Data,
                                            const AnswerScanRequest Request)
        -> std::expected<AnswerSet, Fault::Failure>
    {
        const auto Header = ReadHeader(Data);
        if (!Header) return std::unexpected(Header.error());
        AnswerScanState State{{Data, 12}, Request.Type, Request.Pool, {}, std::nullopt, AliasIndex(Data), true};
        SetHeader(State.Result, *Header);
        for (std::uint16_t Index = 0; Index < Header->Questions; ++Index)
        {
            const auto Question = ReadQuestion(State.Cursor);
            if (!Question) return std::unexpected(Question.error());
        }
        const auto Scanned = ScanRecords(State, *Header);
        if (!Scanned) return std::unexpected(Scanned.error());
        return std::move(State.Result);
    }
}

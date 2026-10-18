/** @file UsageLedger.hpp @brief 仅存储线程调用的账户预约、累计结算、异常恢复后的人工调整。 */
#pragma once
#include <Prism/Account/UsageModels.hpp>
#include <Prism/Account/UsageCalendar.hpp>
#include <Prism/Application/Storage/StorageRuntime.hpp>
#include <algorithm>
#include <expected>
#include <optional>

namespace Prism::Application::Storage
{
    /** @brief 同步持久适配内核；调用方必须使用 StorageRuntime::Domain，不能在网络线程直接构造。 */
    class UsageLedger final
    {
    public:
        explicit UsageLedger(Prism::Storage::Database& Database) : Database_(Database) {}
        [[nodiscard]] auto ResolveCycle(const Account::UsageCycleRequest& Request)
            -> std::expected<Account::UsageCycle, Fault::Failure>
        {
            Prism::Storage::Transaction Transaction(Database_);
            auto Row = Database_.Prepare("SELECT current_start,current_end,active_kind,active_offset,pending_kind,pending_offset FROM usage_schedule WHERE account_key=?");
            Row.Text(1, Request.AccountKey);
            std::optional<Account::UsageSchedule> Previous;
            if (Row.Step())
            {
                Previous = Account::UsageSchedule{Cycle(Row, 0),
                    {static_cast<Account::CycleKind>(Row.Signed(2)), static_cast<int>(Row.Signed(3))},
                    {static_cast<Account::CycleKind>(Row.Signed(4)), static_cast<int>(Row.Signed(5))}};
            }
            auto Updated = Account::AdvanceUsageSchedule(Previous, Request);
            if (!Updated) return std::unexpected(Updated.error());
            StoreSchedule(Request.AccountKey, *Updated);
            if (Previous && Previous->Current.Start == Updated->Current.Start && Previous->Current.End != Updated->Current.End)
                UpdateCycleEnd(Request.AccountKey, Updated->Current);
            Transaction.Commit();
            return Updated->Current;
        }
        [[nodiscard]] auto Read(const Account::UsageReadRequest& Request)
            -> std::expected<Account::UsageSnapshot, Fault::Failure>
        {
            if (!Valid(Request)) return Invalid();
            return Load(Request);
        }
        [[nodiscard]] auto Reserve(const Account::UsageReservationRequest& Request)
            -> std::expected<Account::UsageReservation, Fault::Failure>
        {
            if (!Valid(Request.Usage) || Request.RequestKey.empty() || Request.Bytes == 0 ||
                Request.Bytes > 1024U * 1024U || Request.OutstandingLimit == 0 ||
                Request.OutstandingLimit > 2U * 1024U * 1024U) return Invalid();
            Prism::Storage::Transaction Transaction(Database_);
            auto Existing = ExistingReservation(Request);
            if (Existing) return Existing;
            if (Existing.error().Code != Fault::Code::Eof) return std::unexpected(Existing.error());
            auto Snapshot = Load(Request.Usage);
            const auto Outstanding = OutstandingBytes(Request.Usage.AccountKey);
            auto Granted = (std::min)(Request.Bytes, Request.OutstandingLimit > Outstanding ?
                Request.OutstandingLimit - Outstanding : std::uint64_t{0});
            if (Snapshot.LimitBytes) Granted = (std::min)(Granted, Snapshot.RemainingBytes);
            if (Granted == 0) return std::unexpected(Fault::Failure{Fault::Code::Blocked});
            Snapshot.ReservedBytes = Prism::Storage::AddExact(Snapshot.ReservedBytes, Granted);
            Advance(Snapshot);
            Store(Snapshot);
            auto Identity = Database_.Prepare("SELECT lower(hex(randomblob(16)))");
            if (!Identity.Step()) throw Prism::Storage::SqliteError(SQLITE_IOERR);
            Account::UsageReservation Result{Identity.String(0), Request.RequestKey, Request.Usage.AccountKey,
                Request.Usage.Cycle, Granted, Snapshot.Revision};
            InsertReservation(Request, Result);
            Transaction.Commit();
            return Result;
        }
        [[nodiscard]] auto Settle(const Account::UsageSettlementRequest& Request)
            -> std::expected<Account::UsageSnapshot, Fault::Failure>
        {
            Prism::Storage::Transaction Transaction(Database_);
            auto Row = Database_.Prepare("SELECT account_key,cycle_start,cycle_end,original_bytes,consumed,state,limit_bytes FROM usage_reservation WHERE id=?");
            Row.Text(1, Request.ReservationId);
            if (!Row.Step()) return Invalid();
            const auto Original = Row.Uint(3);
            const auto Consumed = Row.Uint(4);
            const auto State = Row.Signed(5);
            if (Consumed > Original || Request.ConsumedBytes < Consumed || Request.ConsumedBytes > Original)
                return Invalid();
            if (State == 2 || (State == 1 && (!Request.Final || Request.ConsumedBytes != Consumed)))
                return std::unexpected(Fault::Failure{Fault::Code::ReplayDetected});
            Account::UsageReadRequest Read{Row.String(0), Cycle(Row, 1), OptionalUint(Row, 6)};
            auto Snapshot = Load(Read);
            if (State == 1 || (Consumed == Request.ConsumedBytes && !Request.Final)) return Snapshot;
            const auto Delta = Request.ConsumedBytes - Consumed;
            const auto Released = Request.Final ? Original - Request.ConsumedBytes : 0;
            const auto Reduction = Prism::Storage::AddExact(Delta, Released);
            if (Snapshot.ReservedBytes < Reduction) throw Prism::Storage::SqliteError(SQLITE_CORRUPT);
            Snapshot.ReservedBytes -= Reduction;
            Snapshot.SettledBytes = Prism::Storage::AddExact(Snapshot.SettledBytes, Delta);
            Advance(Snapshot);
            Store(Snapshot);
            auto Update = Database_.Prepare("UPDATE usage_reservation SET consumed=?,state=? WHERE id=?");
            Update.Unsigned(1, Request.ConsumedBytes); Update.Integer(2, Request.Final ? 1 : 0);
            Update.Text(3, Request.ReservationId); Update.Run();
            Transaction.Commit();
            return Snapshot;
        }
        [[nodiscard]] auto Adjust(const Account::UsageAdjustmentRequest& Request)
            -> std::expected<Account::UsageSnapshot, Fault::Failure>
        {
            if (!Valid(Request.Usage) || Request.RequestKey.empty() || Request.Reason.empty() || Request.Bytes == 0)
                return Invalid();
            Prism::Storage::Transaction Transaction(Database_);
            auto Existing = ExistingAdjustment(Request);
            if (Existing) return Existing;
            if (Existing.error().Code != Fault::Code::Eof) return std::unexpected(Existing.error());
            auto Snapshot = Load(Request.Usage);
            if (Snapshot.Revision != Request.ExpectedRevision)
                return std::unexpected(Fault::Failure{Fault::Code::ReplayDetected});
            if (Request.Kind == Account::UsageAdjustmentKind::AddAllowance)
            {
                if (!Snapshot.LimitBytes) return Invalid();
                Snapshot.AdditionalBytes = Prism::Storage::AddExact(Snapshot.AdditionalBytes, Request.Bytes);
            }
            else if (Request.Kind == Account::UsageAdjustmentKind::ReleaseUncertain)
            {
                if (Request.Bytes > Snapshot.UncertainBytes) return Invalid();
                Snapshot.UncertainBytes -= Request.Bytes;
            }
            else return Invalid();
            Advance(Snapshot);
            Store(Snapshot);
            InsertAdjustment(Request, Snapshot);
            Transaction.Commit();
            return Snapshot;
        }
    private:
        auto StoreSchedule(std::string_view AccountKey, const Account::UsageSchedule& Value) -> void
        {
            auto Row = Database_.Prepare(R"sql(INSERT INTO usage_schedule VALUES(?,?,?,?,?,?,?)
ON CONFLICT(account_key) DO UPDATE SET current_start=excluded.current_start,current_end=excluded.current_end,
active_kind=excluded.active_kind,active_offset=excluded.active_offset,pending_kind=excluded.pending_kind,pending_offset=excluded.pending_offset)sql");
            Row.Text(1, AccountKey); Row.Integer(2, Value.Current.Start); BindEnd(Row, 3, Value.Current);
            Row.Integer(4, static_cast<int>(Value.Active.Kind)); Row.Integer(5, Value.Active.OffsetMinutes);
            Row.Integer(6, static_cast<int>(Value.Pending.Kind)); Row.Integer(7, Value.Pending.OffsetMinutes); Row.Run();
        }
        auto UpdateCycleEnd(std::string_view AccountKey, const Account::UsageCycle& Cycle) -> void
        {
            auto Ledger = Database_.Prepare("UPDATE usage_cycle SET cycle_end=? WHERE account_key=? AND cycle_start=?");
            BindEnd(Ledger, 1, Cycle); Ledger.Text(2, AccountKey); Ledger.Integer(3, Cycle.Start); Ledger.Run();
            auto Reservations = Database_.Prepare("UPDATE usage_reservation SET cycle_end=? WHERE account_key=? AND cycle_start=?");
            BindEnd(Reservations, 1, Cycle); Reservations.Text(2, AccountKey); Reservations.Integer(3, Cycle.Start); Reservations.Run();
        }
        static auto Invalid() -> std::unexpected<Fault::Failure>
        { return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument}); }
        static auto Valid(const Account::UsageReadRequest& Request) -> bool
        {
            return !Request.AccountKey.empty() && (!Request.Cycle.End || *Request.Cycle.End > Request.Cycle.Start);
        }
        static auto Cycle(const Prism::Storage::Statement& Row, int Column) -> Account::UsageCycle
        {
            return {Row.Signed(Column), Row.IsNull(Column + 1) ? std::optional<std::int64_t>{} : Row.Signed(Column + 1)};
        }
        static auto OptionalUint(const Prism::Storage::Statement& Row, int Column) -> std::optional<std::uint64_t>
        { return Row.IsNull(Column) ? std::optional<std::uint64_t>{} : Row.Uint(Column); }
        static auto BindOptional(Prism::Storage::Statement& Row, int Column, std::optional<std::uint64_t> Value) -> void
        { if (Value) Row.Unsigned(Column, *Value); else Row.Null(Column); }
        static auto BindEnd(Prism::Storage::Statement& Row, int Column, const Account::UsageCycle& Value) -> void
        { if (Value.End) Row.Integer(Column, *Value.End); else Row.Null(Column); }
        static auto Balances(Account::UsageSnapshot& Value) -> void
        {
            if (!Value.LimitBytes) { Value.RemainingBytes = 0; Value.OverageBytes = 0; return; }
            const auto Limit = Prism::Storage::AddExact(*Value.LimitBytes, Value.AdditionalBytes);
            const auto Used = Prism::Storage::AddExact(Prism::Storage::AddExact(
                Value.SettledBytes, Value.ReservedBytes), Value.UncertainBytes);
            Value.RemainingBytes = Limit > Used ? Limit - Used : 0;
            Value.OverageBytes = Used > Limit ? Used - Limit : 0;
        }
        static auto Advance(Account::UsageSnapshot& Snapshot) -> void
        {
            Snapshot.Revision = Prism::Storage::AddExact(Snapshot.Revision, 1);
            Balances(Snapshot);
        }
        auto Load(const Account::UsageReadRequest& Request) -> Account::UsageSnapshot
        {
            Account::UsageSnapshot Result;
            Result.AccountKey = Request.AccountKey; Result.Cycle = Request.Cycle; Result.LimitBytes = Request.LimitBytes;
            auto Query = Database_.Prepare("SELECT cycle_end,revision,settled,reserved,uncertain,additional FROM usage_cycle WHERE account_key=? AND cycle_start=?");
            Query.Text(1, Request.AccountKey); Query.Integer(2, Request.Cycle.Start);
            if (Query.Step())
            {
                const auto End = Query.IsNull(0) ? std::optional<std::int64_t>{} : Query.Signed(0);
                if (End != Request.Cycle.End) throw Prism::Storage::SqliteError(SQLITE_CONSTRAINT);
                Result.Revision = Query.Uint(1); Result.SettledBytes = Query.Uint(2);
                Result.ReservedBytes = Query.Uint(3); Result.UncertainBytes = Query.Uint(4);
                Result.AdditionalBytes = Query.Uint(5);
            }
            Balances(Result);
            return Result;
        }
        auto Store(const Account::UsageSnapshot& Value) -> void
        {
            auto Update = Database_.Prepare(R"sql(INSERT INTO usage_cycle VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(account_key,cycle_start) DO UPDATE SET revision=excluded.revision,limit_bytes=excluded.limit_bytes,
settled=excluded.settled,reserved=excluded.reserved,uncertain=excluded.uncertain,additional=excluded.additional)sql");
            Update.Text(1, Value.AccountKey); Update.Integer(2, Value.Cycle.Start); BindEnd(Update, 3, Value.Cycle);
            Update.Unsigned(4, Value.Revision); BindOptional(Update, 5, Value.LimitBytes);
            Update.Unsigned(6, Value.SettledBytes); Update.Unsigned(7, Value.ReservedBytes);
            Update.Unsigned(8, Value.UncertainBytes); Update.Unsigned(9, Value.AdditionalBytes); Update.Run();
        }
        auto OutstandingBytes(std::string_view AccountKey) -> std::uint64_t
        {
            auto Query = Database_.Prepare("SELECT original_bytes FROM usage_reservation WHERE account_key=? AND state=0");
            Query.Text(1, AccountKey);
            std::uint64_t Result = 0;
            while (Query.Step()) Result = Prism::Storage::AddExact(Result, Query.Uint(0));
            return Result;
        }
        auto ExistingReservation(const Account::UsageReservationRequest& Request)
            -> std::expected<Account::UsageReservation, Fault::Failure>
        {
            auto Row = Database_.Prepare("SELECT id,account_key,cycle_start,cycle_end,original_bytes,revision,requested_bytes,outstanding_limit,limit_bytes,state FROM usage_reservation WHERE request_key=?");
            Row.Text(1, Request.RequestKey);
            if (!Row.Step()) return std::unexpected(Fault::Failure{Fault::Code::Eof});
            if (Row.String(1) != Request.Usage.AccountKey || Cycle(Row, 2) != Request.Usage.Cycle ||
                Row.Uint(6) != Request.Bytes || Row.Uint(7) != Request.OutstandingLimit ||
                OptionalUint(Row, 8) != Request.Usage.LimitBytes)
                return std::unexpected(Fault::Failure{Fault::Code::ReplayDetected});
            if (Row.Signed(9) != 0) return std::unexpected(Fault::Failure{Fault::Code::ReplayDetected});
            return Account::UsageReservation{Row.String(0), Request.RequestKey, Row.String(1), Cycle(Row, 2),
                Row.Uint(4), Row.Uint(5)};
        }
        auto InsertReservation(const Account::UsageReservationRequest& Request, const Account::UsageReservation& Value) -> void
        {
            auto Insert = Database_.Prepare("INSERT INTO usage_reservation VALUES(?,?,?,?,?,?,?,?,?,?,?,?)");
            Insert.Text(1, Value.ReservationId); Insert.Text(2, Request.RequestKey); Insert.Text(3, Value.AccountKey);
            Insert.Integer(4, Value.Cycle.Start); BindEnd(Insert, 5, Value.Cycle);
            Insert.Unsigned(6, Value.Bytes); Insert.Unsigned(7, Request.Bytes);
            Insert.Unsigned(8, Request.OutstandingLimit); Insert.Unsigned(9, 0); Insert.Integer(10, 0);
            Insert.Unsigned(11, Value.Revision); BindOptional(Insert, 12, Request.Usage.LimitBytes);
            Insert.Run();
        }
        auto ExistingAdjustment(const Account::UsageAdjustmentRequest& Request)
            -> std::expected<Account::UsageSnapshot, Fault::Failure>
        {
            auto Row = Database_.Prepare("SELECT account_key,cycle_start,cycle_end,kind,bytes,expected_revision,reason,limit_bytes,result_revision,result_settled,result_reserved,result_uncertain,result_additional FROM usage_adjustment WHERE request_key=?");
            Row.Text(1, Request.RequestKey);
            if (!Row.Step()) return std::unexpected(Fault::Failure{Fault::Code::Eof});
            if (Row.String(0) != Request.Usage.AccountKey || Cycle(Row, 1) != Request.Usage.Cycle ||
                Row.Signed(3) != static_cast<int>(Request.Kind) || Row.Uint(4) != Request.Bytes ||
                Row.Uint(5) != Request.ExpectedRevision || Row.String(6) != Request.Reason ||
                OptionalUint(Row, 7) != Request.Usage.LimitBytes)
                return std::unexpected(Fault::Failure{Fault::Code::ReplayDetected});
            Account::UsageSnapshot Result;
            Result.AccountKey = Row.String(0); Result.Cycle = Cycle(Row, 1); Result.LimitBytes = OptionalUint(Row, 7);
            Result.Revision = Row.Uint(8); Result.SettledBytes = Row.Uint(9); Result.ReservedBytes = Row.Uint(10);
            Result.UncertainBytes = Row.Uint(11); Result.AdditionalBytes = Row.Uint(12); Balances(Result);
            return Result;
        }
        auto InsertAdjustment(const Account::UsageAdjustmentRequest& Request, const Account::UsageSnapshot& Value) -> void
        {
            auto Insert = Database_.Prepare("INSERT INTO usage_adjustment VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
            Insert.Text(1, Request.RequestKey); Insert.Text(2, Value.AccountKey); Insert.Integer(3, Value.Cycle.Start);
            BindEnd(Insert, 4, Value.Cycle); Insert.Integer(5, static_cast<int>(Request.Kind));
            Insert.Unsigned(6, Request.Bytes); Insert.Unsigned(7, Request.ExpectedRevision); Insert.Text(8, Request.Reason);
            BindOptional(Insert, 9, Value.LimitBytes); Insert.Unsigned(10, Value.Revision);
            Insert.Unsigned(11, Value.SettledBytes); Insert.Unsigned(12, Value.ReservedBytes);
            Insert.Unsigned(13, Value.UncertainBytes); Insert.Unsigned(14, Value.AdditionalBytes); Insert.Run();
        }
        Prism::Storage::Database& Database_;
    };
}

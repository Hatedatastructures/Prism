/**
 * @file StorageRuntime.cpp
 * @brief 双数据库 owner 的初始化、恢复与关闭实现。
 */

#include <Prism/Application/Storage/StorageRuntime.hpp>
#include <Prism/Application/Storage/Detail/DirectoryLock.hpp>

#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Application::Storage
{
    StorageRuntime::StorageRuntime(StorageOptions Options)
        : Options_(std::move(Options)), Domain_(std::make_shared<Resource::Storage::Executor>()),
          Lock_(std::make_unique<Detail::DirectoryLock>())
    {
    }

    StorageRuntime::~StorageRuntime() = default;

    auto StorageRuntime::Open(StorageOptions Options)
        -> boost::asio::awaitable<std::expected<std::shared_ptr<StorageRuntime>, Fault::Failure>>
    {
        auto Owner = std::make_shared<StorageRuntime>(std::move(Options));
        auto Result = co_await Owner->Domain_->Execute([Owner]() -> std::expected<void, Fault::Failure>
            { Owner->Initialize(); return {}; });
        if (!Result)
        {
            const auto Failure = Result.error();
            (void)co_await Owner->Shutdown();
            co_return std::unexpected(Failure);
        }
        co_return Owner;
    }

    auto StorageRuntime::Shutdown() -> boost::asio::awaitable<std::expected<void, Fault::Failure>>
    {
        const auto Owner = shared_from_this();
        co_return co_await Domain_->Shutdown([Owner]() -> std::expected<void, Fault::Failure>
            { Owner->History_.Close(); Owner->Ledger_.Close(); Owner->Lock_->Close(); return {}; });
    }

    auto StorageRuntime::Join() -> void
    {
        Domain_->Join();
    }

    auto StorageRuntime::RandomKey(Prism::Storage::Database& Database) -> std::string
    {
        auto Query = Database.Prepare("SELECT lower(hex(randomblob(16)))");
        if (!Query.Step()) throw Prism::Storage::SqliteError(SQLITE_IOERR);
        return Query.String(0);
    }

    auto StorageRuntime::Initialize() -> void
    {
        if (Options_.Directory.empty()) throw std::system_error(std::make_error_code(std::errc::invalid_argument));
        Lock_->Open(Options_.Directory);
        Ledger_.Open(Options_.Directory / "ledger.sqlite3");
        History_.Open(Options_.Directory / "history.sqlite3");
        CheckVersion(Ledger_);
        CheckVersion(History_);
        Ledger_.Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL");
        History_.Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL");
        InitializeLedger();
        InitializeHistory();
        auto Query = Ledger_.Prepare("SELECT value FROM storage_meta WHERE key='instance_key'");
        if (!Query.Step()) throw Prism::Storage::SqliteError(SQLITE_CORRUPT);
        InstanceKey_ = Query.String(0);
        Incarnation_ = Options_.Incarnation.empty() ? RandomKey(Ledger_) : Options_.Incarnation;
    }

    auto StorageRuntime::CheckVersion(Prism::Storage::Database& Database) -> void
    {
        const auto Version = Database.Scalar("PRAGMA user_version");
        if (Version < 0 || Version > 1) throw Prism::Storage::SqliteError(SQLITE_SCHEMA);
    }

    auto StorageRuntime::InitializeLedger() -> void
    {
        Prism::Storage::Transaction Transaction(Ledger_);
        Ledger_.Execute(R"sql(
CREATE TABLE IF NOT EXISTS storage_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
INSERT OR IGNORE INTO storage_meta VALUES('instance_key',lower(hex(randomblob(16))));
CREATE TABLE IF NOT EXISTS usage_cycle(
 account_key TEXT NOT NULL,cycle_start INTEGER NOT NULL,cycle_end INTEGER,
 revision TEXT NOT NULL,limit_bytes TEXT,settled TEXT NOT NULL,reserved TEXT NOT NULL,
 uncertain TEXT NOT NULL,additional TEXT NOT NULL,PRIMARY KEY(account_key,cycle_start));
CREATE TABLE IF NOT EXISTS usage_schedule(
 account_key TEXT PRIMARY KEY,current_start INTEGER NOT NULL,current_end INTEGER,
 active_kind INTEGER NOT NULL,active_offset INTEGER NOT NULL,pending_kind INTEGER NOT NULL,pending_offset INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS usage_reservation(
 id TEXT PRIMARY KEY,request_key TEXT NOT NULL UNIQUE,account_key TEXT NOT NULL,
 cycle_start INTEGER NOT NULL,cycle_end INTEGER,original_bytes TEXT NOT NULL,
 requested_bytes TEXT NOT NULL,outstanding_limit TEXT NOT NULL,consumed TEXT NOT NULL,
 state INTEGER NOT NULL,revision TEXT NOT NULL,limit_bytes TEXT);
CREATE INDEX IF NOT EXISTS usage_reservation_account ON usage_reservation(account_key,state);
CREATE TABLE IF NOT EXISTS usage_adjustment(
 request_key TEXT PRIMARY KEY,account_key TEXT NOT NULL,cycle_start INTEGER NOT NULL,
 cycle_end INTEGER,kind INTEGER NOT NULL,bytes TEXT NOT NULL,expected_revision TEXT NOT NULL,
 reason TEXT NOT NULL,limit_bytes TEXT,result_revision TEXT NOT NULL,result_settled TEXT NOT NULL,
 result_reserved TEXT NOT NULL,result_uncertain TEXT NOT NULL,result_additional TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS command_journal(
 request_key TEXT PRIMARY KEY,payload TEXT NOT NULL,operation_id TEXT NOT NULL UNIQUE,
 incarnation TEXT NOT NULL,target TEXT NOT NULL,state TEXT NOT NULL,accepted_at INTEGER NOT NULL,
 completed_at INTEGER,result TEXT NOT NULL);
PRAGMA user_version=1;
)sql");
        RecoverReservations();
        Ledger_.Execute("UPDATE command_journal SET state='interrupted',result='process_restarted' WHERE state='accepted'");
        Transaction.Commit();
    }

    auto StorageRuntime::RecoverReservations() -> void
    {
        auto Query = Ledger_.Prepare("SELECT id,account_key,cycle_start,original_bytes,consumed FROM usage_reservation WHERE state=0");
        std::vector<std::tuple<std::string, std::string, std::int64_t, std::uint64_t>> Rows;
        while (Query.Step())
        {
            if (Query.Uint(3) < Query.Uint(4)) throw Prism::Storage::SqliteError(SQLITE_CORRUPT);
            Rows.emplace_back(Query.String(0), Query.String(1), Query.Signed(2), Query.Uint(3) - Query.Uint(4));
        }
        for (const auto& Row : Rows) RecoverReservation(Row);
    }

    auto StorageRuntime::RecoverReservation(
        const std::tuple<std::string, std::string, std::int64_t, std::uint64_t>& Row) -> void
    {
        const auto& [Identity, Account, Start, Remaining] = Row;
        auto Cycle = Ledger_.Prepare("SELECT reserved,uncertain,revision FROM usage_cycle WHERE account_key=? AND cycle_start=?");
        Cycle.Text(1, Account); Cycle.Integer(2, Start);
        if (!Cycle.Step() || Cycle.Uint(0) < Remaining) throw Prism::Storage::SqliteError(SQLITE_CORRUPT);
        auto Update = Ledger_.Prepare("UPDATE usage_cycle SET reserved=?,uncertain=?,revision=? WHERE account_key=? AND cycle_start=?");
        Update.Unsigned(1, Cycle.Uint(0) - Remaining);
        Update.Unsigned(2, Prism::Storage::AddExact(Cycle.Uint(1), Remaining));
        Update.Unsigned(3, Prism::Storage::AddExact(Cycle.Uint(2), 1));
        Update.Text(4, Account); Update.Integer(5, Start); Update.Run();
        auto Reservation = Ledger_.Prepare("UPDATE usage_reservation SET state=2 WHERE id=?");
        Reservation.Text(1, Identity); Reservation.Run();
    }

    auto StorageRuntime::InitializeHistory() -> void
    {
        Prism::Storage::Transaction Transaction(History_);
        History_.Execute(R"sql(
CREATE TABLE IF NOT EXISTS history_record(
 scope INTEGER NOT NULL,resource_key TEXT NOT NULL,instance_key TEXT NOT NULL,incarnation TEXT NOT NULL,
 generation TEXT NOT NULL,time INTEGER NOT NULL,resolution INTEGER NOT NULL,up TEXT NOT NULL,
 down TEXT NOT NULL,events TEXT NOT NULL,errors TEXT NOT NULL,active TEXT,latency TEXT NOT NULL,
 maximum TEXT NOT NULL,range_exceeded TEXT NOT NULL,dropped TEXT NOT NULL,aggregation_failures TEXT NOT NULL,
 incomplete INTEGER NOT NULL,PRIMARY KEY(scope,resource_key,instance_key,incarnation,generation,time,resolution));
CREATE INDEX IF NOT EXISTS history_time ON history_record(scope,resource_key,resolution,time);
CREATE TABLE IF NOT EXISTS history_gap(from_time INTEGER NOT NULL,to_time INTEGER NOT NULL,reason TEXT NOT NULL,
 PRIMARY KEY(from_time,to_time,reason));
PRAGMA user_version=1;
)sql");
        Transaction.Commit();
    }
} // namespace Prism::Application::Storage

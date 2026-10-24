/**
 * @file CommandJournal.cpp
 * @brief 管理命令持久日志的 SQLite 实现。
 */

#include <Prism/Application/Storage/CommandJournal.hpp>
#include <Prism/Application/Storage/StorageRuntime.hpp>

#include <stdexcept>
#include <utility>

namespace Prism::Application::Storage
{
    CommandJournal::CommandJournal(std::shared_ptr<StorageRuntime> Owner)
        : Owner_(std::move(Owner))
    {
        if (!Owner_) throw std::invalid_argument("storage owner required");
    }

    auto CommandJournal::Claim(CommandClaim Request)
        -> boost::asio::awaitable<std::expected<CommandRecord, Fault::Failure>>
    {
        const auto Owner = Owner_;
        co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
            { return CommandJournal::ClaimOnStorage(*Owner, Request); });
    }

    auto CommandJournal::Complete(CommandCompletion Request)
        -> boost::asio::awaitable<std::expected<CommandRecord, Fault::Failure>>
    {
        const auto Owner = Owner_;
        co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
            { return CommandJournal::CompleteOnStorage(*Owner, Request); });
    }

    auto CommandJournal::Read(CommandLookup Request)
        -> boost::asio::awaitable<std::expected<CommandRecord, Fault::Failure>>
    {
        const auto Owner = Owner_;
        co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
            { return CommandJournal::ReadOnStorage(Owner->Ledger(), Request); });
    }

    auto CommandJournal::Decode(const Prism::Storage::Statement& Row) -> CommandRecord
    {
        return {Row.String(0), Row.String(1), Row.String(2), Row.String(3), Row.String(4), Row.String(5),
            Row.Signed(6), Row.IsNull(7) ? std::optional<std::int64_t>{} : Row.Signed(7), Row.String(8), false};
    }

    auto CommandJournal::ReadOnStorage(Prism::Storage::Database& Database,
                                       const CommandLookup& Request)
        -> std::expected<CommandRecord, Fault::Failure>
    {
        if (Request.RequestKey.empty() == Request.OperationId.empty())
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        auto Query = Database.Prepare(Request.RequestKey.empty() ?
            "SELECT * FROM command_journal WHERE operation_id=?" :
            "SELECT * FROM command_journal WHERE request_key=?");
        Query.Text(1, Request.RequestKey.empty() ? Request.OperationId : Request.RequestKey);
        if (!Query.Step()) return std::unexpected(Fault::Failure{Fault::Code::Eof});
        return Decode(Query);
    }

    auto CommandJournal::ClaimOnStorage(StorageRuntime& Owner, const CommandClaim& Request)
        -> std::expected<CommandRecord, Fault::Failure>
    {
        if (Request.RequestKey.empty() || Request.Payload.empty() || Request.OperationId.empty() || Request.Target.empty())
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        if (Request.ExpectedIncarnation != Owner.Incarnation())
            return std::unexpected(Fault::Failure{Fault::Code::ReplayDetected});
        auto& Database = Owner.Ledger();
        Prism::Storage::Transaction Transaction(Database);
        auto Existing = ReadOnStorage(Database, {Request.RequestKey, {}});
        if (Existing)
        {
            if (Existing->Payload != Request.Payload || Existing->Target != Request.Target)
                return std::unexpected(Fault::Failure{Fault::Code::ReplayDetected});
            return Existing;
        }
        if (Existing.error().Code != Fault::Code::Eof) return std::unexpected(Existing.error());
        auto Insert = Database.Prepare("INSERT INTO command_journal VALUES(?,?,?,?,?,'accepted',?,NULL,'')");
        Insert.Text(1, Request.RequestKey); Insert.Text(2, Request.Payload); Insert.Text(3, Request.OperationId);
        Insert.Text(4, Owner.Incarnation()); Insert.Text(5, Request.Target); Insert.Integer(6, Request.Timestamp);
        Insert.Run();
        Transaction.Commit();
        return CommandRecord{Request.RequestKey, Request.Payload, Request.OperationId, Owner.Incarnation(),
            Request.Target, "accepted", Request.Timestamp, {}, {}, true};
    }

    auto CommandJournal::Terminal(std::string_view State) -> bool
    {
        return State == "completed" || State == "rejected" || State == "unavailable" || State == "failed" ||
            State == "timed_out" || State == "blocked" || State == "restart_required" || State == "conflict" ||
            State == "invalid";
    }

    auto CommandJournal::CompleteOnStorage(StorageRuntime& Owner, const CommandCompletion& Request)
        -> std::expected<CommandRecord, Fault::Failure>
    {
        if (!Terminal(Request.State)) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
        auto& Database = Owner.Ledger();
        Prism::Storage::Transaction Transaction(Database);
        auto Existing = ReadOnStorage(Database, {{}, Request.OperationId});
        if (!Existing) return std::unexpected(Existing.error());
        if (Existing->State != "accepted")
        {
            if (Existing->State == Request.State && Existing->Result == Request.Result) return Existing;
            return std::unexpected(Fault::Failure{Fault::Code::ReplayDetected});
        }
        if (Existing->Incarnation != Owner.Incarnation() || Request.Timestamp < Existing->AcceptedAt)
            return std::unexpected(Fault::Failure{Fault::Code::ReplayDetected});
        auto Update = Database.Prepare("UPDATE command_journal SET state=?,completed_at=?,result=? WHERE operation_id=?");
        Update.Text(1, Request.State); Update.Integer(2, Request.Timestamp); Update.Text(3, Request.Result);
        Update.Text(4, Request.OperationId); Update.Run();
        Transaction.Commit();
        Existing->State = Request.State; Existing->CompletedAt = Request.Timestamp; Existing->Result = Request.Result;
        return Existing;
    }
} // namespace Prism::Application::Storage

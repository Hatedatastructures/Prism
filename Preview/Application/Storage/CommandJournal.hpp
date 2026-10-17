/** @file CommandJournal.hpp @brief 管理意图先持久受理、幂等恢复和重启后的明确中断状态。 */
#pragma once
#include <Preview/Application/Storage/StorageRuntime.hpp>
#include <optional>

namespace Preview::Application::Storage
{
    struct CommandRecord final
    {
        std::string RequestKey;
        std::string Payload;
        std::string OperationId;
        std::string Incarnation;
        std::string Target;
        std::string State;
        std::int64_t AcceptedAt{0};
        std::optional<std::int64_t> CompletedAt;
        std::string Result;
        bool Execute{false}; ///< 仅新持久受理为 true，重复请求或重启恢复绝不重新执行。
    };
    struct CommandClaim final
    {
        std::string RequestKey;
        std::string Payload; ///< 路由正规化后的完整命令，不包含凭据或令牌。
        std::string OperationId;
        std::string ExpectedIncarnation;
        std::string Target;
        std::int64_t Timestamp{0};
    };
    struct CommandCompletion final
    {
        std::string OperationId;
        std::string State;
        std::string Result;
        std::int64_t Timestamp{0};
    };
    struct CommandLookup final
    {
        std::string RequestKey;
        std::string OperationId;
    };
    /** @brief journal 拥有 storage，SQL 只在独立执行域；这里只记录事实，不执行管理副作用。 */
    class CommandJournal final
    {
    public:
        explicit CommandJournal(std::shared_ptr<StorageRuntime> Owner) : Owner_(std::move(Owner))
        { if (!Owner_) throw std::invalid_argument("storage owner required"); }
        [[nodiscard]] auto Claim(CommandClaim Request)
            -> boost::asio::awaitable<std::expected<CommandRecord, Fault::Failure>>
        {
            const auto Owner = Owner_;
            co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
                { return ClaimOnStorage(*Owner, Request); });
        }
        [[nodiscard]] auto Complete(CommandCompletion Request)
            -> boost::asio::awaitable<std::expected<CommandRecord, Fault::Failure>>
        {
            const auto Owner = Owner_;
            co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
                { return CompleteOnStorage(*Owner, Request); });
        }
        [[nodiscard]] auto Read(CommandLookup Request)
            -> boost::asio::awaitable<std::expected<CommandRecord, Fault::Failure>>
        {
            const auto Owner = Owner_;
            co_return co_await Owner->Domain()->Execute([Owner, Request = std::move(Request)]()
                { return ReadOnStorage(Owner->Ledger(), Request); });
        }
    private:
        static auto Decode(const Preview::Storage::Statement& Row) -> CommandRecord
        {
            return {Row.String(0), Row.String(1), Row.String(2), Row.String(3), Row.String(4), Row.String(5),
                Row.Signed(6), Row.IsNull(7) ? std::optional<std::int64_t>{} : Row.Signed(7), Row.String(8), false};
        }
        static auto ReadOnStorage(Preview::Storage::Database& Database, const CommandLookup& Request)
            -> std::expected<CommandRecord, Fault::Failure>
        {
            if (Request.RequestKey.empty() == Request.OperationId.empty())
                return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            auto Query = Database.Prepare(Request.RequestKey.empty() ?
                "SELECT * FROM command_journal WHERE operation_id=?" : "SELECT * FROM command_journal WHERE request_key=?");
            Query.Text(1, Request.RequestKey.empty() ? Request.OperationId : Request.RequestKey);
            if (!Query.Step()) return std::unexpected(Fault::Failure{Fault::Code::Eof});
            return Decode(Query);
        }
        static auto ClaimOnStorage(StorageRuntime& Owner, const CommandClaim& Request)
            -> std::expected<CommandRecord, Fault::Failure>
        {
            if (Request.RequestKey.empty() || Request.Payload.empty() || Request.OperationId.empty() || Request.Target.empty())
                return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            if (Request.ExpectedIncarnation != Owner.Incarnation())
                return std::unexpected(Fault::Failure{Fault::Code::ReplayDetected});
            auto& Database = Owner.Ledger();
            Preview::Storage::Transaction Transaction(Database);
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
        static auto Terminal(std::string_view State) -> bool
        {
            return State == "completed" || State == "rejected" || State == "unavailable" || State == "failed" ||
                State == "timed_out" || State == "blocked" || State == "restart_required" || State == "conflict" ||
                State == "invalid";
        }
        static auto CompleteOnStorage(StorageRuntime& Owner, const CommandCompletion& Request)
            -> std::expected<CommandRecord, Fault::Failure>
        {
            if (!Terminal(Request.State)) return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument});
            auto& Database = Owner.Ledger();
            Preview::Storage::Transaction Transaction(Database);
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
        std::shared_ptr<StorageRuntime> Owner_;
    };
}

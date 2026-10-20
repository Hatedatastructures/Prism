/** @file CommandJournal.hpp @brief 管理意图先持久受理、幂等恢复和重启后的明确中断状态。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Storage/Sqlite.hpp>
#include <boost/asio/awaitable.hpp>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace Prism::Application::Storage
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
    class StorageRuntime;

    /** @brief journal 拥有 storage，SQL 只在独立执行域；这里只记录事实，不执行管理副作用。 */
    class CommandJournal final
    {
    public:
        explicit CommandJournal(std::shared_ptr<StorageRuntime> Owner);
        [[nodiscard]] auto Claim(CommandClaim Request)
            -> boost::asio::awaitable<std::expected<CommandRecord, Fault::Failure>>;
        [[nodiscard]] auto Complete(CommandCompletion Request)
            -> boost::asio::awaitable<std::expected<CommandRecord, Fault::Failure>>;
        [[nodiscard]] auto Read(CommandLookup Request)
            -> boost::asio::awaitable<std::expected<CommandRecord, Fault::Failure>>;
    private:
        static auto Decode(const Prism::Storage::Statement& Row) -> CommandRecord;
        static auto ReadOnStorage(Prism::Storage::Database& Database, const CommandLookup& Request)
            -> std::expected<CommandRecord, Fault::Failure>;
        static auto ClaimOnStorage(StorageRuntime& Owner, const CommandClaim& Request)
            -> std::expected<CommandRecord, Fault::Failure>;
        static auto Terminal(std::string_view State) -> bool;
        static auto CompleteOnStorage(StorageRuntime& Owner, const CommandCompletion& Request)
            -> std::expected<CommandRecord, Fault::Failure>;
        std::shared_ptr<StorageRuntime> Owner_;
    };
}

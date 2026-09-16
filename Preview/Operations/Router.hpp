/**
 * @file Router.hpp
 * @brief Preview 管理面 typed 查询、命令和异步 Operation 路由。
 * @details Router 只处理值模型。所有可变路由状态在独立 strand 上访问，
 *          因此管理面不会把 handler、快照或控制器引用暴露给调用方。
 */

#pragma once

#include <Preview/Operations/Models.hpp>
#include <Preview/Operations/Redaction.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace Preview::Operations
{

    namespace Net = boost::asio;

    /** @brief 独立管理面监听端点的值配置；实际 HTTP listener 由外层单独拥有。 */
    struct ManagementEndpoint final
    {
        std::string Address{"127.0.0.1"};
        std::uint16_t Port{9090};
    };

    /** @brief typed in-process router 的冷路径配置。 */
    struct RouterOptions final
    {
        ManagementEndpoint Endpoint{};
        std::size_t MaxOperations{1024};
    };

    namespace Detail
    {

        template <typename Value>
        struct IsPage : std::false_type
        {
        };

        template <typename Value>
        struct IsPage<Page<Value>> : std::true_type
        {
        };

        template <typename Value>
        [[nodiscard]] auto CursorOf(const Value &ValueObject) noexcept -> std::uint64_t
        {
            if constexpr (std::is_same_v<std::remove_cvref_t<Value>, EventSnapshot>)
            {
                return ValueObject.Sequence;
            }
            else
            {
                return ValueObject.Id.Value();
            }
        }

        template <typename Value>
        [[nodiscard]] auto NormalizePage(Page<Value> ValuePage,
                                          const std::uint64_t Cursor,
                                          const std::size_t Limit) -> Page<Value>
        {
            Page<Value> Result;
            Result.HasMore = ValuePage.HasMore;
            for (auto &Item : ValuePage.Items)
            {
                if (CursorOf(Item) <= Cursor)
                {
                    continue;
                }
                if (Limit == 0)
                {
                    Result.HasMore = true;
                    break;
                }
                if (Result.Items.size() >= Limit)
                {
                    Result.HasMore = true;
                    break;
                }
                Result.Items.push_back(std::move(Item));
            }

            if (Result.Items.empty())
            {
                Result.NextCursor = Cursor;
            }
            else
            {
                Result.NextCursor = CursorOf(Result.Items.back());
            }
            return Result;
        }

        [[nodiscard]] inline auto PageBounds(const Query &QueryValue)
            -> std::optional<std::pair<std::uint64_t, std::size_t>>
        {
            return std::visit(
                [](const auto &ValueObject)
                    -> std::optional<std::pair<std::uint64_t, std::size_t>>
                {
                    if constexpr (requires { ValueObject.Page.Cursor; ValueObject.Page.Limit; })
                    {
                        return std::pair{ValueObject.Page.Cursor, ValueObject.Page.BoundedLimit()};
                    }
                    else
                    {
                        return std::nullopt;
                    }
                },
                QueryValue.Value);
        }

        [[nodiscard]] inline auto NormalizeQueryResult(const Query &QueryValue,
                                                        QueryResult Result) -> QueryResult
        {
            const auto Bounds = PageBounds(QueryValue);
            if (!Bounds)
            {
                return Result;
            }

            std::visit(
                [&Bounds](auto &Payload)
                {
                    using PayloadType = std::remove_cvref_t<decltype(Payload)>;
                    if constexpr (IsPage<PayloadType>::value)
                    {
                        Payload = NormalizePage(std::move(Payload), Bounds->first, Bounds->second);
                    }
                },
                Result.Value);

            const auto *EventQueryValue = std::get_if<EventQuery>(&QueryValue.Value);
            if (EventQueryValue != nullptr && !EventQueryValue->IncludeDetails)
            {
                std::visit(
                    [](auto &Payload)
                    {
                        using PayloadType = std::remove_cvref_t<decltype(Payload)>;
                        if constexpr (std::is_same_v<PayloadType, Page<EventSnapshot>>)
                        {
                            for (auto &EventValue : Payload.Items)
                            {
                                EventValue.Detail.clear();
                            }
                        }
                    },
                    Result.Value);
            }
            return Result;
        }

        struct State final
        {
            State(Net::any_io_executor Executor,
                  RouterOptions OptionsValue,
                  std::function<QueryResult(const Query &)> QueryValue,
                  std::function<CommandResult(const Command &)> CommandValue)
                : Strand_(Net::make_strand(std::move(Executor))),
                  Configuration_(std::move(OptionsValue)),
                  QueryHandler_(std::move(QueryValue)),
                  CommandHandler_(std::move(CommandValue))
            {
                if (Configuration_.MaxOperations == 0)
                {
                    Configuration_.MaxOperations = 1;
                }
            }

            Net::strand<Net::any_io_executor> Strand_;
            RouterOptions Configuration_;
            std::function<QueryResult(const Query &)> QueryHandler_;
            std::function<CommandResult(const Command &)> CommandHandler_;
            std::map<std::uint64_t, CommandResult> Operations_;
            std::uint64_t NextOperation_{1};
        };

        [[nodiscard]] inline auto AllocateOperation(State &StateValue)
            -> std::optional<OperationId>
        {
            while (StateValue.Operations_.size() >= StateValue.Configuration_.MaxOperations)
            {
                const auto It = std::find_if(
                    StateValue.Operations_.begin(), StateValue.Operations_.end(),
                    [](const auto &Entry)
                    { return Entry.second.Status != CommandStatus::Accepted; });
                if (It == StateValue.Operations_.end())
                {
                    return std::nullopt;
                }
                StateValue.Operations_.erase(It);
            }

            auto Value = StateValue.NextOperation_++;
            if (Value == 0)
            {
                Value = StateValue.NextOperation_++;
            }
            return OperationId{Value};
        }

        [[nodiscard]] inline auto CompleteOperation(State &StateValue,
                                                     const OperationId Operation,
                                                     CommandResult Result) -> bool
        {
            if (!Operation)
            {
                return false;
            }
            const auto It = StateValue.Operations_.find(Operation.Value());
            if (It == StateValue.Operations_.end() ||
                It->second.Status != CommandStatus::Accepted ||
                Result.Status == CommandStatus::Accepted)
            {
                return false;
            }

            Result.Correlation = It->second.Correlation;
            Result.Operation = Operation;
            It->second = Redact(std::move(Result));
            return true;
        }

    } // namespace Detail

    /**
     * @class Router
     * @brief 独立 executor 上运行的 typed Operations 路由器。
     * @details 查询 handler 和命令 handler 都在 router strand 上调用；命令
     *          返回 Accepted 时生成 OperationId，外部通过 Complete/Status
     *          交换值结果。该类不提供 HTTP 解析或 listener 所有权。
     */
    class Router final
    {
    public:
        using QueryHandler = std::function<QueryResult(const Query &)>;
        using CommandHandler = std::function<CommandResult(const Command &)>;

        explicit Router(Net::any_io_executor Executor, RouterOptions Options = {})
            : State_(std::make_shared<Detail::State>(std::move(Executor),
                                                      std::move(Options),
                                                      QueryHandler{},
                                                      CommandHandler{}))
        {
        }

        Router(Net::any_io_executor Executor,
               QueryHandler QueryValue,
               CommandHandler CommandValue = {},
               RouterOptions Options = {})
            : State_(std::make_shared<Detail::State>(std::move(Executor),
                                                      std::move(Options),
                                                      std::move(QueryValue),
                                                      std::move(CommandValue)))
        {
        }

        Router(const Router &) = default;
        auto operator=(const Router &) -> Router & = default;
        Router(Router &&) noexcept = default;
        auto operator=(Router &&) noexcept -> Router & = default;

        auto SetQueryHandler(QueryHandler Handler) -> void
        {
            const auto StateValue = State_;
            Net::post(StateValue->Strand_,
                      [StateValue, Handler = std::move(Handler)]() mutable
                      { StateValue->QueryHandler_ = std::move(Handler); });
        }

        auto SetCommandHandler(CommandHandler Handler) -> void
        {
            const auto StateValue = State_;
            Net::post(StateValue->Strand_,
                      [StateValue, Handler = std::move(Handler)]() mutable
                      { StateValue->CommandHandler_ = std::move(Handler); });
        }

        [[nodiscard]] auto Endpoint() const -> ManagementEndpoint
        {
            return State_->Configuration_.Endpoint;
        }

        [[nodiscard]] auto QueryAsync(Query QueryValue) const -> Net::awaitable<QueryResult>
        {
            const auto StateValue = State_;
            co_await Net::post(StateValue->Strand_, Net::use_awaitable);

            const auto Correlation = CorrelationOf(QueryValue);
            if (!StateValue->QueryHandler_)
            {
                co_return QueryResult::Unavailable(Correlation);
            }

            try
            {
                auto Result = StateValue->QueryHandler_(QueryValue);
                Result.Correlation = Correlation;
                Result = Detail::NormalizeQueryResult(QueryValue, std::move(Result));
                co_return Redact(std::move(Result));
            }
            catch (...)
            {
                co_return QueryResult::Failed(Correlation);
            }
        }

        [[nodiscard]] auto ExecuteAsync(Command CommandValue) const
            -> Net::awaitable<CommandResult>
        {
            const auto StateValue = State_;
            co_await Net::post(StateValue->Strand_, Net::use_awaitable);

            const auto Correlation = CorrelationOf(CommandValue);
            if (!StateValue->CommandHandler_)
            {
                co_return CommandResult::Unavailable(Correlation);
            }

            const auto Operation = Detail::AllocateOperation(*StateValue);
            if (!Operation)
            {
                auto Rejected = CommandResult::Rejected(Correlation);
                Rejected.Message = "operation_limit";
                co_return Redact(std::move(Rejected));
            }

            CommandResult Result;
            try
            {
                Result = StateValue->CommandHandler_(CommandValue);
            }
            catch (...)
            {
                co_return CommandResult::Failed(Correlation);
            }

            Result.Correlation = Correlation;
            Result = Redact(std::move(Result));
            if (Result.Status == CommandStatus::Accepted)
            {
                Result.Operation = *Operation;
                StateValue->Operations_.emplace(Operation->Value(), Result);
            }
            co_return Result;
        }

        [[nodiscard]] auto StatusAsync(const OperationId Operation,
                                       const Preview::RequestId Correlation = {}) const
            -> Net::awaitable<CommandResult>
        {
            const auto StateValue = State_;
            co_await Net::post(StateValue->Strand_, Net::use_awaitable);

            if (!Operation)
            {
                co_return CommandResult::Invalid(Correlation);
            }
            const auto It = StateValue->Operations_.find(Operation.Value());
            if (It == StateValue->Operations_.end())
            {
                co_return CommandResult::Invalid(Correlation);
            }

            auto Result = It->second;
            if (Correlation)
            {
                Result.Correlation = Correlation;
            }
            co_return Redact(std::move(Result));
        }

        [[nodiscard]] auto CompleteAsync(const OperationId Operation,
                                         CommandResult Result) const -> Net::awaitable<bool>
        {
            const auto StateValue = State_;
            co_await Net::post(StateValue->Strand_, Net::use_awaitable);
            co_return Detail::CompleteOperation(*StateValue, Operation, std::move(Result));
        }

        auto Complete(const OperationId Operation, CommandResult Result) const -> void
        {
            const auto StateValue = State_;
            Net::post(StateValue->Strand_,
                      [StateValue, Operation, Result = std::move(Result)]() mutable
                      { (void)Detail::CompleteOperation(*StateValue, Operation, std::move(Result)); });
        }

    private:
        std::shared_ptr<Detail::State> State_;
    };

    using OperationsRouter = Router;

} // namespace Preview::Operations

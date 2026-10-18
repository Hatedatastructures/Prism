/**
 * @file Router.hpp
 * @brief Prism 管理面 typed 查询、命令和异步 Operation 路由。
 * @details Router 只处理值模型。所有可变路由状态在独立 strand 上访问，
 *          因此管理面不会把 handler、快照或控制器引用暴露给调用方。
 */

#pragma once
#include <Prism/Operations/OperationPublicationReceipt.hpp>

#include <Prism/Operations/Models.hpp>
#include <Prism/Operations/Redaction.hpp>
#include <Prism/Operations/ResponseDeliveryReceipt.hpp>
#include <Prism/Operations/QueryNormalization.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>

namespace Prism::Operations
{

    namespace Net = boost::asio;
    namespace Detail
    {
        struct State;
    }

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

    /**
     * @brief 一个已登记 Accepted 命令的唯一终态 owner。
     * @details Router 在调用命令 handler 前创建并登记 OperationId；真实业务 owner
     *          只持有此值句柄并提交终态，不拥有 Router、HTTP connection 或业务数据面。
     */
    class OperationCompletion final
    {
    public:
        using Deadline = ResponseDeliveryReceipt::Deadline;

        /** @brief 返回由 Router 预先登记的稳定 operation identity。 */
        [[nodiscard]] auto Id() const noexcept -> OperationId;

        /** @brief 提交真实终态；成功回执证明已提交，失败表示未提交，通知失败独立保留。 */
        [[nodiscard]] auto CompleteAsync(CommandResult Result) const
            -> Net::awaitable<std::expected<OperationPublicationReceipt, Prism::Fault::Failure>>;

        /** @brief 等待对应 HTTP 初始命令响应真实写完；失败只作为观察回执返回。 */
        [[nodiscard]] auto WaitForResponseDeliveryAsync(const Deadline Limit) const
            -> Net::awaitable<ResponseDeliveryReceipt::Outcome>;

        /** @brief 等待此前已接受的其它命令终态后再启动 ProcessDrain。 */
        [[nodiscard]] auto WaitForPriorOperationsAsync(const Deadline Limit) const
            -> Net::awaitable<ResponseDeliveryReceipt::Outcome>;

    private:
        friend class Router;

        OperationCompletion(std::weak_ptr<Detail::State> StateValue,
                            OperationId OperationValue,
                            ResponseDeliveryReceipt DeliveryValue)
            : State_(std::move(StateValue)),
              Operation_(OperationValue),
              Delivery_(std::move(DeliveryValue))
        {
        }

        std::weak_ptr<Detail::State> State_;
        OperationId Operation_{};
        ResponseDeliveryReceipt Delivery_;
    };

    /** @brief 同一管理路由的查询与命令绑定；冷构造按值接管，后续调用均在 router strand。 */
    struct RouterHandlers final
    {
        std::function<Net::awaitable<QueryResult>(Query)> Query;
        std::function<Net::awaitable<CommandResult>(Command, OperationCompletion)> Command;
    };

    namespace Detail
    {
        struct State final
        {
            State(Net::any_io_executor Executor,
                  RouterOptions OptionsValue,
                  RouterHandlers Handlers)
                : Strand_(Net::make_strand(std::move(Executor))),
                  OperationChangeTimer_(Strand_),
                  Configuration_(std::move(OptionsValue)),
                  QueryHandler_(std::move(Handlers.Query)),
                  CommandHandler_(std::move(Handlers.Command))
            {
                if (Configuration_.MaxOperations == 0)
                {
                    Configuration_.MaxOperations = 1;
                }
            }

            Net::strand<Net::any_io_executor> Strand_;
            Net::steady_timer OperationChangeTimer_;
            RouterOptions Configuration_;
            std::function<Net::awaitable<QueryResult>(Query)> QueryHandler_;
            std::function<Net::awaitable<CommandResult>(Command, OperationCompletion)> CommandHandler_;
            std::map<std::uint64_t, CommandResult> Operations_;
            std::uint64_t NextOperation_{1};
            bool OperationWaiterActive_{false};
            std::optional<Prism::Fault::Failure> OperationSignalFailure_;
        };

        [[nodiscard]] inline auto NotifyOperationWaiter(State &StateValue) noexcept -> bool
        {
            if (!StateValue.OperationWaiterActive_)
            {
                return true;
            }
            try
            {
                if (StateValue.OperationChangeTimer_.cancel() != 0U)
                {
                    return true;
                }
                StateValue.OperationSignalFailure_ =
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked};
            }
            catch (const boost::system::system_error &Error)
            {
                StateValue.OperationSignalFailure_ = Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code()));
            }
            catch (const std::system_error &Error)
            {
                StateValue.OperationSignalFailure_ = Prism::Fault::FromNative(Error.code());
            }
            catch (...)
            {
                StateValue.OperationSignalFailure_ =
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked};
            }
            return false;
        }
        [[nodiscard]] inline auto AllocateOperation(State &StateValue)
            -> std::optional<OperationId>
        {
            if (StateValue.NextOperation_ == 0U)
            {
                return std::nullopt;
            }
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

            const auto Value = StateValue.NextOperation_;
            if (Value == std::numeric_limits<std::uint64_t>::max())
            {
                StateValue.NextOperation_ = 0U;
            }
            else
            {
                ++StateValue.NextOperation_;
            }
            return OperationId{Value};
        }

        [[nodiscard]] inline auto CompleteOperation(State &StateValue,
                                                     const OperationId Operation,
                                                     CommandResult Result)
            -> std::expected<OperationPublicationReceipt, Prism::Fault::Failure>
        {
            if (!Operation)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            const auto It = StateValue.Operations_.find(Operation.Value());
            if (It == StateValue.Operations_.end() ||
                It->second.Status != CommandStatus::Accepted ||
                Result.Status == CommandStatus::Accepted ||
                Result.Status == CommandStatus::Rejected ||
                Result.Status == CommandStatus::Unavailable ||
                Result.Status == CommandStatus::Invalid)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            if (Result.Status == CommandStatus::Completed && Result.Failure.Failed())
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            if ((Result.Status == CommandStatus::Failed ||
                 Result.Status == CommandStatus::TimedOut ||
                 Result.Status == CommandStatus::Blocked) && !Result.Failure.Failed())
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }

            Result.Correlation = It->second.Correlation;
            Result.Operation = Operation;
            It->second = Redact(std::move(Result));
            if (!NotifyOperationWaiter(StateValue))
            {
                return OperationPublicationReceipt{StateValue.OperationSignalFailure_.value_or(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked})};
            }
            return OperationPublicationReceipt{};
        }

        /** @brief 在 Router owner strand 等待其它 Accepted 命令全部获得终态。 */
        [[nodiscard]] inline auto WaitForPriorOperations(
            const std::shared_ptr<State> &StateValue,
            const OperationId Operation,
            const OperationCompletion::Deadline Limit)
            -> Net::awaitable<ResponseDeliveryReceipt::Outcome>
        {
            if (StateValue->OperationWaiterActive_)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            StateValue->OperationWaiterActive_ = true;
            while (true)
            {
                if (StateValue->OperationSignalFailure_)
                {
                    StateValue->OperationWaiterActive_ = false;
                    co_return std::unexpected(*StateValue->OperationSignalFailure_);
                }
                const auto Pending = std::find_if(
                    StateValue->Operations_.begin(), StateValue->Operations_.end(),
                    [Operation](const auto &Entry)
                    {
                        return Entry.first != Operation.Value() &&
                               Entry.second.Status == CommandStatus::Accepted;
                    });
                if (Pending == StateValue->Operations_.end())
                {
                    StateValue->OperationWaiterActive_ = false;
                    co_return ResponseDeliveryReceipt::Outcome{};
                }
                if (std::chrono::steady_clock::now() >= Limit)
                {
                    StateValue->OperationWaiterActive_ = false;
                    co_return std::unexpected(Prism::Fault::Failure{
                        Prism::Fault::Code::Timeout,
                        std::make_error_code(std::errc::timed_out)});
                }
                StateValue->OperationChangeTimer_.expires_at(Limit);
                boost::system::error_code Error;
                co_await StateValue->OperationChangeTimer_.async_wait(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error && Error != Net::error::operation_aborted)
                {
                    StateValue->OperationWaiterActive_ = false;
                    co_return std::unexpected(Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error)));
                }
                if (!Error)
                {
                    StateValue->OperationWaiterActive_ = false;
                    co_return std::unexpected(Prism::Fault::Failure{
                        Prism::Fault::Code::Timeout,
                        std::make_error_code(std::errc::timed_out)});
                }
            }
        }

        /** @brief 在 Router owner strand 提交一份真实 operation 终态。 */
        [[nodiscard]] inline auto CompleteOperationOnStrand(
            const std::shared_ptr<State> &StateValue,
            const OperationId Operation,
            CommandResult Result)
            -> Net::awaitable<std::expected<OperationPublicationReceipt, Prism::Fault::Failure>>
        {
            co_return CompleteOperation(*StateValue, Operation, std::move(Result));
        }

    } // namespace Detail

    inline auto OperationCompletion::Id() const noexcept -> OperationId
    {
        return Operation_;
    }

    inline auto OperationCompletion::CompleteAsync(CommandResult Result) const
        -> Net::awaitable<std::expected<OperationPublicationReceipt, Prism::Fault::Failure>>
    {
        const auto StateValue = State_.lock();
        if (!StateValue)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_await Net::this_coro::throw_if_cancelled(false);
        co_return co_await Net::co_spawn(StateValue->Strand_,
            Detail::CompleteOperationOnStrand(
                StateValue, Operation_, std::move(Result)), Net::use_awaitable);
    }

    inline auto OperationCompletion::WaitForResponseDeliveryAsync(const Deadline Limit) const
        -> Net::awaitable<ResponseDeliveryReceipt::Outcome>
    {
        co_return co_await Delivery_.WaitAsync(Limit);
    }

    inline auto OperationCompletion::WaitForPriorOperationsAsync(const Deadline Limit) const
        -> Net::awaitable<ResponseDeliveryReceipt::Outcome>
    {
        const auto StateValue = State_.lock();
        if (!StateValue)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_await Net::this_coro::throw_if_cancelled(false);
        co_return co_await Net::co_spawn(StateValue->Strand_,
            Detail::WaitForPriorOperations(StateValue, Operation_, Limit),
            Net::use_awaitable);
    }

    /**
     * @class Router
     * @brief 独立 executor 上运行的 typed Operations 路由器。
     * @details 查询 handler 和命令 handler 都在 router strand 上调用。命令 handler
     *          收到预先登记的 OperationCompletion；实际业务 owner 只能通过该句柄提交
     *          终态。该类不提供 HTTP 解析或 listener 所有权。
     */
    class Router final
    {
    public:
        using QueryHandler = std::function<Net::awaitable<QueryResult>(Query)>;
        using CommandHandler =
            std::function<Net::awaitable<CommandResult>(Command, OperationCompletion)>;

        /** @brief 在独立 strand 构造路由；接管绑定与配置，未绑定操作返回 unavailable。 */
        Router(Net::any_io_executor Executor,
               RouterHandlers Handlers = {},
               RouterOptions Options = {})
            : State_(std::make_shared<Detail::State>(std::move(Executor),
                                                      std::move(Options),
                                                      std::move(Handlers)))
        {
        }

        Router(const Router &Other) noexcept : State_(Other.State_)
        {
        }

        auto operator=(const Router &Other) noexcept -> Router &
        {
            if (this != &Other)
            {
                State_ = Other.State_;
            }
            return *this;
        }

        Router(Router &&Other) noexcept : State_(std::exchange(Other.State_, {}))
        {
        }

        auto operator=(Router &&Other) noexcept -> Router &
        {
            if (this != &Other)
            {
                State_ = std::exchange(Other.State_, {});
            }
            return *this;
        }

        [[nodiscard]] auto Endpoint() const -> ManagementEndpoint
        {
            return State_->Configuration_.Endpoint;
        }

        [[nodiscard]] auto QueryAsync(Query QueryValue) const -> Net::awaitable<QueryResult>
        {
            const auto StateValue = State_;
            co_return co_await Net::co_spawn(StateValue->Strand_,
                QueryOnStrand(StateValue, std::move(QueryValue)), Net::use_awaitable);
        }

        [[nodiscard]] auto ExecuteAsync(Command CommandValue,
                                        ResponseDeliveryReceipt Delivery) const
            -> Net::awaitable<CommandResult>
        {
            const auto StateValue = State_;
            co_return co_await Net::co_spawn(StateValue->Strand_,
                ExecuteOnStrand(StateValue, std::move(CommandValue), std::move(Delivery)),
                Net::use_awaitable);
        }

        [[nodiscard]] auto StatusAsync(const OperationId Operation,
                                       const Prism::RequestId Correlation = {}) const
            -> Net::awaitable<CommandResult>
        {
            const auto StateValue = State_;
            co_return co_await Net::co_spawn(StateValue->Strand_,
                StatusOnStrand(StateValue, Operation, Correlation), Net::use_awaitable);
        }

    private:
        [[nodiscard]] static auto QueryFailureFromException(
            const std::exception_ptr Error) noexcept -> Prism::Fault::Failure
        {
            try
            {
                if (Error) std::rethrow_exception(Error);
            }
            catch (const boost::system::system_error &Native)
            {
                return Prism::Fault::FromNative(
                    static_cast<std::error_code>(Native.code()));
            }
            catch (const std::system_error &Native)
            {
                return Prism::Fault::FromNative(Native.code());
            }
            catch (...)
            {
                return {Prism::Fault::Code::IoError};
            }
            return {Prism::Fault::Code::IoError};
        }

        [[nodiscard]] static auto QueryOnStrand(
            const std::shared_ptr<Detail::State> &StateValue,
            Query QueryValue) -> Net::awaitable<QueryResult>
        {
            const auto Correlation = CorrelationOf(QueryValue);
            if (!StateValue->QueryHandler_)
            {
                co_return QueryResult::Unavailable(Correlation);
            }
            try
            {
                auto Result = co_await StateValue->QueryHandler_(std::move(QueryValue));
                Result.Correlation = Correlation;
                Result = Detail::NormalizeQueryResult(QueryValue, std::move(Result));
                co_return Redact(std::move(Result));
            }
            catch (...)
            {
                co_return QueryResult::Failed(
                    Correlation, QueryFailureFromException(std::current_exception()));
            }
        }

        [[nodiscard]] static auto ExecuteOnStrand(
            const std::shared_ptr<Detail::State> &StateValue,
            Command CommandValue,
            ResponseDeliveryReceipt Delivery) -> Net::awaitable<CommandResult>
        {
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
            auto Pending = CommandResult::Accepted(Correlation, *Operation);
            try
            {
                const auto [Entry, Inserted] =
                    StateValue->Operations_.emplace(Operation->Value(), Pending);
                (void)Entry;
                if (!Inserted)
                {
                    co_return CommandResult::Failed(Correlation,
                        Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
                }
            }
            catch (...)
            {
                co_return CommandResult::Failed(Correlation,
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
            }

            const OperationCompletion Completion{StateValue, *Operation, std::move(Delivery)};
            CommandResult Result;
            try
            {
                Result = co_await StateValue->CommandHandler_(std::move(CommandValue), Completion);
            }
            catch (...)
            {
                StateValue->Operations_.erase(Operation->Value());
                (void)Detail::NotifyOperationWaiter(*StateValue);
                co_return CommandResult::HandlerFailed(Correlation);
            }
            Result.Correlation = Correlation;
            Result = Redact(std::move(Result));
            if (Result.Status == CommandStatus::Accepted)
            {
                Result.Operation = *Operation;
                /** @brief 异步 owner 可能先发布终态；handler 返回 Accepted 不覆盖该回执。 */
                const auto It = StateValue->Operations_.find(Operation->Value());
                if (It != StateValue->Operations_.end() &&
                    It->second.Status == CommandStatus::Accepted)
                {
                    It->second = Result;
                }
            }
            else
            {
                StateValue->Operations_.erase(Operation->Value());
                Result.Operation = {};
            }
            co_return Result;
        }

        [[nodiscard]] static auto StatusOnStrand(
            const std::shared_ptr<Detail::State> &StateValue,
            const OperationId Operation,
            const Prism::RequestId Correlation) -> Net::awaitable<CommandResult>
        {
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

        std::shared_ptr<Detail::State> State_;
    };

} // namespace Prism::Operations

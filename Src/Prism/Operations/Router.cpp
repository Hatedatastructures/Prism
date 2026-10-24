/** @file Router.cpp @brief 类型化管理操作状态机的实现。 */
#include <Prism/Operations/Router.hpp>
#include <Prism/Operations/Detail/QueryNormalization.hpp>
#include <Prism/Operations/Detail/RouterState.hpp>

#include <boost/asio/error.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <chrono>
#include <limits>
#include <map>
#include <optional>
#include <system_error>
#include <utility>

namespace Prism::Operations
{
    namespace Detail
    {
        [[nodiscard]] auto NotifyOperationWaiter(State& StateValue) noexcept -> bool
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
            catch (const boost::system::system_error& Error)
            {
                StateValue.OperationSignalFailure_ = Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code()));
            }
            catch (const std::system_error& Error)
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

        [[nodiscard]] auto AllocateOperation(State& StateValue) -> std::optional<OperationId>
        {
            if (StateValue.NextOperation_ == 0U)
            {
                return std::nullopt;
            }
            while (StateValue.Operations_.size() >= StateValue.Configuration_.MaxOperations)
            {
                const auto It = std::find_if(
                    StateValue.Operations_.begin(), StateValue.Operations_.end(),
                    [](const auto& Entry)
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

        [[nodiscard]] auto CompleteOperation(
            State& StateValue,
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
        [[nodiscard]] auto WaitForPriorOperations(
            const std::shared_ptr<State>& StateValue,
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
                    [Operation](const auto& Entry)
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
        [[nodiscard]] auto CompleteOperationOnStrand(
            const std::shared_ptr<State>& StateValue,
            const OperationId Operation,
            CommandResult Result)
            -> Net::awaitable<std::expected<OperationPublicationReceipt, Prism::Fault::Failure>>
        {
            co_return CompleteOperation(*StateValue, Operation, std::move(Result));
        }
    }

    OperationCompletion::OperationCompletion(
        std::weak_ptr<Detail::State> StateValue,
        const OperationId OperationValue,
        ResponseDeliveryReceipt DeliveryValue)
        : State_(std::move(StateValue)),
          Operation_(OperationValue),
          Delivery_(std::move(DeliveryValue))
    {
    }

    auto OperationCompletion::CompleteAsync(CommandResult Result) const
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

    auto OperationCompletion::WaitForPriorOperationsAsync(const Deadline Limit) const
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

    Router::Router(
        Net::any_io_executor Executor,
        RouterHandlers Handlers,
        RouterOptions Options)
        : State_(std::make_shared<Detail::State>(
              std::move(Executor), std::move(Options), std::move(Handlers)))
    {
    }

    Router::Router(const Router& Other) noexcept : State_(Other.State_)
    {
    }

    auto Router::operator=(const Router& Other) noexcept -> Router&
    {
        if (this != &Other)
        {
            State_ = Other.State_;
        }
        return *this;
    }

    Router::Router(Router&& Other) noexcept : State_(std::exchange(Other.State_, {}))
    {
    }

    auto Router::operator=(Router&& Other) noexcept -> Router&
    {
        if (this != &Other)
        {
            State_ = std::exchange(Other.State_, {});
        }
        return *this;
    }

    auto Router::Endpoint() const -> ManagementEndpoint
    {
        return State_->Configuration_.Endpoint;
    }

    auto Router::QueryAsync(Query QueryValue) const -> Net::awaitable<QueryResult>
    {
        const auto StateValue = State_;
        co_return co_await Net::co_spawn(StateValue->Strand_,
            QueryOnStrand(StateValue, std::move(QueryValue)), Net::use_awaitable);
    }

    auto Router::ExecuteAsync(
        Command CommandValue,
        ResponseDeliveryReceipt Delivery) const -> Net::awaitable<CommandResult>
    {
        const auto StateValue = State_;
        co_return co_await Net::co_spawn(StateValue->Strand_,
            ExecuteOnStrand(StateValue, std::move(CommandValue), std::move(Delivery)),
            Net::use_awaitable);
    }

    auto Router::StatusAsync(
        const OperationId Operation,
        const Prism::RequestId Correlation) const -> Net::awaitable<CommandResult>
    {
        const auto StateValue = State_;
        co_return co_await Net::co_spawn(StateValue->Strand_,
            StatusOnStrand(StateValue, Operation, Correlation), Net::use_awaitable);
    }

    auto Router::QueryFailureFromException(const std::exception_ptr Error) noexcept
        -> Prism::Fault::Failure
    {
        try
        {
            if (Error) std::rethrow_exception(Error);
        }
        catch (const boost::system::system_error& Native)
        {
            return Prism::Fault::FromNative(static_cast<std::error_code>(Native.code()));
        }
        catch (const std::system_error& Native)
        {
            return Prism::Fault::FromNative(Native.code());
        }
        catch (...)
        {
            return {Prism::Fault::Code::IoError};
        }
        return {Prism::Fault::Code::IoError};
    }

    auto Router::QueryOnStrand(
        const std::shared_ptr<Detail::State>& StateValue,
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

    auto Router::ExecuteOnStrand(
        const std::shared_ptr<Detail::State>& StateValue,
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

    auto Router::StatusOnStrand(
        const std::shared_ptr<Detail::State>& StateValue,
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
}

/** @file ResponseDeliveryReceipt.cpp @brief 响应完整写出的 strand owner 实现。 */
#include <Prism/Operations/ResponseDeliveryReceipt.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <optional>
#include <system_error>
#include <utility>

namespace Prism::Operations
{
    struct ResponseDeliveryReceipt::State final
    {
        explicit State(Net::any_io_executor ExecutorValue)
            : Strand(Net::make_strand(std::move(ExecutorValue))), Timer(Strand)
        {
        }

        Net::strand<Net::any_io_executor> Strand;
        Net::steady_timer Timer;
        std::optional<Outcome> Result;
        std::optional<Prism::Fault::Failure> TimerFailure;
        Deadline CompletedAt{};
        bool WaitStarted{false};
        bool WaitFinished{false};
    };

    auto ResponseDeliveryReceipt::Create(Net::any_io_executor Executor)
        -> ResponseDeliveryReceipt
    {
        return ResponseDeliveryReceipt{std::make_shared<State>(std::move(Executor))};
    }

    auto ResponseDeliveryReceipt::WaitAsync(const Deadline Limit) const -> Net::awaitable<Outcome>
    {
        const auto StateValue = State_;
        try
        {
            co_return co_await Net::co_spawn(
                StateValue->Strand, WaitOnStrand(StateValue, Limit), Net::use_awaitable);
        }
        catch (...)
        {
            co_return std::unexpected(FailureFromException(std::current_exception()));
        }
    }

    auto ResponseDeliveryReceipt::CompleteAsync(Outcome Result) const
        -> Net::awaitable<Completion>
    {
        const auto StateValue = State_;
        try
        {
            co_return co_await Net::co_spawn(StateValue->Strand,
                CompleteOnStrand(StateValue, std::move(Result)), Net::use_awaitable);
        }
        catch (...)
        {
            co_return std::unexpected(FailureFromException(std::current_exception()));
        }
    }

    auto ResponseDeliveryReceipt::FailureFromException(const std::exception_ptr Exception) noexcept
        -> Prism::Fault::Failure
    {
        if (!Exception)
        {
            return {Prism::Fault::Code::Blocked};
        }
        try
        {
            std::rethrow_exception(Exception);
        }
        catch (const std::system_error &Error)
        {
            return Prism::Fault::FromNative(Error.code());
        }
        catch (const boost::system::system_error &Error)
        {
            return Prism::Fault::FromNative(
                static_cast<std::error_code>(Error.code()));
        }
        catch (...)
        {
            return {Prism::Fault::Code::Blocked};
        }
    }

    auto ResponseDeliveryReceipt::WaitOnStrand(
        const std::shared_ptr<State> &StateValue,
        const Deadline Limit) -> Net::awaitable<Outcome>
    {
        if (StateValue->Result)
        {
            if (StateValue->TimerFailure)
            {
                co_return std::unexpected(*StateValue->TimerFailure);
            }
            if (StateValue->CompletedAt <= Limit)
            {
                co_return *StateValue->Result;
            }
            co_return std::unexpected(TimeoutFailure());
        }
        if (StateValue->WaitStarted)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }

        StateValue->WaitStarted = true;
        StateValue->Timer.expires_at(Limit);
        boost::system::error_code Error;
        try
        {
            co_await StateValue->Timer.async_wait(
                Net::redirect_error(Net::use_awaitable, Error));
        }
        catch (...)
        {
            StateValue->WaitFinished = true;
            co_return std::unexpected(FailureFromException(std::current_exception()));
        }
        StateValue->WaitFinished = true;
        if (StateValue->Result)
        {
            if (StateValue->TimerFailure)
            {
                co_return std::unexpected(*StateValue->TimerFailure);
            }
            if (StateValue->CompletedAt > Limit)
            {
                co_return std::unexpected(TimeoutFailure());
            }
            co_return *StateValue->Result;
        }
        if (!Error)
        {
            co_return std::unexpected(TimeoutFailure());
        }
        co_return std::unexpected(Prism::Fault::Failure{
            Prism::Fault::Code::Blocked,
            static_cast<std::error_code>(Error)});
    }

    auto ResponseDeliveryReceipt::CompleteOnStrand(
        const std::shared_ptr<State> &StateValue,
        Outcome Result) -> Net::awaitable<Completion>
    {
        if (StateValue->Result || StateValue->WaitFinished)
        {
            co_return false;
        }
        StateValue->Result = std::move(Result);
        StateValue->CompletedAt = std::chrono::steady_clock::now();
        try
        {
            (void)StateValue->Timer.cancel();
        }
        catch (...)
        {
            StateValue->TimerFailure = FailureFromException(std::current_exception());
            co_return std::unexpected(*StateValue->TimerFailure);
        }
        co_return true;
    }

    auto ResponseDeliveryReceipt::TimeoutFailure() noexcept -> Prism::Fault::Failure
    {
        return {Prism::Fault::Code::Timeout,
            std::make_error_code(std::errc::timed_out)};
    }

    ResponseDeliveryReceipt::ResponseDeliveryReceipt(std::shared_ptr<State> StateValue)
        : State_(std::move(StateValue))
    {
    }
} // namespace Prism::Operations

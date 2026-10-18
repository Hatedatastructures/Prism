/**
 * @file ResponseDeliveryReceipt.hpp
 * @brief 管理请求响应完整写出后的 typed 回执。
 * @details 创建者借 executor 生命周期拥有回执状态；同一回执可由 handler 等待、
 *          由连接 owner 在写完或失败后完成。deadline 只限制等待，不取消 socket。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <chrono>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>

namespace Prism::Operations
{

    namespace Net = boost::asio;

    /**
     * @brief 某个 HTTP 响应的单次送达回执。
     * @details 所有状态只在内部 strand 上访问。写入者拥有 socket 并报告完整写入或
     *          原生失败；等待者不持有连接，超时不会伪造送达，也不改变业务结果。
     */
    class ResponseDeliveryReceipt final
    {
        struct State;

    public:
        using Outcome = std::expected<void, Prism::Fault::Failure>;
        using Completion = std::expected<bool, Prism::Fault::Failure>;
        using Deadline = std::chrono::steady_clock::time_point;

        /** @brief 在请求 connection executor 上创建一份尚未完成的响应回执。 */
        [[nodiscard]] static auto Create(Net::any_io_executor Executor)
            -> ResponseDeliveryReceipt
        {
            return ResponseDeliveryReceipt{std::make_shared<State>(std::move(Executor))};
        }

        /**
         * @brief 等待连接 owner 报告完整响应写入或失败。
         * @param Limit 同一停机操作使用的绝对 deadline；超时返回 Timeout，不推断送达。
         */
        [[nodiscard]] auto WaitAsync(const Deadline Limit) const -> Net::awaitable<Outcome>
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

        /**
         * @brief 连接 owner 报告一次真实写入结果。
         * @param Result 完整写入的 success，或保留原生 category/value 的写入失败。
         * @return true 表示回报被接收；重复/迟到为 false，timer 操作失败返回原生错误。
         */
        [[nodiscard]] auto CompleteAsync(Outcome Result) const -> Net::awaitable<Completion>
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

    private:
        [[nodiscard]] static auto FailureFromException(const std::exception_ptr Exception) noexcept
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

        [[nodiscard]] static auto WaitOnStrand(
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

        [[nodiscard]] static auto CompleteOnStrand(
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

        [[nodiscard]] static auto TimeoutFailure() noexcept -> Prism::Fault::Failure
        {
            return {Prism::Fault::Code::Timeout,
                std::make_error_code(std::errc::timed_out)};
        }
        struct State final
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

        explicit ResponseDeliveryReceipt(std::shared_ptr<State> StateValue)
            : State_(std::move(StateValue))
        {
        }

        std::shared_ptr<State> State_;
    };

} // namespace Prism::Operations

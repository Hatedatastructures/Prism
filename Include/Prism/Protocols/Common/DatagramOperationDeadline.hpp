/** @file DatagramOperationDeadline.hpp @brief Common UDP 队列、resolver 与 carrier 操作期限。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <expected>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>

namespace Prism::Protocols
{
    namespace Net = boost::asio;

    /** @brief 一个 association 共享的非阻塞期限 owner；非正期限显式禁用计时。 */
    class DatagramOperationDeadline final
    {
        using Failure = Prism::Fault::Failure;

    public:
        DatagramOperationDeadline(Net::any_io_executor Executor, std::chrono::milliseconds Timeout)
            : Executor_(std::move(Executor)), Timeout_(Timeout) {}

        /** @brief 为 typed resolver 或 Wire 操作限时并等待被取消子操作退栈。 */
        template<class Value>
        [[nodiscard]] auto Await(Net::awaitable<std::expected<Value, Failure>> Operation)
            -> Net::awaitable<std::expected<Value, Failure>>
        {
            if (Timeout_.count() <= 0) co_return co_await std::move(Operation);
            Net::steady_timer Timer(Executor_);
            Timer.expires_after(Timeout_);
            boost::system::error_code TimerError;
            using Net::experimental::awaitable_operators::operator||;
            auto Timeout = Timer.async_wait(
                Net::redirect_error(Net::use_awaitable, TimerError));
            const auto Outcome = co_await (std::move(Operation) || std::move(Timeout));
            if (Outcome.index() == 1U)
            {
                if (TimerError)
                    co_return std::unexpected(Prism::Fault::FromNative(
                        static_cast<std::error_code>(TimerError)));
                co_return std::unexpected(Failure{Prism::Fault::Code::Timeout});
            }
            co_return std::get<0>(std::move(Outcome));
        }

        /** @brief 为 Asio 与有界队列操作限时；错误保留原生 category/value。 */
        template<class Value>
        [[nodiscard]] auto AwaitIo(Net::awaitable<Value> Operation,
                                   boost::system::error_code& Error)
            -> Net::awaitable<std::expected<Value, Failure>>
        {
            if (Timeout_.count() <= 0)
            {
                if constexpr (std::is_void_v<Value>)
                {
                    co_await std::move(Operation);
                    if (Error) co_return std::unexpected(Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error)));
                    co_return std::expected<void, Failure>{};
                }
                else
                {
                    const auto Result = co_await std::move(Operation);
                    if (Error) co_return std::unexpected(Prism::Fault::FromNative(
                        static_cast<std::error_code>(Error)));
                    co_return Result;
                }
            }

            Net::steady_timer Timer(Executor_);
            Timer.expires_after(Timeout_);
            boost::system::error_code TimerError;
            using Net::experimental::awaitable_operators::operator||;
            auto Timeout = Timer.async_wait(
                Net::redirect_error(Net::use_awaitable, TimerError));
            const auto Outcome = co_await (std::move(Operation) || std::move(Timeout));
            if (Outcome.index() == 1U)
            {
                if (TimerError)
                    co_return std::unexpected(Prism::Fault::FromNative(
                        static_cast<std::error_code>(TimerError)));
                co_return std::unexpected(Failure{Prism::Fault::Code::Timeout});
            }
            if (Error) co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error)));
            if constexpr (std::is_void_v<Value>)
                co_return std::expected<void, Failure>{};
            else
                co_return std::get<0>(std::move(Outcome));
        }

    private:
        Net::any_io_executor Executor_;
        std::chrono::milliseconds Timeout_;
    };
} // namespace Prism::Protocols

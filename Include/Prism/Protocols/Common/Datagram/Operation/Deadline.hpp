/** @file Deadline.hpp @brief Common UDP 队列、resolver 与 carrier 操作期限。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <chrono>
#include <atomic>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
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

        /** @brief 超时先提交 owning cancel，再等待底层操作真实退栈。 */
        template<class Value, class CancelOperation>
        [[nodiscard]] auto AwaitWithCancel(
            Net::awaitable<std::expected<Value, Failure>> Operation,
            CancelOperation Cancel)
            -> Net::awaitable<std::expected<Value, Failure>>
        {
            if (Timeout_.count() <= 0) co_return co_await std::move(Operation);
            const auto ParentCancellation = co_await Net::this_coro::cancellation_state;
            if (ParentCancellation.cancelled() != Net::cancellation_type::none)
            {
                Cancel();
                co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            }
            const auto CancellationSlot = ParentCancellation.slot();
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            const auto Executor = co_await Net::this_coro::executor;
            struct Completion final
            {
                explicit Completion(Net::any_io_executor ExecutorValue,
                    CancelOperation CancelValue)
                    : Changed(ExecutorValue, 1), Timer(std::move(ExecutorValue)),
                      Cancel(std::move(CancelValue))
                {
                }

                Net::experimental::concurrent_channel<void(boost::system::error_code)> Changed;
                Net::steady_timer Timer;
                std::atomic_uint8_t Winner{0};
                std::optional<std::expected<Value, Failure>> Result;
                std::exception_ptr Exception;
                CancelOperation Cancel;

                auto CancelParent(const Net::cancellation_type Type) noexcept -> void
                {
                    if (Type == Net::cancellation_type::none) return;
                    std::uint8_t Pending = 0;
                    if (Winner.compare_exchange_strong(
                            Pending, 3, std::memory_order_acq_rel))
                    {
                        Cancel();
                    }
                }

                auto CancelTimeout(const boost::system::error_code Error) noexcept -> void
                {
                    if (Error) return;
                    std::uint8_t Pending = 0;
                    if (Winner.compare_exchange_strong(
                            Pending, 2, std::memory_order_acq_rel))
                    {
                        Cancel();
                    }
                }

                auto Complete(
                    std::exception_ptr ExceptionValue,
                    std::expected<Value, Failure> ResultValue) -> void
                {
                    std::uint8_t Pending = 0;
                    (void)Winner.compare_exchange_strong(
                        Pending, 1, std::memory_order_acq_rel);
                    Exception = std::move(ExceptionValue);
                    if (!Exception) Result.emplace(std::move(ResultValue));
                    try
                    {
                        (void)Timer.cancel();
                    }
                    catch (...)
                    {
                    }
                    (void)Changed.try_send(boost::system::error_code{});
                }
            };
            struct CancellationSlotReset final
            {
                explicit CancellationSlotReset(Net::cancellation_slot SlotValue)
                    : Slot(std::move(SlotValue)) {}
                ~CancellationSlotReset() { Slot.clear(); }
                auto Clear() noexcept -> void { Slot.clear(); }
                Net::cancellation_slot Slot;
            } ResetCancellationSlot{CancellationSlot};

            const auto State = std::make_shared<Completion>(Executor, std::move(Cancel));
            ResetCancellationSlot.Slot.assign(
                [Weak = std::weak_ptr<Completion>(State)](Net::cancellation_type Type)
                {
                    const auto Owner = Weak.lock();
                    if (Owner) Owner->CancelParent(Type);
                });
            State->Timer.expires_after(Timeout_);
            State->Timer.async_wait(
                [State](boost::system::error_code Error)
                {
                    State->CancelTimeout(Error);
                });
            Net::co_spawn(Executor, std::move(Operation),
                [State](std::exception_ptr Exception,
                        std::expected<Value, Failure> Result) mutable
                {
                    State->Complete(std::move(Exception), std::move(Result));
                });

            boost::system::error_code Error;
            co_await State->Changed.async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            const auto Winner = State->Winner.load(std::memory_order_acquire);
            ResetCancellationSlot.Clear();
            co_await Net::this_coro::reset_cancellation_state();
            if (Error)
            {
                co_return std::unexpected(
                    Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
            }
            if (State->Exception) std::rethrow_exception(State->Exception);
            if (Winner == 2)
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::Timeout});
            }
            if (Winner == 3)
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            }
            co_return std::move(*State->Result);
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

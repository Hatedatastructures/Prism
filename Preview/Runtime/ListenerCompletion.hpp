/**
 * @file ListenerCompletion.hpp
 * @brief detached listener 协程的 completion signal owner。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <utility>

namespace Preview::Runtime::Detail
{

    namespace Net = boost::asio;

    class ListenerCompletion final
    {
    public:
        explicit ListenerCompletion(Net::any_io_executor ExecutorValue)
            : Signal(std::move(ExecutorValue), 1)
        {
        }

        auto Reset() noexcept -> void
        {
            Completed.store(false, std::memory_order_release);
        }

        auto Complete() noexcept -> void
        {
            if (Completed.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            (void)Signal.try_send(boost::system::error_code{});
        }

        [[nodiscard]] auto IsComplete() const noexcept -> bool
        {
            return Completed.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Wait() -> Net::awaitable<void>
        {
            if (IsComplete())
            {
                co_return;
            }
            boost::system::error_code Error;
            co_await Signal.async_receive(Net::redirect_error(Net::use_awaitable, Error));
        }

    private:
        using Channel = Net::experimental::channel<void(boost::system::error_code)>;

        Channel Signal;
        std::atomic<bool> Completed{true};
    };

    class ListenerCompletionGuard final
    {
    public:
        explicit ListenerCompletionGuard(std::shared_ptr<ListenerCompletion> CompletionValue)
            : Value(std::move(CompletionValue))
        {
        }

        ~ListenerCompletionGuard() noexcept
        {
            if (Value)
            {
                Value->Complete();
            }
        }

        ListenerCompletionGuard(const ListenerCompletionGuard &) = delete;
        auto operator=(const ListenerCompletionGuard &) -> ListenerCompletionGuard & = delete;

    private:
        std::shared_ptr<ListenerCompletion> Value;
    };

} // namespace Preview::Runtime::Detail


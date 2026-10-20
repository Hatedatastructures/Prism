/**
 * @file ListenerCompletion.hpp
 * @brief detached listener 协程的 completion signal owner。
 */

#pragma once

#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <memory>
#include <utility>

namespace Prism::Runtime::Detail
{

    namespace Net = boost::asio;

    class ListenerCompletion final
    {
    public:
        explicit ListenerCompletion(Net::any_io_executor ExecutorValue)
            : Signal(std::move(ExecutorValue), 1)
        {
        }

        auto Reset() noexcept -> void;

        auto Complete() noexcept -> void;

        [[nodiscard]] auto IsComplete() const noexcept -> bool;

        [[nodiscard]] auto Wait() -> Net::awaitable<void>;

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

} // namespace Prism::Runtime::Detail

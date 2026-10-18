/** @file TaskRetirementReceipt.hpp @brief 任务 owner 真正退栈后的可并发回执。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <cstddef>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Lifecycle
{
    namespace Net = boost::asio;

    /** @brief 只在 TaskSubmission 完成异步清理并退栈后发布一次信号。 */
    class TaskRetirementReceipt final
        : public std::enable_shared_from_this<TaskRetirementReceipt>
    {
        inline static constexpr std::size_t MaxWaiters = 64U;
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

        struct Waiter final
        {
            explicit Waiter(Net::any_io_executor Executor)
                : Channel(std::move(Executor), 1U)
            {
            }

            Signal Channel;
        };

        using WaiterList = std::vector<std::weak_ptr<Waiter>>;

    public:
        /** @brief 在调用方 executor 等待真实 retirement；取消不解除 owner 回执。 */
        [[nodiscard]] auto WaitAsync() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            const auto Self = weak_from_this().lock();
            if (!Self)
            {
                return Failed(Prism::Fault::Failure{
                    Prism::Fault::Code::InvalidArgument});
            }
            return WaitAsyncPinned(Self);
        }

        /** @brief 在 TaskSubmission completion handler 中广播一次真实 owner 回执。 */
        auto Publish() noexcept -> void
        {
            if (Retired_.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            const auto Waiting = Waiters_.load(std::memory_order_acquire);
            if (!Waiting)
            {
                return;
            }
            for (const auto &Weak : *Waiting)
            {
                if (const auto Value = Weak.lock())
                {
                    try
                    {
                        if (!Value->Channel.try_send(boost::system::error_code{}))
                        {
                            Value->Channel.close();
                        }
                    }
                    catch (...)
                    {
                        try
                        {
                            Value->Channel.close();
                        }
                        catch (...)
                        {
                        }
                    }
                }
            }
        }

    private:
        [[nodiscard]] static auto Failed(Prism::Fault::Failure Failure)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return std::unexpected(std::move(Failure));
        }

        /** @brief 由值 pin 的 owner 执行协程，等待期间不借用调用对象。 */
        [[nodiscard]] static auto WaitAsyncPinned(
            std::shared_ptr<TaskRetirementReceipt> Self)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            if (Self->Retired_.load(std::memory_order_acquire))
            {
                co_return std::expected<void, Prism::Fault::Failure>{};
            }

            std::shared_ptr<Waiter> Waiting;
            try
            {
                const auto Executor = co_await Net::this_coro::executor;
                Waiting = std::make_shared<Waiter>(Executor);
            }
            catch (const boost::system::system_error &Error)
            {
                if (Self->Retired_.load(std::memory_order_acquire))
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            catch (const std::system_error &Error)
            {
                if (Self->Retired_.load(std::memory_order_acquire))
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                co_return std::unexpected(Prism::Fault::FromNative(Error.code()));
            }
            catch (...)
            {
                if (Self->Retired_.load(std::memory_order_acquire))
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
            }

            const auto Registered = Self->RegisterWaiter(Waiting);
            if (!Registered)
            {
                if (Self->Retired_.load(std::memory_order_acquire))
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                co_return std::unexpected(Registered.error());
            }
            if (Self->Retired_.load(std::memory_order_acquire))
            {
                (void)Waiting->Channel.try_send(boost::system::error_code{});
            }

            boost::system::error_code Error;
            try
            {
                co_await Waiting->Channel.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
            }
            catch (const boost::system::system_error &Failure)
            {
                if (Self->Retired_.load(std::memory_order_acquire))
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Failure.code())));
            }
            catch (const std::system_error &Failure)
            {
                if (Self->Retired_.load(std::memory_order_acquire))
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                co_return std::unexpected(Prism::Fault::FromNative(Failure.code()));
            }
            catch (...)
            {
                if (Self->Retired_.load(std::memory_order_acquire))
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            if (Error)
            {
                if (Self->Retired_.load(std::memory_order_acquire))
                {
                    co_return std::expected<void, Prism::Fault::Failure>{};
                }
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            }
            if (!Self->Retired_.load(std::memory_order_acquire))
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 以原子 copy-on-write 注册 waiter，并清理已离开的观察者。 */
        [[nodiscard]] auto RegisterWaiter(const std::shared_ptr<Waiter> &Value)
            -> std::expected<void, Prism::Fault::Failure>
        {
            auto Current = Waiters_.load(std::memory_order_acquire);
            while (true)
            {
                try
                {
                    auto Next = std::make_shared<WaiterList>();
                    if (Current)
                    {
                        Next->reserve(MaxWaiters);
                        for (const auto &Existing : *Current)
                        {
                            if (!Existing.expired())
                            {
                                Next->push_back(Existing);
                            }
                        }
                    }
                    if (Next->size() >= MaxWaiters)
                    {
                        return std::unexpected(
                            Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
                    }
                    Next->push_back(Value);
                    std::shared_ptr<const WaiterList> Desired = std::move(Next);
                    if (Waiters_.compare_exchange_weak(
                            Current, Desired, std::memory_order_acq_rel,
                            std::memory_order_acquire))
                    {
                        return {};
                    }
                }
                catch (...)
                {
                    return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
                }
            }
        }

        std::atomic<bool> Retired_{false};
        std::atomic<std::shared_ptr<const WaiterList>> Waiters_;
    };
}

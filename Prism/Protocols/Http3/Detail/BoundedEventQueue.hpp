/**
 * @file BoundedEventQueue.hpp
 * @brief 拥有并限制 HTTP/3 异步事件队列。
 * @details 队列在所属 executor 上串行记账；关闭后由所属会话排空任务，再释放队列。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

#include <Prism/Protocols/Http3/HeaderLimits.hpp>

namespace Prism::Http3::Detail
{
    namespace Net = boost::asio;

    template <class Event>
    class BoundedEventQueue final
    {
    public:
        using EventPointer = std::shared_ptr<Event>;
        using Channel = Net::experimental::channel<void(boost::system::error_code, EventPointer)>;

        class Reservation final
        {
        public:
            Reservation(BoundedEventQueue &Queue, Event &Value) noexcept
                : Queue_(Queue), Value_(Value) {}
            ~Reservation() { Queue_.Release(Value_); }
            Reservation(const Reservation &) = delete;
            auto operator=(const Reservation &) -> Reservation & = delete;

        private:
            BoundedEventQueue &Queue_;
            Event &Value_;
        };

        explicit BoundedEventQueue(Net::any_io_executor Executor)
            : Channel_(std::make_unique<Channel>(std::move(Executor), HeaderLimits::MaxPendingEvents))
        {
        }

        [[nodiscard]] auto Reserve(Event &Value, const std::size_t Bytes) noexcept -> bool
        {
            if (PendingCount_ >= HeaderLimits::MaxPendingEvents ||
                PendingBytes_ > HeaderLimits::MaxPendingEventBytes ||
                Bytes > HeaderLimits::MaxPendingEventBytes - PendingBytes_)
            {
                return false;
            }
            ++PendingCount_;
            PendingBytes_ += Bytes;
            Value.BudgetReserved = true;
            Value.BudgetBytes = Bytes;
            return true;
        }

        auto Release(Event &Value) noexcept -> void
        {
            if (!Value.BudgetReserved)
            {
                return;
            }
            if (PendingCount_ != 0)
            {
                --PendingCount_;
            }
            if (Value.BudgetBytes <= PendingBytes_)
            {
                PendingBytes_ -= Value.BudgetBytes;
            }
            Value.BudgetReserved = false;
            Value.BudgetBytes = 0;
        }

        [[nodiscard]] auto Publish(EventPointer Value) -> bool
        {
            if (!Channel_ || !Value)
            {
                if (Value)
                {
                    Release(*Value);
                }
                return false;
            }
            if (!Value->BudgetReserved && !Reserve(*Value, Value->Data.size()))
            {
                return false;
            }
            if (Channel_->try_send(boost::system::error_code{}, Value))
            {
                return true;
            }
            Release(*Value);
            return false;
        }

        [[nodiscard]] auto Receive() -> Net::awaitable<EventPointer>
        {
            if (!Channel_)
            {
                co_return nullptr;
            }
            boost::system::error_code Error;
            auto Value = co_await Channel_->async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return nullptr;
            }
            co_return Value;
        }

        auto Close() noexcept -> void
        {
            if (Channel_)
            {
                Channel_->close();
            }
        }

        auto Retire() noexcept -> void
        {
            Channel_.reset();
            PendingCount_ = 0;
            PendingBytes_ = 0;
        }

    private:
        std::unique_ptr<Channel> Channel_;
        std::size_t PendingCount_{0};
        std::size_t PendingBytes_{0};
    };
}

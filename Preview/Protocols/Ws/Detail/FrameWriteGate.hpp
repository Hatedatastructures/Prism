/**
 * @file FrameWriteGate.hpp
 * @brief WebSocket 连接唯一帧写入门闩。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <expected>
#include <memory>
#include <utility>

#include <Preview/Foundation/Fault/Failure.hpp>

namespace Preview::Ws::Detail
{

    namespace Net = boost::asio;

    /** @brief 持有整帧发送权；析构时归还唯一写入令牌。 */
    class FrameWritePermit final
    {
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;

        struct State final
        {
            explicit State(Net::any_io_executor Executor)
                : Available(std::make_shared<Signal>(std::move(Executor), 1))
            {
            }

            std::shared_ptr<Signal> Available;
            std::atomic<bool> Closed{false};
        };

        explicit FrameWritePermit(std::shared_ptr<State> Owner) noexcept
            : Owner_(std::move(Owner))
        {
        }

        friend class FrameWriteGate;

    public:
        FrameWritePermit(const FrameWritePermit &) = delete;
        auto operator=(const FrameWritePermit &) -> FrameWritePermit & = delete;

        FrameWritePermit(FrameWritePermit &&Other) noexcept
            : Owner_(std::move(Other.Owner_))
        {
        }

        auto operator=(FrameWritePermit &&Other) noexcept -> FrameWritePermit &
        {
            if (this != &Other)
            {
                Release();
                Owner_ = std::move(Other.Owner_);
            }
            return *this;
        }

        ~FrameWritePermit() noexcept
        {
            Release();
        }

    private:
        auto Release() noexcept -> void
        {
            if (Owner_ && !Owner_->Closed.load(std::memory_order_acquire))
            {
                const auto Released = Owner_->Available->try_send(
                    boost::system::error_code{});
                if (!Released)
                {
                    Owner_->Closed.store(true, std::memory_order_release);
                    Owner_->Available->close();
                }
            }
            Owner_.reset();
        }

        std::shared_ptr<State> Owner_;
    };

    /** @brief 以有界并发 channel 串行化完整 WebSocket 帧写入。 */
    class FrameWriteGate final
    {
        using Signal = Net::experimental::concurrent_channel<void(boost::system::error_code)>;
        using State = FrameWritePermit::State;

    public:
        explicit FrameWriteGate(Net::any_io_executor Executor)
            : State_(std::make_shared<State>(std::move(Executor)))
        {
            const auto Ready = State_->Available->try_send(boost::system::error_code{});
            if (!Ready)
            {
                State_->Closed.store(true, std::memory_order_release);
                State_->Available->close();
            }
        }

        FrameWriteGate(const FrameWriteGate &) = delete;
        auto operator=(const FrameWriteGate &) -> FrameWriteGate & = delete;

        [[nodiscard]] auto Acquire()
            -> Net::awaitable<std::expected<FrameWritePermit, Preview::Fault::Failure>>
        {
            const auto Owner = State_;
            if (!Owner || Owner->Closed.load(std::memory_order_acquire))
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }

            boost::system::error_code Error;
            co_await Owner->Available->async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            }
            if (Owner->Closed.load(std::memory_order_acquire))
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            co_return FrameWritePermit{Owner};
        }

        auto Close() noexcept -> void
        {
            const auto Owner = State_;
            if (Owner && !Owner->Closed.exchange(true, std::memory_order_acq_rel))
            {
                Owner->Available->close();
            }
        }

    private:
        std::shared_ptr<State> State_;
    };

} // namespace Preview::Ws::Detail

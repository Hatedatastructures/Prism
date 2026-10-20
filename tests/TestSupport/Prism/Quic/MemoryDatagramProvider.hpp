/** @file MemoryDatagramProvider.hpp @brief QUIC 数据报测试用内存 provider。 */
#pragma once

#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Quic/DatagramAdapter.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <deque>
#include <memory>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Testing
{
    namespace net = boost::asio;

    /**
     * @brief 测试用内存数据报提供者。
     * @details 两个端点通过独立数据报队列互联；每次 Send 只投递一个数据报，MaxSend 用于注入短写；
     *          Close/Cancel 会唤醒挂起操作。
     */
    class MemoryDatagramProvider final : public Prism::Quic::DatagramProvider
    {
    public:
        explicit MemoryDatagramProvider(net::any_io_executor Ex)
            : State_(std::make_shared<State>(std::move(Ex)))
        {
        }

        [[nodiscard]] static auto MakePair(net::any_io_executor Ex)
            -> std::pair<std::shared_ptr<MemoryDatagramProvider>,
                         std::shared_ptr<MemoryDatagramProvider>>
        {
            auto First = std::make_shared<MemoryDatagramProvider>(Ex);
            auto Second = std::make_shared<MemoryDatagramProvider>(std::move(Ex));
            First->State_->Peer = Second->State_;
            Second->State_->Peer = First->State_;
            return {std::move(First), std::move(Second)};
        }

        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return State_->Ex;
        }

        [[nodiscard]] auto Receive(std::span<std::byte> Buffer, std::error_code &Ec)
            -> net::awaitable<std::size_t> override
        {
            Ec.clear();
            while (true)
            {
                if (State_->Closed)
                {
                    Ec = make_error_code(Prism::Error::UnexpectedEof);
                    co_return 0;
                }
                if (State_->Canceled)
                {
                    State_->Canceled = false;
                    Ec = make_error_code(Prism::Error::Canceled);
                    co_return 0;
                }
                if (!State_->Queue.empty())
                {
                    auto Data = std::move(State_->Queue.front());
                    State_->Queue.pop_front();
                    const auto Count = std::min(Buffer.size(), Data.size());
                    if (Count > 0)
                    {
                        std::memcpy(Buffer.data(), Data.data(), Count);
                    }
                    co_return Count;
                }
                if (State_->PeerClosed)
                {
                    Ec = make_error_code(Prism::Error::UnexpectedEof);
                    co_return 0;
                }
                State_->Events.reset();
                (void)co_await State_->Events.async_receive(net::use_awaitable);
            }
        }

        [[nodiscard]] auto Send(std::span<const std::byte> Buffer, std::error_code &Ec)
            -> net::awaitable<std::size_t> override
        {
            Ec.clear();
            const auto Peer = State_->Peer.lock();
            if (State_->Closed || !Peer || Peer->Closed || Peer->PeerClosed)
            {
                Ec = make_error_code(Prism::Error::BrokenPipe);
                co_return 0;
            }
            const auto Count = MaxSend == 0 ? Buffer.size() : std::min(Buffer.size(), MaxSend);
            Peer->Queue.emplace_back(Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
            Peer->Events.try_send(boost::system::error_code{});
            Sent.emplace_back(Buffer.begin(), Buffer.begin() + static_cast<std::ptrdiff_t>(Count));
            co_return Count;
        }

        auto Close() -> void override
        {
            if (State_->Closed)
            {
                return;
            }
            State_->Closed = true;
            State_->Events.try_send(boost::system::error_code{});
            if (const auto Peer = State_->Peer.lock())
            {
                Peer->PeerClosed = true;
                Peer->Events.try_send(boost::system::error_code{});
            }
        }

        auto Cancel() -> void override
        {
            State_->Canceled = true;
            State_->Events.try_send(boost::system::error_code{});
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool override
        {
            return State_->Closed;
        }

        auto Inject(std::vector<std::byte> Data) -> void
        {
            State_->Queue.push_back(std::move(Data));
            State_->Events.try_send(boost::system::error_code{});
        }

        [[nodiscard]] auto IsCanceled() const noexcept -> bool
        {
            return State_->Canceled;
        }

        std::size_t MaxSend{0};
        std::vector<std::vector<std::byte>> Sent;

    private:
        struct State final
        {
            explicit State(net::any_io_executor Executor)
                : Ex(std::move(Executor)), Events(Ex, 1)
            {
            }

            net::any_io_executor Ex;
            net::experimental::channel<void(boost::system::error_code)> Events;
            std::deque<std::vector<std::byte>> Queue;
            std::weak_ptr<State> Peer;
            bool Closed{false};
            bool PeerClosed{false};
            bool Canceled{false};
        };

        std::shared_ptr<State> State_;
    };
}

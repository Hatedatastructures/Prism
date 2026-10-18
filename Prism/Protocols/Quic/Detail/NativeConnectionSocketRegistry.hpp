/**
 * @file NativeConnectionSocketRegistry.hpp
 * @brief 为原生 QUIC connection 独占注册 UDP socket。
 */

#pragma once

#include <boost/asio/ip/udp.hpp>

#include <atomic>
#include <memory>
#include <vector>

namespace Prism::Quic::Detail
{
    struct SocketToken final
    {
    };

    struct SocketEntry final
    {
        std::weak_ptr<boost::asio::ip::udp::socket> Socket;
        std::shared_ptr<SocketToken> Token;
    };

    using SocketEntries = std::vector<SocketEntry>;

    inline std::atomic<std::shared_ptr<const SocketEntries>> ActiveSockets{
        std::make_shared<const SocketEntries>()};

    [[nodiscard]] inline auto AcquireSocketToken(
        const std::shared_ptr<boost::asio::ip::udp::socket> &Socket)
        -> std::shared_ptr<SocketToken>
    {
        if (!Socket)
        {
            return nullptr;
        }
        while (true)
        {
            auto Current = ActiveSockets.load(std::memory_order_acquire);
            auto Next = std::make_shared<SocketEntries>();
            for (const auto &Entry : *Current)
            {
                const auto ExistingSocket = Entry.Socket.lock();
                if (!ExistingSocket)
                {
                    continue;
                }
                if (ExistingSocket.get() == Socket.get())
                {
                    return nullptr;
                }
                Next->push_back(Entry);
            }
            auto Token = std::make_shared<SocketToken>();
            Next->push_back(SocketEntry{Socket, Token});
            std::shared_ptr<const SocketEntries> Desired = Next;
            if (ActiveSockets.compare_exchange_weak(
                    Current,
                    std::move(Desired),
                    std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                return Token;
            }
        }
    }

    inline auto ReleaseSocketToken(
        const std::shared_ptr<boost::asio::ip::udp::socket> &Socket,
        const std::shared_ptr<SocketToken> &Token) -> void
    {
        if (!Socket || !Token)
        {
            return;
        }
        while (true)
        {
            auto Current = ActiveSockets.load(std::memory_order_acquire);
            auto Next = std::make_shared<SocketEntries>();
            for (const auto &Entry : *Current)
            {
                const auto ExistingSocket = Entry.Socket.lock();
                if (ExistingSocket && ExistingSocket.get() == Socket.get() && Entry.Token == Token)
                {
                    continue;
                }
                if (ExistingSocket)
                {
                    Next->push_back(Entry);
                }
            }
            std::shared_ptr<const SocketEntries> Desired = Next;
            if (ActiveSockets.compare_exchange_weak(
                    Current,
                    std::move(Desired),
                    std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                return;
            }
        }
    }
} // namespace Prism::Quic::Detail

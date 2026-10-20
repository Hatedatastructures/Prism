/**
 * @file NativeConnectionSocketRegistry.cpp
 * @brief 原生 QUIC connection 的 UDP socket 独占登记实现。
 */

#include <Prism/Protocols/Quic/Detail/NativeConnectionSocketRegistry.hpp>

#include <atomic>
#include <memory>
#include <utility>
#include <vector>

namespace Prism::Quic::Detail
{
    namespace
    {
        struct SocketEntry final
        {
            std::weak_ptr<boost::asio::ip::udp::socket> Socket;
            std::shared_ptr<SocketToken> Token;
        };

        using SocketEntries = std::vector<SocketEntry>;

        std::atomic<std::shared_ptr<const SocketEntries>> ActiveSockets{
            std::make_shared<const SocketEntries>()};
    }

    [[nodiscard]] auto AcquireSocketToken(
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

    auto ReleaseSocketToken(
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

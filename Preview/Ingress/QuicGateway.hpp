/**
 * @file QuicGateway.hpp
 * @brief Preview UDP 入口中的 QUIC CID 生命周期与包接收边界。
 * @details Gateway 不解析应用协议；协议 descriptor/QUIC engine 通过
 *          PacketHandler 接入，Gateway 只拥有 CID 表、预算和 shutdown 状态。
 */
#pragma once

#include <Preview/Ingress/UdpDemux.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Preview::Ingress
{

    enum class QuicReadiness : std::uint8_t
    {
        Offline,
        Socket,
        ReceiveLoop,
        Handshake,
        Protocol,
        Draining,
        Closed,
        Failed,
    };

    struct QuicGatewayHealth final
    {
        bool SocketReady{false};
        bool ReceiveLoopReady{false};
        bool HandshakeReady{false};
        bool ProtocolReady{false};
        bool Draining{false};
        bool BoundedFailure{false};
        std::size_t Connections{0};
        std::size_t Packets{0};
        QuicReadiness Readiness{QuicReadiness::Offline};

        [[nodiscard]] auto Healthy() const noexcept -> bool
        {
            return SocketReady && ReceiveLoopReady && HandshakeReady && ProtocolReady &&
                   !Draining && !BoundedFailure;
        }
    };

    struct QuicGatewayOptions final
    {
        std::size_t MaxConnections{4096};
        std::size_t MaxPacketsPerConnection{65536};
        std::function<void(const UdpPacket &)> OnPacket;
        std::function<bool(const UdpPacket &)> Dispatch;
    };

    class QuicGateway final
    {
    public:
        explicit QuicGateway(QuicGatewayOptions OptionsValue = {})
            : Options_(std::move(OptionsValue))
        {
        }

        auto MarkSocketReady() noexcept -> void
        {
            if (!Closed_ && !Draining_ && !BoundedFailure_)
            {
                SocketReady_ = true;
                if (Readiness_ == QuicReadiness::Offline)
                {
                    Readiness_ = QuicReadiness::Socket;
                }
            }
        }

        auto MarkReceiveLoopReady() noexcept -> void
        {
            if (SocketReady_ && !Closed_ && !Draining_ && !BoundedFailure_)
            {
                ReceiveLoopReady_ = true;
                if (Readiness_ == QuicReadiness::Socket)
                {
                    Readiness_ = QuicReadiness::ReceiveLoop;
                }
            }
        }

        auto MarkHandshakeReady() noexcept -> void
        {
            if (ReceiveLoopReady_ && !Closed_ && !Draining_ && !BoundedFailure_)
            {
                HandshakeReady_ = true;
                if (Readiness_ == QuicReadiness::ReceiveLoop)
                {
                    Readiness_ = QuicReadiness::Handshake;
                }
            }
        }

        auto MarkProtocolReady() noexcept -> void
        {
            if (HandshakeReady_ && !Closed_ && !Draining_ && !BoundedFailure_)
            {
                ProtocolReady_ = true;
                if (Readiness_ == QuicReadiness::Handshake)
                {
                    Readiness_ = QuicReadiness::Protocol;
                }
            }
        }

        [[nodiscard]] auto RegisterConnection(
            const std::uint64_t ConnectionId,
            std::function<bool(const UdpPacket &)> Handler) -> bool
        {
            if (Closed_ || Draining_ || ConnectionId == 0U || !Handler ||
                ConnectionCount() >= Options_.MaxConnections || LegacyConnections_.contains(ConnectionId))
            {
                return false;
            }
            LegacyConnections_.emplace(ConnectionId, ConnectionState{std::move(Handler), 0});
            return true;
        }

        [[nodiscard]] auto RegisterConnection(
            std::span<const std::byte> ConnectionId,
            std::function<bool(const UdpPacket &)> Handler) -> bool
        {
            if (Closed_ || Draining_ || ConnectionId.empty() || ConnectionId.size() > MaxConnectionIdLength ||
                !Handler || ConnectionCount() >= Options_.MaxConnections)
            {
                return false;
            }
            const auto Key = MakeCidKey(ConnectionId);
            if (Connections_.contains(Key))
            {
                return false;
            }
            Connections_.emplace(Key, ConnectionState{std::move(Handler), 0});
            return true;
        }

        auto RemoveConnection(const std::uint64_t ConnectionId) noexcept -> bool
        {
            return LegacyConnections_.erase(ConnectionId) != 0U;
        }

        auto RemoveConnection(std::span<const std::byte> ConnectionId) -> bool
        {
            if (ConnectionId.empty())
            {
                return false;
            }
            return Connections_.erase(MakeCidKey(ConnectionId)) != 0U;
        }

        auto Handle(UdpPacket Packet) -> bool
        {
            if (Closed_ || Draining_ || Packet.Classification.Kind != DatagramKind::Quic ||
                (Packet.Classification.ConnectionId == 0U &&
                 Packet.Classification.ConnectionIdBytes.empty()))
            {
                return false;
            }
            const auto Cid = Packet.Classification.ConnectionId;
            ConnectionState *State = nullptr;
            if (!Packet.Classification.ConnectionIdBytes.empty())
            {
                const auto It = Connections_.find(MakeCidKey(Packet.Classification.ConnectionIdBytes));
                if (It != Connections_.end())
                {
                    State = &It->second;
                }
                if (!State && Packet.Classification.Route != DatagramRoute::UnknownCid &&
                    Packet.Classification.Route != DatagramRoute::RegisteredCid)
                {
                    const auto Legacy = LegacyConnections_.find(Cid);
                    if (Legacy != LegacyConnections_.end())
                    {
                        State = &Legacy->second;
                    }
                }
            }
            else
            {
                const auto Legacy = LegacyConnections_.find(Cid);
                if (Legacy != LegacyConnections_.end())
                {
                    State = &Legacy->second;
                }
            }
            if (!State)
            {
                return false;
            }
            if (State->Packets >= Options_.MaxPacketsPerConnection)
            {
                MarkBoundedFailure();
                return false;
            }
            try
            {
                if (State->Handler && !State->Handler(Packet))
                {
                    MarkBoundedFailure();
                    return false;
                }
                if (Options_.Dispatch && !Options_.Dispatch(Packet))
                {
                    MarkBoundedFailure();
                    return false;
                }
            }
            catch (...)
            {
                MarkBoundedFailure();
                return false;
            }
            ++State->Packets;
            ++Packets_;
            if (Options_.OnPacket)
            {
                try
                {
                    Options_.OnPacket(Packet);
                }
                catch (...)
                {
                    MarkBoundedFailure();
                    return false;
                }
            }
            return true;
        }

        auto Drain() noexcept -> void
        {
            Draining_ = true;
            HandshakeReady_ = false;
            ProtocolReady_ = false;
            Readiness_ = QuicReadiness::Draining;
        }

        auto Close() noexcept -> void
        {
            Drain();
            Closed_ = true;
            Connections_.clear();
            LegacyConnections_.clear();
            SocketReady_ = false;
            ReceiveLoopReady_ = false;
            Readiness_ = QuicReadiness::Closed;
        }

        [[nodiscard]] auto Health() const noexcept -> QuicGatewayHealth
        {
            return {SocketReady_, ReceiveLoopReady_, HandshakeReady_, ProtocolReady_, Draining_,
                    BoundedFailure_, ConnectionCount(), Packets_, Readiness_};
        }

        [[nodiscard]] auto ConnectionCount() const noexcept -> std::size_t
        {
            return Connections_.size() + LegacyConnections_.size();
        }

        [[nodiscard]] auto Readiness() const noexcept -> QuicReadiness
        {
            return Readiness_;
        }

    private:
        static constexpr std::size_t MaxConnectionIdLength = 20U;

        struct ConnectionState final
        {
            std::function<bool(const UdpPacket &)> Handler;
            std::size_t Packets{0};
        };

        [[nodiscard]] static auto MakeCidKey(std::span<const std::byte> ConnectionId) -> std::string
        {
            return {reinterpret_cast<const char *>(ConnectionId.data()), ConnectionId.size()};
        }

        auto MarkBoundedFailure() noexcept -> void
        {
            BoundedFailure_ = true;
            Readiness_ = QuicReadiness::Failed;
        }

        QuicGatewayOptions Options_;
        std::unordered_map<std::string, ConnectionState> Connections_;
        std::unordered_map<std::uint64_t, ConnectionState> LegacyConnections_;
        std::size_t Packets_{0};
        bool SocketReady_{false};
        bool ReceiveLoopReady_{false};
        bool HandshakeReady_{false};
        bool ProtocolReady_{false};
        bool Draining_{false};
        bool Closed_{false};
        bool BoundedFailure_{false};
        QuicReadiness Readiness_{QuicReadiness::Offline};
    };

    using SharedQuicGateway = std::shared_ptr<QuicGateway>;

} // namespace Preview::Ingress

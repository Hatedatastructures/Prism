/** @file QuicPacketGateway.cpp @brief QUIC packet admission 与 readiness 实现。 */
#include <Prism/Boundary/Quic/QuicPacketGateway.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace Prism::Boundary
{
    auto QuicPacketGatewayHealth::Healthy() const noexcept -> bool
    {
        return SocketReady && ReceiveLoopReady && HandshakeReady && ProtocolReady &&
            !Draining && !BoundedFailure;
    }

    QuicPacketGateway::QuicPacketGateway(QuicPacketGatewayOptions OptionsValue)
        : Options_(std::move(OptionsValue))
    {
        if (!Options_.AdmissionBudget)
        {
            throw std::invalid_argument("QUIC admission budget is required");
        }
    }

    auto QuicPacketGateway::MarkSocketReady() noexcept -> void
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

    auto QuicPacketGateway::MarkReceiveLoopReady() noexcept -> void
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

    auto QuicPacketGateway::MarkHandshakeReady() noexcept -> void
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

    auto QuicPacketGateway::MarkProtocolReady() noexcept -> void
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

    auto QuicPacketGateway::RegisterConnection(std::span<const std::byte> ConnectionId,
        std::function<bool(const BoundaryPacket&)> Handler) -> bool
    {
        if (Closed_ || Draining_ || ConnectionId.empty() || ConnectionId.size() > MaxConnectionIdLength ||
            !Handler)
        {
            return false;
        }
        const auto Key = MakeCidKey(ConnectionId);
        if (Connections_.contains(Key))
        {
            return false;
        }
        auto Reservation = Options_.AdmissionBudget->TryReserve();
        if (!Reservation)
        {
            return false;
        }
        if (!Reservation->RetainOwner())
        {
            Reservation->Complete();
            return false;
        }
        auto State = ConnectionState{std::move(Handler), Reservation};
        try
        {
            const auto [It, Inserted] = Connections_.emplace(Key, std::move(State));
            (void)It;
            if (!Inserted)
            {
                Reservation->Complete();
                return false;
            }
        }
        catch (...)
        {
            Reservation->Complete();
            throw;
        }
        return true;
    }

    auto QuicPacketGateway::OnConnectionClosed(std::span<const std::byte> ConnectionId) -> bool
    {
        if (ConnectionId.empty())
        {
            return false;
        }
        const auto It = Connections_.find(MakeCidKey(ConnectionId));
        if (It == Connections_.end())
        {
            return false;
        }
        It->second.Admission->Complete();
        Connections_.erase(It);
        return true;
    }

    auto QuicPacketGateway::Handle(const BoundaryPacket& Packet) -> bool
    {
        if (Closed_ || Draining_ || Packet.Classification.Kind != DatagramKind::Quic ||
            Packet.Classification.ConnectionIdBytes.empty())
        {
            return false;
        }

        const auto It = Connections_.find(MakeCidKey(Packet.Classification.ConnectionIdBytes));
        if (It == Connections_.end())
        {
            return false;
        }
        auto* State = &It->second;
        if (!State->Admission->CanAcceptPacket())
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
        State->Admission->RecordAcceptedPacket();
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

    auto QuicPacketGateway::Drain() noexcept -> void
    {
        Draining_ = true;
        HandshakeReady_ = false;
        ProtocolReady_ = false;
        Readiness_ = QuicReadiness::Draining;
    }

    auto QuicPacketGateway::Close() noexcept -> void
    {
        Drain();
        Closed_ = true;
        SocketReady_ = false;
        ReceiveLoopReady_ = false;
        Readiness_ = QuicReadiness::Closed;
    }

    auto QuicPacketGateway::Health() const noexcept -> QuicPacketGatewayHealth
    {
        return {SocketReady_, ReceiveLoopReady_, HandshakeReady_, ProtocolReady_, Draining_,
            BoundedFailure_, ConnectionCount(), Options_.AdmissionBudget->AcceptedPackets(), Readiness_};
    }

    auto QuicPacketGateway::ConnectionCount() const noexcept -> std::size_t
    {
        return Options_.AdmissionBudget->ActiveConnections();
    }

    auto QuicPacketGateway::AdmissionBudget() const noexcept
        -> std::shared_ptr<QuicAdmissionBudget>
    {
        return Options_.AdmissionBudget;
    }

    auto QuicPacketGateway::Readiness() const noexcept -> QuicReadiness
    {
        return Readiness_;
    }

    auto QuicPacketGateway::MakeCidKey(std::span<const std::byte> ConnectionId) -> std::string
    {
        return {reinterpret_cast<const char*>(ConnectionId.data()), ConnectionId.size()};
    }

    auto QuicPacketGateway::MarkBoundedFailure() noexcept -> void
    {
        BoundedFailure_ = true;
        Readiness_ = QuicReadiness::Failed;
    }
}

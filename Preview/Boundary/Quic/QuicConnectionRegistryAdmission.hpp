/**
 * @file QuicConnectionRegistryAdmission.hpp
 * @brief QUIC registry 的包分类、工厂前预约与协议接纳。
 */

#pragma once

#include <Preview/Boundary/Quic/QuicConnectionRegistry.hpp>

namespace Preview::Boundary
{
    inline auto QuicConnectionRegistry::Handle(
        const BoundaryPacket& Packet,
        const std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot>& Ingress)
        -> QuicAdmissionDisposition
    {
        Notify(QuicConnectionRegistryStage::PacketReceived, false);
        if (Closed_.load(std::memory_order_acquire) ||
            Draining_.load(std::memory_order_acquire))
        {
            return QuicAdmissionDisposition::NotHandled;
        }

        if (Packet.Classification.ConnectionIdBytes.empty())
        {
            const auto It = FindPeer(Packet.Peer);
            if (It == Entries_.end())
            {
                return QuicAdmissionDisposition::NotHandled;
            }

            return DispatchAndPrune(It, Packet);
        }

        const auto It = Entries_.find(Packet.Classification.ConnectionIdBytes);
        if (It != Entries_.end())
        {
            return DispatchAndPrune(It, Packet);
        }

        return HandleUnknownConnection(Packet, Ingress);
    }

    inline auto QuicConnectionRegistry::HandleUnknownConnection(
        const BoundaryPacket& Packet,
        const std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot>& Ingress)
        -> QuicAdmissionDisposition
    {
        const auto Existing = FindPeer(Packet.Peer);
        if (Existing != Entries_.end())
        {
            auto Owner = Existing->second.Owner;
            auto Lease = Owner->LeaseValue;
            if (!IsQuicInitialPacket(Packet.Payload))
            {
                return QuicAdmissionDisposition::NotHandled;
            }
            if (!Lease->State().HandshakeReady)
            {
                return DispatchAndPrune(Existing, Packet);
            }

            // 同一 peer 上已建立连接不因未知 CID 的冲突 Initial 被移除或关闭。
            return QuicAdmissionDisposition::Rejected;
        }

        if (!Ingress)
        {
            return QuicAdmissionDisposition::NotHandled;
        }
        if (!Ingress->IsValid()) return QuicAdmissionDisposition::Rejected;
        if (!Ingress->HasListener()) return QuicAdmissionDisposition::NotHandled;

        auto Metadata = Ingress->Metadata();
        Metadata.TaskIdentity.Generation = Ingress->Generation();
        Metadata.TaskIdentity.SessionId =
            Preview::Foundation::Identifier::ReserveSessionId();
        if (!Metadata.TaskIdentity.SessionId)
        {
            Notify(
                QuicConnectionRegistryStage::SessionIdentityUnavailable,
                false);
            return QuicAdmissionDisposition::Rejected;
        }

        auto Reservation = CloseOwner_.TryReserve();
        if (!Reservation)
        {
            return QuicAdmissionDisposition::CapacityExceeded;
        }

        auto GenerationUse = Ingress->AcquireUse();
        if (!GenerationUse)
        {
            Reservation->Complete();
            return QuicAdmissionDisposition::Rejected;
        }

        Notify(QuicConnectionRegistryStage::FactoryCalled, false);
        auto Created = Ingress->Factory()->Create({
            Packet.Classification.ConnectionIdBytes,
            Packet.Peer,
            CloseObserver(Reservation),
            std::move(Metadata),
            std::move(*GenerationUse)});

        if (!Created || !Created->Identity())
        {
            Reservation->Complete();
            Notify(QuicConnectionRegistryStage::FactoryReturnedNull, false);
            return QuicAdmissionDisposition::Rejected;
        }

        auto Lease = std::make_shared<Preview::Contract::QuicConnectionLease>(
            std::move(*Created));
        Notify(QuicConnectionRegistryStage::FactoryReturned, true);

        auto Owner = CloseOwner_.Retain({Lease, Reservation,
            Packet.Classification.ConnectionIdBytes});
        if (!Owner)
        {
            (void)Lease->RequestClose();
            return QuicAdmissionDisposition::Rejected;
        }

        const auto [InsertedIt, Inserted] = Entries_.emplace(
            Packet.Classification.ConnectionIdBytes,
            Entry{Owner, Packet.Peer});
        if (!Inserted)
        {
            (void)CloseOwner_.RequestClose(*Owner);
            return QuicAdmissionDisposition::Rejected;
        }
        if (!Reservation->RetainOwner())
        {
            Entries_.erase(InsertedIt);
            CloseOwner_.Retire(Lease->Identity());
            UpdatePhysicalRetirement();
            return QuicAdmissionDisposition::Rejected;
        }

        Lease->Start();
        Notify(QuicConnectionRegistryStage::ServerStarted, true);
        const auto Disposition = DispatchAndPrune(InsertedIt, Packet);
        if (Disposition != QuicAdmissionDisposition::Accepted)
        {
            const auto Closed = CloseOwner_.RequestClose(*Owner);
            if (Closed)
            {
                EraseAliases(Lease->Identity());
                UpdatePhysicalRetirement();
            }
        }

        return Disposition;
    }
} // namespace Preview::Boundary

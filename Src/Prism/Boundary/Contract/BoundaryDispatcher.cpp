/** @file BoundaryDispatcher.cpp @brief QUIC 与普通 datagram 的入口分发实现。 */
#include <Prism/Boundary/Contract/BoundaryDispatcher.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

namespace Prism::Boundary
{
    BoundaryDispatcher::BoundaryDispatcher(Options OptionsValue)
        : Options_(std::move(OptionsValue))
    {
    }

    auto BoundaryDispatcher::Dispatch(BoundaryPacket Packet,
        std::shared_ptr<const Prism::Contract::DatagramIngressSelection> Selection) -> void
    {
        const auto RawIngress = Selection ? Selection->Raw()
            : std::shared_ptr<const Prism::Contract::RawDatagramIngressSnapshot>{};
        const auto QuicIngress = Selection ? Selection->Quic()
            : std::shared_ptr<const Prism::Contract::QuicIngressBindingSnapshot>{};
        Notify(BoundaryDispatchStage::PacketReceived, Packet);
        if (Selection && !Selection->Matches(Selection->GenerationOwner(), Selection->UseState()))
        {
            Reject(Packet);
            return;
        }
        if (Packet.Classification.Kind == DatagramKind::Quic &&
            Packet.Classification.Route == DatagramRoute::UnknownCid)
        {
            const auto PayloadBytes = Packet.Payload.size();
            const auto Raw = DispatchRaw(RawIngress, Packet);
            if (Raw == RawDispatchResult::Consumed)
            {
                const BoundaryDispatchEvent Accepted{BoundaryDispatchStage::QuicAdmissionAccepted,
                    Packet.Classification.Kind, Packet.Classification.Route, PayloadBytes};
                Notify(Accepted);
                return;
            }
            if (Raw == RawDispatchResult::ReservationFailed)
            {
                Reject(Packet);
                return;
            }
        }
        bool QuicRejected = false;
        if (Packet.Classification.Kind == DatagramKind::Quic && Options_.QuicAdmission)
        {
            const auto Admission = Options_.QuicAdmission(Packet, QuicIngress);
            if (Admission == QuicAdmissionDisposition::Accepted)
            {
                Notify(BoundaryDispatchStage::QuicAdmissionAccepted, Packet);
                return;
            }
            if (Admission == QuicAdmissionDisposition::CapacityExceeded)
            {
                Notify(BoundaryDispatchStage::QuicAdmissionRejected, Packet);
                Notify(BoundaryDispatchStage::Rejected, Packet);
                RejectedPackets_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (Admission == QuicAdmissionDisposition::Rejected)
            {
                Notify(BoundaryDispatchStage::QuicAdmissionRejected, Packet);
                Reject(Packet);
                return;
            }
            Notify(BoundaryDispatchStage::QuicAdmissionRejected, Packet);
        }
        if (Packet.Classification.Kind == DatagramKind::Quic && Options_.Quic)
        {
            const auto GatewayEvent = BoundaryDispatchEvent{
                BoundaryDispatchStage::QuicGatewayAccepted,
                Packet.Classification.Kind,
                Packet.Classification.Route,
                Packet.Payload.size()};
            if (Options_.Quic->Handle(Packet))
            {
                Notify(GatewayEvent);
                QuicPackets_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            QuicRejected = true;
        }
        else if (Packet.Classification.Kind == DatagramKind::Quic)
        {
            // 未配置 QUIC gateway 时，QUIC-like 数据报必须回落到普通
            // datagram handler：SS2022 等协议的包头是密文，其首字节可能
            // 偶然命中 QUIC short header 的 fixed bit，静默丢弃会造成
            // 随机丢包。
            QuicRejected = true;
        }
        if ((Packet.Classification.Kind == DatagramKind::Ordinary || QuicRejected) && Options_.Datagram)
        {
            Notify(BoundaryDispatchStage::DatagramFallback, Packet);
            const auto Raw = DispatchRaw(RawIngress, Packet);
            if (Raw == RawDispatchResult::ReservationFailed)
            {
                Reject(Packet);
                return;
            }
            if (Raw == RawDispatchResult::NotMatched)
            {
                Options_.Datagram(std::move(Packet));
            }
            DatagramPackets_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        Reject(Packet);
    }

    auto BoundaryDispatcher::Snapshot() const noexcept -> BoundarySnapshot
    {
        return {QuicPackets_.load(std::memory_order_relaxed),
            DatagramPackets_.load(std::memory_order_relaxed),
            RejectedPackets_.load(std::memory_order_relaxed)};
    }

    auto BoundaryDispatcher::DispatchRaw(
        const std::shared_ptr<const Prism::Contract::RawDatagramIngressSnapshot>& Ingress,
        BoundaryPacket& Packet) -> RawDispatchResult
    {
        if (!Ingress)
        {
            return RawDispatchResult::NotMatched;
        }
        const Prism::Contract::DatagramView View{Packet.Payload, Packet.Peer, Packet.Sequence};
        for (const auto& Binding : Ingress->RetiredBindings())
        {
            if (Binding.Owner && Binding.Owner->MatchesExistingAssociation(View))
            {
                Binding.Owner->Consume(Prism::Contract::DatagramPacket{
                    std::move(Packet.Payload), Packet.Peer, Packet.Sequence, {}});
                return RawDispatchResult::Consumed;
            }
        }
        for (const auto& Binding : Ingress->Bindings())
        {
            if (Binding.Owner && Binding.Owner->MatchesExistingAssociation(View))
            {
                Binding.Owner->Consume(Prism::Contract::DatagramPacket{
                    std::move(Packet.Payload), Packet.Peer, Packet.Sequence, {}});
                return RawDispatchResult::Consumed;
            }
        }
        for (const auto& Binding : Ingress->Bindings())
        {
            if (!Binding.Owner || !Binding.Owner->Matches(View))
            {
                continue;
            }
            auto Use = Binding.AcquireUse();
            if (!Use)
            {
                return RawDispatchResult::ReservationFailed;
            }
            Binding.Owner->Consume(Prism::Contract::DatagramPacket{
                std::move(Packet.Payload), Packet.Peer, Packet.Sequence, std::move(*Use)});
            return RawDispatchResult::Consumed;
        }
        return RawDispatchResult::NotMatched;
    }

    auto BoundaryDispatcher::Reject(const BoundaryPacket& Packet) noexcept -> void
    {
        Notify(BoundaryDispatchStage::Rejected, Packet);
        RejectedPackets_.fetch_add(1, std::memory_order_relaxed);
    }

    auto BoundaryDispatcher::Notify(const BoundaryDispatchEvent Event) noexcept -> void
    {
        if (!Options_.OnEvent)
        {
            return;
        }
        try
        {
            Options_.OnEvent(Event);
        }
        catch (...)
        {
        }
    }

    auto BoundaryDispatcher::Notify(const BoundaryDispatchStage Stage,
        const BoundaryPacket& Packet) noexcept -> void
    {
        Notify(BoundaryDispatchEvent{
            Stage, Packet.Classification.Kind, Packet.Classification.Route,
            Packet.Payload.size()});
    }
}

/**
 * @file BoundaryDispatcher.hpp
 * @brief UDP demux 后的 QUIC/普通 datagram 分发边界。
 */
#pragma once

#include <Prism/Boundary/Quic/QuicPacketGateway.hpp>
#include <Prism/Contract/Ingress/DatagramIngressSelection.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>

namespace Prism::Boundary
{

    enum class BoundaryDispatchStage : std::uint8_t
    {
        PacketReceived,
        QuicAdmissionAccepted,
        QuicAdmissionRejected,
        QuicGatewayAccepted,
        DatagramFallback,
        Rejected,
    };

    struct BoundaryDispatchEvent final
    {
        BoundaryDispatchStage Stage{BoundaryDispatchStage::PacketReceived};
        DatagramKind Kind{DatagramKind::Invalid};
        DatagramRoute Route{DatagramRoute::Malformed};
        std::size_t PayloadBytes{0};
    };

    using BoundaryDispatchEventHandler = std::function<void(BoundaryDispatchEvent)>;

    [[nodiscard]] constexpr auto BoundaryDispatchStageName(
        const BoundaryDispatchStage Stage) noexcept -> std::string_view
    {
        switch (Stage)
        {
        case BoundaryDispatchStage::PacketReceived:
            return "PacketReceived";
        case BoundaryDispatchStage::QuicAdmissionAccepted:
            return "QuicAdmissionAccepted";
        case BoundaryDispatchStage::QuicAdmissionRejected:
            return "QuicAdmissionRejected";
        case BoundaryDispatchStage::QuicGatewayAccepted:
            return "QuicGatewayAccepted";
        case BoundaryDispatchStage::DatagramFallback:
            return "DatagramFallback";
        case BoundaryDispatchStage::Rejected:
            return "Rejected";
        }
        return "Unknown";
    }

    struct BoundarySnapshot final
    {
        std::uint64_t QuicPackets{0};
        std::uint64_t DatagramPackets{0};
        std::uint64_t RejectedPackets{0};
    };

    class BoundaryDispatcher final
    {
    public:
        using DatagramHandler = std::function<void(BoundaryPacket)>;

        struct Options final
        {
            SharedQuicPacketGateway Quic;
            DatagramHandler Datagram;
            std::function<QuicAdmissionDisposition(BoundaryPacket,
                std::shared_ptr<const Prism::Contract::QuicIngressBindingSnapshot>)> QuicAdmission;
            BoundaryDispatchEventHandler OnEvent;
        };

        explicit BoundaryDispatcher(Options OptionsValue)
            : Options_(std::move(OptionsValue))
        {
        }

        auto Dispatch(BoundaryPacket Packet,
            std::shared_ptr<const Prism::Contract::DatagramIngressSelection> Selection) -> void
        {
            const auto RawIngress = Selection ? Selection->Raw()
                : std::shared_ptr<const Prism::Contract::RawDatagramIngressSnapshot>{};
            const auto QuicIngress = Selection ? Selection->Quic()
                : std::shared_ptr<const Prism::Contract::QuicIngressBindingSnapshot>{};
            Notify(BoundaryDispatchStage::PacketReceived, Packet);
            if (Selection && !Selection->Matches(
                    Selection->GenerationOwner(), Selection->UseState()))
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
            if ((Packet.Classification.Kind == DatagramKind::Ordinary || QuicRejected) &&
                Options_.Datagram)
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

        [[nodiscard]] auto Snapshot() const noexcept -> BoundarySnapshot
        {
            return {QuicPackets_.load(std::memory_order_relaxed),
                    DatagramPackets_.load(std::memory_order_relaxed),
                    RejectedPackets_.load(std::memory_order_relaxed)};
        }

    private:
        enum class RawDispatchResult : std::uint8_t
        {
            NotMatched,
            Consumed,
            ReservationFailed,
        };

        [[nodiscard]] auto DispatchRaw(
            const std::shared_ptr<const Prism::Contract::RawDatagramIngressSnapshot> &Ingress,
            BoundaryPacket &Packet) -> RawDispatchResult
        {
            if (!Ingress)
            {
                return RawDispatchResult::NotMatched;
            }
            const Prism::Contract::DatagramView View{Packet.Payload, Packet.Peer, Packet.Sequence};
            for (const auto &Binding : Ingress->RetiredBindings())
            {
                if (Binding.Owner && Binding.Owner->MatchesExistingAssociation(View))
                {
                    Binding.Owner->Consume(Prism::Contract::DatagramPacket{
                        std::move(Packet.Payload), Packet.Peer, Packet.Sequence, {}});
                    return RawDispatchResult::Consumed;
                }
            }
            for (const auto &Binding : Ingress->Bindings())
            {
                if (Binding.Owner && Binding.Owner->MatchesExistingAssociation(View))
                {
                    Binding.Owner->Consume(Prism::Contract::DatagramPacket{
                        std::move(Packet.Payload), Packet.Peer, Packet.Sequence, {}});
                    return RawDispatchResult::Consumed;
                }
            }
            for (const auto &Binding : Ingress->Bindings())
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

        auto Reject(const BoundaryPacket &Packet) noexcept -> void
        {
            Notify(BoundaryDispatchStage::Rejected, Packet);
            RejectedPackets_.fetch_add(1, std::memory_order_relaxed);
        }

        auto Notify(const BoundaryDispatchEvent Event) noexcept -> void
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

        auto Notify(const BoundaryDispatchStage Stage, const BoundaryPacket &Packet) noexcept -> void
        {
            Notify(BoundaryDispatchEvent{
                Stage, Packet.Classification.Kind, Packet.Classification.Route,
                Packet.Payload.size()});
        }

        Options Options_;
        std::atomic<std::uint64_t> QuicPackets_{0};
        std::atomic<std::uint64_t> DatagramPackets_{0};
        std::atomic<std::uint64_t> RejectedPackets_{0};
    };

} // namespace Prism::Boundary

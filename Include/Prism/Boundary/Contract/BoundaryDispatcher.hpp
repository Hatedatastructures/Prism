/**
 * @file BoundaryDispatcher.hpp
 * @brief UDP demux 后的 QUIC/普通 datagram 分发边界。
 */
#pragma once

#include <Prism/Boundary/Quic/QuicPacketGateway.hpp>
#include <Prism/Contract/Ingress/Datagram/Selection.hpp>
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

        explicit BoundaryDispatcher(Options OptionsValue);

        auto Dispatch(BoundaryPacket Packet,
            std::shared_ptr<const Prism::Contract::DatagramIngressSelection> Selection) -> void;

        [[nodiscard]] auto Snapshot() const noexcept -> BoundarySnapshot;

    private:
        enum class RawDispatchResult : std::uint8_t
        {
            NotMatched,
            Consumed,
            ReservationFailed,
        };

        [[nodiscard]] auto DispatchRaw(
            const std::shared_ptr<const Prism::Contract::RawDatagramIngressSnapshot> &Ingress,
            BoundaryPacket &Packet) -> RawDispatchResult;

        auto Reject(const BoundaryPacket &Packet) noexcept -> void;

        auto Notify(const BoundaryDispatchEvent Event) noexcept -> void;

        auto Notify(const BoundaryDispatchStage Stage, const BoundaryPacket &Packet) noexcept -> void;

        Options Options_;
        std::atomic<std::uint64_t> QuicPackets_{0};
        std::atomic<std::uint64_t> DatagramPackets_{0};
        std::atomic<std::uint64_t> RejectedPackets_{0};
    };

} // namespace Prism::Boundary

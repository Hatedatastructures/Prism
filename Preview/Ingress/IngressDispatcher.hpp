/**
 * @file IngressDispatcher.hpp
 * @brief UDP demux 后的 QUIC/普通 datagram 分发边界。
 */
#pragma once

#include <Preview/Ingress/QuicGateway.hpp>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>

namespace Preview::Ingress
{

    struct IngressSnapshot final
    {
        std::uint64_t QuicPackets{0};
        std::uint64_t DatagramPackets{0};
        std::uint64_t RejectedPackets{0};
    };

    class IngressDispatcher final
    {
    public:
        using DatagramHandler = std::function<void(UdpPacket)>;

        struct Options final
        {
            SharedQuicGateway Quic;
            DatagramHandler Datagram;
        };

        explicit IngressDispatcher(Options OptionsValue)
            : Options_(std::move(OptionsValue))
        {
        }

        auto Dispatch(UdpPacket Packet) -> void
        {
            if (Packet.Classification.Kind == DatagramKind::Quic && Options_.Quic)
            {
                if (Options_.Quic->Handle(std::move(Packet)))
                {
                    QuicPackets_.fetch_add(1, std::memory_order_relaxed);
                }
                else
                {
                    RejectedPackets_.fetch_add(1, std::memory_order_relaxed);
                }
                return;
            }
            if (Packet.Classification.Kind == DatagramKind::Ordinary && Options_.Datagram)
            {
                Options_.Datagram(std::move(Packet));
                DatagramPackets_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            RejectedPackets_.fetch_add(1, std::memory_order_relaxed);
        }

        [[nodiscard]] auto Snapshot() const noexcept -> IngressSnapshot
        {
            return {QuicPackets_.load(std::memory_order_relaxed),
                    DatagramPackets_.load(std::memory_order_relaxed),
                    RejectedPackets_.load(std::memory_order_relaxed)};
        }

    private:
        Options Options_;
        std::atomic<std::uint64_t> QuicPackets_{0};
        std::atomic<std::uint64_t> DatagramPackets_{0};
        std::atomic<std::uint64_t> RejectedPackets_{0};
    };

} // namespace Preview::Ingress

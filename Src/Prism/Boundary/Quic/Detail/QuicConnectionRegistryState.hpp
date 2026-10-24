/**
 * @file QuicConnectionRegistryState.hpp
 * @brief QUIC Boundary 注册表的 CID、peer 与 close owner 私有状态。
 */
#pragma once

#include <Prism/Boundary/Quic/QuicConnectionRegistry.hpp>

#include "QuicConnectionRegistryCloseOwner.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <unordered_map>

namespace Prism::Boundary
{
    struct QuicConnectionRegistry::State final
    {
        using Cid = QuicConnectionId;

        /** @brief 以二进制字节计算透明 QUIC CID 哈希。 */
        struct QuicConnectionIdHash final
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(const QuicConnectionId &Id) const noexcept -> std::size_t
            {
                return (*this)(std::span<const std::byte>(Id.data(), Id.size()));
            }

            [[nodiscard]] auto operator()(const std::span<const std::byte> Id) const noexcept
                -> std::size_t
            {
                std::size_t Hash = 2166136261U;
                for (const auto Byte : Id)
                {
                    Hash = (Hash ^ std::to_integer<std::uint8_t>(Byte)) * 16777619U;
                }
                return Hash;
            }
        };

        /** @brief 对 vector CID 与借用 span 执行透明二进制相等比较。 */
        struct QuicConnectionIdEqual final
        {
            using is_transparent = void;

            [[nodiscard]] auto operator()(
                const QuicConnectionId &Left, const QuicConnectionId &Right) const noexcept -> bool
            {
                return Left.size() == Right.size() && std::equal(Left.begin(), Left.end(), Right.begin());
            }

            [[nodiscard]] auto operator()(
                const QuicConnectionId &Left, const std::span<const std::byte> Right) const noexcept
                -> bool
            {
                return Left.size() == Right.size() && std::equal(Left.begin(), Left.end(), Right.begin());
            }

            [[nodiscard]] auto operator()(
                const std::span<const std::byte> Left, const QuicConnectionId &Right) const noexcept
                -> bool
            {
                return Left.size() == Right.size() && std::equal(Left.begin(), Left.end(), Right.begin());
            }
        };

        struct Entry final
        {
            std::shared_ptr<QuicConnectionRegistryCloseOwner::Owner> Owner;
            Udp::endpoint Peer;
        };

        using EntryMap = std::unordered_map<Cid, Entry,
            QuicConnectionIdHash, QuicConnectionIdEqual>;

        explicit State(Options Value);

        [[nodiscard]] auto Handle(
            const BoundaryPacket& Packet,
            const std::shared_ptr<const Prism::Contract::QuicIngressBindingSnapshot>& Ingress,
            QuicConnectionRegistry& Registry)
            -> QuicAdmissionDisposition;
        [[nodiscard]] auto HandleUnknownConnection(
            const BoundaryPacket& Packet,
            const std::shared_ptr<const Prism::Contract::QuicIngressBindingSnapshot>& Ingress,
            QuicConnectionRegistry& Registry)
            -> QuicAdmissionDisposition;
        [[nodiscard]] auto Register(Registration Input) -> bool;
        [[nodiscard]] auto Remove(std::span<const std::byte> ConnectionId) -> bool;
        [[nodiscard]] auto OnOwnerClosed(std::span<const std::byte> ConnectionId) -> bool;
        auto StopAdmission() noexcept -> void;
        [[nodiscard]] auto Drain() -> std::expected<void, Prism::Fault::Failure>;
        [[nodiscard]] auto Close() -> std::expected<void, Prism::Fault::Failure>;
        [[nodiscard]] auto HasPendingClose() const noexcept -> bool;
        [[nodiscard]] auto CanRetryClose() const noexcept -> bool;
        [[nodiscard]] auto Size() const noexcept -> std::size_t;
        [[nodiscard]] auto ActiveConnectionCount() const noexcept -> std::size_t;
        [[nodiscard]] auto IsRetired() const noexcept -> bool;

    private:
        [[nodiscard]] auto CloseObserver(
            const std::shared_ptr<QuicAdmissionBudget::Reservation>& Reservation,
            std::weak_ptr<QuicConnectionRegistry> Registry) -> std::function<void()>;
        [[nodiscard]] auto FindPeer(const Udp::endpoint& Peer) -> EntryMap::iterator;
        [[nodiscard]] auto HasPeer(const Udp::endpoint& Peer) const -> bool;
        [[nodiscard]] auto HasPeerOwner(
            const Udp::endpoint& Peer,
            const Prism::Contract::QuicConnectionOwner* Identity) const -> bool;
        [[nodiscard]] auto HasOwnerAtDifferentPeer(
            const Prism::Contract::QuicConnectionOwner* Identity,
            const Udp::endpoint& Peer) const -> bool;
        auto EraseAliases(const Prism::Contract::QuicConnectionOwner* Identity) -> void;
        auto RetireOwner(const QuicAdmissionBudget::Reservation* Reservation) -> void;
        [[nodiscard]] auto RequestCloseAll()
            -> std::expected<void, Prism::Fault::Failure>;
        [[nodiscard]] auto DispatchAndPrune(
            EntryMap::iterator It,
            const BoundaryPacket& Packet) -> QuicAdmissionDisposition;
        auto Notify(QuicConnectionRegistryStage Stage, bool Accepted) noexcept -> void;
        auto UpdatePhysicalRetirement() noexcept -> void;

        Options Options_;
        QuicConnectionRegistryCloseOwner CloseOwner_;
        EntryMap Entries_;
        std::atomic<bool> Draining_{false};
        std::atomic<bool> Closed_{false};
        std::atomic<bool> PhysicallyRetired_{false};
    };
}

/** @file QuicConnectionRegistry.cpp @brief QUIC CID 注册、退役与关闭状态实现。 */
#include "Detail/QuicConnectionRegistryState.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>

namespace Prism::Boundary
{
    namespace
    {
        /** @brief 发送诊断快照；诊断异常不改变注册表数据面结果。 */
        inline auto NotifyQuicConnectionRegistryEvent(
            const QuicConnectionRegistryEventHandler &Handler,
            const QuicConnectionRegistryEvent Event) noexcept -> void
        {
            try
            {
                if (Handler)
                {
                    Handler(Event);
                }
            }
            catch (...)
            {
            }
        }
    }

    QuicConnectionRegistry::State::State(Options Value)
        : Options_(std::move(Value)), CloseOwner_(Options_.AdmissionBudget)
    {
        if (!Options_.AdmissionBudget)
        {
            throw std::invalid_argument("QUIC admission budget is required");
        }
    }

    QuicConnectionRegistry::QuicConnectionRegistry(Options Value)
        : State_(std::make_unique<State>(std::move(Value)))
    {
    }

    QuicConnectionRegistry::~QuicConnectionRegistry()
    {
        (void)Close();
    }

    auto QuicConnectionRegistry::Register(Registration Input) -> bool
    {
        return State_->Register(std::move(Input));
    }

    auto QuicConnectionRegistry::State::Register(Registration Input) -> bool
    {
        if (!Input.Lease)
        {
            return false;
        }
        const auto Identity = Input.Lease->Identity();
        const auto State = Input.Lease->State();
        auto Key = std::move(Input.ConnectionId);
        if (Closed_.load(std::memory_order_acquire) ||
            Draining_.load(std::memory_order_acquire) || Key.empty() || !Identity ||
            State.Closed || Entries_.contains(Key))
        {
            return false;
        }

        if (HasOwnerAtDifferentPeer(Identity, Input.Peer))
        {
            return false;
        }

        if (HasPeer(Input.Peer) && !HasPeerOwner(Input.Peer, Identity))
        {
            return false;
        }

        auto Owner = CloseOwner_.Find(Identity);
        const auto NewOwner = !Owner;
        if (NewOwner)
        {
            auto Reservation = CloseOwner_.TryReserve();
            if (!Reservation)
            {
                return false;
            }
            Owner = CloseOwner_.Retain({Input.Lease, std::move(Reservation), Key});
            if (!Owner)
            {
                return false;
            }
        }
        else
        {
            CloseOwner_.AddConnectionId(*Owner, Key);
        }

        const auto [It, Inserted] = Entries_.emplace(
            std::move(Key), Entry{Owner, std::move(Input.Peer)});
        (void)It;
        if (!Inserted)
        {
            if (NewOwner)
            {
                CloseOwner_.Retire(Identity);
            }
            return false;
        }
        if (NewOwner && !Owner->Admission->RetainOwner())
        {
            Entries_.erase(It);
            Owner->Admission->Complete();
            CloseOwner_.Retire(Identity);
            return false;
        }
        return true;
    }

    auto QuicConnectionRegistry::Remove(
        const std::span<const std::byte> ConnectionId) -> bool
    {
        return State_->Remove(ConnectionId);
    }

    auto QuicConnectionRegistry::State::Remove(
        const std::span<const std::byte> ConnectionId) -> bool
    {
        const auto It = Entries_.find(ConnectionId);
        if (It == Entries_.end())
        {
            return false;
        }

        auto Owner = It->second.Owner;
        auto Lease = Owner->LeaseValue;
        const auto Identity = Lease->Identity();
        if (Lease->State().Closed)
        {
            const auto Closed = CloseOwner_.RequestClose(*Owner);
            if (!Closed)
            {
                return false;
            }
            EraseAliases(Identity);
            UpdatePhysicalRetirement();
            return true;
        }
        const auto HasOtherAlias = std::any_of(
            Entries_.begin(), Entries_.end(),
            [It, Identity](const auto& Pair)
            {
                return Pair.second.Owner->LeaseValue->Identity() == Identity &&
                    std::addressof(Pair.second) != std::addressof(It->second);
            });
        if (HasOtherAlias)
        {
            Entries_.erase(It);
            return true;
        }

        const auto Closed = CloseOwner_.RequestClose(*Owner);
        if (!Closed)
        {
            return false;
        }
        EraseAliases(Identity);
        UpdatePhysicalRetirement();
        return true;
    }

    auto QuicConnectionRegistry::OnOwnerClosed(
        const std::span<const std::byte> ConnectionId) -> bool
    {
        return State_->OnOwnerClosed(ConnectionId);
    }

    auto QuicConnectionRegistry::State::OnOwnerClosed(
        const std::span<const std::byte> ConnectionId) -> bool
    {
        const auto Owner = CloseOwner_.FindByConnectionId(ConnectionId);
        if (!Owner)
        {
            return false;
        }
        RetireOwner(Owner->Admission.get());
        UpdatePhysicalRetirement();
        return true;
    }

    auto QuicConnectionRegistry::StopAdmission() noexcept -> void
    {
        State_->StopAdmission();
    }

    auto QuicConnectionRegistry::State::StopAdmission() noexcept -> void
    {
        Draining_.store(true, std::memory_order_release);
    }

    auto QuicConnectionRegistry::Drain()
        -> std::expected<void, Prism::Fault::Failure>
    {
        return State_->Drain();
    }

    auto QuicConnectionRegistry::State::Drain()
        -> std::expected<void, Prism::Fault::Failure>
    {
        StopAdmission();
        return RequestCloseAll();
    }

    auto QuicConnectionRegistry::Close()
        -> std::expected<void, Prism::Fault::Failure>
    {
        return State_->Close();
    }

    auto QuicConnectionRegistry::State::Close()
        -> std::expected<void, Prism::Fault::Failure>
    {
        StopAdmission();
        Closed_.store(true, std::memory_order_release);
        const auto Result = RequestCloseAll();
        UpdatePhysicalRetirement();
        return Result;
    }

    auto QuicConnectionRegistry::HasPendingClose() const noexcept -> bool
    {
        return State_->HasPendingClose();
    }

    auto QuicConnectionRegistry::State::HasPendingClose() const noexcept -> bool
    {
        return CloseOwner_.HasPendingClose();
    }

    auto QuicConnectionRegistry::CanRetryClose() const noexcept -> bool
    {
        return State_->CanRetryClose();
    }

    auto QuicConnectionRegistry::State::CanRetryClose() const noexcept -> bool
    {
        return Closed_.load(std::memory_order_acquire) && CloseOwner_.HasPendingClose();
    }

    auto QuicConnectionRegistry::Size() const noexcept -> std::size_t
    {
        return State_->Size();
    }

    auto QuicConnectionRegistry::State::Size() const noexcept -> std::size_t
    {
        return Entries_.size();
    }

    auto QuicConnectionRegistry::ActiveConnectionCount() const noexcept -> std::size_t
    {
        return State_->ActiveConnectionCount();
    }

    auto QuicConnectionRegistry::State::ActiveConnectionCount() const noexcept -> std::size_t
    {
        return Options_.AdmissionBudget->ActiveConnections();
    }

    auto QuicConnectionRegistry::IsRetired() const noexcept -> bool
    {
        return State_->IsRetired();
    }

    auto QuicConnectionRegistry::State::IsRetired() const noexcept -> bool
    {
        return PhysicallyRetired_.load(std::memory_order_acquire);
    }

    auto QuicConnectionRegistry::State::CloseObserver(
        const std::shared_ptr<QuicAdmissionBudget::Reservation>& Reservation,
        std::weak_ptr<QuicConnectionRegistry> Registry)
        -> std::function<void()>
    {
        return [Weak = std::move(Registry), Reservation]
        {
            Reservation->Complete();
            if (auto Owner = Weak.lock())
            {
                Owner->State_->RetireOwner(Reservation.get());
                Owner->State_->UpdatePhysicalRetirement();
            }
        };
    }

    auto QuicConnectionRegistry::State::FindPeer(const Udp::endpoint& Peer) -> EntryMap::iterator
    {
        return std::find_if(
            Entries_.begin(),
            Entries_.end(),
            [&Peer](const auto& Value)
            {
                return Value.second.Peer == Peer &&
                    !Value.second.Owner->LeaseValue->State().Closed;
            });
    }

    auto QuicConnectionRegistry::State::HasPeer(const Udp::endpoint& Peer) const -> bool
    {
        return std::any_of(
            Entries_.begin(),
            Entries_.end(),
            [&Peer](const auto& Value)
            {
                return Value.second.Peer == Peer;
            });
    }

    auto QuicConnectionRegistry::State::HasPeerOwner(
        const Udp::endpoint& Peer,
        const Prism::Contract::QuicConnectionOwner* Identity) const -> bool
    {
        return std::any_of(
            Entries_.begin(),
            Entries_.end(),
            [&Peer, Identity](const auto& Value)
            {
                return Value.second.Peer == Peer &&
                    Value.second.Owner->LeaseValue->Identity() == Identity;
            });
    }

    auto QuicConnectionRegistry::State::HasOwnerAtDifferentPeer(
        const Prism::Contract::QuicConnectionOwner* Identity,
        const Udp::endpoint& Peer) const -> bool
    {
        return std::any_of(
            Entries_.begin(),
            Entries_.end(),
            [&Peer, Identity](const auto& Value)
            {
                return Value.second.Peer != Peer &&
                    Value.second.Owner->LeaseValue->Identity() == Identity;
            });
    }

    auto QuicConnectionRegistry::State::EraseAliases(
        const Prism::Contract::QuicConnectionOwner* Identity) -> void
    {
        for (auto It = Entries_.begin(); It != Entries_.end();)
        {
            if (It->second.Owner->LeaseValue->Identity() == Identity)
            {
                It = Entries_.erase(It);
            }
            else
            {
                ++It;
            }
        }
    }

    auto QuicConnectionRegistry::State::RetireOwner(
        const QuicAdmissionBudget::Reservation* Reservation) -> void
    {
        const auto Owner = CloseOwner_.Find(Reservation);
        if (!Owner)
        {
            return;
        }
        Owner->Admission->Complete();
        const auto Identity = Owner->LeaseValue->Identity();
        EraseAliases(Identity);
        CloseOwner_.Retire(Identity);
    }

    auto QuicConnectionRegistry::State::RequestCloseAll()
        -> std::expected<void, Prism::Fault::Failure>
    {
        const auto Result = CloseOwner_.RequestCloseAll();
        for (auto It = Entries_.begin(); It != Entries_.end();)
        {
            if (It->second.Owner->CloseAccepted)
            {
                It = Entries_.erase(It);
            }
            else
            {
                ++It;
            }
        }
        return Result;
    }

    auto QuicConnectionRegistry::State::DispatchAndPrune(
        EntryMap::iterator It,
        const BoundaryPacket& Packet) -> QuicAdmissionDisposition
    {
        auto Owner = It->second.Owner;
        auto Lease = Owner->LeaseValue;
        const auto Identity = Lease->Identity();
        const auto Before = Lease->State();
        const auto PeerMatches = It->second.Peer == Packet.Peer;

        if (!PeerMatches)
        {
            Notify(QuicConnectionRegistryStage::ReceiveRejected, false);
            return QuicAdmissionDisposition::NotHandled;
        }

        if (Before.Closed)
        {
            Notify(QuicConnectionRegistryStage::ReceiveRejected, false);
            if (Lease->State().Closed)
            {
                const auto Closed = CloseOwner_.RequestClose(*Owner);
                if (Closed)
                {
                    EraseAliases(Identity);
                }
            }
            return QuicAdmissionDisposition::Rejected;
        }

        if (!Owner->Admission->CanAcceptPacket())
        {
            Notify(QuicConnectionRegistryStage::ReceiveRejected, false);
            if (Lease->State().Closed)
            {
                const auto Closed = CloseOwner_.RequestClose(*Owner);
                if (Closed)
                {
                    EraseAliases(Identity);
                }
            }
            return QuicAdmissionDisposition::NotHandled;
        }

        const auto Accepted = Lease->ReceivePacket(Packet.Payload, Packet.Peer);
        if (Accepted)
        {
            Owner->Admission->RecordAcceptedPacket();
            Notify(QuicConnectionRegistryStage::ReceiveAccepted, true);
        }
        else
        {
            Notify(QuicConnectionRegistryStage::ReceiveRejected, false);
        }

        if (Lease->State().Closed)
        {
            const auto Closed = CloseOwner_.RequestClose(*Owner);
            if (Closed)
            {
                EraseAliases(Identity);
            }
        }

        if (Accepted)
        {
            return QuicAdmissionDisposition::Accepted;
        }
        return QuicAdmissionDisposition::Rejected;
    }

    auto QuicConnectionRegistry::State::Notify(
        QuicConnectionRegistryStage Stage,
        const bool Accepted) noexcept -> void
    {
        NotifyQuicConnectionRegistryEvent(
            Options_.OnEvent, {Stage, Accepted, ActiveConnectionCount()});
    }

    auto QuicConnectionRegistry::State::UpdatePhysicalRetirement() noexcept -> void
    {
        if (Closed_.load(std::memory_order_acquire) && Entries_.empty() &&
            CloseOwner_.Size() == 0U)
        {
            PhysicallyRetired_.store(true, std::memory_order_release);
        }
    }
} // namespace Prism::Boundary

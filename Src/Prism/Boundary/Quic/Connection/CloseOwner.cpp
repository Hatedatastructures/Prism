/** @file CloseOwner.cpp @brief QUIC registry唯一owner与关闭回执实现。 */
#include <Prism/Boundary/Quic/Connection/Detail/CloseOwner.hpp>

#include <algorithm>
#include <memory>
#include <utility>

namespace Prism::Boundary
{
    QuicConnectionRegistryCloseOwner::QuicConnectionRegistryCloseOwner(
        std::shared_ptr<QuicAdmissionBudget> Budget)
        : Budget_(std::move(Budget))
    {
    }

    auto QuicConnectionRegistryCloseOwner::TryReserve() -> std::shared_ptr<Reservation>
    {
        return Budget_->TryReserve();
    }

    auto QuicConnectionRegistryCloseOwner::Find(const OwnerIdentity Identity) const noexcept
        -> std::shared_ptr<Owner>
    {
        const auto It = Owners_.find(Identity);
        return It == Owners_.end() ? std::shared_ptr<Owner>{} : It->second;
    }

    auto QuicConnectionRegistryCloseOwner::Find(const Reservation* Value) const noexcept
        -> std::shared_ptr<Owner>
    {
        const auto It = std::find_if(Owners_.begin(), Owners_.end(),
            [Value](const auto& Pair)
            {
                return Pair.second->Admission.get() == Value;
            });
        return It == Owners_.end() ? std::shared_ptr<Owner>{} : It->second;
    }

    auto QuicConnectionRegistryCloseOwner::Retain(Admission Input) -> std::shared_ptr<Owner>
    {
        if (!Input.LeaseValue || !Input.ReservationValue ||
            !Input.LeaseValue->Identity())
        {
            return {};
        }
        auto Value = std::make_shared<Owner>(Owner{
            std::move(Input.LeaseValue), std::move(Input.ReservationValue),
            {std::move(Input.ConnectionId)}, {}, false});
        const auto Identity = Value->LeaseValue->Identity();
        const auto [It, Inserted] = Owners_.emplace(Identity, Value);
        return Inserted ? Value : It->second;
    }

    auto QuicConnectionRegistryCloseOwner::AddConnectionId(
        Owner& Value, QuicConnectionId ConnectionId) -> void
    {
        if (std::find(Value.ConnectionIds.begin(), Value.ConnectionIds.end(), ConnectionId) ==
            Value.ConnectionIds.end())
        {
            Value.ConnectionIds.push_back(std::move(ConnectionId));
        }
    }

    auto QuicConnectionRegistryCloseOwner::FindByConnectionId(
        const std::span<const std::byte> ConnectionId) const -> std::shared_ptr<Owner>
    {
        for (const auto& Pair : Owners_)
        {
            const auto Match = std::find_if(Pair.second->ConnectionIds.begin(),
                Pair.second->ConnectionIds.end(),
                [ConnectionId](const QuicConnectionId& Candidate)
                {
                    return Candidate.size() == ConnectionId.size() &&
                        std::equal(Candidate.begin(), Candidate.end(), ConnectionId.begin());
                });
            if (Match != Pair.second->ConnectionIds.end())
            {
                return Pair.second;
            }
        }
        return {};
    }

    auto QuicConnectionRegistryCloseOwner::Retire(const OwnerIdentity Identity) -> void
    {
        Owners_.erase(Identity);
    }

    auto QuicConnectionRegistryCloseOwner::RequestClose(Owner& Value)
        -> std::expected<void, Prism::Fault::Failure>
    {
        const auto Result = Value.LeaseValue->RequestClose();
        if (Result)
        {
            Value.CloseFailure.reset();
            Value.CloseAccepted = true;
            return {};
        }
        if (!Value.CloseFailure)
        {
            Value.CloseFailure = Result.error();
        }
        Value.CloseAccepted = false;
        return std::unexpected(*Value.CloseFailure);
    }

    auto QuicConnectionRegistryCloseOwner::RequestCloseAll()
        -> std::expected<void, Prism::Fault::Failure>
    {
        const auto Snapshot = Owners_;
        auto FirstFailure = std::optional<Prism::Fault::Failure>{};
        for (const auto& Pair : Snapshot)
        {
            const auto Result = RequestClose(*Pair.second);
            if (!Result && !FirstFailure)
            {
                FirstFailure = Result.error();
            }
        }
        if (FirstFailure)
        {
            return std::unexpected(*FirstFailure);
        }
        return {};
    }

    auto QuicConnectionRegistryCloseOwner::HasPendingClose() const noexcept -> bool
    {
        return std::any_of(Owners_.begin(), Owners_.end(),
            [](const auto& Pair)
            {
                return Pair.second->CloseFailure.has_value();
            });
    }

    auto QuicConnectionRegistryCloseOwner::Size() const noexcept -> std::size_t
    {
        return Owners_.size();
    }
}

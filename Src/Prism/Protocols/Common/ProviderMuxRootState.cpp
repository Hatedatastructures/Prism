/** @file ProviderMuxRootState.cpp @brief Provider mux root slot 状态实现。 */

#include <Prism/Protocols/Common/ProviderMuxRootState.hpp>

#include <memory>
#include <utility>

namespace Prism::Protocols
{
    ProviderMuxRootState::ProviderMuxRootState()
        : RootSlot_(std::make_shared<RootOwner>())
    {
    }

    [[nodiscard]] auto ProviderMuxRootState::ClaimMuxRootCreate() noexcept -> bool
    {
        bool Expected = false;
        return MuxRootCreateClaimed_.compare_exchange_strong(
            Expected, true, std::memory_order_acq_rel);
    }

    auto ProviderMuxRootState::AttachMuxRootPlane(
        Prism::Contract::ProtocolDataPlane &&Plane) noexcept -> void
    {
        RootSlot_->Transport = Plane.Transport();
        RootSlot_->PendingPlane.emplace(std::move(Plane));
    }

    auto ProviderMuxRootState::AttachMuxRootGenerationLease(
        Prism::Foundation::GenerationUseLease &&Lease) noexcept -> void
    {
        RootGenerationUseLease_ = std::move(Lease);
    }

    auto ProviderMuxRootState::AttachMuxRootSession(
        std::shared_ptr<Prism::Contract::MuxSession> Session) noexcept -> void
    {
        if (!Session)
        {
            return;
        }
        RootSlot_->Mux = std::move(Session);
        if (RootSlot_->PendingPlane)
        {
            if (auto *Mux = RootSlot_->PendingPlane->Mux())
            {
                Mux->Session = RootSlot_->Mux;
            }
        }
        Root_.store(RootSlot_, std::memory_order_release);
        OnMuxRootSessionAttached();
    }

    [[nodiscard]] auto ProviderMuxRootState::TakeMuxRootPlane() noexcept
        -> Prism::Contract::ProtocolDataPlane
    {
        if (!RootSlot_ || !RootSlot_->PendingPlane)
        {
            return {};
        }
        auto Plane = std::move(*RootSlot_->PendingPlane);
        RootSlot_->PendingPlane.reset();
        return Plane;
    }

    [[nodiscard]] auto ProviderMuxRootState::TakeMuxRootGenerationLease() noexcept
        -> Prism::Foundation::GenerationUseLease
    {
        return std::move(RootGenerationUseLease_);
    }

    auto ProviderMuxRootState::OnMuxRootRetired() noexcept -> void
    {
        Root_.store({}, std::memory_order_release);
        if (RootSlot_) RootSlot_->Mux.reset();
    }
} // namespace Prism::Protocols

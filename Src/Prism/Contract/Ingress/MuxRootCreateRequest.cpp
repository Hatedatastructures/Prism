/** @file MuxRootCreateRequest.cpp @brief mux 根创建资源交接实现。 */
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>

#include <expected>
#include <memory>
#include <utility>

namespace Prism::Contract
{
    auto MuxRootCreateOwner::AttachMuxRootParentStreamLease(
        Prism::Account::StreamLease &&Lease) noexcept -> bool
    {
        if (ParentStreamLeaseClaimed_ || !CanAttachMuxRootParentStreamLease()) return false;
        ParentStreamLease_ = std::move(Lease);
        ParentStreamLeaseClaimed_ = true;
        return true;
    }

    auto MuxRootCreateOwner::TakeMuxRootParentStreamLease() noexcept
        -> Prism::Account::StreamLease
    {
        return std::move(ParentStreamLease_);
    }

    auto MuxRootCreateOwner::ReleaseMuxRootParentStreamLease() noexcept -> void
    {
        ParentStreamLease_.Release();
    }

    MuxRootCreateRequest::MuxRootCreateRequest(MuxRootCreateRequest &&Other) noexcept
        : Owner_(std::move(Other.Owner_)), GenerationUseState_(std::move(Other.GenerationUseState_)),
          Transferred_(std::exchange(Other.Transferred_, true)),
          SessionCreationClaimed_(std::exchange(Other.SessionCreationClaimed_, true)),
          SessionAttached_(std::exchange(Other.SessionAttached_, false)),
          ParentStreamLeaseTaken_(std::exchange(Other.ParentStreamLeaseTaken_, false))
    {
    }

    auto MuxRootCreateRequest::operator=(MuxRootCreateRequest &&Other) noexcept
        -> MuxRootCreateRequest &
    {
        if (this != &Other)
        {
            Retain();
            Owner_ = std::move(Other.Owner_);
            GenerationUseState_ = std::move(Other.GenerationUseState_);
            Transferred_ = std::exchange(Other.Transferred_, true);
            SessionCreationClaimed_ = std::exchange(Other.SessionCreationClaimed_, true);
            SessionAttached_ = std::exchange(Other.SessionAttached_, false);
            ParentStreamLeaseTaken_ = std::exchange(Other.ParentStreamLeaseTaken_, false);
        }
        return *this;
    }

    MuxRootCreateRequest::~MuxRootCreateRequest() noexcept
    {
        Retain();
    }

    auto MuxRootCreateRequest::Prepare(
        std::shared_ptr<MuxRootCreateOwner> Owner,
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState,
        ProtocolDataPlane &&Plane) -> std::expected<MuxRootCreateRequest, Prism::Fault::Failure>
    {
        if (!Owner || !GenerationUseState || !Plane.IsMux() || !Plane.Transport())
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (!Owner->ClaimMuxRootCreate())
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }

        Owner->AttachMuxRootPlane(std::move(Plane));
        auto Request = MuxRootCreateRequest(std::move(Owner), std::move(GenerationUseState));
        auto Lease = Request.GenerationUseState_->Acquire();
        if (!Lease)
        {
            Request.Retain();
            return std::unexpected(Lease.error());
        }
        Request.Owner_->AttachMuxRootGenerationLease(std::move(*Lease));
        return Request;
    }

    auto MuxRootCreateRequest::BeginSessionCreation() noexcept -> bool
    {
        if (!Owner_ || Transferred_ || SessionCreationClaimed_) return false;
        SessionCreationClaimed_ = true;
        return true;
    }

    auto MuxRootCreateRequest::AttachSession(std::shared_ptr<MuxSession> Session) noexcept -> void
    {
        if (!SessionCreationClaimed_ || SessionAttached_ || !Session) return;
        Owner_->AttachMuxRootSession(std::move(Session));
        SessionAttached_ = true;
    }

    auto MuxRootCreateRequest::TakePlane() noexcept -> ProtocolDataPlane
    {
        if (!SessionAttached_) return {};
        return Owner_->TakeMuxRootPlane();
    }

    auto MuxRootCreateRequest::TakeGenerationUseLease() noexcept
        -> Prism::Foundation::GenerationUseLease
    {
        if (!SessionAttached_) return {};
        return Owner_->TakeMuxRootGenerationLease();
    }

    auto MuxRootCreateRequest::TakeParentStreamLease() noexcept
        -> Prism::Account::StreamLease
    {
        if (!SessionAttached_ || ParentStreamLeaseTaken_) return {};
        ParentStreamLeaseTaken_ = true;
        return Owner_->TakeMuxRootParentStreamLease();
    }

    auto MuxRootCreateRequest::Transfer() noexcept -> void
    {
        if (!Owner_ || Transferred_ || !SessionAttached_ || !ParentStreamLeaseTaken_) return;
        Owner_->TransferMuxRoot();
        Transferred_ = true;
        Owner_.reset();
        GenerationUseState_.reset();
    }

    MuxRootCreateRequest::MuxRootCreateRequest(
        std::shared_ptr<MuxRootCreateOwner> Owner,
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState) noexcept
        : Owner_(std::move(Owner)), GenerationUseState_(std::move(GenerationUseState))
    {
    }

    auto MuxRootCreateRequest::Retain() noexcept -> void
    {
        if (Owner_ && !Transferred_)
        {
            Owner_->RetainMuxRoot();
            Transferred_ = true;
        }
    }
}

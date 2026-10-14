/**
 * @file MuxRootCreateRequest.hpp
 * @brief 已认证 mux 根创建的唯一资源交接与失败保留请求。
 */
#pragma once

#include <Preview/Contract/Ingress/DataPlane.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <expected>
#include <memory>
#include <utility>

namespace Preview::Contract
{
    /**
     * @brief 握手前预预约的 mux 根失败退休 owner。
     * @details C4 入站票据和 AnyTLS C3 票据直接实现本生命周期接口。Plane、根代次 lease
     *          与已构造的 MuxSession 在同一个既有票据内移动；退休前不得释放或复制实物。
     */
    class MuxRootCreateOwner
    {
    public:
        virtual ~MuxRootCreateOwner() = default;
        [[nodiscard]] virtual auto ClaimMuxRootCreate() noexcept -> bool = 0;
        virtual auto AttachMuxRootPlane(ProtocolDataPlane &&Plane) noexcept -> void = 0;
        virtual auto AttachMuxRootGenerationLease(
            Preview::Foundation::GenerationUseLease &&Lease) noexcept -> void = 0;
        /** @brief 接管嵌套 mux 根的祖先 stream 配额；每个预构造 owner 只接管一次。 */
        [[nodiscard]] virtual auto CanAttachMuxRootParentStreamLease() const noexcept -> bool = 0;
        [[nodiscard]] auto AttachMuxRootParentStreamLease(
            Preview::Account::StreamLease &&Lease) noexcept -> bool
        {
            if (ParentStreamLeaseClaimed_ || !CanAttachMuxRootParentStreamLease()) return false;
            ParentStreamLease_ = std::move(Lease);
            ParentStreamLeaseClaimed_ = true;
            return true;
        }
        [[nodiscard]] virtual auto MuxRootTransport() const noexcept
            -> Preview::SharedTransmission = 0;
        virtual auto AttachMuxRootSession(std::shared_ptr<MuxSession> Session) noexcept -> void = 0;
        [[nodiscard]] virtual auto TakeMuxRootPlane() noexcept -> ProtocolDataPlane = 0;
        [[nodiscard]] virtual auto TakeMuxRootGenerationLease() noexcept
            -> Preview::Foundation::GenerationUseLease = 0;
        [[nodiscard]] auto TakeMuxRootParentStreamLease() noexcept
            -> Preview::Account::StreamLease
        {
            return std::move(ParentStreamLease_);
        }
        virtual auto TransferMuxRoot() noexcept -> void = 0;
        virtual auto RetainMuxRoot() noexcept -> void = 0;

    protected:
        auto ReleaseMuxRootParentStreamLease() noexcept -> void
        {
            ParentStreamLease_.Release();
        }

    private:
        Preview::Account::StreamLease ParentStreamLease_;
        bool ParentStreamLeaseClaimed_{false};
    };

    /**
     * @brief 唯一的 mux 根创建请求；析构时未完成转移就保留其预预约 owner。
     * @details Prepare 先把完整 plane 放进预预约票据，再 Acquire 同代 lease；后续 Session/Registry
     *          分配抛出时票据仍握有 inbound、AccountLease 与 GenerationUseLease。
     */
    class MuxRootCreateRequest final
    {
    public:
        MuxRootCreateRequest() = delete;
        MuxRootCreateRequest(const MuxRootCreateRequest &) = delete;
        auto operator=(const MuxRootCreateRequest &) -> MuxRootCreateRequest & = delete;

        MuxRootCreateRequest(MuxRootCreateRequest &&Other) noexcept
            : Owner_(std::move(Other.Owner_)), GenerationUseState_(std::move(Other.GenerationUseState_)),
              Transferred_(std::exchange(Other.Transferred_, true)),
              SessionCreationClaimed_(std::exchange(Other.SessionCreationClaimed_, true)),
              SessionAttached_(std::exchange(Other.SessionAttached_, false)),
              ParentStreamLeaseTaken_(std::exchange(Other.ParentStreamLeaseTaken_, false))
        {
        }

        auto operator=(MuxRootCreateRequest &&Other) noexcept -> MuxRootCreateRequest &
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

        ~MuxRootCreateRequest() noexcept { Retain(); }

        /** @brief 一次性接管 plane 与同代状态，并在创建前预留实际 generation lease。 */
        [[nodiscard]] static auto Prepare(
            std::shared_ptr<MuxRootCreateOwner> Owner,
            std::shared_ptr<Preview::Foundation::GenerationUseState> GenerationUseState,
            ProtocolDataPlane &&Plane) -> std::expected<MuxRootCreateRequest, Preview::Fault::Failure>
        {
            if (!Owner || !GenerationUseState || !Plane.IsMux() || !Plane.Transport())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (!Owner->ClaimMuxRootCreate())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable});
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

        [[nodiscard]] auto GenerationUseState() const noexcept
            -> const std::shared_ptr<Preview::Foundation::GenerationUseState> &
        {
            return GenerationUseState_;
        }

        [[nodiscard]] auto Inbound() const noexcept -> Preview::SharedTransmission
        {
            if (!Owner_) return {};
            return Owner_->MuxRootTransport();
        }

        /** @brief 每个已预约请求仅允许创建一个正式 mux session。 */
        [[nodiscard]] auto BeginSessionCreation() noexcept -> bool
        {
            if (!Owner_ || Transferred_ || SessionCreationClaimed_) return false;
            SessionCreationClaimed_ = true;
            return true;
        }

        auto AttachSession(std::shared_ptr<MuxSession> Session) noexcept -> void
        {
            if (!SessionCreationClaimed_ || SessionAttached_ || !Session) return;
            Owner_->AttachMuxRootSession(std::move(Session));
            SessionAttached_ = true;
        }

        [[nodiscard]] auto TakePlane() noexcept -> ProtocolDataPlane
        {
            if (!SessionAttached_) return {};
            return Owner_->TakeMuxRootPlane();
        }

        [[nodiscard]] auto TakeGenerationUseLease() noexcept
            -> Preview::Foundation::GenerationUseLease
        {
            if (!SessionAttached_) return {};
            return Owner_->TakeMuxRootGenerationLease();
        }

        [[nodiscard]] auto TakeParentStreamLease() noexcept -> Preview::Account::StreamLease
        {
            if (!SessionAttached_ || ParentStreamLeaseTaken_) return {};
            ParentStreamLeaseTaken_ = true;
            return Owner_->TakeMuxRootParentStreamLease();
        }

        auto Transfer() noexcept -> void
        {
            if (!Owner_ || Transferred_ || !SessionAttached_ || !ParentStreamLeaseTaken_) return;
            Owner_->TransferMuxRoot();
            Transferred_ = true;
            Owner_.reset();
            GenerationUseState_.reset();
        }

    private:
        MuxRootCreateRequest(
            std::shared_ptr<MuxRootCreateOwner> Owner,
            std::shared_ptr<Preview::Foundation::GenerationUseState> GenerationUseState) noexcept
            : Owner_(std::move(Owner)), GenerationUseState_(std::move(GenerationUseState))
        {
        }

        auto Retain() noexcept -> void
        {
            if (Owner_ && !Transferred_)
            {
                Owner_->RetainMuxRoot();
                Transferred_ = true;
            }
        }

        std::shared_ptr<MuxRootCreateOwner> Owner_;
        std::shared_ptr<Preview::Foundation::GenerationUseState> GenerationUseState_;
        bool Transferred_{false};
        bool SessionCreationClaimed_{false};
        bool SessionAttached_{false};
        bool ParentStreamLeaseTaken_{false};
    };
}

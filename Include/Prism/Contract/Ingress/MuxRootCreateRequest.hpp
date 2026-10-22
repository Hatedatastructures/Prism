/**
 * @file MuxRootCreateRequest.hpp
 * @brief 已认证 mux 根创建的唯一资源交接与失败保留请求。
 */
#pragma once

#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <expected>
#include <memory>

namespace Prism::Contract
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
            Prism::Foundation::GenerationUseLease &&Lease) noexcept -> void = 0;
        /** @brief 接管嵌套 mux 根的祖先 stream 配额；每个预构造 owner 只接管一次。 */
        [[nodiscard]] virtual auto CanAttachMuxRootParentStreamLease() const noexcept -> bool = 0;
        [[nodiscard]] auto AttachMuxRootParentStreamLease(
            Prism::Account::StreamLease &&Lease) noexcept -> bool;
        [[nodiscard]] virtual auto MuxRootTransport() const noexcept
            -> Prism::SharedTransmission = 0;
        virtual auto AttachMuxRootSession(std::shared_ptr<MuxSession> Session) noexcept -> void = 0;
        [[nodiscard]] virtual auto TakeMuxRootPlane() noexcept -> ProtocolDataPlane = 0;
        [[nodiscard]] virtual auto TakeMuxRootGenerationLease() noexcept
            -> Prism::Foundation::GenerationUseLease = 0;
        [[nodiscard]] auto TakeMuxRootParentStreamLease() noexcept
            -> Prism::Account::StreamLease;
        virtual auto TransferMuxRoot() noexcept -> void = 0;
        virtual auto RetainMuxRoot() noexcept -> void = 0;
        /** @brief root 已完成物理退休；同票据归还仅供根生命周期的活动预约。 */
        virtual auto OnMuxRootRetired() noexcept -> void = 0;

    protected:
        auto ReleaseMuxRootParentStreamLease() noexcept -> void;

    private:
        Prism::Account::StreamLease ParentStreamLease_;
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

        MuxRootCreateRequest(MuxRootCreateRequest &&Other) noexcept;

        auto operator=(MuxRootCreateRequest &&Other) noexcept -> MuxRootCreateRequest &;

        ~MuxRootCreateRequest() noexcept;

        /** @brief 一次性接管 plane 与同代状态，并在创建前预留实际 generation lease。 */
        [[nodiscard]] static auto Prepare(
            std::shared_ptr<MuxRootCreateOwner> Owner,
            std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState,
            ProtocolDataPlane &&Plane) -> std::expected<MuxRootCreateRequest, Prism::Fault::Failure>;

        [[nodiscard]] auto GenerationUseState() const noexcept
            -> const std::shared_ptr<Prism::Foundation::GenerationUseState> &
        {
            return GenerationUseState_;
        }

        [[nodiscard]] auto Inbound() const noexcept -> Prism::SharedTransmission
        {
            if (!Owner_) return {};
            return Owner_->MuxRootTransport();
        }

        /** @brief 仅用于把根物理退休事实通知给创建票据，不转移资源。 */
        [[nodiscard]] auto CreateOwner() const noexcept
            -> std::shared_ptr<MuxRootCreateOwner>
        {
            return Owner_;
        }

        /** @brief 每个已预约请求仅允许创建一个正式 mux session。 */
        [[nodiscard]] auto BeginSessionCreation() noexcept -> bool;

        auto AttachSession(std::shared_ptr<MuxSession> Session) noexcept -> void;

        [[nodiscard]] auto TakePlane() noexcept -> ProtocolDataPlane;

        [[nodiscard]] auto TakeGenerationUseLease() noexcept
            -> Prism::Foundation::GenerationUseLease;

        [[nodiscard]] auto TakeParentStreamLease() noexcept -> Prism::Account::StreamLease;

        auto Transfer() noexcept -> void;

    private:
        MuxRootCreateRequest(
            std::shared_ptr<MuxRootCreateOwner> Owner,
            std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState) noexcept;

        auto Retain() noexcept -> void;

        std::shared_ptr<MuxRootCreateOwner> Owner_;
        std::shared_ptr<Prism::Foundation::GenerationUseState> GenerationUseState_;
        bool Transferred_{false};
        bool SessionCreationClaimed_{false};
        bool SessionAttached_{false};
        bool ParentStreamLeaseTaken_{false};
    };
}

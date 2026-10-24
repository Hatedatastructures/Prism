/**
 * @file ProviderMuxRootState.hpp
 * @brief provider 接入票据内的 mux root 创建资源槽。
 */
#pragma once

#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>

#include <atomic>
#include <memory>
#include <optional>

namespace Prism::Protocols
{
    /**
     * @brief MuxRootCreateOwner 的同票据状态基类，不拥有独立关闭或重试生命周期。
     * @details 派生的实际 session retirement ticket 同时持有接入、账户与 transport 资源；
     *          本基类只实现 C7 请求所需的 root plane/session/lease 槽位。
     */
    class ProviderMuxRootState : public Prism::Contract::MuxRootCreateOwner
    {
        friend class ProviderSessionResources;

    protected:
        struct RootOwner final
        {
            Prism::SharedTransmission Transport;
            std::shared_ptr<Prism::Contract::DatagramSession> Datagram;
            std::shared_ptr<Prism::Contract::MuxSession> Mux;
            std::optional<Prism::Contract::ProtocolDataPlane> PendingPlane;
        };

        ProviderMuxRootState();

        virtual auto OnMuxRootSessionAttached() noexcept -> void = 0;
        virtual auto RetainMuxRootTicket() noexcept -> void = 0;

    public:
        [[nodiscard]] auto ClaimMuxRootCreate() noexcept -> bool override;

        auto AttachMuxRootPlane(Prism::Contract::ProtocolDataPlane &&Plane) noexcept
            -> void override;

        auto AttachMuxRootGenerationLease(
            Prism::Foundation::GenerationUseLease &&Lease) noexcept -> void override;

        [[nodiscard]] auto CanAttachMuxRootParentStreamLease() const noexcept
            -> bool override
        {
            return false;
        }

        [[nodiscard]] auto MuxRootTransport() const noexcept
            -> Prism::SharedTransmission override
        {
            return RootSlot_ ? RootSlot_->Transport : Prism::SharedTransmission{};
        }

        auto AttachMuxRootSession(
            std::shared_ptr<Prism::Contract::MuxSession> Session) noexcept -> void override;

        [[nodiscard]] auto TakeMuxRootPlane() noexcept
            -> Prism::Contract::ProtocolDataPlane override;

        [[nodiscard]] auto TakeMuxRootGenerationLease() noexcept
            -> Prism::Foundation::GenerationUseLease override;

        auto TransferMuxRoot() noexcept -> void override {}
        auto RetainMuxRoot() noexcept -> void override { RetainMuxRootTicket(); }
        auto OnMuxRootRetired() noexcept -> void override;

    protected:
        std::shared_ptr<RootOwner> RootSlot_;
        std::atomic<std::shared_ptr<RootOwner>> Root_;
        Prism::Foundation::GenerationUseLease RootGenerationUseLease_;
        std::atomic<bool> MuxRootCreateClaimed_{false};
    };
}

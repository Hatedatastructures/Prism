/**
 * @file ProviderMuxRootState.hpp
 * @brief provider 接入票据内的 mux root 创建资源槽。
 */
#pragma once

#include <Preview/Contract/Ingress/MuxRootCreateRequest.hpp>

#include <atomic>
#include <memory>
#include <optional>
#include <utility>

namespace Preview::Protocols
{
    /**
     * @brief MuxRootCreateOwner 的同票据状态基类，不拥有独立关闭或重试生命周期。
     * @details 派生的实际 session retirement ticket 同时持有接入、账户与 transport 资源；
     *          本基类只实现 C7 请求所需的 root plane/session/lease 槽位。
     */
    class ProviderMuxRootState : public Preview::Contract::MuxRootCreateOwner
    {
    protected:
        struct RootOwner final
        {
            Preview::SharedTransmission Transport;
            std::shared_ptr<Preview::Contract::DatagramSession> Datagram;
            std::shared_ptr<Preview::Contract::MuxSession> Mux;
            std::optional<Preview::Contract::ProtocolDataPlane> PendingPlane;
        };

        ProviderMuxRootState() : RootSlot_(std::make_shared<RootOwner>()) {}

        virtual auto OnMuxRootSessionAttached() noexcept -> void = 0;
        virtual auto RetainMuxRootTicket() noexcept -> void = 0;

    public:
        [[nodiscard]] auto ClaimMuxRootCreate() noexcept -> bool override
        {
            bool Expected = false;
            return MuxRootCreateClaimed_.compare_exchange_strong(
                Expected, true, std::memory_order_acq_rel);
        }

        auto AttachMuxRootPlane(Preview::Contract::ProtocolDataPlane &&Plane) noexcept
            -> void override
        {
            RootSlot_->Transport = Plane.Transport();
            RootSlot_->PendingPlane.emplace(std::move(Plane));
        }

        auto AttachMuxRootGenerationLease(
            Preview::Foundation::GenerationUseLease &&Lease) noexcept -> void override
        {
            RootGenerationUseLease_ = std::move(Lease);
        }

        [[nodiscard]] auto CanAttachMuxRootParentStreamLease() const noexcept
            -> bool override
        {
            return false;
        }

        [[nodiscard]] auto MuxRootTransport() const noexcept
            -> Preview::SharedTransmission override
        {
            return RootSlot_ ? RootSlot_->Transport : Preview::SharedTransmission{};
        }

        auto AttachMuxRootSession(std::shared_ptr<Preview::Contract::MuxSession> Session) noexcept
            -> void override
        {
            if (!Session)
            {
                return;
            }
            RootSlot_->Mux = std::move(Session);
            Root_.store(RootSlot_, std::memory_order_release);
            OnMuxRootSessionAttached();
        }

        [[nodiscard]] auto TakeMuxRootPlane() noexcept
            -> Preview::Contract::ProtocolDataPlane override
        {
            if (!RootSlot_ || !RootSlot_->PendingPlane)
            {
                return {};
            }
            auto Plane = std::move(*RootSlot_->PendingPlane);
            RootSlot_->PendingPlane.reset();
            return Plane;
        }

        [[nodiscard]] auto TakeMuxRootGenerationLease() noexcept
            -> Preview::Foundation::GenerationUseLease override
        {
            return std::move(RootGenerationUseLease_);
        }

        auto TransferMuxRoot() noexcept -> void override {}
        auto RetainMuxRoot() noexcept -> void override { RetainMuxRootTicket(); }

    protected:
        std::shared_ptr<RootOwner> RootSlot_;
        std::atomic<std::shared_ptr<RootOwner>> Root_;
        Preview::Foundation::GenerationUseLease RootGenerationUseLease_;
        std::atomic<bool> MuxRootCreateClaimed_{false};
    };
}

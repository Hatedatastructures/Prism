/** @file AdmissionRetirementState.hpp @brief 入站预约票据的私有退休状态所有者。 */
#pragma once

#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Ingress/MuxRootCreateRequest.hpp>
#include <Prism/Contract/Ingress/AdmissionTransportRetirement.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <boost/asio/awaitable.hpp>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>

namespace Prism::Contract
{
    struct AdmissionRetirementEnvironment final
    {
        std::shared_ptr<Prism::Executor::ContextOwner> Context;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
    };

    class AdmissionRetirementState final
        : public Prism::Executor::ClosingResource,
          public MuxRootCreateOwner,
          public std::enable_shared_from_this<AdmissionRetirementState>
    {
        friend class InboundAdmission;

        struct TrackedResource final
        {
            Prism::SharedTransmission Transport;
            bool CancelAttempted{false};
            bool CloseAttempted{false};
        };

    public:
        AdmissionRetirementState(
            Prism::SharedTransmission Inbound,
            AdmissionRetirementEnvironment Environment);

    private:
        auto Attach(ProtocolDataPlane Plane) noexcept -> void;

        [[nodiscard]] auto ClaimMuxRootCreate() noexcept -> bool override;

        [[nodiscard]] auto CanAttachMuxRootParentStreamLease() const noexcept
            -> bool override;

        auto AttachMuxRootPlane(ProtocolDataPlane &&Plane) noexcept -> void override;

        auto AttachMuxRootGenerationLease(
            Prism::Foundation::GenerationUseLease &&Lease) noexcept -> void override;

        [[nodiscard]] auto MuxRootTransport() const noexcept
            -> Prism::SharedTransmission override;

        auto AttachMuxRootSession(std::shared_ptr<MuxSession> Session) noexcept -> void override;

        [[nodiscard]] auto TakeMuxRootPlane() noexcept -> ProtocolDataPlane override;

        [[nodiscard]] auto TakeMuxRootGenerationLease() noexcept
            -> Prism::Foundation::GenerationUseLease override;

        auto TransferMuxRoot() noexcept -> void override;

        auto RetainMuxRoot() noexcept -> void override;

        [[nodiscard]] auto Track(const Prism::SharedTransmission& Transport)
            -> std::expected<void, Prism::Fault::Failure>;

        auto Transfer() noexcept -> void;

        [[nodiscard]] auto Retire(Prism::Fault::Failure Primary)
            -> Net::awaitable<Prism::Fault::Failure>;

        auto RequestRetirement() -> void override;

        [[nodiscard]] auto IsRetired() const noexcept -> bool override;

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override;

        static constexpr std::uint8_t RetryScheduledFlag{1U};
        static constexpr std::uint8_t RetryRequestedFlag{2U};

        auto PostRetryCommand() noexcept -> void;

        /** @brief 完成重试时交接并发请求；单次失败不自行形成无界重试。 */
        auto FinishScheduledRetry() noexcept -> void;

        struct RetryCommand final
        {
            std::shared_ptr<AdmissionRetirementState> Owner;
            auto operator()() noexcept -> void;
        };

        struct RetryCompletion final
        {
            std::shared_ptr<AdmissionRetirementState> Owner;
            auto operator()(std::exception_ptr Exception,
                std::expected<void, Prism::Fault::Failure> Result) noexcept -> void;
        };

        [[nodiscard]] static auto RetireResources(std::shared_ptr<AdmissionRetirementState> Owner)
            -> Net::awaitable<AdmissionRetirementResult>;

        [[nodiscard]] static auto RetireRoot(std::shared_ptr<AdmissionRetirementState> Owner)
            -> Net::awaitable<AdmissionRetirementResult>;

        [[nodiscard]] static auto RetireDatagram(
            const std::shared_ptr<AdmissionRetirementState> &Owner,
            const std::shared_ptr<DatagramSession>& Session)
            -> Net::awaitable<AdmissionRetirementResult>;

        [[nodiscard]] static auto RetireMux(
            const std::shared_ptr<AdmissionRetirementState> &Owner,
            const std::shared_ptr<MuxSession>& Session)
            -> Net::awaitable<AdmissionRetirementResult>;

        auto ResetAttempts() noexcept -> void;

        auto Complete() noexcept -> void;

        auto StartRetry() noexcept -> void;

        [[nodiscard]] static auto RetryOnExecutor(std::shared_ptr<AdmissionRetirementState> Owner)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>;

        Prism::SharedTransmission Inbound_;
        std::array<TrackedResource, 8> Tracked_{};
        std::size_t TrackedCount_{0};
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        std::optional<ProtocolDataPlane> Plane_;
        Prism::Foundation::GenerationUseLease RootGenerationLease_;
        std::atomic<bool> Running_{false};
        std::atomic<std::uint8_t> RetrySchedule_{0U};
        std::atomic<bool> Retired_{false};
        std::atomic<bool> MuxRootClaimed_{false};
        bool InboundCancelAttempted_{false};
        bool InboundCloseAttempted_{false};
        bool RootCancelAttempted_{false};
        bool RootCloseAttempted_{false};
        /// 协议任务退休后，入站准入状态再独立确认根传输关闭；重试不重发控制。
        bool RootTransportCancelAttempted_{false};
        bool RootTransportCloseAttempted_{false};
    };
}

/**
 * @file DatagramServices.hpp
 * @brief 冻结每代 raw 与 QUIC ingress 的同一包选择。
 */
#pragma once

#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Application/Startup/GenerationPhase.hpp>
#include <Preview/Boundary/Datagram/DatagramSender.hpp>
#include <Preview/Boundary/Quic/QuicAdmissionBudget.hpp>
#include <Preview/Contract/Ingress/DatagramIngressSelection.hpp>
#include <Preview/Contract/Ingress/QuicConnection.hpp>
#include <Preview/Contract/Ingress/RawDatagramIngress.hpp>

#include <expected>
#include <memory>
#include <utility>
#include <vector>

namespace Preview::Application::Startup::DatagramServices
{
    namespace Net = boost::asio;
    using RuntimeOwner = std::shared_ptr<Application::RuntimeState>;
    using RawSnapshot = Preview::Contract::RawDatagramIngressSnapshot;
    using Selection = Preview::Contract::DatagramIngressSelection;
    using QuicSnapshot = Preview::Contract::QuicIngressBindingSnapshot;
    using ProviderFailure = Preview::Contract::ProviderFailure;

    /** @brief 冷路径准备一个不可变 generation ingress selection。 */
    struct IngressSelectionPreparation final
    {
        std::shared_ptr<Preview::Composition::Provider::BoundCatalog> Providers;
        Preview::Foundation::GenerationPin Generation;
        std::shared_ptr<Preview::Foundation::GenerationUseState> UseState;
        std::shared_ptr<const Selection> Previous;
    };

    /** @brief 以当前 published process epoch 写进程级 UDP boundary 事件。 */
    inline auto WriteBoundaryDispatchEvent(
        const std::weak_ptr<Application::RuntimeState> &Owner,
        const Preview::Boundary::BoundaryDispatchEvent Event) noexcept -> void
    {
        const auto Runtime = Owner.lock();
        if (!Runtime)
        {
            return;
        }
        (void)Preview::Diagnose::Trace(Runtime->CurrentProcessContext(),
            "BoundaryDispatchStage Stage={} Kind={} Route={} Bytes={}",
            Preview::Boundary::BoundaryDispatchStageName(Event.Stage),
            static_cast<unsigned>(Event.Kind), static_cast<unsigned>(Event.Route), Event.PayloadBytes);
    }

    [[nodiscard]] inline auto MakeRawSnapshot(const IngressSelectionPreparation &Request)
        -> std::shared_ptr<const RawSnapshot>
    {
        std::vector<RawSnapshot::Binding> Current;
        for (const auto &Entry : Request.Providers->Entries())
        {
            if (auto Raw = Entry.Raw())
            {
                Current.push_back(RawSnapshot::Binding{std::move(Raw), Request.UseState});
            }
        }
        std::vector<RawSnapshot::Binding> Retired;
        std::shared_ptr<const RawSnapshot> Previous;
        if (Request.Previous) Previous = Request.Previous->Raw();
        if (Previous)
        {
            Retired.reserve(Previous->RetiredBindings().size() + Previous->Bindings().size());
            for (const auto &Binding : Previous->RetiredBindings())
            {
                const auto AdmissionsOpen = Binding.UseState && Binding.UseState->AdmissionOpen();
                if (Binding.Owner && (AdmissionsOpen || Binding.Owner->HasActiveAssociations()))
                {
                    Retired.push_back(Binding);
                }
            }
            for (const auto &Binding : Previous->Bindings())
            {
                const auto AdmissionsOpen = Binding.UseState && Binding.UseState->AdmissionOpen();
                if (Binding.Owner && (AdmissionsOpen || Binding.Owner->HasActiveAssociations()))
                {
                    Retired.push_back(Binding);
                }
            }
        }
        return std::make_shared<const RawSnapshot>(RawSnapshot::Options{
            Request.Generation->Id(), Request.UseState, std::move(Current), std::move(Retired)});
    }

    [[nodiscard]] inline auto MakeQuicSnapshot(const IngressSelectionPreparation &Request)
        -> std::expected<std::shared_ptr<const QuicSnapshot>, ProviderFailure>
    {
        const auto Binding = Request.Providers->QuicIngressBinding();
        if (!Binding)
        {
            return std::unexpected(Binding.error());
        }
        Preview::Contract::RequestMetadata Metadata;
        Metadata.TaskIdentity.Generation = Request.Generation->Id();
        Metadata.TaskIdentity.WorkerId = Preview::WorkerId{};
        auto Snapshot = std::make_shared<const QuicSnapshot>(QuicSnapshot::Options{
            Request.Generation, Request.UseState, std::move(Metadata), std::move(*Binding)});
        if (!Snapshot->IsValid())
        {
            return std::unexpected(ProviderFailure{
                Preview::Contract::ProviderError::InvalidConfiguration, {}, "Quic.Listener"});
        }
        return Snapshot;
    }

    /**
     * @brief 同时冻结当前 raw factories 与 QUIC listener identity。
     * @param Request 同一 generation、UseState、BoundCatalog 与上代 selection。
     * @return 带稳定 pointer identity 的完整 packet selection；多 QUIC listener 时返回 ProviderFailure。
     */
    [[nodiscard]] inline auto MakeIngressSelection(IngressSelectionPreparation Request)
        -> std::expected<std::shared_ptr<const Selection>, ProviderFailure>
    {
        if (!Request.Providers || !Request.Generation || !Request.UseState)
        {
            return std::unexpected(ProviderFailure{
                Preview::Contract::ProviderError::InvalidConfiguration, {}, "Quic.Listener"});
        }
        auto Raw = MakeRawSnapshot(Request);
        auto Quic = MakeQuicSnapshot(Request);
        if (!Quic)
        {
            return std::unexpected(Quic.error());
        }
        auto Result = std::make_shared<const Selection>(Selection::Options{
            Request.Generation, Request.UseState, std::move(Raw), std::move(*Quic)});
        if (!Result->Matches(Request.Generation, Request.UseState))
        {
            return std::unexpected(ProviderFailure{
                Preview::Contract::ProviderError::GenerationMismatch, {}, "Quic.Listener"});
        }
        return Result;
    }

    /** @brief 使用本包本次选择中的 QUIC binding；已知 CID 仍由同一 Registry 查旧 lease。 */
    struct QuicAdmissionRequest final
    {
        Preview::Boundary::BoundaryPacket Packet;
        std::shared_ptr<const QuicSnapshot> Ingress;
    };

    [[nodiscard]] inline auto DispatchQuicAdmission(
        const std::weak_ptr<Preview::Boundary::QuicConnectionRegistry> &Registry,
        QuicAdmissionRequest Request) -> Preview::Boundary::QuicAdmissionDisposition
    {
        const auto Owner = Registry.lock();
        if (Owner) return Owner->Handle(Request.Packet, Request.Ingress);
        return Preview::Boundary::QuicAdmissionDisposition::NotHandled;
    }

    /** @brief 只分配未监听的 Boundary 入口；事务拥有关闭/排空，协议尚未准备。 */
    inline auto Build(const RuntimeOwner &Runtime, const GenerationPhase::Result &) -> void
    {
        Runtime->DatagramClassifier = std::make_shared<Preview::Boundary::DatagramClassifier>();
        auto AdmissionBudget = std::make_shared<Preview::Boundary::QuicAdmissionBudget>(
            Preview::Boundary::QuicAdmissionBudgetLimits{4096, 65536});
        Runtime->QuicPacketGateway = std::make_shared<Preview::Boundary::QuicPacketGateway>(
            Preview::Boundary::QuicPacketGatewayOptions{std::move(AdmissionBudget)});
        Runtime->DatagramListener =
            std::make_unique<Preview::Boundary::DatagramListener>(Runtime->Io.get_executor());
    }

    /** @brief 入口 dispatcher 不捕获初代 factory；每包由 Application 传入完整 selection。 */
    inline auto Bind(const RuntimeOwner &Runtime) -> void
    {
        if (!Runtime->DatagramListener)
        {
            return;
        }
        const auto WeakRuntime = std::weak_ptr<Application::RuntimeState>(Runtime);
        const auto Events = [WeakRuntime](const Preview::Boundary::BoundaryDispatchEvent Event)
        { WriteBoundaryDispatchEvent(WeakRuntime, Event); };
        const auto Registry =
            std::weak_ptr<Preview::Boundary::QuicConnectionRegistry>(Runtime->QuicConnectionRegistry);
        const auto QuicAdmission = [Registry](Preview::Boundary::BoundaryPacket Packet,
            std::shared_ptr<const QuicSnapshot> Ingress)
        {
            return DispatchQuicAdmission(Registry,
                QuicAdmissionRequest{std::move(Packet), std::move(Ingress)});
        };
        Runtime->BoundaryDispatcher = std::make_shared<Preview::Boundary::BoundaryDispatcher>(
            Preview::Boundary::BoundaryDispatcher::Options{
                Runtime->QuicPacketGateway,
                [](Preview::Boundary::BoundaryPacket) {},
                QuicAdmission,
                Events});
    }
}

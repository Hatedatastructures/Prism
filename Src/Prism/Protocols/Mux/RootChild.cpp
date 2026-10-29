/** @file RootChild.cpp @brief Mux root 子流拨号、中继和退休 owner 实现。 */

#include <Prism/Protocols/Mux/Root/Child.hpp>

#include <Prism/Contract/Ingress/StreamCatalog.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Foundation/Utility/TrafficSink.hpp>
#include <Prism/Lifecycle/Task/Registry.hpp>
#include <Prism/Protocols/Mux/Detail/RootChildOwner.hpp>
#include <Prism/Net/Relay/Relay.hpp>
#include <Prism/Protocols/Mux/Root/State.hpp>
#include "Detail/SingMux/SingMux.hpp"
#include <Prism/Protocols/Mux/SingMux/Stream.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <array>
#include <cstddef>
#include <expected>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>

namespace Prism::Mux::Detail
{
    class StreamResetTaskOwner final : public Prism::Contract::Ingress::StreamResetOwner
    {
    public:
        StreamResetTaskOwner(
            Prism::Lifecycle::TaskHandle Task,
            std::shared_ptr<Prism::Fault::FailureState> ControlFailure,
            Prism::Contract::Ingress::StreamResetRequest Scope)
            : Task_(std::move(Task)), ControlFailure_(std::move(ControlFailure)), Scope_(Scope)
        {
        }

        [[nodiscard]] auto ResetAndDrain(
            Prism::Contract::Ingress::StreamResetRequest Request)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            using Failure = Prism::Fault::Failure;
            if (Request != Scope_)
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            }
            if (!Task_.IsCompleted()) (void)Task_.RequestCancel();
            const auto Observation = Task_.Observation();
            if (Observation.DrainBlocked)
            {
                const auto ControlFailure = ControlFailure_->Load();
                if (ControlFailure.Failed()) co_return std::unexpected(ControlFailure);
                if (Observation.Result.Outcome == Prism::Lifecycle::TaskOutcome::Failed ||
                    Observation.Result.Outcome == Prism::Lifecycle::TaskOutcome::Quarantined)
                {
                    if (Observation.Result.Failure.Failed())
                        co_return std::unexpected(Observation.Result.Failure);
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                }
                const auto Failure = Observation.DrainFailure.Failed()
                    ? Observation.DrainFailure
                    : Prism::Fault::Failure{Prism::Fault::Code::Blocked};
                co_return std::unexpected(Failure);
            }
            const auto Retired = co_await Task_.WaitForRetirementAsync();
            if (!Retired) co_return std::unexpected(Retired.error());
            const auto ControlFailure = ControlFailure_->Load();
            if (ControlFailure.Failed()) co_return std::unexpected(ControlFailure);
            const auto Result = Task_.Result();
            if (Result.Outcome == Prism::Lifecycle::TaskOutcome::Failed ||
                Result.Outcome == Prism::Lifecycle::TaskOutcome::Quarantined)
            {
                if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
                co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            }
            co_return std::expected<void, Failure>{};
        }

    private:
        Prism::Lifecycle::TaskHandle Task_;
        std::shared_ptr<Prism::Fault::FailureState> ControlFailure_;
        Prism::Contract::Ingress::StreamResetRequest Scope_;
    };

    auto CreateStreamResetTaskOwner(
        Prism::Lifecycle::TaskHandle Task,
        std::shared_ptr<Prism::Fault::FailureState> ControlFailure,
        Prism::Contract::Ingress::StreamResetRequest Scope)
        -> std::shared_ptr<Prism::Contract::Ingress::StreamResetOwner>
    {
        return std::make_shared<StreamResetTaskOwner>(
            std::move(Task), std::move(ControlFailure), Scope);
    }

    inline auto RecordCloseFailure(
        std::expected<void, Prism::Fault::Failure> Result,
        std::exception_ptr &Failure,
        const std::shared_ptr<RootState> &Root) -> void
    {
        if (Result) return;
        if (!(Root->IsClosingNormally() &&
            Result.error().Code == Prism::Fault::Code::Canceled))
            Root->RecordTerminalFailure(Result.error());
        if (Failure) return;
        try
        {
            throw std::system_error(Prism::Fault::ToNative(Result.error()));
        }
        catch (...)
        {
            Failure = std::current_exception();
        }
    }

    inline auto RecordCloseException(
        const std::exception_ptr &Exception,
        const std::shared_ptr<RootState> &Root) noexcept -> void
    {
        const auto Failure = ControlFailureFromException(Exception);
        if (!(Root->IsClosingNormally() &&
            Failure.Code == Prism::Fault::Code::Canceled))
            Root->RecordTerminalFailure(Failure);
    }

    inline auto RejectChild(std::shared_ptr<ChildState> Child) -> Net::awaitable<void>
    {
        const std::array<std::byte, 1> ErrorStatus{std::byte{1}};
        (void)co_await Child->Inbound->WriteSome(std::span<const std::byte>(ErrorStatus));
        if (Child->Reject) Child->Reject();
        else (void)Child->Inbound->Close();
    }
    inline auto RelayChild(std::shared_ptr<ChildState> Child,
        Prism::Foundation::TrafficObservation Observation)
        -> Net::awaitable<Prism::Network::Relay::Result>
    {
        using Prism::Fault::Code;
        if (!Child->Admitted)
        { co_await RejectChild(Child); co_return Prism::Network::Relay::Result{.Failure = {Code::Streamcap}}; }
        const auto RequestRead = co_await Prism::Mux::Detail::SingMux::ReadStreamRequest(Child->Inbound);
        if (!RequestRead && Child->NormalCloseCancellation.load(std::memory_order_acquire) &&
            RequestRead.error().Code == Code::Canceled)
            co_return Prism::Network::Relay::Result{.Failure = {Code::Canceled}};
        if (!RequestRead)
        {
            co_await RejectChild(Child);
            co_return Prism::Network::Relay::Result{.Failure = RequestRead.error()};
        }
        const auto &Request = RequestRead->Request;
        if (Request.Udp || Request.PacketAddress || Request.Target.Host.Empty())
        { co_await RejectChild(Child); co_return Prism::Network::Relay::Result{.Failure = {Code::NotSupported}}; }
        Child->Target = Request.Target;
        if (Child->Root->Stopping.load()) co_return Prism::Network::Relay::Result{.Failure = {Code::Canceled}};
        if (!Child->Root->Options.Services.Egress)
        { co_await RejectChild(Child); co_return Prism::Network::Relay::Result{.Failure = {Code::NotSupported}}; }
        auto Dialed = co_await Child->Root->Options.Services.Egress->Connect(Child->Target);
        if (!Dialed)
        { co_await RejectChild(Child); co_return Prism::Network::Relay::Result{.Failure = Dialed.error()}; }
        Child->Outbound = std::move(*Dialed);
        Child->Inbound = std::make_shared<Prism::Mux::SingMux::ServerStream>(
            Child->Inbound, Child->Target, RequestRead->Terminal);
        const auto& Services = Child->Root->Options.Services;
        co_return co_await Prism::Network::Relay::Run(
            {Child->Inbound, Child->Outbound, Services.BufferSize, Services.IdleTimeout, Observation, Services.Bytes});
    }

    struct ChildCompletion final
    {
        ChildCompletion(std::shared_ptr<ChildState> Value,
            Prism::Foundation::TrafficObservation ObservationValue)
            : Child(std::move(Value)), Observation(std::move(ObservationValue)) {}
        std::shared_ptr<ChildState> Child;
        Prism::Network::Relay::Result Result;
        Prism::Foundation::TrafficObservation Observation;
        std::exception_ptr Failure;
        Prism::Fault::Failure FinishFailure;
        bool FinishDrained{false};
    };
    inline auto CompleteChild(ChildCompletion Completion) -> Net::awaitable<void>;

    /** @brief 唯一实际 child completion 报告；异常观察不改业务 fault，根不重复累计这些 bytes。 */
    inline auto RunChild(std::shared_ptr<ChildState> Child) -> Net::awaitable<void>
    {
        const auto StartGate = Child->StartGate;
        if (StartGate)
        {
            boost::system::error_code GateError;
            co_await StartGate->async_receive(
                Net::redirect_error(Net::use_awaitable, GateError));
            // 关闭 gate 表示该 child 未完成 catalog 登记，只能结束，不能进入数据面。
            if (GateError)
            {
                ChildCompletion Completion{Child, Prism::Foundation::TrafficObservation{
                    Child->Root->Options.Services.Traffic,
                    Prism::Foundation::TrafficEvent{
                        .Generation = Child->Root->Metadata.TaskIdentity.Generation,
                        .Worker = Child->Root->Metadata.TaskIdentity.WorkerId,
                        .Session = Child->Root->Metadata.TaskIdentity.SessionId,
                        .Stream = Child->Identity.StreamId,
                        .Task = Child->Identity.TaskId,
                        .Account = Child->Root->Admission.Binding()
                            ? Child->Root->Admission.Binding()->AccountId()
                            : Prism::AccountId{}}}};
                Completion.Result.Failure = {Prism::Fault::Code::Canceled};
                co_await CompleteChild(std::move(Completion));
                co_return;
            }
        }
        const auto Binding = Child->Root->Admission.Binding();
        Prism::Foundation::TrafficObservation Observation{
            Child->Root->Options.Services.Traffic,
            Prism::Foundation::TrafficEvent{
                .Generation = Child->Root->Metadata.TaskIdentity.Generation,
                .Worker = Child->Root->Metadata.TaskIdentity.WorkerId,
                .Session = Child->Root->Metadata.TaskIdentity.SessionId,
                .Stream = Child->Identity.StreamId,
                .Task = Child->Identity.TaskId,
                .Account = Binding ? Binding->AccountId() : Prism::AccountId{}}};
        ChildCompletion Completion{Child, std::move(Observation)};
        try
        {
            Completion.Result = co_await Net::co_spawn(Child->Root->Executor,
                RelayChild(Child, Completion.Observation),
                Net::bind_cancellation_slot(Child->Cancellation.slot(), Net::use_awaitable));
        }
        catch (...)
        {
            Completion.Failure = std::current_exception();
            Completion.Result.Failure = ControlFailureFromException(Completion.Failure);
        }
        co_await CompleteChild(std::move(Completion));
    }

    /**
     * @brief 排空同一child完成帧的协议终止阶段并保留首因。
     * @details Completion由等待本函数的完成协程保活，执行于同一root executor；
     *          只在真实Finish回执成功时记录完成，不释放child或配额。
     */
    inline auto DrainChildFinish(ChildCompletion &Completion) -> Net::awaitable<void>
    {
        const auto Child = Completion.Child;
        if (!Child->Finish) co_return;
        try
        {
            const auto Finished = co_await Child->Finish();
            if (Finished) Completion.FinishDrained = true;
            else
            {
                Completion.FinishFailure = Finished.error();
                if (!Completion.Result.Failure.Failed())
                    Completion.Result.Failure = Finished.error();
            }
        }
        catch (...)
        {
            Completion.FinishFailure = ControlFailureFromException(std::current_exception());
            if (!Completion.Failure)
            {
                Completion.Failure = std::current_exception();
            }
        }
    }

    inline auto DrainRetainedActivity(
        const std::shared_ptr<RootState> &Root,
        const Prism::SharedTransmission &Transport,
        Prism::Fault::Failure &Failure) -> Net::awaitable<bool>;

    struct ChildActivityDrainReceipt final
    {
        bool Retired{true};
        Prism::Fault::Failure Failure;
    };

    inline auto DrainChildActivities(std::shared_ptr<ChildState> Child)
        -> Net::awaitable<ChildActivityDrainReceipt>
    {
        Prism::Fault::Failure Failure;
        const bool InboundRetired = co_await DrainRetainedActivity(
            Child->Root, Child->Inbound, Failure);
        bool OutboundRetired = InboundRetired;
        if (Child->Outbound != Child->Inbound)
        {
            OutboundRetired = co_await DrainRetainedActivity(
                Child->Root, Child->Outbound, Failure);
        }
        co_return ChildActivityDrainReceipt{InboundRetired && OutboundRetired, Failure};
    }

    inline auto CloseChildTransports(ChildCompletion &Completion)
        -> Net::awaitable<void>
    {
        const auto Child = Completion.Child;
        const auto Root = Child->Root;
        auto &Failure = Completion.Failure;
        if (Child->RetirementSlot && Root->StreamCatalogOwner)
        {
            const Prism::Contract::Ingress::StreamIdentity Identity{
                Root->Metadata.TaskIdentity.SessionId,
                Root->Metadata.TaskIdentity.WorkerId,
                Root->Metadata.TaskIdentity.Generation,
                Child->Identity.StreamId};
            if (!Root->StreamCatalogOwner->MarkDraining(Identity))
                Root->StreamCatalogOwner->Disable();
        }
        try
        {
            if (Child->Inbound)
                RecordCloseFailure(Child->Inbound->Close(), Failure, Root);
        }
        catch (...)
        {
            if (!Failure)
            {
                Failure = std::current_exception();
                RecordCloseException(Failure, Root);
            }
        }
        try
        {
            if (Child->Outbound)
                RecordCloseFailure(Child->Outbound->Close(), Failure, Root);
        }
        catch (...)
        {
            if (!Failure)
            {
                Failure = std::current_exception();
                RecordCloseException(Failure, Root);
            }
        }
        co_await DrainChildFinish(Completion);
    }

    inline auto UpdateChildStreamCatalog(
        const std::shared_ptr<ChildState> &Child, bool ChildRetired) -> void
    {
        const auto Root = Child->Root;
        if (!Child->RetirementSlot || !Root->StreamCatalogOwner) return;
        const Prism::Contract::Ingress::StreamIdentity Identity{
            Root->Metadata.TaskIdentity.SessionId,
            Root->Metadata.TaskIdentity.WorkerId,
            Root->Metadata.TaskIdentity.Generation,
            Child->Identity.StreamId};
        if (ChildRetired && Root->StreamCatalogOwner->IsAvailable() &&
            !Root->StreamCatalogOwner->Retire(Identity))
        {
            Root->StreamCatalogOwner->Disable();
        }
    }

    enum class ChildRetirementKind : std::uint8_t
    {
        None,
        Normal,
        Canceled
    };

    /** @brief 历史取消与物理退休分开判断；只有活动、终止和两端都已真实退栈才算退休。 */
    inline auto ClassifyChildRetirement(
        const ChildCompletion &Completion,
        const ChildActivityDrainReceipt &ActivityDrain) -> ChildRetirementKind
    {
        const auto &Root = Completion.Child->Root;
        const auto &Result = Completion.Result;
        const auto IsClearOrCanceled = [](Prism::Fault::Failure Value)
        {
            return !Value.Failed() || Value.Code == Prism::Fault::Code::Canceled;
        };
        const auto ExceptionFailure = Completion.Failure
            ? ControlFailureFromException(Completion.Failure) : Prism::Fault::Failure{};
        Prism::Fault::Failure ControlFailure;
        if (Completion.Child->ControlFailure)
            ControlFailure = Completion.Child->ControlFailure->Load();
        const bool Terminated = Completion.FinishDrained ||
            Completion.FinishFailure.Code == Prism::Fault::Code::Canceled;
        const bool Retired = ActivityDrain.Retired && Terminated &&
            IsClearOrCanceled(Completion.FinishFailure) &&
            IsClearOrCanceled(Result.Failure) &&
            IsClearOrCanceled(Result.DirectionFailure[0]) &&
            IsClearOrCanceled(Result.DirectionFailure[1]) &&
            IsClearOrCanceled(ControlFailure) && IsClearOrCanceled(ExceptionFailure) &&
            IsClearOrCanceled(ActivityDrain.Failure);
        if (!Retired) return ChildRetirementKind::None;
        if (Completion.Child->NormalCloseCancellation.load(std::memory_order_acquire) &&
            Root->IsClosingNormally())
            return ChildRetirementKind::Normal;
        if (Completion.Child->ExplicitCancellation.load(std::memory_order_acquire) ||
            Root->IsExplicitlyCanceled())
            return ChildRetirementKind::Canceled;
        return ChildRetirementKind::None;
    }

    inline auto RecordChildRetirementFailure(
        const std::shared_ptr<RootState> &Root,
        const ChildCompletion &Completion,
        const ChildActivityDrainReceipt &ActivityDrain) -> void
    {
        if (Completion.FinishFailure.Failed())
            Root->RecordTerminalFailure(Completion.FinishFailure);
        if (ActivityDrain.Failure.Failed())
            Root->RecordTerminalFailure(ActivityDrain.Failure);
        if (Completion.Failure)
            Root->RecordTerminalFailure(
                ControlFailureFromException(Completion.Failure));
        if (Completion.Child->ControlFailure)
        {
            const auto ControlFailure = Completion.Child->ControlFailure->Load();
            if (ControlFailure.Failed())
                Root->RecordTerminalFailure(ControlFailure);
        }
    }

    inline auto CompleteChild(ChildCompletion Completion) -> Net::awaitable<void>
    {
        const auto Child = Completion.Child;
        const auto Root = Child->Root;
        auto &Result = Completion.Result;
        auto &Failure = Completion.Failure;
        auto &Observation = Completion.Observation;
        auto &FinishDrained = Completion.FinishDrained;
        try
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        }
        catch (...)
        {
            if (!Failure)
            {
                Failure = std::current_exception();
            }
        }
        co_await CloseChildTransports(Completion);
        const auto ActivityDrain = co_await DrainChildActivities(Child);
        const bool ActivitiesRetired = ActivityDrain.Retired;
        Prism::Fault::Failure ControlFailure;
        if (Child->ControlFailure)
        {
            ControlFailure = Child->ControlFailure->Load();
            if (ControlFailure.Failed())
            {
                if (!Result.Failure.Failed()) Result.Failure = ControlFailure;
                if (!Failure)
                {
                    try { throw std::system_error(Prism::Fault::ToNative(ControlFailure)); }
                    catch (...) { Failure = std::current_exception(); }
                }
            }
        }
        if (Failure && !Result.Failure.Failed())
            Result.Failure = ControlFailureFromException(Failure);
        const auto ExceptionFailure = Failure
            ? ControlFailureFromException(Failure) : Prism::Fault::Failure{};
        const auto Retirement = ClassifyChildRetirement(Completion, ActivityDrain);
        const bool NormalCloseRetired = Retirement == ChildRetirementKind::Normal;
        const bool CancellationRetired = Retirement == ChildRetirementKind::Canceled;
        if (NormalCloseRetired)
        {
            Result = {};
            Failure = nullptr;
            ControlFailure = {};
        }
        else
        {
            // 取消引起的异常不是任务失败；保留 Result 中的 Canceled 事实后让任务正常退休。
            if (CancellationRetired &&
                ExceptionFailure.Code == Prism::Fault::Code::Canceled)
                Failure = nullptr;
            RecordChildRetirementFailure(Root, Completion, ActivityDrain);
        }
        const bool ChildRetired =
            (FinishDrained || NormalCloseRetired || CancellationRetired) &&
            ActivitiesRetired &&
            (NormalCloseRetired || CancellationRetired ||
                (!Result.DirectionFailure[0].Failed() && !Result.DirectionFailure[1].Failed()));
        UpdateChildStreamCatalog(Child, ChildRetired);
        Observation.Complete();
        try
        {
            if (Root->Options.Observe)
                Root->Options.Observe({Child->Identity, Child->Target, Result});
        }
        catch (...) {}
        if (!Failure && Root->Options.Services.Traffic &&
            Child->Identity.StreamId.Value() != 0U)
        {
            const auto Retired = co_await Prism::Foundation::RetireTraffic(
                Root->Options.Services.Traffic,
                Prism::Foundation::TrafficRetirement{Prism::Foundation::StreamTrafficOwner{
                    Child->Identity.WorkerId, Child->Identity.SessionId, Child->Identity.StreamId}});
            (void)Retired;
        }
        Root->StreamResetOwners.erase(Child->Identity.TaskId.Value());
        if (Child->RetirementSlot)
        {
            const auto Slot = *Child->RetirementSlot;
            if (ChildRetired)
            {
                Child->Lease.Release();
                Root->ReleaseChildRetirementSlot(Slot);
                Child->RetirementSlot.reset();
            }
            else
            {
                Root->RetainChildUntilRootRetired(std::move(Completion.Child));
            }
        }
        if (Failure)
        {
            const auto Cause = ControlFailureFromException(Failure);
            Root->RecordTerminalFailure(Cause);
            Root->ExitStatus.store(Cause.Code);
            std::rethrow_exception(Failure);
        }
    }

    auto PreserveChildDrainFailure(
        Prism::Fault::Failure &Primary,
        const Prism::Fault::Failure &Next) noexcept -> void
    {
        if (Next.Failed() && (!Primary.Failed() ||
            (Primary.Code == Prism::Fault::Code::Canceled &&
             Next.Code != Prism::Fault::Code::Canceled)))
        {
            Primary = Next;
        }
    }
    inline auto DrainRetainedActivity(
        const std::shared_ptr<RootState> &Root,
        const Prism::SharedTransmission &Transport,
        Prism::Fault::Failure &Failure)
        -> Net::awaitable<bool>
    {
        if (!Transport) co_return true;
        bool Retired = true;
        for (auto *Layer = Transport.get(); Layer; Layer = Layer->NextLayer())
        {
            const auto Activity = Layer->Activity();
            if (!Activity)
            {
                Retired = false;
                PreserveChildDrainFailure(
                    Failure, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                continue;
            }
            Activity->Seal();
            auto LayerFailure = Prism::Fault::Failure{};
            try
            {
                const auto Drained = co_await Activity->Drain();
                if (!Drained) LayerFailure = Drained.error();
            }
            catch (...)
            {
                LayerFailure = ControlFailureFromException(std::current_exception());
            }
            const bool LayerRetired = Activity->IsRetired();
            if (!Root->IsExpectedRetirementCancellation(LayerFailure, LayerRetired))
                PreserveChildDrainFailure(Failure, LayerFailure);
            Retired = LayerRetired && Retired;
            if (!LayerRetired && !Failure.Failed())
                PreserveChildDrainFailure(
                    Failure, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        co_return Retired;
    }
    /** @brief 仅用同 engine 的物理回执和 child 两端 Activity drain 释放 retained owner。 */
    auto DrainRetainedChildren(
        const std::shared_ptr<RootState> &Root,
        bool EngineRetired)
        -> Net::awaitable<RetainedChildDrainReceipt>
    {
        RetainedChildDrainReceipt Receipt;
        Prism::Fault::Failure FirstFailure;
        if ((!EngineRetired || !Root->EngineControl) && Root->HasOutstandingChildRetirement())
        {
            Receipt.Retired = false;
            Receipt.Failure = {Prism::Fault::Code::Blocked};
            co_return Receipt;
        }
        for (std::size_t Index = 0; Index < Root->ChildRetirementSlots.size(); ++Index)
        {
            const auto Child = Root->ChildRetirementSlots[Index].Retained;
            if (!Child)
            {
                if (Root->ChildRetirementSlots[Index].Reserved)
                {
                    Receipt.Retired = false;
                    PreserveChildDrainFailure(
                        FirstFailure, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                }
                continue;
            }
            const auto Inbound = co_await DrainRetainedActivity(
                Root, Child->Inbound, FirstFailure);
            bool Outbound = Inbound;
            if (Child->Outbound != Child->Inbound)
                Outbound = co_await DrainRetainedActivity(
                    Root, Child->Outbound, FirstFailure);
            if (!Inbound || !Outbound)
            {
                Receipt.Retired = false;
                continue;
            }
            if (Root->StreamCatalogOwner && Root->StreamCatalogOwner->IsAvailable())
            {
                const Prism::Contract::Ingress::StreamIdentity Identity{
                    Root->Metadata.TaskIdentity.SessionId,
                    Root->Metadata.TaskIdentity.WorkerId,
                    Root->Metadata.TaskIdentity.Generation,
                    Child->Identity.StreamId};
                if (!Root->StreamCatalogOwner->Retire(Identity))
                    Root->StreamCatalogOwner->Disable();
            }
            Child->Lease.Release();
            Child->Inbound.reset();
            Child->Outbound.reset();
            Child->Finish = {};
            Child->Reset = {};
            Child->Reject = {};
            Root->ReleaseChildRetirementSlot(Index);
        }
        if (Root->HasOutstandingChildRetirement())
        {
            Receipt.Retired = false;
            PreserveChildDrainFailure(
                FirstFailure, Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        Receipt.Failure = FirstFailure;
        co_return Receipt;
    }

    /** @brief 每个真正 wire child 申请 StreamLease、派生父身份，取消 hook 弱持 child。 */
    auto StartChild(
        std::shared_ptr<RootState> Root,
        std::shared_ptr<ChildState> Child,
        const bool DeferStart) -> bool
    {
        Child->Root = Root;
        if (DeferStart)
        {
            Child->StartGate = std::make_shared<ChildState::StartSignal>(
                Root->Executor, 1);
        }
        const auto RetirementSlot = Root->ReserveChildRetirementSlot();
        if (RetirementSlot) Child->RetirementSlot = *RetirementSlot;
        else Child->Admitted = false;
        if (!Child->ControlFailure)
        {
            Child->ControlFailure = std::make_shared<Prism::Fault::FailureState>();
        }
        if (Child->Admitted && Root->Admission)
        {
            auto Lease = Root->Admission.Acquire();
            Child->Admitted = bool(Lease);
            if (Lease) Child->Lease = std::move(*Lease);
        }
        auto Identity = Root->Metadata.TaskIdentity;
        Identity.StreamId = Child->Identity.StreamId;
        Prism::Lifecycle::TaskRequest Request{.Context = Prism::Lifecycle::FromParent(Identity), .StartOnSubmit = true};
        const auto Weak = std::weak_ptr<ChildState>(Child);
        Request.Cancel = [Weak] { if (const auto Owner = Weak.lock()) Owner->Cancel(); };
        const auto Task = Root->Children->SpawnTracked(std::move(Request), RunChild(Child));
        if (!Task)
        {
            if (Root->StreamCatalogOwner) Root->StreamCatalogOwner->Disable();
            Child->Cancel();
            if (Child->RetirementSlot)
                Root->RetainChildUntilRootRetired(std::move(Child));
            return false;
        }
        Child->Identity = Task->Identity();
        if (Child->RetirementSlot && Root->StreamCatalogOwner &&
            Root->StreamCatalogOwner->IsAvailable())
        {
            const auto Binding = Root->Admission.Binding();
            Prism::AccountId Account;
            if (Binding)
            {
                Account = Binding->AccountId();
            }
            std::optional<Prism::Contract::Ingress::StreamProtocol> Protocol;
            switch (Root->SelectedWire)
            {
            case Mode::Smux:
                Protocol = Prism::Contract::Ingress::StreamProtocol::Smux;
                break;
            case Mode::Yamux:
                Protocol = Prism::Contract::Ingress::StreamProtocol::Yamux;
                break;
            case Mode::H2Mux:
                Protocol = Prism::Contract::Ingress::StreamProtocol::H2Mux;
                break;
            case Mode::Auto:
            default:
                Root->StreamCatalogOwner->Disable();
                return true;
            }
            const Prism::Contract::Ingress::StreamDescriptor Descriptor{
                .Identity = {Root->Metadata.TaskIdentity.SessionId,
                    Root->Metadata.TaskIdentity.WorkerId,
                    Root->Metadata.TaskIdentity.Generation,
                    Child->Identity.StreamId},
                .Task = Child->Identity.TaskId,
                .ParentTask = Child->Identity.ParentTaskId,
                .Account = Account,
                .Protocol = *Protocol,
                .State = Prism::Contract::Ingress::StreamState::Active};
            const Prism::Contract::Ingress::StreamResetRequest Scope{
                Descriptor.Identity, Child->Identity.TaskId, Child->Identity.ParentTaskId};
            auto ResetOwner = CreateStreamResetTaskOwner(
                *Task, Child->ControlFailure, Scope);
            Root->StreamResetOwners.emplace(Child->Identity.TaskId.Value(), ResetOwner);
            const auto Registered = Root->StreamCatalogOwner->Register(
                Descriptor,
                Prism::Contract::Ingress::StreamResetBinding{ResetOwner});
            if (!Registered)
            {
                Root->StreamCatalogOwner->Disable();
                if (Child->StartGate) Child->StartGate->close();
                Child->Cancel();
                return false;
            }
        }
        return true;
    }

    auto OpenChildStart(const std::shared_ptr<ChildState> &Child) noexcept -> void
    {
        if (!Child || !Child->StartGate) return;
        (void)Child->StartGate->try_send(boost::system::error_code{});
    }
}

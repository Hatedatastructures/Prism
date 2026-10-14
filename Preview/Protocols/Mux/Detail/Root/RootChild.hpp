/** @file RootChild.hpp @brief sing-mux child 的真实配额、拨号、可靠 relay 与一次 completion。 */
#pragma once
#include <Preview/Protocols/Mux/Detail/Root/RootState.hpp>
#include <Preview/Protocols/Mux/Detail/SingMux/Handshake.hpp>
#include <Preview/Protocols/Mux/SingMux/Stream.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/system_error.hpp>
#include <expected>
#include <exception>
#include <system_error>

namespace Preview::Mux::Detail
{
    class StreamResetTaskOwner final : public Preview::Contract::Ingress::StreamResetOwner
    {
    public:
        StreamResetTaskOwner(
            Preview::Lifecycle::TaskHandle Task,
            std::shared_ptr<Preview::Fault::FailureState> ControlFailure,
            Preview::Contract::Ingress::StreamResetRequest Scope)
            : Task_(std::move(Task)), ControlFailure_(std::move(ControlFailure)), Scope_(Scope)
        {
        }

        [[nodiscard]] auto ResetAndDrain(
            Preview::Contract::Ingress::StreamResetRequest Request)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            using Failure = Preview::Fault::Failure;
            if (Request != Scope_)
            {
                co_return std::unexpected(Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (!Task_.IsCompleted()) (void)Task_.RequestCancel();
            const auto Retired = co_await Task_.WaitForRetirementAsync();
            if (!Retired) co_return std::unexpected(Retired.error());
            const auto ControlFailure = ControlFailure_->Load();
            if (ControlFailure.Failed()) co_return std::unexpected(ControlFailure);
            const auto Result = Task_.Result();
            if (Result.Outcome == Preview::Lifecycle::TaskOutcome::Failed ||
                Result.Outcome == Preview::Lifecycle::TaskOutcome::Quarantined)
            {
                if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
                co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
            }
            co_return std::expected<void, Failure>{};
        }

    private:
        Preview::Lifecycle::TaskHandle Task_;
        std::shared_ptr<Preview::Fault::FailureState> ControlFailure_;
        Preview::Contract::Ingress::StreamResetRequest Scope_;
    };

    inline auto RecordCloseFailure(
        std::expected<void, Preview::Fault::Failure> Result,
        std::exception_ptr &Failure,
        const std::shared_ptr<RootState> &Root) -> void
    {
        if (Result) return;
        Root->RecordTerminalFailure(Result.error());
        if (Failure) return;
        try
        {
            throw std::system_error(Preview::Fault::ToNative(Result.error()));
        }
        catch (...)
        {
            Failure = std::current_exception();
        }
    }

    inline auto RejectChild(std::shared_ptr<ChildState> Child) -> Net::awaitable<void>
    {
        const std::array<std::byte, 1> ErrorStatus{std::byte{1}};
        (void)co_await Child->Inbound->WriteSome(std::span<const std::byte>(ErrorStatus));
        if (Child->Reject) Child->Reject();
        else (void)Child->Inbound->Close();
    }
    inline auto RelayChild(std::shared_ptr<ChildState> Child,
        Preview::Foundation::TrafficObservation Observation)
        -> Net::awaitable<Preview::Network::Relay::Result>
    {
        using Preview::Fault::Code;
        if (!Child->Admitted)
        { co_await RejectChild(Child); co_return Preview::Network::Relay::Result{.Failure = {Code::Streamcap}}; }
        const auto Request = co_await Preview::Mux::Detail::SingMux::ReadStreamRequest(Child->Inbound);
        if (!Request || Request->Udp || Request->PacketAddress || Request->Target.Host.Empty())
        { co_await RejectChild(Child); co_return Preview::Network::Relay::Result{.Failure = {Code::NotSupported}}; }
        Child->Target = Request->Target;
        if (Child->Root->Stopping.load()) co_return Preview::Network::Relay::Result{.Failure = {Code::Canceled}};
        if (!Child->Root->Options.Services.Egress)
        { co_await RejectChild(Child); co_return Preview::Network::Relay::Result{.Failure = {Code::NotSupported}}; }
        auto Dialed = co_await Child->Root->Options.Services.Egress->Connect(Child->Target);
        if (!Dialed)
        { co_await RejectChild(Child); co_return Preview::Network::Relay::Result{.Failure = Dialed.error()}; }
        Child->Outbound = std::move(*Dialed);
        Child->Inbound = std::make_shared<Preview::Mux::SingMux::ServerStream>(
            Child->Inbound, Child->Target);
        const auto& Services = Child->Root->Options.Services;
        co_return co_await Preview::Network::Relay::Run(
            {Child->Inbound, Child->Outbound, Services.BufferSize, Services.IdleTimeout, Observation, Services.Bytes});
    }

    struct ChildCompletion final
    {
        ChildCompletion(std::shared_ptr<ChildState> Value,
            Preview::Foundation::TrafficObservation ObservationValue)
            : Child(std::move(Value)), Observation(std::move(ObservationValue)) {}
        std::shared_ptr<ChildState> Child;
        Preview::Network::Relay::Result Result;
        Preview::Foundation::TrafficObservation Observation;
        std::exception_ptr Failure;
        bool FinishDrained{false};
    };
    inline auto CompleteChild(ChildCompletion Completion) -> Net::awaitable<void>;

    /** @brief 唯一实际 child completion 报告；异常观察不改业务 fault，根不重复累计这些 bytes。 */
    inline auto RunChild(std::shared_ptr<ChildState> Child) -> Net::awaitable<void>
    {
        const auto Binding = Child->Root->Admission.Binding();
        Preview::Foundation::TrafficObservation Observation{
            Child->Root->Options.Services.Traffic,
            Preview::Foundation::TrafficEvent{
                .Generation = Child->Root->Metadata.TaskIdentity.Generation,
                .Worker = Child->Root->Metadata.TaskIdentity.WorkerId,
                .Session = Child->Root->Metadata.TaskIdentity.SessionId,
                .Stream = Child->Identity.StreamId,
                .Task = Child->Identity.TaskId,
                .Account = Binding ? Binding->AccountId() : Preview::AccountId{}}};
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
            Child->Root->RecordTerminalFailure(Completion.Result.Failure);
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
                if (!Completion.Result.Failure.Failed())
                    Completion.Result.Failure = Finished.error();
                Child->Root->RecordTerminalFailure(Finished.error());
            }
        }
        catch (...)
        {
            if (!Completion.Failure)
            {
                Completion.Failure = std::current_exception();
                Child->Root->RecordTerminalFailure(
                    ControlFailureFromException(Completion.Failure));
            }
        }
    }

    inline auto DrainRetainedActivity(
        const Preview::SharedTransmission &Transport,
        Preview::Fault::Failure &Failure) -> Net::awaitable<bool>;

    inline auto DrainChildActivities(std::shared_ptr<ChildState> Child)
        -> Net::awaitable<bool>
    {
        Preview::Fault::Failure Failure;
        const bool InboundRetired = co_await DrainRetainedActivity(
            Child->Inbound, Failure);
        bool OutboundRetired = InboundRetired;
        if (Child->Outbound != Child->Inbound)
        {
            OutboundRetired = co_await DrainRetainedActivity(
                Child->Outbound, Failure);
        }
        if (Failure.Failed()) Child->Root->RecordTerminalFailure(Failure);
        co_return InboundRetired && OutboundRetired;
    }

    inline auto CloseChildTransports(ChildCompletion &Completion)
        -> Net::awaitable<void>
    {
        const auto Child = Completion.Child;
        const auto Root = Child->Root;
        auto &Failure = Completion.Failure;
        if (Child->RetirementSlot && Root->StreamCatalogOwner)
        {
            const Preview::Contract::Ingress::StreamIdentity Identity{
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
                Root->RecordTerminalFailure(ControlFailureFromException(Failure));
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
                Root->RecordTerminalFailure(ControlFailureFromException(Failure));
            }
        }
        co_await DrainChildFinish(Completion);
    }

    inline auto CompleteChild(ChildCompletion Completion) -> Net::awaitable<void>
    {
        const auto Child = Completion.Child;
        const auto Root = Child->Root;
        auto &Result = Completion.Result;
        auto &Failure = Completion.Failure;
        auto &Observation = Completion.Observation;
        auto &FinishDrained = Completion.FinishDrained;
        if (Failure) Root->RecordTerminalFailure(ControlFailureFromException(Failure));
        if (Child->ControlFailure)
        {
            const auto ControlFailure = Child->ControlFailure->Load();
            if (ControlFailure.Failed()) Root->RecordTerminalFailure(ControlFailure);
        }
        try
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        }
        catch (...)
        {
            if (!Failure)
            {
                Failure = std::current_exception();
                Root->RecordTerminalFailure(ControlFailureFromException(Failure));
            }
        }
        co_await CloseChildTransports(Completion);
        const bool ActivitiesRetired = co_await DrainChildActivities(Child);
        Preview::Fault::Failure ControlFailure;
        if (Child->ControlFailure)
        {
            ControlFailure = Child->ControlFailure->Load();
            if (ControlFailure.Failed())
            {
                if (!Result.Failure.Failed()) Result.Failure = ControlFailure;
                if (!Failure)
                {
                    try { throw std::system_error(Preview::Fault::ToNative(ControlFailure)); }
                    catch (...) { Failure = std::current_exception(); }
                }
            }
        }
        if (Failure && !Result.Failure.Failed())
            Result.Failure = ControlFailureFromException(Failure);
        const bool ChildRetired = FinishDrained && ActivitiesRetired &&
            !Result.DirectionFailure[0].Failed() && !Result.DirectionFailure[1].Failed();
        if (Child->RetirementSlot && Root->StreamCatalogOwner)
        {
            const auto Identity = Preview::Contract::Ingress::StreamIdentity{
                Root->Metadata.TaskIdentity.SessionId,
                Root->Metadata.TaskIdentity.WorkerId,
                Root->Metadata.TaskIdentity.Generation,
                Child->Identity.StreamId};
            if (ChildRetired && Root->StreamCatalogOwner->IsAvailable())
            {
                if (!Root->StreamCatalogOwner->Retire(Identity))
                {
                    Root->StreamCatalogOwner->Disable();
                }
            }
        }
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
            const auto Retired = co_await Preview::Foundation::RetireTraffic(
                Root->Options.Services.Traffic,
                Preview::Foundation::TrafficRetirement{Preview::Foundation::StreamTrafficOwner{
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

    inline auto PreserveChildDrainFailure(
        Preview::Fault::Failure &Primary,
        const Preview::Fault::Failure &Next) noexcept -> void
    {
        if (!Primary.Failed() && Next.Failed()) Primary = Next;
    }
    inline auto DrainRetainedActivity(
        const Preview::SharedTransmission &Transport,
        Preview::Fault::Failure &Failure)
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
                    Failure, Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                continue;
            }
            Activity->Seal();
            try
            {
                const auto Drained = co_await Activity->Drain();
                if (!Drained) PreserveChildDrainFailure(Failure, Drained.error());
            }
            catch (...)
            {
                PreserveChildDrainFailure(
                    Failure, ControlFailureFromException(std::current_exception()));
            }
            const bool LayerRetired = Activity->IsRetired();
            Retired = LayerRetired && Retired;
            if (!LayerRetired && !Failure.Failed())
                PreserveChildDrainFailure(
                    Failure, Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        co_return Retired;
    }
    struct RetainedChildDrainReceipt final
    {
        bool Retired{true};
        Preview::Fault::Failure Failure;
    };
    /** @brief 仅用同 engine 的物理回执和 child 两端 Activity drain 释放 retained owner。 */
    inline auto DrainRetainedChildren(
        const std::shared_ptr<RootState> &Root,
        bool EngineRetired)
        -> Net::awaitable<RetainedChildDrainReceipt>
    {
        RetainedChildDrainReceipt Receipt;
        Preview::Fault::Failure FirstFailure;
        if ((!EngineRetired || !Root->EngineControl) && Root->HasOutstandingChildRetirement())
        {
            Receipt.Retired = false;
            Receipt.Failure = {Preview::Fault::Code::Blocked};
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
                        FirstFailure, Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                }
                continue;
            }
            const auto Inbound = co_await DrainRetainedActivity(Child->Inbound, FirstFailure);
            bool Outbound = Inbound;
            if (Child->Outbound != Child->Inbound)
                Outbound = co_await DrainRetainedActivity(Child->Outbound, FirstFailure);
            if (!Inbound || !Outbound)
            {
                Receipt.Retired = false;
                continue;
            }
            if (Root->StreamCatalogOwner && Root->StreamCatalogOwner->IsAvailable())
            {
                const Preview::Contract::Ingress::StreamIdentity Identity{
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
                FirstFailure, Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        Receipt.Failure = FirstFailure;
        co_return Receipt;
    }

    /** @brief 每个真正 wire child 申请 StreamLease、派生父身份，取消 hook 弱持 child。 */
    inline auto StartChild(std::shared_ptr<RootState> Root, std::shared_ptr<ChildState> Child) -> bool
    {
        Child->Root = Root;
        const auto RetirementSlot = Root->ReserveChildRetirementSlot();
        if (RetirementSlot) Child->RetirementSlot = *RetirementSlot;
        else Child->Admitted = false;
        if (!Child->ControlFailure)
        {
            Child->ControlFailure = std::make_shared<Preview::Fault::FailureState>();
        }
        if (Child->Admitted && Root->Admission)
        {
            auto Lease = Root->Admission.Acquire();
            Child->Admitted = bool(Lease);
            if (Lease) Child->Lease = std::move(*Lease);
        }
        auto Identity = Root->Metadata.TaskIdentity;
        Identity.StreamId = Child->Identity.StreamId;
        Preview::Lifecycle::TaskRequest Request{.Context = Preview::Lifecycle::FromParent(Identity), .StartOnSubmit = true};
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
            Preview::AccountId Account;
            if (Binding)
            {
                Account = Binding->AccountId();
            }
            auto Protocol = Preview::Contract::Ingress::StreamProtocol::Smux;
            if (Root->SelectedWire != Mode::Smux && Root->SelectedWire != Mode::Yamux)
            {
                if (Root->SelectedWire == Mode::H2Mux)
                {
                    Protocol = Preview::Contract::Ingress::StreamProtocol::H2Mux;
                }
                else
                {
                    Root->StreamCatalogOwner->Disable();
                    return true;
                }
            }
            if (Root->SelectedWire == Mode::Yamux)
            {
                Protocol = Preview::Contract::Ingress::StreamProtocol::Yamux;
            }
            const Preview::Contract::Ingress::StreamDescriptor Descriptor{
                .Identity = {Root->Metadata.TaskIdentity.SessionId,
                    Root->Metadata.TaskIdentity.WorkerId,
                    Root->Metadata.TaskIdentity.Generation,
                    Child->Identity.StreamId},
                .Task = Child->Identity.TaskId,
                .ParentTask = Child->Identity.ParentTaskId,
                .Account = Account,
                .Protocol = Protocol,
                .State = Preview::Contract::Ingress::StreamState::Active};
            const Preview::Contract::Ingress::StreamResetRequest Scope{
                Descriptor.Identity, Child->Identity.TaskId, Child->Identity.ParentTaskId};
            auto ResetOwner = std::make_shared<StreamResetTaskOwner>(
                *Task, Child->ControlFailure, Scope);
            Root->StreamResetOwners.emplace(Child->Identity.TaskId.Value(), ResetOwner);
            const auto Registered = Root->StreamCatalogOwner->Register(
                Descriptor,
                Preview::Contract::Ingress::StreamResetBinding{ResetOwner});
            if (!Registered) Root->StreamCatalogOwner->Disable();
        }
        return true;
    }
}

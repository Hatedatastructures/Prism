/**
 * @file RootLifecycle.cpp
 * @brief Mux root 状态、会话、registry 与物理退休生命周期实现。
 */
#include <Prism/Protocols/Mux/RootBinding.hpp>

#include <Prism/Protocols/Mux/Detail/Root/RootChild.hpp>
#include <Prism/Protocols/Mux/Detail/Root/RootRegistry.hpp>
#include <Prism/Protocols/Mux/Detail/Root/RootRetirement.hpp>
#include <Prism/Protocols/Mux/Detail/Root/RootState.hpp>
#include <Prism/Protocols/Mux/Detail/Root/RootSession.hpp>
#include "Detail/SingMux/SingMux.hpp"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>

#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

namespace Prism::Mux::Detail
{

    RootState::RootState(Prism::SharedTransmission Transport, RootOptions Value)
        : Inbound(std::move(Transport)), Options(std::move(Value)),
          ChildRetirementSlots(Options.MaxStreams),
          Executor(Net::make_strand(Inbound->Executor())),
          Children(std::make_shared<Prism::Lifecycle::TaskRegistry>(Executor)),
          Loops(std::make_shared<Prism::Lifecycle::TaskRegistry>(Executor)),
          Lifetime(Loops->Reclaimer()),
          DrainGate(std::make_shared<Net::experimental::concurrent_channel<
              void(boost::system::error_code)>>(Executor, 1))
    {
        (void)DrainGate->try_send(boost::system::error_code{});
        for (std::size_t Index = 0; Index < ChildRetirementSlots.size(); ++Index)
        {
            if (Index + 1U < ChildRetirementSlots.size())
                ChildRetirementSlots[Index].NextFree = Index + 1U;
        }
        if (!ChildRetirementSlots.empty()) FreeChildRetirementSlot = 0U;
    }

    [[nodiscard]] auto RootState::ReserveChildRetirementSlot() noexcept
        -> std::optional<std::size_t>
    {
        if (!FreeChildRetirementSlot) return {};
        const auto Index = *FreeChildRetirementSlot;
        FreeChildRetirementSlot = ChildRetirementSlots[Index].NextFree;
        ChildRetirementSlots[Index].NextFree.reset();
        ChildRetirementSlots[Index].Reserved = true;
        return Index;
    }

    auto RootState::ReleaseChildRetirementSlot(std::size_t Index) noexcept -> void
    {
        if (Index >= ChildRetirementSlots.size()) return;
        auto &Slot = ChildRetirementSlots[Index];
        if (!Slot.Reserved) return;
        Slot.Retained.reset();
        Slot.Reserved = false;
        Slot.NextFree = FreeChildRetirementSlot;
        FreeChildRetirementSlot = Index;
    }

    [[nodiscard]] auto RootState::HasOutstandingChildRetirement() const noexcept -> bool
    {
        for (const auto &Slot : ChildRetirementSlots)
            if (Slot.Reserved) return true;
        return false;
    }

    auto RootState::RetainChildUntilRootRetired(std::shared_ptr<ChildState> Child) noexcept -> void
    {
        if (!Child || !Child->RetirementSlot ||
            *Child->RetirementSlot >= ChildRetirementSlots.size()) return;
        const auto Index = *Child->RetirementSlot;
        auto &Slot = ChildRetirementSlots[Index];
        if (!Slot.Reserved || Slot.Retained) return;
        Child->RetirementSlot.reset();
        Child->Root.reset();
        Slot.Retained = std::move(Child);
    }

    auto RootState::RequestCancel() noexcept -> void
    {
        auto Expected = RunPhase::AcceptingCancellation;
        if (!Phase.compare_exchange_strong(Expected, RunPhase::CancellationRequested,
                std::memory_order_acq_rel) &&
            Expected != RunPhase::CancellationRequested) return;
        ExitStatus.store(Prism::Fault::Code::Canceled);
        if (Started.load(std::memory_order_acquire))
        {
            RecordTerminalFailure(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        Stop();
    }

    [[nodiscard]] auto RootState::IsClosingNormally() const noexcept -> bool
    {
        const auto Current = Phase.load(std::memory_order_acquire);
        return Stopping.load(std::memory_order_acquire) &&
            Current != RunPhase::CancellationRequested &&
            Current != RunPhase::ResourcesRetired;
    }

    [[nodiscard]] auto RootState::IsExplicitlyCanceled() const noexcept -> bool
    {
        return Phase.load(std::memory_order_acquire) == RunPhase::CancellationRequested ||
            ExitStatus.load(std::memory_order_acquire) == Prism::Fault::Code::Canceled;
    }

    [[nodiscard]] auto RootState::IsExpectedRetirementCancellation(
        const Prism::Fault::Failure &Failure, bool Retired) const noexcept -> bool
    {
        return IsClosingNormally() && Retired &&
            Failure.Code == Prism::Fault::Code::Canceled;
    }

    [[nodiscard]] auto RootState::PublishRunOutcome() noexcept -> bool
    {
        auto Expected = RunPhase::AcceptingCancellation;
        if (Phase.compare_exchange_strong(Expected, RunPhase::OutcomePublished,
            std::memory_order_acq_rel)) return false;
        return Expected == RunPhase::CancellationRequested;
    }

    auto RootState::RecordTerminalFailure(Prism::Fault::Failure Failure) noexcept -> void
    {
        const auto Stored = TerminalFailure.TrySet(Failure);
        (void)Stored;
    }

    [[nodiscard]] auto RootState::FailureFromException(std::exception_ptr Failure) noexcept
        -> Prism::Fault::Failure
    {
        try
        {
            if (Failure) std::rethrow_exception(Failure);
        }
        catch (const boost::system::system_error &Error)
        {
            return Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
        }
        catch (const std::system_error &Error)
        {
            return Prism::Fault::FromNative(Error.code());
        }
        catch (...) { return {Prism::Fault::Code::IoError}; }
        return {Prism::Fault::Code::IoError};
    }

    [[nodiscard]] auto RootState::DrainTaskScope(
        const std::shared_ptr<Prism::Lifecycle::TaskRegistry> &Scope)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        std::expected<void, Prism::Fault::Failure> Drained;
        try { Drained = co_await Scope->Drain(); }
        catch (...) { Drained = std::unexpected(FailureFromException(std::current_exception())); }
        const auto Stats = Scope->Stats();
        const bool PhysicallyRetired = Stats.Active == 0U && !Stats.DrainBlocked;
        const bool ExpectedCancellation = IsClosingNormally() && !Drained &&
            Drained.error().Code == Prism::Fault::Code::Canceled && PhysicallyRetired;
        if (!Drained && !ExpectedCancellation)
            RecordTerminalFailure(Drained.error());
        if (PhysicallyRetired)
            co_return std::expected<void, Prism::Fault::Failure>{};
        if (!Drained) co_return std::unexpected(Drained.error());
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::Blocked});
    }

    auto RootState::ReleaseResources() -> bool
    {
        if (ResourcesRetired.load()) return true;
        // 唯一物理释放 owner：并发 Drain 或 Run 最终化只能有一个调用者真正清空资源。
        bool Expected = false;
        if (!ReleaseInProgress.compare_exchange_strong(
                Expected, true, std::memory_order_acq_rel))
            return ResourcesRetired.load(std::memory_order_acquire);
        if (Lifetime.Active() != 0U || Lifetime.IsBlocked() ||
            HasOutstandingChildRetirement())
        {
            ReleaseInProgress.store(false, std::memory_order_release);
            return false;
        }
        Phase.store(RunPhase::ResourcesRetired, std::memory_order_release);
        Admission = {};
        Lease.Release();
        ParentStreamLease.Release();
        for (auto &Slot : ChildRetirementSlots)
        {
            if (Slot.Retained && StreamCatalogOwner && StreamCatalogOwner->IsAvailable())
            {
                const Prism::Contract::Ingress::StreamIdentity Identity{
                    Metadata.TaskIdentity.SessionId,
                    Metadata.TaskIdentity.WorkerId,
                    Metadata.TaskIdentity.Generation,
                    Slot.Retained->Identity.StreamId};
                if (!StreamCatalogOwner->Retire(Identity)) StreamCatalogOwner->Disable();
            }
            if (Slot.Retained) Slot.Retained->Lease.Release();
            Slot.Retained.reset();
            Slot.Reserved = false;
        }
        Options.Services = {};
        Options.Admission = {};
        Options.GenerationUseState.reset();
        Options.Observe = {};
        StreamCatalogOwner.reset();
        StreamResetOwners.clear();
        EngineControl.reset();
        Inbound.reset();
        GenerationLease = {};
        if (const auto Owner = CreateOwner.lock()) Owner->OnMuxRootRetired();
        CreateOwner.reset();
        ResourcesRetired.store(true, std::memory_order_release);
        ResourcesReadyForFinalization.store(false, std::memory_order_release);
        ReleaseInProgress.store(false, std::memory_order_release);
        if (const auto Owner = RetirementOwner.lock())
            Owner->Retire(TerminalFailure.Load());
        return true;
    }

    auto RootState::Stop() noexcept -> void
    {
        if (Stopping.exchange(true)) return;
        auto Self = shared_from_this();
        try { Net::dispatch(Executor, [Self] { Self->StopOnExecutor(); }); }
        catch (const boost::system::system_error &Error)
        {
            RecordTerminalFailure(Prism::Fault::FromNative(
                static_cast<std::error_code>(Error.code())));
        }
        catch (const std::system_error &Error)
        { RecordTerminalFailure(Prism::Fault::FromNative(Error.code())); }
        catch (...) { RecordTerminalFailure(Prism::Fault::Failure{Prism::Fault::Code::IoError}); }
    }

    auto RootState::StopOnExecutor() noexcept -> void
    {
        Stopping.store(true);
        const bool H2Closing = EngineControl && SelectedWire == Mode::H2Mux;
        if (H2Closing)
        {
            const auto Closed = EngineControl->RequestClose();
            if (!Closed) RecordTerminalFailure(Closed.error());
        }
        (void)Children->Cancel();
        if (EngineControl && !H2Closing)
        {
            const auto Closed = EngineControl->RequestClose();
            if (!Closed) RecordTerminalFailure(Closed.error());
        }
        else if (!EngineControl)
        {
            try
            {
                const auto Canceled = Inbound->Cancel();
                if (!Canceled) RecordTerminalFailure(Canceled.error());
                const auto Closed = Inbound->Close();
                if (!Closed) RecordTerminalFailure(Closed.error());
            }
            catch (const boost::system::system_error &Error)
            {
                RecordTerminalFailure(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error.code())));
            }
            catch (const std::system_error &Error)
            { RecordTerminalFailure(Prism::Fault::FromNative(Error.code())); }
            catch (...)
            {
                RecordTerminalFailure(
                    Prism::Fault::Failure{Prism::Fault::Code::IoError});
            }
        }
    }

    [[nodiscard]] auto ControlFailureFromException(std::exception_ptr Exception) noexcept
        -> Prism::Fault::Failure
    {
        try
        {
            if (Exception) std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error &Error)
        {
            return Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
        }
        catch (const std::system_error &Error)
        {
            return Prism::Fault::FromNative(Error.code());
        }
        catch (...)
        {
            return {Prism::Fault::Code::IoError};
        }
        return {Prism::Fault::Code::IoError};
    }

    auto RecordControlResult(
        const std::shared_ptr<Prism::Fault::FailureState> &Owner,
        const std::expected<void, Prism::Fault::Failure> &Result,
        const std::shared_ptr<RootState> &Root) noexcept -> void
    {
        if (Result) return;
        if (Root && !(Root->IsClosingNormally() &&
            Result.error().Code == Prism::Fault::Code::Canceled))
            Root->RecordTerminalFailure(Result.error());
        if (Owner) (void)Owner->TrySet(Result.error());
    }

    auto RecordControlException(
        const std::shared_ptr<Prism::Fault::FailureState> &Owner,
        std::exception_ptr Exception,
        const std::shared_ptr<RootState> &Root) noexcept -> void
    {
        if (!Exception) return;
        const auto Failure = ControlFailureFromException(std::move(Exception));
        if (Root && !(Root->IsClosingNormally() &&
            Failure.Code == Prism::Fault::Code::Canceled))
            Root->RecordTerminalFailure(Failure);
        if (Owner) (void)Owner->TrySet(Failure);
    }

    auto ChildState::Cancel() noexcept -> void
    {
        bool FirstCancel = false;
        if (!CancelIssued.compare_exchange_strong(
                FirstCancel, true, std::memory_order_acq_rel))
            return;
        ExplicitCancellation.store(true, std::memory_order_release);
        if (Root && Root->IsClosingNormally())
            NormalCloseCancellation.store(true, std::memory_order_release);
        try { Cancellation.emit(Net::cancellation_type::all); }
        catch (...)
        {
            RecordControlException(
                ControlFailure, std::current_exception(), Root);
        }
        if (StartGate)
        {
            StartGate->close();
            StartGate.reset();
        }
        if (Root && Root->StreamCatalogOwner)
        {
            const Prism::Contract::Ingress::StreamIdentity StreamIdentity{
                Root->Metadata.TaskIdentity.SessionId,
                Root->Metadata.TaskIdentity.WorkerId,
                Root->Metadata.TaskIdentity.Generation,
                Identity.StreamId};
            if (!Root->StreamCatalogOwner->MarkDraining(StreamIdentity))
                Root->StreamCatalogOwner->Disable();
        }
        if (Reset)
        {
            try
            {
                const auto ResetResult = Reset();
                if (ControlFailure)
                    RecordControlResult(ControlFailure, ResetResult, Root);
                else if (!ResetResult && Root)
                    Root->RecordTerminalFailure(ResetResult.error());
            }
            catch (...)
            {
                RecordControlException(
                    ControlFailure, std::current_exception(), Root);
            }
        }
        // Reset/Cancel 的失败只保留 first cause，最终关闭仍必须独立尝试。
        CancelAndClose(Inbound, ControlFailure, Root);
        if (Outbound != Inbound)
            CancelAndClose(Outbound, ControlFailure, Root);
    }

    auto PreserveRootDrainFailure(
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

    auto DrainRootEngine(const std::shared_ptr<RootState> &State)
        -> Net::awaitable<RootEngineDrainReceipt>
    {
        RootEngineDrainReceipt Receipt;
        if (!State->EngineControl) co_return Receipt;
        try
        {
            const auto Drained = co_await State->EngineControl->Drain();
            Receipt.Retired = State->EngineControl->IsRetired();
            if (!Drained && !State->IsExpectedRetirementCancellation(
                Drained.error(), Receipt.Retired))
            {
                Receipt.Failure = Drained.error();
            }
            else if (!Receipt.Retired)
                Receipt.Failure = {Prism::Fault::Code::Blocked};
        }
        catch (...)
        {
            Receipt.Failure = ControlFailureFromException(std::current_exception());
            Receipt.Retired = State->EngineControl->IsRetired();
        }
        if (State->IsExpectedRetirementCancellation(Receipt.Failure, Receipt.Retired))
            Receipt.Failure = {};
        Receipt.H2Retired = State->SelectedWire == Mode::H2Mux && Receipt.Retired;
        if (Receipt.Failure.Failed()) State->RecordTerminalFailure(Receipt.Failure);
        co_return Receipt;
    }

    auto DrainRootCarrier(
        const std::shared_ptr<RootState> &State,
        bool CoveredByEngine)
        -> Net::awaitable<RootCarrierDrainReceipt>
    {
        RootCarrierDrainReceipt Receipt;
        if (CoveredByEngine)
        {
            Receipt.Retired = true;
            co_return Receipt;
        }
        const auto Carrier = State->Inbound->Activity();
        if (!Carrier)
        {
            Receipt.Failure = {Prism::Fault::Code::Blocked};
            co_return Receipt;
        }
        Carrier->Seal();
        try
        {
            const auto Drained = co_await Carrier->Drain();
            if (!Drained) Receipt.Failure = Drained.error();
        }
        catch (...)
        {
            Receipt.Failure = ControlFailureFromException(std::current_exception());
        }
        Receipt.Retired = Carrier->IsRetired();
        if (State->IsExpectedRetirementCancellation(Receipt.Failure, Receipt.Retired))
            Receipt.Failure = {};
        if (!Receipt.Retired && !Receipt.Failure.Failed())
            Receipt.Failure = {Prism::Fault::Code::Blocked};
        co_return Receipt;
    }

    auto FinalizeRootRunResources(
        std::shared_ptr<RootState> State,
        std::expected<void, Prism::Fault::Failure> Result)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (State->ResourcesReadyForFinalization.exchange(false, std::memory_order_acq_rel))
        {
            try
            {
                boost::system::error_code GateError;
                co_await State->DrainGate->async_receive(
                    Net::redirect_error(Net::use_awaitable, GateError));
                struct FinalizeRelease final
                {
                    std::shared_ptr<Net::experimental::concurrent_channel<
                        void(boost::system::error_code)>> Gate;
                    ~FinalizeRelease() noexcept
                    {
                        if (Gate) (void)Gate->try_send(boost::system::error_code{});
                    }
                } Release{State->DrainGate};
                if (GateError)
                {
                    throw boost::system::system_error(GateError);
                }
                co_await Net::dispatch(State->Executor, Net::use_awaitable);
                if (!State->ReleaseResources())
                {
                    const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
                    State->RecordTerminalFailure(Failure);
                    if (Result) Result = std::unexpected(Failure);
                }
            }
            catch (...)
            {
                const auto Failure = RootState::FailureFromException(std::current_exception());
                State->RecordTerminalFailure(Failure);
                if (Result) Result = std::unexpected(Failure);
            }
        }
        co_return Result;
    }

    [[nodiscard]] auto IsExpectedRootRunCancellation(
        const std::shared_ptr<RootState>& State,
        const std::expected<void, Prism::Fault::Failure>& Result) noexcept -> bool
    {
        return State && !Result &&
            Result.error().Code == Prism::Fault::Code::Canceled &&
            State->IsClosingNormally();
    }

    auto RecordHttp2RunFailure(
        const std::shared_ptr<RootState>& State,
        Prism::Fault::Failure Failure) noexcept -> void
    {
        if (!State || (State->IsClosingNormally() &&
            Failure.Code == Prism::Fault::Code::Canceled))
        {
            return;
        }
        State->RecordTerminalFailure(Failure);
    }

    RootSession::RootActivity::RootActivity(std::shared_ptr<RootState> Value) : State_(std::move(Value))
    {}

    auto RootSession::RootActivity::Seal() noexcept -> void
    {
        State_->Lifetime.Seal();
        State_->Children->Seal();
    }

    [[nodiscard]] auto RootSession::RootActivity::Executor() const -> Net::any_io_executor
    { return State_->Executor; }

    [[nodiscard]] auto RootSession::RootActivity::IsRetired() const noexcept -> bool
    { return State_->ResourcesRetired.load(std::memory_order_acquire); }

    [[nodiscard]] auto RootSession::RootActivity::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Seal();
        State_->Stop();
        co_await Net::dispatch(State_->Executor, Net::use_awaitable);
        const auto Run = co_await State_->Lifetime.Drain();
        if (!Run) State_->RecordTerminalFailure(Run.error());
        const auto Resources = co_await DrainResources(State_);
        if (State_->ResourcesRetired.load(std::memory_order_acquire))
        {
            const auto Failure = State_->TerminalFailure.Load();
            if (Failure.Failed() && Failure.Code != Prism::Fault::Code::Canceled)
                co_return std::unexpected(Failure);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (!Resources) co_return std::unexpected(Resources.error());
        if (!Run) co_return std::unexpected(Run.error());
        co_return std::unexpected(
            Prism::Fault::Failure{Prism::Fault::Code::Blocked});
    }

    [[nodiscard]] auto RootSession::Create(
        Prism::Contract::MuxRootCreateRequest &Request,
        const RootOptions &Options)
        -> std::expected<std::shared_ptr<RootSession>, Prism::Fault::Failure>
    {
        if (!Request.BeginSessionCreation())
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Inbound = Request.Inbound();
        if (!Inbound || !Request.GenerationUseState() ||
            Request.GenerationUseState() != Options.GenerationUseState)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto RegistrationNode = std::make_shared<RootRegistryNode>();
        auto State = std::make_shared<RootState>(Inbound, Options);
        auto Root = std::shared_ptr<RootSession>(
            new RootSession(std::move(State), std::move(RegistrationNode)));
        Request.AttachSession(Root);
        Root->State_->ParentStreamLease = Request.TakeParentStreamLease();
        Root->State_->GenerationLease = Request.TakeGenerationUseLease();
        Root->State_->CreateOwner = Request.CreateOwner();
        Root->CreateCommitted_ = true;
        return Root;
    }

    RootSession::~RootSession()
    {
        if (CreateCommitted_) Close();
    }

    auto RootSession::SetRetirementOwner(const std::shared_ptr<RootRetirementOwner> &Owner) noexcept -> void
    { State_->RetirementOwner = Owner; }

    [[nodiscard]] auto RootSession::HistoricalFailure() const noexcept -> Prism::Fault::Failure
    { return State_->TerminalFailure.Load(); }

    [[nodiscard]] auto RootSession::WasStarted() const noexcept -> bool
    { return State_->Started.load(std::memory_order_acquire); }

    [[nodiscard]] auto RootSession::IsStopping() const noexcept -> bool
    { return State_->Stopping.load(std::memory_order_acquire); }

    [[nodiscard]] auto RootSession::IsRetired() const noexcept -> bool
    { return State_->ResourcesRetired.load(std::memory_order_acquire); }

    auto RootSession::Run(Prism::Contract::MuxRootRequest Request)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto State = State_;
        if (State->Started.exchange(true))
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (!State->Lifetime.Enter())
        {
            State->Stop();
            // 已注册但未真正进入 Run 的 root 仍持有 generation/parent lease；
            // 失败路径必须走同一条资源最终化，不能只停 carrier 就返回。
            const auto Drained = co_await DrainResources(State);
            if (!Drained)
            {
                State->RecordTerminalFailure(Drained.error());
                co_return std::unexpected(Drained.error());
            }
            if (State->Stopping.load(std::memory_order_acquire) &&
                State->Phase.load(std::memory_order_acquire) !=
                    RootState::RunPhase::CancellationRequested)
            {
                co_return std::expected<void, Prism::Fault::Failure>{};
            }
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        Prism::Lifecycle::DrainReservation Lifetime(State->Lifetime);
        State->Lease = std::move(Request.Lease);
        if (State->Lease)
        {
            State->Admission = State->Lease.Streams();
        }
        else
        {
            State->Admission = State->Options.Admission;
        }
        State->Metadata = std::move(Request.Metadata);
        State->StreamCatalogOwner = std::move(Request.StreamCatalogOwner);

        std::expected<void, Prism::Fault::Failure> Result;
        std::exception_ptr Fatal;
        if (!Request.GenerationUseState ||
            Request.GenerationUseState != State->Options.GenerationUseState)
        {
            Result = std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            State->RecordTerminalFailure(Result.error());
        }
        else if (!State->GenerationLease)
        {
            Result = std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            State->RecordTerminalFailure(Result.error());
        }
        if (Result)
        {
            try
            {
                Result = co_await Net::co_spawn(State->Executor, Serve(State), Net::use_awaitable);
            }
            catch (const boost::system::system_error &Error)
            {
                const auto Native = static_cast<std::error_code>(Error.code());
                Result = std::unexpected(Prism::Fault::FromNative(Native));
                if (Error.code() != Net::error::operation_aborted)
                {
                    Fatal = std::current_exception();
                }
            }
            catch (const std::system_error &Error)
            {
                Result = std::unexpected(Prism::Fault::FromNative(Error.code()));
                Fatal = std::current_exception();
            }
            catch (...)
            {
                Result = std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
                Fatal = std::current_exception();
            }
        }
        const bool ClosedDuringRun = IsExpectedRootRunCancellation(State, Result);
        if (ClosedDuringRun) Result = {};
        else if (!Result) State->RecordTerminalFailure(Result.error());
        if (State->PublishRunOutcome())
        {
            State->ExitStatus.store(Prism::Fault::Code::Canceled);
            State->RecordTerminalFailure(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }

        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        State->Stop();
        const auto Drained = co_await DrainResources(State);
        if (!Drained)
        {
            State->RecordTerminalFailure(Drained.error());
            if (Result) Result = std::unexpected(Drained.error());
        }
        if (Fatal)
        {
            const auto Context = Prism::Executor::ContextOwner::Find(State->Executor);
            if (Context && Context->Fatal) Context->Fatal->Publish(Fatal);
            State->RecordTerminalFailure(RootState::FailureFromException(Fatal));
            if (Result) Result = std::unexpected(RootState::FailureFromException(Fatal));
        }
        if (State->ExitStatus.load() == Prism::Fault::Code::Canceled && Result)
        {
            State->RecordTerminalFailure(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        const auto TerminalFailure = State->TerminalFailure.Load();
        if (TerminalFailure.Failed()) Result = std::unexpected(TerminalFailure);
        Lifetime.Transfer();
        State->Lifetime.Leave();
        co_return co_await FinalizeRootRunResources(State, std::move(Result));
    }

    [[nodiscard]] auto RootSession::Activity() const
        -> std::shared_ptr<Prism::Contract::CarrierActivity>
    { return Activity_; }

    auto RootSession::Cancel() noexcept -> void
    { Activity_->Seal(); State_->RequestCancel(); }

    auto RootSession::Close() noexcept -> void
    { Activity_->Seal(); State_->Stop(); }

    [[nodiscard]] auto RootSession::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    { co_return co_await Activity_->Drain(); }

    RootSession::RootSession(
        std::shared_ptr<RootState> State,
        std::shared_ptr<RootRegistryNode> RegistrationNode)
        : State_(std::move(State)), Activity_(std::make_shared<RootActivity>(State_)),
          RegistrationNode_(std::move(RegistrationNode))
    {}

    auto RootSession::RunHttp2(
        std::shared_ptr<RootState> State,
        std::shared_ptr<H2Mux::Http2Server> Server) -> Net::awaitable<void>
    {
        try
        {
            const auto Result = co_await Server->Run();
            if (!Result) RecordHttp2RunFailure(State, Result.error());
        }
        catch (const boost::system::system_error &Error)
        {
            RecordHttp2RunFailure(State, Prism::Fault::FromNative(
                static_cast<std::error_code>(Error.code())));
            throw;
        }
        catch (const std::system_error &Error)
        {
            RecordHttp2RunFailure(State, Prism::Fault::FromNative(Error.code()));
            throw;
        }
        catch (...)
        {
            State->RecordTerminalFailure(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
            throw;
        }
    }

    auto RootSession::ServeHttp2(std::shared_ptr<RootState> State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        auto Server = std::make_shared<H2Mux::Http2Server>(
            State->Inbound, State->Options.MaxStreams, true);
        if (!State->EngineControl)
            State->EngineControl = std::make_shared<EngineCloseOwner<H2Mux::Http2Server>>(
                Server, State);
        Server->BindIdentity(State->Metadata.TaskIdentity);
        if (State->StreamCatalogOwner &&
            !State->StreamCatalogOwner->Enable(State->Options.MaxStreams))
        {
            State->StreamCatalogOwner->Disable();
        }
        Prism::Lifecycle::TaskRequest Request{
            .Context = Prism::Lifecycle::FromParent(State->Metadata.TaskIdentity),
            .StartOnSubmit = true};
        const auto Weak = std::weak_ptr<H2Mux::Http2Server>(Server);
        Request.Cancel = [Weak] { if (const auto Owner = Weak.lock()) Owner->Cancel(); };
        if (!State->Loops->SpawnTracked(std::move(Request), RunHttp2(State, Server)))
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        while (!State->Stopping.load())
        {
            const auto Stream = co_await Server->AcceptStream();
            if (!Stream) break;
            auto Child = std::make_shared<ChildState>();
            Child->Inbound = Stream;
            Child->Identity.StreamId = Prism::StreamId{static_cast<std::uint64_t>(Stream->StreamId())};
            Child->Reject = [WeakStream = std::weak_ptr<H2Mux::Http2Stream>(Stream)]
            { if (const auto Owner = WeakStream.lock()) (void)Owner->Close(); };
            Child->Reset = [WeakStream = std::weak_ptr<H2Mux::Http2Stream>(Stream)]()
                -> std::expected<void, Prism::Fault::Failure>
            {
                if (const auto Owner = WeakStream.lock())
                {
                    return Owner->Cancel();
                }
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            };
            Child->Finish = [Stream] { return Stream->DrainTerminations(); };
            if (!StartChild(State, Child, true))
            {
                // 单个 child 的准入/登记失败只拒绝该流，不能让兄弟流和根一起终止。
                (void)Stream->Close();
                continue;
            }
            const auto Accepted = co_await Stream->AcceptRequest();
            if (!Accepted)
            {
                State->RecordTerminalFailure(Accepted.error());
                Child->Cancel();
                (void)Stream->Close();
                continue;
            }
            OpenChildStart(Child);
        }
        State->Stop();
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto RootSession::Serve(std::shared_ptr<RootState> State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (State->Stopping.load())
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        const auto Envelope = co_await Prism::Mux::Detail::SingMux::ReadSessionRequest(State->Inbound);
        if (!Envelope)
        {
            co_return std::unexpected(Envelope.error());
        }
        const auto Selected = Envelope->Request.Wire;
        if (Envelope->Terminal)
        {
            co_return std::unexpected(*Envelope->Terminal);
        }
        if (State->Options.Wire != Mode::Auto && State->Options.Wire != Selected)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
        State->SelectedWire = Selected;
        switch (Selected)
        {
        case Mode::Smux:
            co_return co_await ServeEngine<Smux::Server<>>(State);
        case Mode::Yamux:
            co_return co_await ServeEngine<Yamux::Server<>>(State);
        case Mode::H2Mux:
            co_return co_await ServeHttp2(State);
        case Mode::Auto:
        default:
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        }
    }

    /** @brief 已退休 root 的重复 Drain 只复核最终化并返回持久首因。 */
    [[nodiscard]] auto DrainRetiredRootResources(std::shared_ptr<RootState> State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        try
        {
            if (!State->ReleaseResources())
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
        }
        catch (...)
        {
            const auto Failure =
                RootState::FailureFromException(std::current_exception());
            State->RecordTerminalFailure(Failure);
            co_return std::unexpected(Failure);
        }
        const auto Historical = State->TerminalFailure.Load();
        if (Historical.Failed()) co_return std::unexpected(Historical);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    [[nodiscard]] auto RootSession::DrainResources(std::shared_ptr<RootState> State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        boost::system::error_code GateError;
        co_await State->DrainGate->async_receive(
            Net::redirect_error(Net::use_awaitable, GateError));
        struct DrainRelease final
        {
            std::shared_ptr<Net::experimental::concurrent_channel<
                void(boost::system::error_code)>> Gate;
            ~DrainRelease() noexcept
            {
                if (Gate) (void)Gate->try_send(boost::system::error_code{});
            }
        } Release{State->DrainGate};
        if (GateError)
        {
            co_return std::unexpected(
                Prism::Fault::FromNative(static_cast<std::error_code>(GateError)));
        }
        if (State->ResourcesRetired.load())
            co_return co_await DrainRetiredRootResources(std::move(State));
        State->ResourcesReadyForFinalization.store(false, std::memory_order_release);
        try
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            co_await Net::dispatch(State->Executor, Net::use_awaitable);
        }
        catch (...)
        {
            const auto Failure = RootState::FailureFromException(std::current_exception());
            State->RecordTerminalFailure(Failure);
            co_return std::unexpected(Failure);
        }
        bool ScopesRetired = true;
        try
        {
            const auto Children = co_await State->DrainTaskScope(State->Children);
            if (!Children) ScopesRetired = false;
        }
        catch (...)
        {
            ScopesRetired = false;
            State->RecordTerminalFailure(
                RootState::FailureFromException(std::current_exception()));
        }
        State->Loops->Seal();
        try
        {
            const auto Loops = co_await State->DrainTaskScope(State->Loops);
            if (!Loops) ScopesRetired = false;
        }
        catch (...)
        {
            ScopesRetired = false;
            State->RecordTerminalFailure(
                RootState::FailureFromException(std::current_exception()));
        }
        const auto Engine = co_await DrainRootEngine(State);
        const auto Carrier = co_await DrainRootCarrier(State, Engine.H2Retired);
        if (Carrier.Failure.Failed()) State->RecordTerminalFailure(Carrier.Failure);
        co_await Net::dispatch(State->Executor, Net::use_awaitable);
        const auto RetainedChildren = co_await DrainRetainedChildren(State, Engine.Retired);
        if (RetainedChildren.Failure.Failed())
            State->RecordTerminalFailure(RetainedChildren.Failure);
        if (!RetainedChildren.Retired)
        {
            auto Failure = State->TerminalFailure.Load();
            if (!Failure.Failed()) Failure = {Prism::Fault::Code::Blocked};
            co_return std::unexpected(Failure);
        }
        if (!ScopesRetired || !Engine.Retired || !Carrier.Retired)
        {
            auto Failure = State->TerminalFailure.Load();
            if (!Failure.Failed()) Failure = {Prism::Fault::Code::Blocked};
            State->RecordTerminalFailure(Failure);
            co_return std::unexpected(Failure);
        }
        if (State->Lifetime.Active() != 0U && !State->Lifetime.IsBlocked())
        {
            State->ResourcesReadyForFinalization.store(true, std::memory_order_release);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        if (State->Lifetime.Active() != 0U || State->Lifetime.IsBlocked())
        {
            const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
            State->RecordTerminalFailure(Failure);
            co_return std::unexpected(Failure);
        }
        try
        {
            if (!State->ReleaseResources())
            {
                const Prism::Fault::Failure Failure{Prism::Fault::Code::Blocked};
                State->RecordTerminalFailure(Failure);
                co_return std::unexpected(Failure);
            }
        }
        catch (...)
        {
            const auto Failure = RootState::FailureFromException(std::current_exception());
            State->RecordTerminalFailure(Failure);
            co_return std::unexpected(Failure);
        }
        const auto Historical = State->TerminalFailure.Load();
        if (Historical.Failed()) co_return std::unexpected(Historical);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    RootRegistry::Registration::Registration(std::atomic_uint64_t &Value) noexcept : Gate(Value)
    {
        auto Current = Gate.load(std::memory_order_acquire);
        while (!(Current & ClosedMask))
        {
            if ((Current & RegistrationMask) == RegistrationMask) return;
            if (Gate.compare_exchange_weak(Current, Current + 1U,
                    std::memory_order_acq_rel, std::memory_order_acquire))
            {
                Active = true;
                return;
            }
        }
    }

    RootRegistry::Registration::Registration(Registration &&Other) noexcept
        : Gate(Other.Gate), Active(std::exchange(Other.Active, false))
    {}

    RootRegistry::Registration::~Registration()
    {
        if (Active) Gate.fetch_sub(1U, std::memory_order_release);
    }

    RootRegistry::Registration::operator bool() const noexcept
    { return Active; }

    auto RootRegistry::State::Retire(Prism::Fault::Failure Failure) noexcept -> void
    {
        (void)HistoricalFailure.TrySet(Failure);
        CollectRetired();
    }

    auto RootRegistry::State::CollectRetired() noexcept -> void
    {
        for (;;)
        {
            std::shared_ptr<RootRegistryNode> Previous;
            auto Current = Head.load(std::memory_order_acquire);
            bool Retry = false;
            while (Current)
            {
                const auto Next = Current->Next.load(std::memory_order_acquire);
                if (Current->Owner && Current->Owner->IsRetired())
                {
                    auto Expected = Current;
                    bool Removed = false;
                    if (Previous)
                        Removed = Previous->Next.compare_exchange_weak(
                            Expected, Next, std::memory_order_acq_rel,
                            std::memory_order_acquire);
                    else
                        Removed = Head.compare_exchange_weak(
                            Expected, Next, std::memory_order_acq_rel,
                            std::memory_order_acquire);
                    if (!Removed)
                    {
                        Retry = true;
                        break;
                    }
                    Current = Next;
                    continue;
                }
                Previous = Current;
                Current = Next;
            }
            if (!Retry) return;
        }
    }

    RootRegistry::PendingRootOwner::PendingRootOwner(std::shared_ptr<RootRegistryNode> Value) noexcept
        : Node(std::move(Value))
    {}

    RootRegistry::PendingRootOwner::~PendingRootOwner()
    {
        if (!Published) Node->Owner.reset();
    }

    [[nodiscard]] auto RootRegistry::FailureFromException(std::exception_ptr Failure) noexcept
        -> Prism::Fault::Failure
    {
        try
        {
            if (Failure) std::rethrow_exception(Failure);
        }
        catch (const boost::system::system_error &Error)
        {
            return Prism::Fault::FromNative(static_cast<std::error_code>(Error.code()));
        }
        catch (const std::system_error &Error)
        {
            return Prism::Fault::FromNative(Error.code());
        }
        catch (...) { return {Prism::Fault::Code::IoError}; }
        return {Prism::Fault::Code::IoError};
    }

    RootRegistry::RootRegistry() : State_(std::make_shared<State>())
    {}

    [[nodiscard]] auto RootRegistry::BeginRegistration()
        -> std::optional<Registration>
    {
        Registration InFlight(State_->RegistrationGate);
        if (!InFlight) return {};
        return std::optional<Registration>{std::move(InFlight)};
    }

    [[nodiscard]] auto RootRegistry::Register(
        const Registration &Ticket,
        const std::shared_ptr<RootSession> &Root)
        -> bool
    {
        if (!Ticket.Active || &Ticket.Gate != &State_->RegistrationGate || !Root)
            return false;
        const auto Node = Root->RegistrationNode_;
        if (!Node) return false;
        bool Unregistered = false;
        if (!Node->Registered.compare_exchange_strong(
                Unregistered, true, std::memory_order_acq_rel,
                std::memory_order_acquire)) return false;

        PendingRootOwner OwnerGuard(Node);
        Root->SetRetirementOwner(State_);
        Node->Owner = Root;
        auto Current = State_->Head.load(std::memory_order_acquire);
        do
        {
            Node->Next.store(Current, std::memory_order_release);
        }
        while (!State_->Head.compare_exchange_weak(
            Current, Node, std::memory_order_acq_rel, std::memory_order_acquire));
        OwnerGuard.Published = true;
        Root->RegistrationNode_.reset();

        const auto Closed = IsClosed();
        if (Closed) Root->Close();
        return true;
    }

    auto RootRegistry::Close() noexcept -> void
    {
        State_->RegistrationGate.fetch_or(ClosedMask, std::memory_order_acq_rel);
        for (auto Node = State_->Head.load(std::memory_order_acquire); Node;
             Node = Node->Next.load(std::memory_order_acquire))
        {
            const auto Owner = Node->Owner;
            if (!Owner || Owner->IsRetired()) continue;
            if (Owner->WasStarted() && !Owner->IsStopping())
            {
                (void)State_->AttemptCancellation.TrySet(
                    Prism::Fault::Failure{Prism::Fault::Code::Canceled});
                Owner->Cancel();
            }
            else
            {
                Owner->Close();
            }
        }
    }

    auto RootRegistry::CloseForDrain() noexcept -> void
    {
        State_->RegistrationGate.fetch_or(ClosedMask, std::memory_order_acq_rel);
        for (auto Node = State_->Head.load(std::memory_order_acquire); Node;
             Node = Node->Next.load(std::memory_order_acquire))
        {
            const auto Owner = Node->Owner;
            if (Owner && !Owner->IsRetired()) Owner->Close();
        }
    }

    [[nodiscard]] auto RootRegistry::IsClosed() const noexcept -> bool
    {
        return (State_->RegistrationGate.load(std::memory_order_acquire) & ClosedMask) != 0U;
    }

    [[nodiscard]] auto RootRegistry::IsRetired() const noexcept -> bool
    {
        const auto Gate = State_->RegistrationGate.load(std::memory_order_acquire);
        return (Gate & ClosedMask) != 0U && (Gate & RegistrationMask) == 0U &&
            !State_->Head.load(std::memory_order_acquire);
    }

    [[nodiscard]] auto RootRegistry::DrainFailure() const noexcept -> Prism::Fault::Failure
    {
        return State_->HistoricalFailure.Load();
    }

    [[nodiscard]] auto RootRegistry::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        CloseForDrain();
        auto AttemptCancellation = std::optional<Prism::Fault::Failure>{};
        const auto Gate = State_->RegistrationGate.load(std::memory_order_acquire);
        if ((Gate & RegistrationMask) != 0U)
        {
            const auto Failure = State_->HistoricalFailure.Load();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        const auto Snapshot = State_->Head.load(std::memory_order_acquire);
        for (auto Node = Snapshot; Node;)
        {
            const auto Next = Node->Next.load(std::memory_order_acquire);
            if (Node->Owner)
            {
                try
                {
                    const auto Result = co_await Node->Owner->Drain();
                    const auto Durable = Node->Owner->HistoricalFailure();
                    if (Durable.Failed())
                        (void)State_->HistoricalFailure.TrySet(Durable);
                    else if (!Result)
                    {
                        if (Result.error().Code == Prism::Fault::Code::Canceled)
                        {
                            if (!AttemptCancellation) AttemptCancellation = Result.error();
                        }
                        else
                        {
                            (void)State_->HistoricalFailure.TrySet(Result.error());
                        }
                    }
                }
                catch (...)
                {
                    (void)State_->HistoricalFailure.TrySet(
                        FailureFromException(std::current_exception()));
                }
            }
            Node = Next;
        }
        State_->CollectRetired();
        const auto Failure = State_->HistoricalFailure.Load();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        if (!IsRetired())
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        if (AttemptCancellation) co_return std::unexpected(*AttemptCancellation);
        const auto Cancellation = State_->AttemptCancellation.Load();
        if (Cancellation.Failed()) co_return std::unexpected(Cancellation);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

} // namespace Prism::Mux::Detail

namespace Prism::Mux
{

    [[nodiscard]] auto NestedRootFactory::Create(
        Prism::Contract::MuxRootCreateRequest &Request)
        -> std::expected<std::shared_ptr<Prism::Contract::MuxSession>,
                         Prism::Fault::Failure>
    {
        if (!Options_.Services.Egress || !Options_.GenerationUseState ||
            Request.GenerationUseState() != Options_.GenerationUseState)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Created = Detail::RootSession::Create(Request, Options_);
        if (!Created) return std::unexpected(Created.error());
        return std::static_pointer_cast<Prism::Contract::MuxSession>(
            std::move(*Created));
    }

    [[nodiscard]] auto RootBinding::Create(Prism::Contract::MuxRootCreateRequest Request)
        -> std::expected<RootCreateResult, Prism::Fault::Failure>
    {
        // 仅持有本 registry 的活动登记票据时才能创建并发布 root；否则由 Request 原 owner 退休。
        auto Registration = Roots_.BeginRegistration();
        if (!Registration)
        {
            // 不向已封止目录迟到发布 root；Request 析构将资源交还既有退休 owner。
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }

        const auto Options = Options_.load(std::memory_order_acquire);
        if (!Options || !Options->Services.Egress ||
            !Options->GenerationUseState)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }
        if (Request.GenerationUseState() != Options->GenerationUseState)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }

        auto Created = Detail::RootSession::Create(Request, *Options);
        if (!Created) return std::unexpected(Created.error());
        if (!Roots_.Register(*Registration, *Created))
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Canceled});
        }

        auto Plane = Request.TakePlane();
        Request.Transfer();
        return RootCreateResult{
            std::static_pointer_cast<Prism::Contract::MuxSession>(
                std::move(*Created)),
            std::move(Plane)};
    }

    [[nodiscard]] auto RootBinding::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Result = co_await Roots_.Drain();
        if (Roots_.IsRetired()) Options_.store({}, std::memory_order_release);
        if (!Result) co_return std::unexpected(Result.error());
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

}

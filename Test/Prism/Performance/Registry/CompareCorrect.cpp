/**
 * @file CompareCorrect.cpp
 * @brief 注册表 trace 回放与 quiescent 合同检查实现。
 */

#include "CompareCorrect.hpp"

#include "CompareTrace.hpp"

#include <exception>
#include <memory>
#include <stdexcept>
#include <thread>

namespace Prism::Runtime::Perf
{

    auto MarkInvalid(Statistics &Stats, std::atomic<bool> &Invalid,
                     const InvalidReason Reason) -> void
    {
        ++Stats.Invalid;
        ++Stats.InvalidReasons[static_cast<std::size_t>(Reason)];
        Invalid.store(true, std::memory_order_release);
    }

    auto MixOperation(Statistics &Stats, const TraceOperation &Operation,
                      const std::uint64_t Result) -> void
    {
        Mix(Stats.Checksum, static_cast<std::uint64_t>(Operation.Operation) + 1);
        Mix(Stats.Checksum, Operation.Id);
        Mix(Stats.Checksum, Operation.Value);
        Mix(Stats.Checksum, Result);
    }

    namespace
    {

        auto ApplyRegister(const TraceOperation &Operation, ExecutionContext &Context) -> void
        {
            auto &Lane = Context.Lane;
            auto &Stats = Context.Stats;
            const auto Active = Lane.Active.find(Operation.Id) != Lane.Active.end();
            const auto ShouldSucceed = !Lane.Shutdown && !Active;
            const auto TokenValue = Context.Model.Register(MakeInfo(Operation.Id, Operation.Value));
            const auto Succeeded = static_cast<bool>(TokenValue);
            if ((Operation.CheckResult && Succeeded != Operation.ExpectedResult) ||
                Succeeded != ShouldSucceed)
            {
                MarkInvalid(Stats, Context.Invalid, InvalidReason::RegisterResult);
            }
            if (Succeeded)
            {
                Lane.Active[Operation.Id] = TokenValue;
                Lane.Expected[Operation.Id] = MakeInfo(Operation.Id, Operation.Value);
                ++Stats.Registers;
            }
            MixOperation(Stats, Operation, Succeeded ? 1 : 0);
        }

        auto ApplyFind(const TraceOperation &Operation, ExecutionContext &Context) -> void
        {
            auto &Stats = Context.Stats;
            const auto &Lane = Context.Lane;
            const auto ExpectedIt = Lane.Expected.find(Operation.Id);
            const auto Active = Lane.Active.find(Operation.Id) != Lane.Active.end();
            const auto ExpectedResult = !Lane.Shutdown && Active;
            SessionInfo Output;
            const auto Succeeded = Context.Model.Find(Operation.Id, Output);
            if ((Operation.CheckResult && Succeeded != Operation.ExpectedResult) ||
                Succeeded != ExpectedResult ||
                (Succeeded && (ExpectedIt == Lane.Expected.end() ||
                               !SameInfo(Output, ExpectedIt->second))))
            {
                MarkInvalid(Stats, Context.Invalid, InvalidReason::FindResult);
            }
            ++Stats.Finds;
            Stats.FindHits += Succeeded ? 1 : 0;
            MixOperation(Stats, Operation, Succeeded ? 1 : 0);
            if (Succeeded)
            {
                Mix(Stats.Checksum, Output.StartedAt);
            }
        }

        auto ApplySize(const TraceOperation &Operation, ExecutionContext &Context) -> void
        {
            const auto Size = Context.Model.Size();
            if (Size > Context.MaxSessions)
            {
                MarkInvalid(Context.Stats, Context.Invalid, InvalidReason::SizeExceeded);
            }
            MixOperation(Context.Stats, Operation, Size);
        }

        auto ApplySnapshot(const TraceOperation &Operation, ExecutionContext &Context) -> void
        {
            const auto Snapshot = Context.Model.Snapshot();
            for (const auto &[Id, Info] : Snapshot)
            {
                if (Id != Info.Id || Info.identity.empty() || Info.Target.empty())
                {
                    MarkInvalid(Context.Stats, Context.Invalid, InvalidReason::SnapshotValue);
                    break;
                }
            }
            ++Context.Stats.Snapshots;
            Mix(Context.Stats.SnapshotChecksum, HashSnapshot(Snapshot));
            MixOperation(Context.Stats, Operation, Snapshot.size());
            Context.CapturedSnapshot = Snapshot;
        }

        auto ApplyCancel(const TraceOperation &Operation, ExecutionContext &Context) -> void
        {
            const auto &Lane = Context.Lane;
            const auto Active = Lane.Active.find(Operation.Id) != Lane.Active.end();
            const auto ExpectedResult = !Lane.Shutdown && Active;
            const auto Succeeded = Context.Model.Cancel(Operation.Id);
            if ((Operation.CheckResult && Succeeded != Operation.ExpectedResult) ||
                Succeeded != ExpectedResult)
            {
                MarkInvalid(Context.Stats, Context.Invalid, InvalidReason::CancelResult);
            }
            ++Context.Stats.Cancels;
            MixOperation(Context.Stats, Operation, Succeeded ? 1 : 0);
        }

        auto ApplyReset(const TraceOperation &Operation, ExecutionContext &Context) -> void
        {
            auto &Lane = Context.Lane;
            const auto ActiveIt = Lane.Active.find(Operation.Id);
            const auto Active = ActiveIt != Lane.Active.end();
            const auto ExpectedResult = !Lane.Shutdown && Active;
            const auto TokenValue = Active ? ActiveIt->second : Token{};
            const auto Succeeded = Context.Model.Reset(TokenValue);
            if ((Operation.CheckResult && Succeeded != Operation.ExpectedResult) ||
                Succeeded != ExpectedResult)
            {
                MarkInvalid(Context.Stats, Context.Invalid, InvalidReason::ResetResult);
            }
            if (Succeeded)
            {
                if (Context.CapturedSnapshot)
                {
                    const auto It = Context.CapturedSnapshot->find(Operation.Id);
                    if (It != Context.CapturedSnapshot->end() &&
                        (It->second.Id != Operation.Id || It->second.identity.empty()))
                    {
                        MarkInvalid(Context.Stats, Context.Invalid,
                                    InvalidReason::SnapshotIsolation);
                    }
                }
                Lane.Active.erase(Operation.Id);
                Lane.Expected.erase(Operation.Id);
                ++Context.Stats.Resets;
            }
            MixOperation(Context.Stats, Operation, Succeeded ? 1 : 0);
        }

        auto ApplyRetireForReuse(const TraceOperation &Operation,
                                 ExecutionContext &Context) -> void
        {
            auto &Lane = Context.Lane;
            const auto ActiveIt = Lane.Active.find(Operation.Id);
            if (ActiveIt == Lane.Active.end() || Lane.Shutdown)
            {
                MarkInvalid(Context.Stats, Context.Invalid, InvalidReason::RetireResult);
                return;
            }
            const auto TokenValue = ActiveIt->second;
            Lane.Stale[Operation.Id] = TokenValue;
            if (!Context.Model.Reset(TokenValue))
            {
                MarkInvalid(Context.Stats, Context.Invalid, InvalidReason::RetireResult);
            }
            Lane.Active.erase(Operation.Id);
            Lane.Expected.erase(Operation.Id);
            MixOperation(Context.Stats, Operation, 1);
        }

        auto ApplyStaleHook(const TraceOperation &Operation, ExecutionContext &Context) -> void
        {
            const auto It = Context.Lane.Stale.find(Operation.Id);
            if (It == Context.Lane.Stale.end() || !It->second || !It->second->Hooks.Error ||
                !It->second->Hooks.Metrics)
            {
                MarkInvalid(Context.Stats, Context.Invalid, InvalidReason::HookShape);
                return;
            }
            It->second->Hooks.Error();
            It->second->Hooks.Metrics();
            MixOperation(Context.Stats, Operation, 1);
        }

        auto ApplyActiveHook(const TraceOperation &Operation, ExecutionContext &Context) -> void
        {
            const auto It = Context.Lane.Active.find(Operation.Id);
            if (It == Context.Lane.Active.end() || !It->second || !It->second->Hooks.Error ||
                !It->second->Hooks.Metrics)
            {
                MarkInvalid(Context.Stats, Context.Invalid, InvalidReason::HookShape);
                return;
            }
            It->second->Hooks.Error();
            It->second->Hooks.Metrics();
            MixOperation(Context.Stats, Operation, 1);
        }

        auto ApplyPending(const TraceOperation &Operation, ExecutionContext &Context) -> void
        {
            const auto Pending = Context.Model.PendingRemovals();
            if (Operation.CheckResult && (Pending != 0) != Operation.ExpectedResult)
            {
                MarkInvalid(Context.Stats, Context.Invalid, InvalidReason::PendingResult);
            }
            MixOperation(Context.Stats, Operation, Pending);
        }

    } // namespace

    auto Apply(const TraceOperation &Operation, ExecutionContext &Context) -> void
    {
        switch (Operation.Operation)
        {
        case TraceOperation::Kind::Register:
            ApplyRegister(Operation, Context);
            break;
        case TraceOperation::Kind::Find:
            ApplyFind(Operation, Context);
            break;
        case TraceOperation::Kind::Size:
            ApplySize(Operation, Context);
            break;
        case TraceOperation::Kind::Snapshot:
            ApplySnapshot(Operation, Context);
            break;
        case TraceOperation::Kind::Cancel:
            ApplyCancel(Operation, Context);
            break;
        case TraceOperation::Kind::Reset:
            ApplyReset(Operation, Context);
            break;
        case TraceOperation::Kind::RetireForReuse:
            ApplyRetireForReuse(Operation, Context);
            break;
        case TraceOperation::Kind::EmitStale:
            ApplyStaleHook(Operation, Context);
            break;
        case TraceOperation::Kind::EmitActive:
            ApplyActiveHook(Operation, Context);
            break;
        case TraceOperation::Kind::FailCompaction:
            Context.Model.FailNextCompaction(Operation.Id);
            MixOperation(Context.Stats, Operation, 1);
            break;
        case TraceOperation::Kind::ObservePending:
            ApplyPending(Operation, Context);
            break;
        case TraceOperation::Kind::Shutdown:
            Context.Model.Shutdown();
            Context.Lane.Shutdown = true;
            MixOperation(Context.Stats, Operation, 1);
            break;
        }
        ++Context.Stats.Operations;
    }

    namespace
    {

        auto FinishProbe(const Statistics &Stats, const std::atomic<bool> &Invalid,
                         const HookCounts Hooks) -> ProbeResult
        {
            ProbeResult Result;
            Result.Valid = !Invalid.load(std::memory_order_acquire);
            Result.Hooks = Hooks;
            Result.InvalidReasons = Stats.InvalidReasons;
            return Result;
        }

        auto MarkContractFailure(Statistics &Stats, std::atomic<bool> &Invalid,
                                 const InvalidReason Reason) -> void
        {
            MarkInvalid(Stats, Invalid, Reason);
        }

    } // namespace

    auto RunProbe(IModel &Model, const Trace &TraceValue, const std::size_t MaxSessions)
        -> ProbeResult
    {
        LaneState Lane;
        Statistics Stats;
        std::atomic<bool> Invalid{false};
        ExecutionContext Context{Model, Lane, Stats, Invalid, MaxSessions};
        for (const auto &Operation : TraceValue.Probe)
        {
            Apply(Operation, Context);
        }
        const auto Hooks = Model.HookSnapshot();
        if (Hooks.Errors != 1 || Hooks.Metrics != 1)
        {
            MarkInvalid(Stats, Invalid, InvalidReason::HookShape);
        }
        return FinishProbe(Stats, Invalid, Hooks);
    }

    auto RunDirectedContracts(IModel &Model) -> ProbeResult
    {
        Statistics Stats;
        std::atomic<bool> Invalid{false};

        Model.FailNextHookInstallation();
        Token Failed;
        try
        {
            Failed = Model.Register(MakeInfo(1001, 1));
        }
        catch (...)
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::HookInstallFailure);
        }
        if (Failed || Model.Size() != 0 || Model.PendingRemovals() != 0)
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::HookInstallFailure);
        }
        const auto BeforeFailedHook = Model.HookSnapshot();
        const auto FailedHookAvailable = Model.EmitFailedErrorHook();
        const auto AfterFailedHook = Model.HookSnapshot();
        if (!FailedHookAvailable || AfterFailedHook.Errors != BeforeFailedHook.Errors ||
            AfterFailedHook.Metrics != BeforeFailedHook.Metrics)
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::HookInstallFailure);
        }

        const auto OldInfo = MakeInfo(1, 10);
        const auto NewInfo = MakeInfo(1, 20);
        const auto Old = Model.Register(OldInfo);
        const auto OldSnapshot = Model.Snapshot();
        if (!Old || !Model.Reset(Old))
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::RetireResult);
            return FinishProbe(Stats, Invalid, Model.HookSnapshot());
        }
        const auto New = Model.Register(NewInfo);
        if (!New)
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::RegisterResult);
            return FinishProbe(Stats, Invalid, Model.HookSnapshot());
        }
        if (Model.Reset(Old))
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::StaleHook);
        }

        SessionInfo CurrentInfo;
        const auto CurrentSnapshot = Model.Snapshot();
        if (!Model.Find(1, CurrentInfo) || !SameInfo(CurrentInfo, NewInfo) ||
            OldSnapshot.find(1) == OldSnapshot.end() ||
            !SameInfo(OldSnapshot.at(1), OldInfo))
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::SnapshotIsolation);
        }
        if (CurrentSnapshot.find(1) == CurrentSnapshot.end() ||
            !SameInfo(CurrentSnapshot.at(1), NewInfo))
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::SnapshotIsolation);
        }

        const auto BeforeStaleHook = Model.HookSnapshot();
        if (Old->Hooks.Error)
        {
            Old->Hooks.Error();
        }
        if (Old->Hooks.Metrics)
        {
            Old->Hooks.Metrics();
        }
        const auto AfterStaleHook = Model.HookSnapshot();
        if (AfterStaleHook.Errors != BeforeStaleHook.Errors ||
            AfterStaleHook.Metrics != BeforeStaleHook.Metrics)
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::StaleHook);
        }

        if (!New->Hooks.Error)
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::HookShape);
            return FinishProbe(Stats, Invalid, Model.HookSnapshot());
        }
        const auto Gate = std::make_shared<HookGate>();
        Gate->Arm();
        Model.SetHookGate(Gate);
        const auto BeforeInFlight = Model.HookSnapshot();
        std::thread HookThread([New] { New->Hooks.Error(); });
        if (!Gate->WaitUntilEntered())
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::InFlightHook);
        }
        if (!Model.Reset(New))
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::InFlightHook);
        }
        Gate->Release();
        HookThread.join();
        Model.SetHookGate({});
        const auto AfterInFlight = Model.HookSnapshot();
        if (AfterInFlight.Errors != BeforeInFlight.Errors + 1 ||
            AfterInFlight.Metrics != BeforeInFlight.Metrics)
        {
            MarkContractFailure(Stats, Invalid, InvalidReason::InFlightHook);
        }
        return FinishProbe(Stats, Invalid, AfterInFlight);
    }

    auto Setup(IModel &Model, const Options &Settings,
               std::array<LaneState, CompareLaneCount> &Lanes) -> void
    {
        for (std::size_t Id = 1; Id <= Settings.ActiveSessions; ++Id)
        {
            const auto Lane = (Id - 1) % CompareLaneCount;
            const auto Info = MakeInfo(Id, 0);
            const auto TokenValue = Model.Register(Info);
            if (!TokenValue)
            {
                throw std::runtime_error("initial Register failed");
            }
            Lanes[Lane].Active.emplace(Id, TokenValue);
            Lanes[Lane].Expected.emplace(Id, Info);
        }
        if (Model.Size() != Settings.ActiveSessions)
        {
            throw std::runtime_error("initial Size differs from active sessions");
        }
    }

    auto ExpectedSnapshot(const std::array<LaneState, CompareLaneCount> &Lanes)
        -> SnapshotMap
    {
        SnapshotMap Result;
        for (const auto &Lane : Lanes)
        {
            for (const auto &[Id, Info] : Lane.Expected)
            {
                Result.emplace(Id, Info);
            }
        }
        return Result;
    }

    auto SameSnapshot(const SnapshotMap &Left, const SnapshotMap &Right) -> bool
    {
        if (Left.size() != Right.size())
        {
            return false;
        }
        auto LeftIt = Left.begin();
        auto RightIt = Right.begin();
        while (LeftIt != Left.end())
        {
            if (LeftIt->first != RightIt->first ||
                !SameInfo(LeftIt->second, RightIt->second))
            {
                return false;
            }
            ++LeftIt;
            ++RightIt;
        }
        return true;
    }

} // namespace Prism::Runtime::Perf

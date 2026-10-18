/**
 * @file SessionRegistryCompareTrace.cpp
 * @brief 会话注册表 trace 生成与值语义校验。
 */

#include "SessionRegistryCompareTrace.hpp"

#include <array>
#include <random>
#include <string>
#include <unordered_map>

namespace Prism::Runtime::Perf
{

    auto Mix(std::uint64_t &Hash, const std::uint64_t Value) -> void
    {
        Hash ^= Value;
        Hash *= 1099511628211ull;
    }

    namespace
    {

        constexpr std::size_t LaneCount = 4;
        auto MixText(std::uint64_t &Hash, const std::string &Value) -> void
        {
            for (const auto Character : Value)
            {
                Mix(Hash, static_cast<std::uint8_t>(Character));
            }
        }

        auto OperationValue(const TraceOperation::Kind Operation) -> std::uint64_t
        {
            return static_cast<std::uint64_t>(Operation) + 1;
        }

        auto MixOperation(std::uint64_t &Hash, const TraceOperation &Operation) -> void
        {
            Mix(Hash, OperationValue(Operation.Operation));
            Mix(Hash, Operation.Id);
            Mix(Hash, Operation.Value);
            Mix(Hash, Operation.Lane);
            Mix(Hash, Operation.CheckResult ? 1 : 0);
            Mix(Hash, Operation.ExpectedResult ? 1 : 0);
        }

        auto AppendProbe(Trace &Result, const TraceOperation &Operation) -> void
        {
            Result.Probe.push_back(Operation);
            MixOperation(Result.Hash, Operation);
        }

        auto AppendWork(Trace &Result, const TraceOperation &Operation) -> void
        {
            Result.Work.push_back(Operation);
            MixOperation(Result.Hash, Operation);
        }

        auto AddProbe(Trace &Result, const TraceOperation &Operation) -> void
        {
            AppendProbe(Result, Operation);
        }

        auto MakeProbe(Trace &Result) -> void
        {
            AddProbe(Result, {TraceOperation::Kind::Register, 1, 1, 0, true, true});
            AddProbe(Result, {TraceOperation::Kind::Register, 2, 2, 0, true, true});
            AddProbe(Result, {TraceOperation::Kind::RetireForReuse, 1, 0, 0, false, false});
            AddProbe(Result, {TraceOperation::Kind::Register, 1, 3, 0, true, true});
            AddProbe(Result, {TraceOperation::Kind::EmitStale, 1, 0, 0, false, false});
            AddProbe(Result, {TraceOperation::Kind::EmitActive, 1, 0, 0, false, false});
            AddProbe(Result, {TraceOperation::Kind::FailCompaction, 2, 0, 0, false, false});
            AddProbe(Result, {TraceOperation::Kind::Reset, 2, 0, 0, true, true});
            AddProbe(Result, {TraceOperation::Kind::ObservePending, 0, 0, 0, true, true});
            AddProbe(Result, {TraceOperation::Kind::Register, 2, 4, 0, true, true});
            AddProbe(Result, {TraceOperation::Kind::Find, 2, 0, 0, true, true});
            AddProbe(Result, {TraceOperation::Kind::Snapshot, 0, 0, 0, false, false});
            AddProbe(Result, {TraceOperation::Kind::Cancel, 2, 0, 0, true, true});
            AddProbe(Result, {TraceOperation::Kind::Reset, 2, 0, 0, true, true});
            AddProbe(Result, {TraceOperation::Kind::Shutdown, 0, 0, 0, false, false});
            AddProbe(Result, {TraceOperation::Kind::Register, 3, 5, 0, true, false});
        }

    } // namespace

    auto MakeInfo(const std::uint64_t Id, const std::uint64_t Value) -> SessionInfo
    {
        SessionInfo Info;
        Info.Id = Id;
        Info.AccountId = Prism::AccountId{Id};
        Info.identity = "user-" + std::to_string(Id) + "-" + std::to_string(Value);
        Info.peer = "peer-" + std::to_string(Id % 251) + ":" +
                    std::to_string(1000 + Value % 100);
        Info.Target = "target-" + std::to_string(Id) + ".example:443";
        Info.Protocol = static_cast<std::uint16_t>(1 + Value % 7);
        Info.StartedAt = Id * 1000 + Value;
        return Info;
    }

    auto SameInfo(const SessionInfo &Left, const SessionInfo &Right) -> bool
    {
        return Left.Id == Right.Id && Left.AccountId == Right.AccountId &&
               Left.identity == Right.identity && Left.peer == Right.peer &&
               Left.Target == Right.Target && Left.Protocol == Right.Protocol &&
               Left.StartedAt == Right.StartedAt;
    }

    auto HashSnapshot(const SnapshotMap &Snapshot) -> std::uint64_t
    {
        std::uint64_t Hash = 14695981039346656037ull;
        for (const auto &[Id, Info] : Snapshot)
        {
            Mix(Hash, Id);
            Mix(Hash, Info.Id);
            Mix(Hash, Info.AccountId.Value());
            MixText(Hash, Info.identity);
            MixText(Hash, Info.peer);
            MixText(Hash, Info.Target);
            Mix(Hash, Info.Protocol);
            Mix(Hash, Info.StartedAt);
        }
        return Hash;
    }

    auto MakeTrace(const Options &Settings) -> Trace
    {
        Trace Result;
        Mix(Result.Hash, Settings.ActiveSessions);
        Mix(Result.Hash, Settings.OperationsPerLane);
        Mix(Result.Hash, Settings.Seed);
        Mix(Result.Hash, static_cast<std::uint64_t>(Settings.Workload));
        for (std::size_t Id = 1; Id <= Settings.ActiveSessions; ++Id)
        {
            Mix(Result.Hash, Id);
            Mix(Result.Hash, (Id - 1) % LaneCount);
            const auto Info = MakeInfo(Id, 0);
            Mix(Result.Hash, Info.Id);
            MixText(Result.Hash, Info.identity);
        }
        MakeProbe(Result);

        std::array<std::vector<std::uint64_t>, LaneCount> LaneIds;
        std::array<std::unordered_map<std::uint64_t, bool>, LaneCount> Active;
        for (std::size_t Id = 1; Id <= Settings.ActiveSessions; ++Id)
        {
            const auto Lane = (Id - 1) % LaneCount;
            LaneIds[Lane].push_back(Id);
            Active[Lane].emplace(Id, true);
        }

        for (std::size_t Round = 0; Round < Settings.OperationsPerLane; ++Round)
        {
            for (std::size_t Lane = 0; Lane < LaneCount; ++Lane)
            {
                std::mt19937_64 Random(
                    Settings.Seed + 0x9E3779B97F4A7C15ull * (Lane + 1) +
                    Round * 0xD1B54A32D192ED03ull);
                const auto &Ids = LaneIds[Lane];
                const auto Id = Ids[Random() % Ids.size()];
                const auto IsActive = Active[Lane].at(Id);
                auto Operation = TraceOperation::Kind::Find;
                if (!IsActive)
                {
                    Operation = TraceOperation::Kind::Register;
                    Active[Lane][Id] = true;
                }
                else
                {
                    const auto Choice = Random() % 100;
                    const auto ReadHeavy = Settings.Workload == WorkloadKind::ReadHeavy;
                    if ((ReadHeavy && Choice < 65) || (!ReadHeavy && Choice < 25))
                    {
                        Operation = TraceOperation::Kind::Find;
                    }
                    else if ((ReadHeavy && Choice < 75) || (!ReadHeavy && Choice < 35))
                    {
                        Operation = TraceOperation::Kind::Snapshot;
                    }
                    else if ((ReadHeavy && Choice < 83) || (!ReadHeavy && Choice < 45))
                    {
                        Operation = TraceOperation::Kind::Size;
                    }
                    else if ((ReadHeavy && Choice < 92) || (!ReadHeavy && Choice < 65))
                    {
                        Operation = TraceOperation::Kind::Cancel;
                    }
                    else
                    {
                        Operation = TraceOperation::Kind::Reset;
                        Active[Lane][Id] = false;
                    }
                }
                AppendWork(Result, TraceOperation{Operation, Id, Round + 1000,
                                                  Lane, false, false});
            }
        }
        return Result;
    }

} // namespace Prism::Runtime::Perf

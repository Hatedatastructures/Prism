/**
 * @file TaskIdSetCompare.cpp
 * @brief 对比旧 std::set 快照与 Lifecycle TaskIdSet 的并发发布成本。
 */
#include <Prism/Lifecycle/TaskIdSet.hpp>
#include "TaskIdSetMeasurement.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <latch>
#include <limits>
#include <memory>
#include <set>
#include <thread>
#include <utility>
#include <vector>
namespace Prism::Lifecycle::Perf
{
    using PersistentSet = Prism::Lifecycle::Detail::TaskIdSet; using Clock = std::chrono::steady_clock;
    inline constexpr std::size_t RoundCount = 5;
    inline constexpr std::uint64_t FnvOffset = 14695981039346656037ull; inline constexpr std::uint64_t FnvPrime = 1099511628211ull;
    enum class Variant
    {
        StdSet,
        TaskIdSet
    };
    enum class OperationKind
    {
        Insert,
        DuplicateInsert,
        Contains,
        Erase,
        ContainsAfterErase,
        DuplicateErase
    };
    enum class Phase
    {
        Reserve,
        Lookup,
        Release
    };
    struct Operation final
    {
        OperationKind Kind{OperationKind::Contains}; std::uint64_t Id{0};
        std::size_t Lane{0}; bool Expected{false}; Phase PhaseValue{Phase::Reserve};
    };
    struct Trace final
    {
        std::size_t IdCount{0};
        std::size_t OwnerCount{0};
        std::vector<Operation> Operations;
        std::uint64_t Hash{FnvOffset};
    };
    struct WorkerStats final
    {
        std::uint64_t Operations{0};
        std::uint64_t InsertsAccepted{0};
        std::uint64_t InsertsRejected{0};
        std::uint64_t ContainsHits{0};
        std::uint64_t ContainsMisses{0};
        std::uint64_t ErasesAccepted{0};
        std::uint64_t ErasesRejected{0};
        std::uint64_t CasPublishes{0};
        std::uint64_t CasRetries{0};
        std::uint64_t ImmutableChecks{0};
        std::uint64_t LocalRetainedChecks{0};
        std::uint64_t Errors{0};
        std::vector<std::weak_ptr<const std::set<std::uint64_t>>> OldStdSnapshots;
        std::vector<std::weak_ptr<const PersistentSet>> OldTaskSnapshots;
    };
    struct SampleResult final
    {
        Variant Model{Variant::StdSet}; std::size_t IdCount{0};
        std::size_t OwnerCount{0}; std::size_t Round{0};
        std::uint64_t TraceHash{0};
        std::uint64_t Operations{0};
        std::uint64_t CasPublishes{0};
        std::uint64_t CasRetries{0};
        std::uint64_t P50{0};
        std::uint64_t P95{0};
        std::uint64_t P99{0};
        std::uint64_t PeakGlobal{0};
        std::uint64_t PeakLocalSum{0};
        std::uint64_t PeakLocalMax{0};
        std::uint64_t ReserveNs{0};
        std::uint64_t LookupNs{0};
        std::uint64_t ReleaseNs{0};
        bool LocalRetireValid{false};
        MeasurementResult Measurement{};
        std::size_t Errors{0};
        bool Valid{false};
    };
    auto Mix(std::uint64_t &Hash, const std::uint64_t Value) -> void
    {
        Hash ^= Value;
        Hash *= FnvPrime;
    }
    auto VariantName(const Variant Value) -> const char *
    {
        return Value == Variant::StdSet ? "std-set" : "task-id-set";
    }
    auto OperationValue(const OperationKind Kind) -> std::uint64_t
    {
        return static_cast<std::uint64_t>(Kind) + 1U;
    }
    auto AppendOperation(Trace &Result, const Operation &Value) -> void
    {
        Result.Operations.push_back(Value);
        Mix(Result.Hash, OperationValue(Value.Kind));
        Mix(Result.Hash, Value.Id);
        Mix(Result.Hash, Value.Lane);
        Mix(Result.Hash, static_cast<std::uint64_t>(Value.PhaseValue));
        Mix(Result.Hash, Value.Expected ? 1U : 0U);
    }
    auto BuildTrace(const std::size_t IdCount, const std::size_t LaneCountValue) -> Trace
    {
        Trace Result;
        Result.IdCount = IdCount;
        Result.OwnerCount = LaneCountValue;
        Result.Operations.reserve(IdCount * 6U);
        const std::array<std::array<OperationKind, 3>, 3> PhaseOperations{
            std::array<OperationKind, 3>{OperationKind::Insert, OperationKind::Contains,
                                         OperationKind::Contains},
            std::array<OperationKind, 3>{OperationKind::DuplicateInsert,
                                         OperationKind::Contains, OperationKind::Contains},
            std::array<OperationKind, 3>{OperationKind::Erase,
                                         OperationKind::ContainsAfterErase,
                                         OperationKind::DuplicateErase}};
        for (std::size_t PhaseIndex = 0; PhaseIndex < PhaseOperations.size(); ++PhaseIndex)
        {
            const auto PhaseValue = static_cast<Phase>(PhaseIndex);
            const auto &Kinds = PhaseOperations[PhaseIndex];
            const auto KindCount = PhaseIndex == 0 ? 1U : PhaseIndex == 1 ? 2U : 3U;
            for (std::uint64_t Id = 1; Id <= IdCount; ++Id)
            {
                const auto Lane = static_cast<std::size_t>((Id - 1U) % LaneCountValue);
                for (std::size_t KindIndex = 0; KindIndex < KindCount; ++KindIndex)
                {
                    const auto Kind = Kinds[KindIndex];
                    const auto Expected = Kind == OperationKind::Insert ||
                        Kind == OperationKind::Contains || Kind == OperationKind::Erase;
                    AppendOperation(Result, Operation{Kind, Id, Lane, Expected, PhaseValue});
                }
            }
        }
        return Result;
    }
    template <typename Set>
    auto ContainsValue(const Set &Value, const std::uint64_t Id) -> bool;
    auto ContainsValue(const std::set<std::uint64_t> &Value, const std::uint64_t Id) -> bool
    {
        return Value.contains(Id);
    }
    auto ContainsValue(const PersistentSet &Value, const std::uint64_t Id) -> bool
    {
        return Value.Contains(Id);
    }
    auto InsertValue(std::set<std::uint64_t> &Value, const std::uint64_t Id) -> bool
    {
        return Value.insert(Id).second;
    }
    auto InsertValue(PersistentSet &Value, const std::uint64_t Id) -> bool
    {
        return Value.Insert(Id);
    }
    auto EraseValue(std::set<std::uint64_t> &Value, const std::uint64_t Id) -> bool
    {
        return Value.erase(Id) != 0;
    }
    auto EraseValue(PersistentSet &Value, const std::uint64_t Id) -> bool
    {
        return Value.Erase(Id);
    }
    auto SizeValue(const std::set<std::uint64_t> &Value) -> std::size_t
    {
        return Value.size();
    }
    auto SizeValue(const PersistentSet &Value) -> std::size_t
    {
        return Value.Size();
    }
    template <typename Set, typename Callback>
    auto ForEachValue(const Set &Value, Callback CallbackValue) -> void
    {
        Value.ForEach(std::move(CallbackValue));
    }
    template <typename Callback>
    auto ForEachValue(const std::set<std::uint64_t> &Value, Callback CallbackValue) -> void
    {
        for (const auto Id : Value)
        {
            CallbackValue(Id);
        }
    }
    auto RecordOldSnapshot(
        WorkerStats &Stats,
        const std::shared_ptr<const std::set<std::uint64_t>> &Snapshot) -> void
    {
        Stats.OldStdSnapshots.push_back(Snapshot);
    }
    auto RecordOldSnapshot(
        WorkerStats &Stats, const std::shared_ptr<const PersistentSet> &Snapshot) -> void
    {
        Stats.OldTaskSnapshots.push_back(Snapshot);
    }
    template <typename Set>
    struct SnapshotOwner final
    {
        std::atomic<std::shared_ptr<const Set>> Snapshot{std::make_shared<const Set>()};
    };
    template <typename Set>
    class SnapshotModel final
    {
    public:
        explicit SnapshotModel(const std::size_t OwnerCount)
        {
            Owners_.reserve(OwnerCount);
            LocalRetired_.reserve(OwnerCount);
            for (std::size_t Index = 0; Index < OwnerCount; ++Index)
            {
                Owners_.push_back(std::make_unique<SnapshotOwner<Set>>());
            }
        }
        [[nodiscard]] auto Snapshot(const std::size_t Owner) const
            -> std::shared_ptr<const Set>
        {
            return Owners_[Owner]->Snapshot.load(std::memory_order_acquire);
        }
        [[nodiscard]] auto GlobalSnapshot() const -> std::shared_ptr<const Set>
        {
            return Global_.load(std::memory_order_acquire);
        }
        [[nodiscard]] auto OwnerCount() const noexcept -> std::size_t
        {
            return Owners_.size();
        }
        auto RecordPeak() -> void
        {
            const auto Global = GlobalSnapshot();
            std::size_t LocalSum = 0;
            std::size_t LocalMax = 0;
            for (std::size_t Owner = 0; Owner < OwnerCount(); ++Owner)
            {
                const auto Local = Snapshot(Owner);
                const auto Size = SizeValue(*Local);
                LocalSum += Size;
                LocalMax = (std::max)(LocalMax, Size);
            }
            PeakGlobal_.store(SizeValue(*Global), std::memory_order_release);
            PeakLocalSum_.store(LocalSum, std::memory_order_release);
            PeakLocalMax_.store(LocalMax, std::memory_order_release);
        }
        [[nodiscard]] auto PeakGlobal() const noexcept -> std::uint64_t
        {
            return PeakGlobal_.load(std::memory_order_acquire);
        }
        [[nodiscard]] auto PeakLocalSum() const noexcept -> std::uint64_t
        {
            return PeakLocalSum_.load(std::memory_order_acquire);
        }
        [[nodiscard]] auto PeakLocalMax() const noexcept -> std::uint64_t
        {
            return PeakLocalMax_.load(std::memory_order_acquire);
        }
        auto RetireLocals(const std::size_t TotalIds) -> void
        {
            bool Valid = true;
            std::size_t Sum = 0;
            for (std::size_t Owner = 0; Owner < OwnerCount(); ++Owner)
            {
                const auto Expected = (TotalIds + OwnerCount() - 1U - Owner) / OwnerCount();
                const auto Current = Snapshot(Owner);
                const auto Size = SizeValue(*Current);
                Valid = Valid && Size == Expected;
                Sum += Size;
            }
            Valid = Valid && Sum == TotalIds;
            for (std::size_t Owner = 0; Owner < OwnerCount(); ++Owner)
            {
                LocalRetired_.push_back(Snapshot(Owner));
                Owners_[Owner]->Snapshot.store(std::make_shared<const Set>(),
                                               std::memory_order_release);
            }
            LocalRetireValid_.store(Valid, std::memory_order_release);
        }
        [[nodiscard]] auto LocalRetireValid() const noexcept -> bool
        {
            return LocalRetireValid_.load(std::memory_order_acquire);
        }
        [[nodiscard]] auto LocalRetiredExpired() const noexcept -> bool
        {
            for (const auto &Weak : LocalRetired_)
            {
                if (!Weak.expired()) return false;
            }
            return true;
        }
        [[nodiscard]] auto Publish(const std::size_t Owner,
                                   std::shared_ptr<const Set> &Current,
                                   std::shared_ptr<Set> Next) -> bool
        {
            return Owners_[Owner]->Snapshot.compare_exchange_weak(
                Current, std::shared_ptr<const Set>(std::move(Next)),
                std::memory_order_acq_rel, std::memory_order_acquire);
        }
        [[nodiscard]] auto PublishGlobal(std::shared_ptr<const Set> &Current,
                                         std::shared_ptr<Set> Next) -> bool
        {
            return Global_.compare_exchange_weak(
                Current, std::shared_ptr<const Set>(std::move(Next)),
                std::memory_order_acq_rel, std::memory_order_acquire);
        }
    private:
        std::vector<std::unique_ptr<SnapshotOwner<Set>>> Owners_;
        std::atomic<std::shared_ptr<const Set>> Global_{std::make_shared<const Set>()};
        std::atomic<std::size_t> PeakGlobal_{0};
        std::atomic<std::size_t> PeakLocalSum_{0};
        std::atomic<std::size_t> PeakLocalMax_{0};
        std::atomic<bool> LocalRetireValid_{false};
        std::vector<std::weak_ptr<const Set>> LocalRetired_;
    };
    auto IsMutation(const OperationKind Kind) -> bool { return Kind == OperationKind::Insert ||
        Kind == OperationKind::DuplicateInsert || Kind == OperationKind::Erase ||
        Kind == OperationKind::DuplicateErase; }
    struct MutationRequest final { std::uint64_t Id{0}; bool IsInsert{false}; bool Expected{false}; };
    template <typename Set>
    class SnapshotPublisher final
    {
    public:
        SnapshotPublisher(SnapshotModel<Set> &ModelValue, WorkerStats &StatsValue,
                          std::optional<std::size_t> LocalOwner)
            : Model_(ModelValue), Stats_(StatsValue), Owner_(LocalOwner) {}
        auto Apply(const MutationRequest &Request) -> bool
        {
            for (;;)
            {
                auto Before = Load();
                const auto BeforeContains = ContainsValue(*Before, Request.Id);
                const auto BeforeSize = SizeValue(*Before);
                const auto ExpectedBefore = Request.IsInsert ? !Request.Expected : Request.Expected;
                if (BeforeContains != ExpectedBefore)
                {
                    ++Stats_.Errors;
                    return false;
                }
                if (!Request.Expected) return false;
                auto Next = std::make_shared<Set>(*Before);
                const auto Changed = Request.IsInsert ? InsertValue(*Next, Request.Id)
                                                       : EraseValue(*Next, Request.Id);
                if (!Changed)
                {
                    ++Stats_.Errors;
                    return false;
                }
                if (!Publish(Before, std::move(Next)))
                {
                    ++Stats_.CasRetries;
                    continue;
                }
                ++Stats_.CasPublishes;
                ++Stats_.ImmutableChecks;
                RecordOldSnapshot(Stats_, Before);
                if (ContainsValue(*Before, Request.Id) != BeforeContains ||
                    SizeValue(*Before) != BeforeSize)
                {
                    ++Stats_.Errors;
                }
                return true;
            }
        }
    private:
        auto Load() const -> std::shared_ptr<const Set>
        { return Owner_ ? Model_.Snapshot(*Owner_) : Model_.GlobalSnapshot(); }
        auto Publish(std::shared_ptr<const Set> &Before, std::shared_ptr<Set> Next) -> bool
        { return Owner_ ? Model_.Publish(*Owner_, Before, std::move(Next))
                         : Model_.PublishGlobal(Before, std::move(Next)); }
        SnapshotModel<Set> &Model_; WorkerStats &Stats_; std::optional<std::size_t> Owner_;
    };

    template <typename Set>
    auto ApplyOperation(SnapshotModel<Set> &Model, const Operation &OperationValue,
                        WorkerStats &Stats) -> void
    {
        const auto Owner = OperationValue.Lane % Model.OwnerCount();
        if (!IsMutation(OperationValue.Kind))
        {
            const auto Global = Model.GlobalSnapshot();
            const auto Local = Model.Snapshot(Owner);
            const auto GlobalPresent = ContainsValue(*Global, OperationValue.Id);
            const auto LocalPresent = ContainsValue(*Local, OperationValue.Id);
            const auto ExpectedLocal = OperationValue.PhaseValue == Phase::Release
                ? true : OperationValue.Expected;
            if (GlobalPresent != OperationValue.Expected || LocalPresent != ExpectedLocal)
            {
                ++Stats.Errors;
            }
            if (OperationValue.Expected) ++Stats.ContainsHits;
            else ++Stats.ContainsMisses;
            return;
        }
        const auto IsInsert = OperationValue.Kind == OperationKind::Insert ||
                              OperationValue.Kind == OperationKind::DuplicateInsert;
        const MutationRequest Request{OperationValue.Id, IsInsert, OperationValue.Expected};
        SnapshotPublisher<Set> Global(Model, Stats, std::nullopt);
        const auto GlobalChanged = Global.Apply(Request);
        const auto IsRelease = OperationValue.PhaseValue == Phase::Release;
        bool LocalChanged = GlobalChanged;
        if (IsRelease)
        {
            const auto Local = Model.Snapshot(Owner);
            if (!ContainsValue(*Local, OperationValue.Id)) ++Stats.Errors;
            ++Stats.LocalRetainedChecks;
        }
        else
        {
            SnapshotPublisher<Set> Local(Model, Stats, Owner);
            LocalChanged = Local.Apply(Request);
            if (GlobalChanged != LocalChanged) ++Stats.Errors;
        }
        if (IsInsert)
        {
            if (GlobalChanged) ++Stats.InsertsAccepted;
            else ++Stats.InsertsRejected;
        }
        else if (GlobalChanged)
        {
            ++Stats.ErasesAccepted;
        }
        else
        {
            ++Stats.ErasesRejected;
        }
    }
    template <typename Set> struct WorkerGroupInput final
    {
        SnapshotModel<Set> &Model; const Trace &TraceValue; std::atomic<bool> &Failed;
    };
    struct WorkerGroupOutput final {
        std::vector<std::uint64_t> &Latencies; std::vector<WorkerStats> &Stats;
    };
    template <typename Set>
    class WorkerGroup final
    {
    public:
        WorkerGroup(WorkerGroupInput<Set> Input, WorkerGroupOutput Output)
            : Model_(Input.Model), Trace_(Input.TraceValue), Latencies_(Output.Latencies), Stats_(Output.Stats),
              Failed_(Input.Failed), Ready_(Input.TraceValue.OwnerCount), Done_(Input.TraceValue.OwnerCount),
              PhaseBarrier_(Input.TraceValue.OwnerCount)
        {
            try
            {
                Threads_.reserve(Trace_.OwnerCount);
                for (std::size_t Lane = 0; Lane < Trace_.OwnerCount; ++Lane)
                {
                    Threads_.emplace_back(&WorkerGroup::RunLane, this, Lane);
                }
            }
            catch (...)
            {
                const auto Missing = static_cast<std::ptrdiff_t>(Trace_.OwnerCount - Threads_.size());
                if (Missing != 0)
                {
                    Ready_.count_down(Missing);
                    Done_.count_down(Missing);
                }
                Failed_.store(true, std::memory_order_release);
                Abort_.store(true, std::memory_order_release);
                Start();
                Join();
                throw;
            }
        }
        ~WorkerGroup() noexcept
        {
            Start();
            Join();
        }
        auto WaitReady() const -> void { Ready_.wait(); }
        auto Start() noexcept -> void
        {
            Go_.store(true, std::memory_order_release);
            Go_.notify_all();
        }
        auto WaitDone() const -> void { Done_.wait(); }
        [[nodiscard]] auto PhaseDurations() const -> std::array<std::uint64_t, 3>
        {
            std::array<std::uint64_t, 3> Result{};
            for (std::size_t Index = 0; Index < Result.size(); ++Index)
            {
                Result[Index] = PhaseEnd_[Index] >= PhaseBegin_[Index]
                    ? static_cast<std::uint64_t>(PhaseEnd_[Index] - PhaseBegin_[Index])
                    : 0U;
            }
            return Result;
        }
        auto Join() noexcept -> void
        {
            for (auto &Thread : Threads_)
            {
                if (Thread.joinable()) Thread.join();
            }
        }
    private:
        auto RunLane(const std::size_t Lane) noexcept -> void
        {
            Ready_.count_down();
            Go_.wait(false, std::memory_order_acquire);
            if (Abort_.load(std::memory_order_acquire))
            {
                Done_.count_down();
                return;
            }
            for (std::size_t PhaseIndex = 0; PhaseIndex < 3; ++PhaseIndex)
            {
                if (Lane == 0) PhaseBegin_[PhaseIndex] = Clock::now().time_since_epoch().count();
                if (!Abort_.load(std::memory_order_acquire))
                {
                    for (std::size_t Index = 0; Index < Trace_.Operations.size(); ++Index)
                    {
                        const auto &OperationValue = Trace_.Operations[Index];
                        if (OperationValue.Lane != Lane ||
                            static_cast<std::size_t>(OperationValue.PhaseValue) != PhaseIndex)
                        {
                            continue;
                        }
                        try
                        {
                            const auto StartTime = Clock::now();
                            ApplyOperation(Model_, OperationValue, Stats_[Lane]);
                            const auto FinishTime = Clock::now();
                            Latencies_[Index] = static_cast<std::uint64_t>(
                                std::chrono::duration_cast<std::chrono::nanoseconds>(FinishTime - StartTime).count()) + 1U;
                            ++Stats_[Lane].Operations;
                        }
                        catch (...)
                        {
                            Failed_.store(true, std::memory_order_release);
                            Abort_.store(true, std::memory_order_release);
                            break;
                        }
                    }
                }
                PhaseBarrier_.arrive_and_wait();
                if (Lane == 0)
                {
                    if (PhaseIndex == 0 && !Abort_.load(std::memory_order_acquire))
                    {
                        Model_.RecordPeak();
                    }
                    if (PhaseIndex == 2 && !Abort_.load(std::memory_order_acquire))
                    {
                        Model_.RetireLocals(Trace_.IdCount);
                    }
                    PhaseEnd_[PhaseIndex] = Clock::now().time_since_epoch().count();
                }
                PhaseBarrier_.arrive_and_wait();
            }
            Done_.count_down();
        }
        SnapshotModel<Set> &Model_; const Trace &Trace_;
        std::vector<std::uint64_t> &Latencies_; std::vector<WorkerStats> &Stats_;
        std::atomic<bool> &Failed_; std::latch Ready_;
        std::latch Done_; std::barrier<> PhaseBarrier_;
        std::atomic<bool> Go_{false}; std::atomic<bool> Abort_{false};
        std::array<std::int64_t, 3> PhaseBegin_{}; std::array<std::int64_t, 3> PhaseEnd_{};
        std::vector<std::thread> Threads_;
    };
    auto ValidateCounters(const Trace &TraceValue, const std::vector<WorkerStats> &Stats, SampleResult &Result) -> void
    {
        for (std::size_t Lane = 0; Lane < TraceValue.OwnerCount; ++Lane)
        {
            const auto Ids = (TraceValue.IdCount + TraceValue.OwnerCount - 1U - Lane) /
                             TraceValue.OwnerCount;
            const auto SnapshotMutations = Ids * 3U;
            const auto LaneValid = Stats[Lane].Operations == Ids * 6U &&
                Stats[Lane].InsertsAccepted == Ids && Stats[Lane].InsertsRejected == Ids &&
                Stats[Lane].ContainsHits == Ids && Stats[Lane].ErasesAccepted == Ids &&
                Stats[Lane].ContainsMisses == Ids && Stats[Lane].ErasesRejected == Ids &&
                Stats[Lane].CasPublishes == SnapshotMutations &&
                Stats[Lane].ImmutableChecks == SnapshotMutations &&
                Stats[Lane].LocalRetainedChecks == Ids * 2U;
            if (!LaneValid) ++Result.Errors;
            if (Stats[Lane].OldStdSnapshots.size() + Stats[Lane].OldTaskSnapshots.size() !=
                SnapshotMutations)
            {
                ++Result.Errors;
            }
            for (const auto &Weak : Stats[Lane].OldStdSnapshots)
            {
                if (!Weak.expired()) ++Result.Errors;
            }
            for (const auto &Weak : Stats[Lane].OldTaskSnapshots)
            {
                if (!Weak.expired()) ++Result.Errors;
            }
            Result.Errors += static_cast<std::size_t>(Stats[Lane].Errors);
        }
    }

    template <typename Set>
    auto ValidateSnapshots(SnapshotModel<Set> &Model, const Trace &TraceValue, SampleResult &Result) -> void
    {
        std::size_t ExpectedLocalMax = 0;
        std::size_t ExpectedLocalSum = 0;
        for (std::size_t Owner = 0; Owner < Model.OwnerCount(); ++Owner)
        {
            std::size_t OwnerIds = 0;
            for (std::size_t Lane = 0; Lane < TraceValue.OwnerCount; ++Lane)
            {
                if (Lane % Model.OwnerCount() == Owner)
                {
                    OwnerIds += (TraceValue.IdCount + TraceValue.OwnerCount - 1U - Lane) /
                                TraceValue.OwnerCount;
                }
            }
            ExpectedLocalSum += OwnerIds;
            ExpectedLocalMax = (std::max)(ExpectedLocalMax, OwnerIds);
        }
        if (Result.PeakGlobal != TraceValue.IdCount ||
            Result.PeakLocalSum != ExpectedLocalSum || Result.PeakLocalMax != ExpectedLocalMax)
        {
            ++Result.Errors;
        }
        if (!Model.LocalRetireValid() || !Model.LocalRetiredExpired()) ++Result.Errors;
        const auto Global = Model.GlobalSnapshot();
        if (SizeValue(*Global) != 0)
        {
            ++Result.Errors;
        }
        for (std::size_t Owner = 0; Owner < Model.OwnerCount(); ++Owner)
        {
            const auto Snapshot = Model.Snapshot(Owner);
            std::size_t Values = 0;
            ForEachValue(*Snapshot, [&Values](const std::uint64_t) { ++Values; });
            if (SizeValue(*Snapshot) != 0 || Values != 0) ++Result.Errors;
        }
    }
    auto Percentile(std::vector<std::uint64_t> Values, const std::size_t Numerator,
                    const std::size_t Denominator) -> std::uint64_t
    {
        if (Values.empty()) return 0;
        std::sort(Values.begin(), Values.end());
        const auto Rank = (Values.size() * Numerator + Denominator - 1U) / Denominator;
        return Values[(std::max)(std::size_t{1}, Rank) - 1U];
    }
    template <typename Set>
    auto RunVariant(const Trace &TraceValue, const Variant ModelKind, const std::size_t Round) -> SampleResult
    {
        SampleResult Result;
        Result.Model = ModelKind;
        Result.IdCount = TraceValue.IdCount;
        Result.OwnerCount = TraceValue.OwnerCount;
        Result.Round = Round;
        Result.TraceHash = TraceValue.Hash;
        std::vector<std::uint64_t> Latencies(TraceValue.Operations.size());
        std::vector<WorkerStats> Stats(TraceValue.OwnerCount);
        std::atomic<bool> Failed{false};
        try
        {
            SnapshotModel<Set> Model(TraceValue.OwnerCount);
            WorkerGroup<Set> Workers(
                WorkerGroupInput<Set>{Model, TraceValue, Failed},
                WorkerGroupOutput{Latencies, Stats});
            Workers.WaitReady();
            const auto Measurement = Measure([&Workers]
            {
                Workers.Start();
                Workers.WaitDone();
            });
            Workers.Join();
            Result.Measurement = Measurement;
            Result.PeakGlobal = Model.PeakGlobal();
            Result.PeakLocalSum = Model.PeakLocalSum();
            Result.PeakLocalMax = Model.PeakLocalMax();
            Result.LocalRetireValid = Model.LocalRetireValid();
            const auto Phases = Workers.PhaseDurations();
            Result.ReserveNs = Phases[0];
            Result.LookupNs = Phases[1];
            Result.ReleaseNs = Phases[2];
            for (const auto &Value : Stats)
            {
                Result.Operations += Value.Operations;
                Result.CasPublishes += Value.CasPublishes;
                Result.CasRetries += Value.CasRetries;
            }
            ValidateCounters(TraceValue, Stats, Result);
            ValidateSnapshots(Model, TraceValue, Result);
            Result.P50 = Percentile(Latencies, 50, 100);
            Result.P95 = Percentile(Latencies, 95, 100);
            Result.P99 = Percentile(Latencies, 99, 100);
            Result.Valid = !Failed.load(std::memory_order_acquire) &&
                           Result.Errors == 0 && Result.Operations == TraceValue.Operations.size();
        }
        catch (...)
        {
            ++Result.Errors;
            Result.Valid = false;
        }
        return Result;
    }
    auto PrintResult(const SampleResult &Result, const char *Order) -> void
    {
        std::printf(
            "task-id-set model=%s ids=%zu lanes=%zu round=%zu order=%s trace_hash=%016llx "
            "operations=%llu cas_publishes=%llu cas_retries=%llu p50_ns=%llu p95_ns=%llu "
            "p99_ns=%llu ordinary_count=%llu ordinary_bytes=%llu aligned_count=%llu "
            "aligned_bytes=%llu samples=%llu peak_available=%s peak_working_set=%llu peak_commit=%llu "
            "peak_global=%llu peak_local_sum=%llu peak_local_max=%llu reserve_ns=%llu "
            "lookup_ns=%llu release_ns=%llu local_retire=%s duration_s=%.6f errors=%zu valid=%s\n",
            VariantName(Result.Model), Result.IdCount, Result.OwnerCount, Result.Round, Order,
            static_cast<unsigned long long>(Result.TraceHash),
            static_cast<unsigned long long>(Result.Operations),
            static_cast<unsigned long long>(Result.CasPublishes),
            static_cast<unsigned long long>(Result.CasRetries),
            static_cast<unsigned long long>(Result.P50),
            static_cast<unsigned long long>(Result.P95),
            static_cast<unsigned long long>(Result.P99),
            static_cast<unsigned long long>(Result.Measurement.Allocations),
            static_cast<unsigned long long>(Result.Measurement.AllocationBytes),
            static_cast<unsigned long long>(Result.Measurement.AlignedAllocations),
            static_cast<unsigned long long>(Result.Measurement.AlignedAllocationBytes),
            static_cast<unsigned long long>(Result.Measurement.ProcessSamples),
            Result.Measurement.PeakAvailable ? "yes" : "no",
            static_cast<unsigned long long>(Result.Measurement.PeakWorkingSet),
            static_cast<unsigned long long>(Result.Measurement.PeakCommit),
            static_cast<unsigned long long>(Result.PeakGlobal),
            static_cast<unsigned long long>(Result.PeakLocalSum),
            static_cast<unsigned long long>(Result.PeakLocalMax),
            static_cast<unsigned long long>(Result.ReserveNs),
            static_cast<unsigned long long>(Result.LookupNs),
            static_cast<unsigned long long>(Result.ReleaseNs),
            Result.LocalRetireValid ? "yes" : "no",
            static_cast<double>(Result.Measurement.EndNs - Result.Measurement.BeginNs) / 1e9,
            Result.Errors, Result.Valid ? "yes" : "no");
        if (Result.Measurement.ProcessBefore && Result.Measurement.ProcessAfter)
        {
            const auto &Before = *Result.Measurement.ProcessBefore;
            const auto &After = *Result.Measurement.ProcessAfter;
            std::printf(
                "task-id-set-process cpu_user_delta_100ns=%llu cpu_kernel_delta_100ns=%llu "
                "rss_before=%llu rss_after=%llu commit_before=%llu commit_after=%llu\n",
                static_cast<unsigned long long>(After.User100ns - Before.User100ns),
                static_cast<unsigned long long>(After.Kernel100ns - Before.Kernel100ns),
                static_cast<unsigned long long>(Before.WorkingSetBytes),
                static_cast<unsigned long long>(After.WorkingSetBytes),
                static_cast<unsigned long long>(Before.CommitBytes),
                static_cast<unsigned long long>(After.CommitBytes));
        }
}
} // namespace Prism::Lifecycle::Perf
int main()
{
    bool AllValid = true;
    constexpr std::array<std::size_t, 3> IdCounts{64, 1024, 32768};
    constexpr std::array<std::size_t, 3> LaneCounts{1, 2, 4};
    for (const auto IdCount : IdCounts)
    {
        for (const auto LaneCountValue : LaneCounts)
        {
            for (std::size_t Round = 0;
                 Round < Prism::Lifecycle::Perf::RoundCount; ++Round)
            {
                const auto TraceValue = Prism::Lifecycle::Perf::BuildTrace(IdCount, LaneCountValue);
                const auto Order = (Round % 2U) == 0U ? "AB" : "BA";
                Prism::Lifecycle::Perf::SampleResult StdResult;
                Prism::Lifecycle::Perf::SampleResult TaskResult;
                if ((Round % 2U) == 0U)
                {
                    StdResult = Prism::Lifecycle::Perf::RunVariant<std::set<std::uint64_t>>(
                        TraceValue, Prism::Lifecycle::Perf::Variant::StdSet, Round + 1U);
                    TaskResult = Prism::Lifecycle::Perf::RunVariant<
                        Prism::Lifecycle::Perf::PersistentSet>(
                        TraceValue, Prism::Lifecycle::Perf::Variant::TaskIdSet, Round + 1U);
                }
                else
                {
                    TaskResult = Prism::Lifecycle::Perf::RunVariant<
                        Prism::Lifecycle::Perf::PersistentSet>(
                        TraceValue, Prism::Lifecycle::Perf::Variant::TaskIdSet, Round + 1U);
                    StdResult = Prism::Lifecycle::Perf::RunVariant<std::set<std::uint64_t>>(
                        TraceValue, Prism::Lifecycle::Perf::Variant::StdSet, Round + 1U);
                }
                Prism::Lifecycle::Perf::PrintResult(StdResult, Order);
                Prism::Lifecycle::Perf::PrintResult(TaskResult, Order);
                const auto PairValid = StdResult.Valid && TaskResult.Valid &&
                    StdResult.TraceHash == TaskResult.TraceHash &&
                    StdResult.Operations == TraceValue.Operations.size() &&
                    TaskResult.Operations == TraceValue.Operations.size();
                AllValid = AllValid && PairValid;
            }
        }
    }
    std::printf("TaskIdSetCompare: %s\n", AllValid ? "ALL PASS" : "FAILED");
    return AllValid ? 0 : 1;
}

/** @file Statistics.cpp @brief 有界流量队列与聚合管理器实现。 */
#include <Prism/Runtime/Statistics.hpp>
#include <Prism/Runtime/Statistics/HistoryCollector.hpp>
#include <Prism/Runtime/Statistics/RecognitionLatency.hpp>

#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <array>
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <variant>

namespace Prism::Runtime::Detail
{
    auto HistoryCollector::Configure(Prism::Statistics::HistoryCatalog Catalog) -> void
    {
        if (Catalog.Generation == 0 || Catalog.InstanceKey.empty() || Catalog.Incarnation.empty()) return;
        Catalogs_.insert_or_assign(Catalog.Generation, std::move(Catalog));
    }

    auto HistoryCollector::RetireGeneration(std::uint64_t Generation) -> void
    {
        Catalogs_.erase(Generation);
    }

    auto HistoryCollector::Record(const Prism::Foundation::TrafficEvent &Event) noexcept -> bool
    {
        try
        {
            const auto Catalog = Event.Kind == Prism::Foundation::TrafficEventKind::NetworkLatency &&
                !Catalogs_.empty() ? std::prev(Catalogs_.end()) : Catalogs_.find(Event.Generation.Value());
            if (Catalog == Catalogs_.end()) return false;
            const auto &Configuration = Catalog->second;
            Add(Configuration, {Prism::Statistics::HistoryScope::Process, "process"}, Event);
            Add(Configuration, {Prism::Statistics::HistoryScope::Worker, std::to_string(Event.Worker.Value())}, Event);
            if (Event.Kind == Prism::Foundation::TrafficEventKind::NetworkLatency) return true;
            const auto Account = std::find_if(Configuration.Accounts.begin(), Configuration.Accounts.end(),
                [&Event](const auto &Value) { return Value.NumericId == Event.Account.Value(); });
            if (Account != Configuration.Accounts.end())
            {
                Add(Configuration, {Prism::Statistics::HistoryScope::Account, Account->Key}, Event);
                Add(Configuration, {Prism::Statistics::HistoryScope::Group,
                    Account->GroupKey.empty() ? "ungrouped" : Account->GroupKey}, Event);
            }
            const auto Protocol = std::find_if(Configuration.Protocols.begin(), Configuration.Protocols.end(),
                [&Event](const auto &Value) { return Value.NumericId == Event.ProtocolInstance; });
            Add(Configuration, {Prism::Statistics::HistoryScope::ProtocolInstance,
                Protocol != Configuration.Protocols.end() ? Protocol->Key : "unattributed"}, Event);
            const auto Type = Event.Protocol != 0 ? Event.Protocol :
                Protocol != Configuration.Protocols.end() ? Protocol->Type : 0U;
            Add(Configuration, {Prism::Statistics::HistoryScope::ProtocolType,
                Type != 0 ? std::to_string(Type) : "unattributed"}, Event);
            const auto Ingress = std::find_if(Configuration.Ingresses.begin(), Configuration.Ingresses.end(),
                [&Event](const auto &Value) { return Value.NumericId == Event.Ingress &&
                    Value.Transport == static_cast<std::uint8_t>(Event.Transport); });
            Add(Configuration, {Prism::Statistics::HistoryScope::Ingress,
                Ingress != Configuration.Ingresses.end() ? Ingress->Key : "unattributed"}, Event);
            return true;
        }
        catch (...) { PendingFailure_ = true; return false; }
    }

    auto HistoryCollector::Sample(std::uint64_t Now, Prism::Statistics::HistoryQuality Quality) noexcept -> void
    {
        try { SampleOwned(Now, Quality); }
        catch (...) { PendingFailure_ = true; }
    }

    auto HistoryCollector::TakePersistenceBatch() -> std::vector<Prism::Statistics::HistoryRecord>
    {
        auto Result = std::move(Persistence_);
        Persistence_.clear();
        return Result;
    }

    auto HistoryCollector::Query(const Prism::Statistics::HistoryQuery &Request, std::uint64_t Now) const
        -> Prism::Statistics::HistoryResult
    {
        Prism::Statistics::HistoryResult Result;
        Result.SampledAt = Now;
        Result.From = Request.From;
        Result.To = Request.To;
        Result.ResolutionMilliseconds = Prism::Statistics::HistoryResolution(Request, Now);
        Result.Coverage = "accepted_observations_at_control_flush; no_zero_fill; active_not_collected";
        if (!Prism::Statistics::ValidHistoryQuery(Request))
        {
            Result.Failure = "invalid_history_query";
            return Result;
        }
        for (const auto &Value : Memory_)
        {
            if (Value.Scope == Request.Scope && Value.Key == Request.Key && Value.Metric == Request.Metric &&
                Value.Timestamp >= Request.From && Value.Timestamp < Request.To)
            {
                Result.Items.push_back(Value);
            }
        }
        Result.Items = Prism::Statistics::AggregateHistory(std::move(Result.Items), Result.ResolutionMilliseconds);
        Result.Available = !Result.Items.empty();
        Prism::Statistics::FindHistoryGaps(Result);
        return Result;
    }

    auto HistoryCollector::Add(const Prism::Statistics::HistoryCatalog &Catalog, Series IdentityValue,
        const Prism::Foundation::TrafficEvent &Event) -> void
    {
        using EventKind = Prism::Foundation::TrafficEventKind;
        using MetricType = Prism::Statistics::HistoryMetric;
        const auto Metric = Event.Kind == EventKind::RecognitionLatency ? MetricType::RecognitionAdmission :
            Event.Kind != EventKind::NetworkLatency ? MetricType::Traffic :
            Event.NetworkStage == Prism::Foundation::NetworkLatencyStage::DnsResolution ? MetricType::DnsResolution :
            MetricType::TcpConnect;
        const auto Generation = Event.Kind == EventKind::NetworkLatency ? 0U : Catalog.Generation;
        const Key Identity{Generation, IdentityValue.Scope, IdentityValue.Key, Metric};
        if (!Pending_.contains(Identity) && Pending_.size() >= MaxPendingSeries)
        { PendingFailure_ = true; return; }
        auto &Value = Pending_[Identity];
        Value.Scope = IdentityValue.Scope; Value.Key = std::move(IdentityValue.Key); Value.InstanceKey = Catalog.InstanceKey;
        Value.Incarnation = Catalog.Incarnation; Value.Generation = Generation; Value.Metric = Metric;
        if (Event.Kind == EventKind::RecognitionLatency || Event.Kind == EventKind::NetworkLatency)
        {
            Value.Latency.Record(Event.DurationMicroseconds);
            ++Value.Events;
            if (Event.Failure.Failed() && Event.Failure.Code != Prism::Fault::Code::Canceled &&
                Event.Failure.Code != Prism::Fault::Code::Eof) ++Value.Errors;
        }
        else
        {
            Value.UpBytes += Event.Up; Value.DownBytes += Event.Down;
            if (Event.Kind == Prism::Foundation::TrafficEventKind::Completed)
            {
                ++Value.Events;
                if (Event.Failure.Failed() && Event.Failure.Code != Prism::Fault::Code::Canceled &&
                    Event.Failure.Code != Prism::Fault::Code::Eof) ++Value.Errors;
            }
        }
    }

    auto HistoryCollector::SampleOwned(std::uint64_t Now, Prism::Statistics::HistoryQuality Quality) -> void
    {
        if (LastSample_ != 0 && Now <= LastSample_) { PendingFailure_ = true; return; }
        if (!Catalogs_.empty())
        {
            const auto &Current = Catalogs_.rbegin()->second;
            Prism::Foundation::TrafficEvent Heartbeat;
            Heartbeat.Kind = Prism::Foundation::TrafficEventKind::Bytes;
            Add(Current, {Prism::Statistics::HistoryScope::Process, "process"}, Heartbeat);
        }
        const auto Width = LastSample_ != 0 ? Now - LastSample_ : 1'000U;
        Quality.Incomplete = Quality.Incomplete || PendingFailure_ || Width > 2'000U;
        for (auto &[Identity, Value] : Pending_)
        {
            (void)Identity;
            Value.Timestamp = LastSample_ != 0 ? LastSample_ : Now - (std::min)(Now, Width);
            Value.ResolutionMilliseconds = Width;
            Value.Quality = Quality;
            Memory_.push_back(Value);
            for (const auto Resolution : {10'000ULL, 60'000ULL, 900'000ULL}) AddPersistent(Value, Resolution);
        }
        Pending_.clear(); PendingFailure_ = false; LastSample_ = Now;
        while (!Memory_.empty() && (Memory_.size() > MaxMemoryRecords ||
            (Now > Memory_.front().Timestamp && Now - Memory_.front().Timestamp >
                Prism::Statistics::HistoryMemoryRetention))) Memory_.pop_front();
        ClosePersistent(Now);
    }

    auto HistoryCollector::AddPersistent(const Prism::Statistics::HistoryRecord &Value,
        std::uint64_t Resolution) -> void
    {
        auto Copy = Value;
        Copy.Timestamp -= Copy.Timestamp % Resolution;
        Copy.ResolutionMilliseconds = Resolution;
        const auto Identity = std::tuple{Resolution, Copy.Timestamp, Copy.Generation, Copy.Scope, Copy.Key, Copy.Metric};
        if (!PersistentWindows_.contains(Identity) && PersistentWindows_.size() >= MaxPendingSeries * 3U)
        { PendingFailure_ = true; return; }
        auto [It, Inserted] = PersistentWindows_.try_emplace(Identity, Copy);
        if (!Inserted) (void)Prism::Statistics::MergeHistoryRecord(It->second, Copy);
    }

    auto HistoryCollector::ClosePersistent(std::uint64_t Now) -> void
    {
        for (auto It = PersistentWindows_.begin(); It != PersistentWindows_.end();)
        {
            const auto &Value = It->second;
            if (Now < Value.Timestamp || Now - Value.Timestamp < Value.ResolutionMilliseconds) { ++It; continue; }
            if (Persistence_.size() < MaxPersistenceRecords) Persistence_.push_back(Value);
            else PendingFailure_ = true;
            It = PersistentWindows_.erase(It);
        }
    }

    auto RecognitionLatencyStore::Record(const Prism::GenerationId Generation,
        const std::uint64_t DurationMicroseconds) noexcept -> bool
    {
        auto *Owner = Find(Generation);
        if (!Owner)
        {
            return false;
        }
        if (DurationMicroseconds > HistogramMaximumMicroseconds &&
            Owner->RangeExceeded != std::numeric_limits<std::uint64_t>::max())
        {
            ++Owner->RangeExceeded;
        }
        Owner->Histogram.Record(DurationMicroseconds);
        Owner->Samples.Sample(DurationMicroseconds);
        return true;
    }

    auto RecognitionLatencyStore::Snapshot(const Prism::GenerationId Generation) const
        -> Prism::Statistics::RecognitionLatencySnapshot
    {
        Prism::Statistics::RecognitionLatencySnapshot Result;
        Result.Generation = Generation;
        for (const auto &Owner : Owners_)
        {
            if (Owner.Generation != Generation)
            {
                continue;
            }
            Result.SampleCount = Owner.Histogram.Count();
            Result.TracerWrittenCount = Owner.Samples.SampledCount();
            Result.TracerDroppedCount = Owner.Samples.DroppedCount();
            Result.HistogramRangeExceeded = Owner.RangeExceeded;
            Result.RecentCount = Owner.Samples.Drain(Result.RecentMicroseconds);
            if (Result.SampleCount != 0U)
            {
                Result.P50BucketLowerBoundMicroseconds = Owner.Histogram.Percentile(50.0);
                Result.P95BucketLowerBoundMicroseconds = Owner.Histogram.Percentile(95.0);
                Result.P99BucketLowerBoundMicroseconds = Owner.Histogram.Percentile(99.0);
                Result.MaximumObservedMicroseconds = Owner.Histogram.Percentile(100.0);
            }
            return Result;
        }
        return Result;
    }

    RecognitionLatencyStore::Owner::Owner()
        : Histogram(HistogramMaximumMicroseconds),
          Samples(1U, RecentSampleCapacity)
    {
    }

    auto RecognitionLatencyStore::Owner::Reset(const Prism::GenerationId Value) noexcept -> void
    {
        Histogram.Reset();
        Samples.Reset();
        RangeExceeded = 0U;
        Generation = Value;
    }

    auto RecognitionLatencyStore::Find(const Prism::GenerationId Generation) noexcept -> Owner *
    {
        if (!Generation)
        {
            return nullptr;
        }
        for (auto &Value : Owners_)
        {
            if (Value.Generation == Generation)
            {
                return &Value;
            }
        }
        for (auto &Value : Owners_)
        {
            if (!Value.Generation || !Publication_ || !Publication_->Contains(Value.Generation))
            {
                Value.Reset(Generation);
                return &Value;
            }
        }
        return nullptr;
    }
}

namespace Prism::Runtime
{
    auto TrafficCounter::ReportRecognitionLatency(
        Prism::Foundation::RecognitionLatencySample Sample) noexcept -> void
    {
        Report(Prism::Foundation::TrafficEvent{
            .Generation = Sample.Generation,
            .Worker = Sample.Worker,
            .Session = Sample.Session,
            .Kind = Prism::Foundation::TrafficEventKind::RecognitionLatency,
            .DurationMicroseconds = Sample.DurationMicroseconds});
    }

    TrafficCounter::TrafficCounter(Options Configuration, Net::any_io_executor ControlExecutor)
        : Process_(Configuration.Process),
          Generation_(Configuration.Generation),
          Publication_(std::move(Configuration.Publication)),
          RecognitionLatency_(Publication_),
          ControlReclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(
              std::move(ControlExecutor))),
          Counters_(Prism::Statistics::SparseCounters::Options{Configuration.MaxCounterEntries})
    {
        Queues_.reserve(Configuration.Workers + 1U);
        for (std::size_t Index = 0; Index <= Configuration.Workers; ++Index)
            Queues_.push_back(std::make_unique<WorkerQueue>());
    }

    auto TrafficCounter::Report(Prism::Foundation::TrafficEvent Event) noexcept -> void
    {
        const auto IsRecognitionLatency =
            Event.Kind == Prism::Foundation::TrafficEventKind::RecognitionLatency;
        const auto Index = Event.Worker.Value();
        if (Index >= Queues_.size())
        {
            UnassignedDrops_.fetch_add(1U, std::memory_order_relaxed);
            RecordRecognitionLatencyQueueDrop(IsRecognitionLatency);
            return;
        }
        auto& Queue = *Queues_[Index];
        const auto GenerationRetained = Publication_
            ? Publication_->Contains(Event.Generation)
            : Event.Generation == Generation_;
        const auto WorkerOwnedStage = Event.Kind == Prism::Foundation::TrafficEventKind::NetworkLatency;
        if (Sealed_.load(std::memory_order_acquire) || (!GenerationRetained && !WorkerOwnedStage) ||
            !Queue.Events.bounded_push(Event))
        {
            Queue.Dropped.fetch_add(1U, std::memory_order_relaxed);
            RecordRecognitionLatencyQueueDrop(IsRecognitionLatency);
            return;
        }
        Accepted_.fetch_add(1U, std::memory_order_relaxed);
    }

    auto TrafficCounter::Retire(Prism::Foundation::TrafficRetirement Owner)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        using Failure = Prism::Fault::Failure;
        try
        {
            const auto Cancellation = co_await Net::this_coro::cancellation_state;
            if (Cancellation.cancelled() != Net::cancellation_type::none)
            {
                RecordRetirementFailure(Owner);
                co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            }

            const auto Worker = std::visit([](const auto& Value) { return Value.Worker; }, Owner);
            const auto Scope = ToCounterScope(Owner);
            if (Scope.Id == 0U || Worker.Value() >= Queues_.size())
            {
                RecordRetirementFailure(Owner);
                co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            }
            if (Scope.ScopeValue == Prism::Statistics::Scope::Stream &&
                Scope.ParentSession.Value() == 0U)
            {
                RecordRetirementFailure(Owner);
                co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            }
            if (Sealed_.load(std::memory_order_acquire) || !ControlReclaimer_->CanDispatch())
            {
                RecordRetirementFailure(Owner);
                co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            }

            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            co_return co_await Net::co_spawn(
                ControlReclaimer_->Executor(), RetireOnControl(Scope, Worker, Owner),
                Net::use_awaitable);
        }
        catch (const boost::system::system_error& Error)
        {
            RecordRetirementFailure(Owner);
            co_return std::unexpected(Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            RecordRetirementFailure(Owner);
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
    }

    auto TrafficCounter::Flush() noexcept -> void
    {
        for (const auto& Queue : Queues_)
        {
            Prism::Foundation::TrafficEvent Event;
            for (std::size_t Count = 0; Count < 1024U && Queue->Events.pop(Event); ++Count)
            {
                if (!Accumulate(Event))
                {
                    Queue->AggregationFailures.fetch_add(1U, std::memory_order_relaxed);
                    RecordRecognitionLatencyAggregationFailure(Event);
                }
                ConsumedObservations_.fetch_add(1U, std::memory_order_relaxed);
            }
        }
    }

    auto TrafficCounter::Finish() noexcept -> void
    {
        Sealed_.store(true, std::memory_order_release);
        Flush();
    }

    auto TrafficCounter::Value(
        const Prism::Statistics::Scope Scope,
        const std::uint64_t Id) const noexcept -> Prism::Statistics::TrafficValue
    {
        using Metric = Prism::Statistics::Metric;
        return {Counters_.Get({Scope, Id, Metric::UpBytes}),
            Counters_.Get({Scope, Id, Metric::DownBytes}),
            Counters_.Get({Scope, Id, Metric::Events}),
            Counters_.Get({Scope, Id, Metric::Errors})};
    }

    auto TrafficCounter::StreamValue(
        const Prism::SessionId Parent,
        const Prism::StreamId Id) const noexcept -> Prism::Statistics::TrafficValue
    {
        using Scope = Prism::Statistics::Scope;
        using Metric = Prism::Statistics::Metric;
        return {Counters_.Get({Scope::Stream, Id.Value(), Metric::UpBytes, Parent}),
            Counters_.Get({Scope::Stream, Id.Value(), Metric::DownBytes, Parent}),
            Counters_.Get({Scope::Stream, Id.Value(), Metric::Events, Parent}),
            Counters_.Get({Scope::Stream, Id.Value(), Metric::Errors, Parent})};
    }

    auto TrafficCounter::ProtocolInstanceValue(
        const Prism::GenerationId Generation,
        const std::uint64_t Instance) const noexcept -> Prism::Statistics::TrafficValue
    {
        using Scope = Prism::Statistics::Scope;
        using Metric = Prism::Statistics::Metric;
        return {Counters_.Get({Scope::ProtocolInstance, Instance, Metric::UpBytes, {}, Generation}),
            Counters_.Get({Scope::ProtocolInstance, Instance, Metric::DownBytes, {}, Generation}),
            Counters_.Get({Scope::ProtocolInstance, Instance, Metric::Events, {}, Generation}),
            Counters_.Get({Scope::ProtocolInstance, Instance, Metric::Errors, {}, Generation})};
    }

    auto TrafficCounter::Dropped() const noexcept -> std::uint64_t
    {
        auto Result = UnassignedDrops_.load(std::memory_order_relaxed);
        for (const auto& Queue : Queues_)
            Result += Queue->Dropped.load(std::memory_order_relaxed);
        return Result;
    }

    auto TrafficCounter::AggregationFailures() const noexcept -> std::uint64_t
    {
        std::uint64_t Result = 0;
        for (const auto& Queue : Queues_)
            Result += Queue->AggregationFailures.load(std::memory_order_relaxed);
        return Result;
    }

    auto TrafficCounter::Sample(const std::uint64_t UnixMilliseconds) noexcept -> void
    {
        History_.Append({UnixMilliseconds,
            Value(Prism::Statistics::Scope::Process, Process_.Value())});
        const auto Drops = Dropped();
        const auto Failures = AggregationFailures();
        Analysis_.Sample(UnixMilliseconds,
            {Drops - PreviousHistoryDrops_, Failures - PreviousHistoryFailures_, false});
        PreviousHistoryDrops_ = Drops;
        PreviousHistoryFailures_ = Failures;
    }

    auto TrafficCounter::History() const -> std::vector<Prism::Statistics::TrafficSample>
    {
        return History_.Snapshot();
    }

    auto TrafficCounter::ConfigureHistory(Prism::Statistics::HistoryCatalog Catalog) -> void
    {
        Analysis_.Configure(std::move(Catalog));
    }

    auto TrafficCounter::HistorySnapshot(
        const Prism::Statistics::HistoryQuery& Request,
        const std::uint64_t Now) const -> Prism::Statistics::HistoryResult
    {
        return Analysis_.Query(Request, Now);
    }

    auto TrafficCounter::TakeHistoryBatch() -> std::vector<Prism::Statistics::HistoryRecord>
    {
        return Analysis_.TakePersistenceBatch();
    }

    auto TrafficCounter::RetireHistoryGeneration(const std::uint64_t Generation) -> void
    {
        Analysis_.RetireGeneration(Generation);
    }

    auto TrafficCounter::RecordRecognitionLatencyQueueDrop(const bool IsLatency) noexcept -> void
    {
        if (IsLatency)
        {
            RecognitionLatencyQueueDrops_.fetch_add(1U, std::memory_order_relaxed);
        }
    }

    auto TrafficCounter::RecordRecognitionLatencyAggregationFailure(
        const Prism::Foundation::TrafficEvent& Event) noexcept -> void
    {
        if (Event.Kind == Prism::Foundation::TrafficEventKind::RecognitionLatency)
        {
            RecognitionLatencyAggregationFailures_.fetch_add(1U, std::memory_order_relaxed);
        }
    }

    auto TrafficCounter::ToCounterScope(
        const Prism::Foundation::SessionTrafficOwner& Owner) noexcept -> CounterScope
    {
        return {Prism::Statistics::Scope::Session, Owner.Session.Value(), {}};
    }

    auto TrafficCounter::ToCounterScope(
        const Prism::Foundation::StreamTrafficOwner& Owner) noexcept -> CounterScope
    {
        return {Prism::Statistics::Scope::Stream, Owner.Stream.Value(), Owner.ParentSession};
    }

    auto TrafficCounter::ToCounterScope(
        const Prism::Foundation::TaskTrafficOwner& Owner) noexcept -> CounterScope
    {
        return {Prism::Statistics::Scope::Task, Owner.Task.Value(), {}};
    }

    auto TrafficCounter::ToCounterScope(
        const Prism::Foundation::TrafficRetirement& Owner) noexcept -> CounterScope
    {
        return std::visit([](const auto& Value) { return ToCounterScope(Value); }, Owner);
    }

    auto TrafficCounter::RecordRetirementFailure(
        const Prism::Foundation::TrafficRetirement& Owner) noexcept -> void
    {
        if (std::holds_alternative<Prism::Foundation::SessionTrafficOwner>(Owner))
            SessionRetirementFailures_.fetch_add(1U, std::memory_order_relaxed);
        else if (std::holds_alternative<Prism::Foundation::StreamTrafficOwner>(Owner))
            StreamRetirementFailures_.fetch_add(1U, std::memory_order_relaxed);
        else
            TaskRetirementFailures_.fetch_add(1U, std::memory_order_relaxed);
    }

    auto TrafficCounter::MatchesCounterScope(
        const Prism::Foundation::TrafficEvent& Event,
        const CounterScope Scope,
        const Prism::WorkerId Worker) noexcept -> bool
    {
        if (Event.Worker != Worker) return false;
        if (Scope.ScopeValue == Prism::Statistics::Scope::Session)
            return Event.Session.Value() == Scope.Id;
        if (Scope.ScopeValue == Prism::Statistics::Scope::Stream)
            return Event.Stream.Value() == Scope.Id && Event.Session == Scope.ParentSession;
        if (Scope.ScopeValue == Prism::Statistics::Scope::Task)
            return Event.Task.Value() == Scope.Id;
        return false;
    }

    auto TrafficCounter::FlushForRetirement(
        const CounterScope Scope,
        const Prism::WorkerId Worker) noexcept -> bool
    {
        bool ScopeComplete = true;
        for (std::size_t Index = 0; Index < Queues_.size(); ++Index)
        {
            const auto& Queue = Queues_[Index];
            Prism::Foundation::TrafficEvent Event;
            for (std::size_t Count = 0; Count < 1024U && Queue->Events.pop(Event); ++Count)
            {
                if (!Accumulate(Event))
                {
                    Queue->AggregationFailures.fetch_add(1U, std::memory_order_relaxed);
                    RecordRecognitionLatencyAggregationFailure(Event);
                    if (Event.Kind != Prism::Foundation::TrafficEventKind::RecognitionLatency &&
                        Index == Worker.Value() && MatchesCounterScope(Event, Scope, Worker))
                        ScopeComplete = false;
                }
                ConsumedObservations_.fetch_add(1U, std::memory_order_relaxed);
            }
        }
        return ScopeComplete;
    }

    auto TrafficCounter::RetireOnControl(
        const CounterScope Scope,
        const Prism::WorkerId Worker,
        Prism::Foundation::TrafficRetirement Owner)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        using Failure = Prism::Fault::Failure;
        if (Sealed_.load(std::memory_order_acquire))
        {
            RecordRetirementFailure(Owner);
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        if (!FlushForRetirement(Scope, Worker))
        {
            RecordRetirementFailure(Owner);
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
        if (Scope.ScopeValue == Prism::Statistics::Scope::Session)
            SessionProtocols_.erase(Scope.Id);
        Counters_.Retire(Scope);
        co_return std::expected<void, Failure>{};
    }

    auto TrafficCounter::Accumulate(const Prism::Foundation::TrafficEvent& Event) noexcept -> bool
    {
        if (Event.Kind == Prism::Foundation::TrafficEventKind::NetworkLatency)
            return Analysis_.Record(Event);
        if (Event.Kind == Prism::Foundation::TrafficEventKind::ProtocolAssociated)
        {
            if (Event.Session.Value() == 0U || Event.Protocol == 0U) return false;
            try
            {
                SessionProtocols_.insert_or_assign(Event.Session.Value(),
                    ProtocolAssociation{Event.Protocol, Event.ProtocolInstance, Event.Ingress,
                        Event.Transport, Event.Account});
            }
            catch (...)
            {
                return false;
            }
            return true;
        }
        if (Event.Kind == Prism::Foundation::TrafficEventKind::RecognitionLatency)
        {
            const auto Accepted = RecognitionLatency_.Record(
                Event.Generation, Event.DurationMicroseconds);
            if (Accepted) ObserveHistory(Event);
            return Accepted;
        }
        using Scope = Prism::Statistics::Scope;
        using Metric = Prism::Statistics::Metric;
        auto Protocol = std::uint64_t{0};
        auto ProtocolInstance = std::uint64_t{0};
        if (const auto It = SessionProtocols_.find(Event.Session.Value()); It != SessionProtocols_.end())
        {
            Protocol = It->second.Type;
            ProtocolInstance = It->second.Instance;
        }
        if (Event.Protocol != 0) Protocol = Event.Protocol;
        if (Event.ProtocolInstance != 0) ProtocolInstance = Event.ProtocolInstance;
        const std::array Scopes{
            std::pair{Scope::Process, Process_.Value()},
            std::pair{Scope::Worker, Event.Worker.Value()},
            std::pair{Scope::Account, Event.Account.Value()},
            std::pair{Scope::Session, Event.Session.Value()},
            std::pair{Scope::Stream, Event.Stream.Value()},
            std::pair{Scope::Task, Event.Task.Value()},
            std::pair{Scope::Protocol, Protocol},
            std::pair{Scope::ProtocolInstance, ProtocolInstance}};
        std::array<Prism::Statistics::CounterKey, 32> Keys{};
        std::array<std::uint64_t, 32> Deltas{};
        std::size_t Size = 0;
        for (const auto& [ScopeValue, Id] : Scopes)
        {
            if (Id == 0U) continue;
            Prism::SessionId Parent;
            if (ScopeValue == Scope::Stream) Parent = Event.Session;
            const auto Generation = ScopeValue == Scope::ProtocolInstance
                ? Event.Generation : Prism::GenerationId{};
            Keys[Size++] = {ScopeValue, Id, Metric::UpBytes, Parent, Generation};
            Keys[Size++] = {ScopeValue, Id, Metric::DownBytes, Parent, Generation};
            Keys[Size++] = {ScopeValue, Id, Metric::Events, Parent, Generation};
            Keys[Size++] = {ScopeValue, Id, Metric::Errors, Parent, Generation};
        }
        if (!Counters_.Prepare(std::span{Keys.data(), Size})) return false;
        const auto Terminal = Event.Kind == Prism::Foundation::TrafficEventKind::Completed;
        const auto Failed = Terminal && Event.Failure.Failed() &&
            Event.Failure.Code != Prism::Fault::Code::Canceled &&
            Event.Failure.Code != Prism::Fault::Code::Eof;
        for (std::size_t Index = 0; Index < Size; Index += 4U)
        {
            Deltas[Index] = Event.Up;
            Deltas[Index + 1U] = Event.Down;
            if (Terminal) Deltas[Index + 2U] = 1U;
            if (Failed) Deltas[Index + 3U] = 1U;
        }
        for (std::size_t Index = 0; Index < Size; ++Index)
            if (!Counters_.CanAdd(Keys[Index], Deltas[Index])) return false;
        for (std::size_t Index = 0; Index < Size; ++Index)
            if (!Counters_.Add(Keys[Index], Deltas[Index])) return false;
        ObserveHistory(Event);
        return true;
    }

    auto TrafficCounter::ObserveHistory(Prism::Foundation::TrafficEvent Event) noexcept -> void
    {
        if (const auto It = SessionProtocols_.find(Event.Session.Value()); It != SessionProtocols_.end())
        {
            if (Event.Protocol == 0) Event.Protocol = It->second.Type;
            if (Event.ProtocolInstance == 0) Event.ProtocolInstance = It->second.Instance;
            if (Event.Ingress == 0) Event.Ingress = It->second.Ingress;
            if (Event.Transport == Prism::Foundation::TrafficTransport::Unknown)
                Event.Transport = It->second.Transport;
            if (!Event.Account) Event.Account = It->second.Account;
        }
        (void)Analysis_.Record(Event);
    }
}

/** @file Metrics.cpp @brief 在控制执行域复制真实进程统计快照。 */

#include <Prism/Application/Operations/Metrics/Detail/Metrics.hpp>

#include <chrono>
#include <utility>

namespace Prism::Application::OperationsMetrics
{

    auto IsSupported(
        const std::shared_ptr<Application::RuntimeState> &State,
        const SharedRuntimeGenerationSnapshot &Snapshot) -> std::optional<MetricsSupport>
    {
        if (!State || !State->Process || !State->Traffic || !Snapshot || !Snapshot->Generation)
        {
            return {};
        }
        const auto Interval = State->StatisticsFlushArmedIntervalMilliseconds.load(
            std::memory_order_acquire);
        if (Interval <= 0 || !Snapshot->Generation->Configuration().Statistics.Enabled)
        {
            return {};
        }
        return MetricsSupport{static_cast<std::uint64_t>(Interval)};
    }

    auto Query(
        const std::shared_ptr<Application::RuntimeState> &State,
        const Prism::Operations::MetricsQuery &Request) -> Prism::Operations::QueryResult
    {
        using Prism::Operations::QueryResult;
        if (!State)
        {
            return QueryResult::Unavailable(Request.Correlation);
        }
        const auto Snapshot = State->ActiveGenerationSnapshot();
        const auto Support = IsSupported(State, Snapshot);
        if (!Support)
        {
            return QueryResult::Unavailable(Request.Correlation);
        }
        Prism::Operations::MetricsSnapshot Value;
        Value.Process = State->Process->Id();
        Value.Generation = Snapshot->Id();
        Value.CheckedAt = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        Value.Traffic = State->Traffic->Value(
            Prism::Statistics::Scope::Process, Value.Process.Value());
        Value.AcceptedObservations = State->Traffic->Accepted();
        Value.ConsumedObservations = State->Traffic->ConsumedObservations();
        Value.DroppedObservations = State->Traffic->Dropped();
        Value.AggregationFailures = State->Traffic->AggregationFailures();
        Value.RecognitionLatencyQueueDrops = State->Traffic->RecognitionLatencyQueueDrops();
        Value.RecognitionLatencyAggregationFailures =
            State->Traffic->RecognitionLatencyAggregationFailures();
        Value.RetirementFailures = {
            State->Traffic->SessionRetirementFailures(),
            State->Traffic->StreamRetirementFailures(),
            State->Traffic->TaskRetirementFailures()};
        Value.SampleIntervalMilliseconds = Support->SampleIntervalMilliseconds;
        Value.History = State->Traffic->History();
        Value.RecognitionLatency = State->Traffic->RecognitionLatency(Value.Generation);
        return QueryResult::Metrics(Request.Correlation, std::move(Value));
    }

} // namespace Prism::Application::OperationsMetrics

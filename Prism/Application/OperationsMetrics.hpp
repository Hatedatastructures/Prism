/** @file OperationsMetrics.hpp @brief Application 控制执行域上的真实进程统计查询。 */
#pragma once

#include <Prism/Application/RuntimeState.hpp>
#include <Prism/Operations/Metrics.hpp>
#include <Prism/Operations/Models.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

namespace Prism::Application::OperationsMetrics
{
    struct MetricsSupport final
    {
        std::uint64_t SampleIntervalMilliseconds{0};
    };

    /**
     * @brief 用本次查询已捕获的代次核验真实进程统计 owner 是否可读。
     * @param State 持有 process counter、timer 和控制 executor 的应用状态。
     * @param Snapshot 本次查询唯一读取的 live generation snapshot。
     * @return collector、实际已 arm timer 周期与该代启用配置均可读时返回同次快照结果。
     */
    [[nodiscard]] inline auto IsSupported(
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

    /**
     * @brief 在 Application 控制 executor 只捕获一次 live generation 并复制 process counter。
     * @details State 仅在此同步读取期间借用。采样历史只复制真实 timer 已写点，不持有
     *          session、stream、task 或代次服务图；未安装 owner 或功能关闭时返回 Unavailable。
     */
    [[nodiscard]] inline auto Query(
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
}

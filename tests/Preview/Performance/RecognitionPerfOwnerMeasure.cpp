/**
 * @file RecognitionPerfOwnerMeasure.cpp
 * @brief owner compare 的平台采样与 JSON 报告 owner。
 */

#include "RecognitionPerfOwnerMeasure.hpp"

#include <cmath>

namespace
{
    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;
    using Preview::Recognition::Perf::OwnerMeasurement;
    using Preview::Recognition::Perf::OwnerCompareVersion;
    using Preview::Recognition::Perf::OwnerTraceId;
    using Preview::Recognition::Perf::OwnerTrace;
    using Preview::Recognition::Perf::OwnerMeasurementReport;
    using Preview::Recognition::Perf::FixedUuidText;
    using Preview::Recognition::Perf::OwnerInputContract;
    using Preview::Recognition::Perf::OwnerProductionEntryGap;
    using Preview::Recognition::Perf::OwnerPlatformSampleIntervalMs;
    using Preview::Recognition::Perf::OwnerRepeatCycles;
    [[nodiscard]] auto JsonOptional(const std::optional<std::uint64_t> &Value) -> std::string
    {
        return Value ? std::to_string(*Value) : std::string{"null"};
    }

    [[nodiscard]] auto JsonString(const std::string_view Value) -> std::string
    {
        std::string Result;
        Result.reserve(Value.size());
        for (const auto Character : Value)
        {
            switch (Character)
            {
            case '\\': Result += "\\\\"; break;
            case '"': Result += "\\\""; break;
            case '\n': Result += "\\n"; break;
            case '\r': Result += "\\r"; break;
            case '\t': Result += "\\t"; break;
            default: Result.push_back(Character); break;
            }
        }
        return Result;
    }

}

namespace Preview::Recognition::Perf
{
    auto PrintOwnerPreflight(const OwnerPreflightReport &Report) -> bool
    {
        const auto &Preflight = Report.Preflight;
        const bool Valid = Preflight.HashValid && Preflight.CorrectnessValid &&
            Preflight.CleanupValid && Preflight.Errors == 0U;
        std::cout << "{\"case\":\"owner_compare_preflight\",\"variant\":\""
                  << Report.Variant << "\",\"semantic_model\":\"" << Report.SemanticModel
                  << "\",\"trace_version\":\"" << OwnerCompareVersion
                  << "\",\"trace_id\":" << OwnerTraceId << ",\"trace_hash\":"
                  << Report.Trace.Hash << ",\"cid_scale\":" << Report.Trace.Capacity
                  << ",\"fixed_uuid\":\"" << FixedUuidText
                  << "\",\"fixed_input_contract\":\"" << ::JsonString(OwnerInputContract)
                  << "\",\"trace_hash_valid\":" << (Preflight.HashValid ? "true" : "false")
                  << ",\"correctness_valid\":"
                  << (Preflight.CorrectnessValid ? "true" : "false")
                  << ",\"cleanup_valid\":" << (Preflight.CleanupValid ? "true" : "false")
                  << ",\"errors\":" << Preflight.Errors << ",\"valid\":"
                  << (Valid ? "true" : "false") << ",\"production_entry_gap\":\""
                  << ::JsonString(OwnerProductionEntryGap) << "\",\"error\":\""
                  << ::JsonString(Preflight.Error) << "\"}\n";
        return Valid;
    }
}

namespace
{
    [[nodiscard]] auto Percentile(
        const std::vector<std::uint64_t> &Values,
        const double Fraction) -> std::uint64_t
    {
        if (Values.empty())
        {
            return 0;
        }
        const auto Position = static_cast<std::size_t>(std::ceil(Fraction * Values.size())) - 1U;
        return Values[(std::min)(Position, Values.size() - 1U)];
    }

    auto PrintOwnerMeasurement(const OwnerMeasurementReport &Report) -> bool
    {
        const auto Owner = Report.Owner;
        const auto Variant = Report.Variant;
        const auto Round = Report.Round;
        const auto Concurrency = Report.Concurrency;
        const auto Order = Report.Order;
        const auto &Trace = Report.Trace;
        const auto Contract = Report.Contract;
        const auto SemanticModel = Report.SemanticModel;
        const auto ExpectedOperations = Report.ExpectedOperations;
        const auto &Measurement = Report.Measurement;
        if (!Measurement.PreflightOk)
        {
            std::cout << "{\"case\":\"owner_compare\",\"owner\":\"" << Owner
                      << "\",\"variant\":\"" << Variant << "\",\"round\":" << Round
                      << ",\"order\":\"" << Order << "\",\"concurrency\":" << Concurrency
                      << ",\"trace_version\":\"" << OwnerCompareVersion
                      << "\",\"trace_id\":" << OwnerTraceId << ",\"trace_hash\":"
                      << Trace.Hash << ",\"cid_scale\":" << Trace.AdditionalCids.size()
                      << ",\"cid_alias_count\":" << Trace.AliasCount
                      << ",\"sni_route_count\":" << Trace.SniRoutes.size()
                      << ",\"fixed_uuid\":\"" << FixedUuidText
                      << "\",\"fixed_input_contract\":\"" << JsonString(OwnerInputContract)
                      << "\",\"semantic_model\":\"" << SemanticModel
                      << "\",\"valid\":false,\"status\":\"preflight_error\","
                      << "\"production_entry_gap\":\"" << JsonString(OwnerProductionEntryGap)
                      << "\",\"error\":\"" << JsonString(Measurement.PreflightError) << "\"}\n";
            return false;
        }
        const bool OperationCountValid = Measurement.Operations == ExpectedOperations;
        if (Measurement.Errors != 0U || !OperationCountValid)
        {
            std::cout << "{\"case\":\"owner_compare\",\"owner\":\"" << Owner
                      << "\",\"variant\":\"" << Variant << "\",\"round\":" << Round
                      << ",\"order\":\"" << Order << "\",\"concurrency\":" << Concurrency
                      << ",\"trace_version\":\"" << OwnerCompareVersion
                      << "\",\"trace_id\":" << OwnerTraceId << ",\"trace_hash\":"
                      << Trace.Hash << ",\"cid_scale\":" << Trace.AdditionalCids.size()
                      << ",\"cid_alias_count\":" << Trace.AliasCount
                      << ",\"sni_route_count\":" << Trace.SniRoutes.size()
                      << ",\"fixed_uuid\":\"" << FixedUuidText
                      << "\",\"fixed_input_contract\":\"" << JsonString(OwnerInputContract)
                      << "\",\"semantic_model\":\"" << SemanticModel
                      << "\",\"valid\":false,\"status\":\"operation_error\",\"errors\":"
                      << Measurement.Errors << ",\"operations\":" << Measurement.Operations
                      << ",\"expected_operations\":" << ExpectedOperations
                      << ",\"operation_count_valid\":"
                      << (OperationCountValid ? "true" : "false")
                      << ",\"production_entry_gap\":\"" << JsonString(OwnerProductionEntryGap)
                      << "\"}\n";
            return false;
        }
        auto Timings = Measurement.Timings;
        std::sort(Timings.begin(), Timings.end());
        const auto PerSecond = Measurement.WallNanoseconds == 0
            ? 0.0
            : static_cast<double>(Measurement.Operations) * 1'000'000'000.0 /
                static_cast<double>(Measurement.WallNanoseconds);
        const auto Cpu = Measurement.After.Cpu100ns && Measurement.Before.Cpu100ns &&
                         *Measurement.After.Cpu100ns >= *Measurement.Before.Cpu100ns
            ? std::optional<std::uint64_t>{*Measurement.After.Cpu100ns - *Measurement.Before.Cpu100ns}
            : std::nullopt;
        std::cout << "{\"case\":\"owner_compare\",\"owner\":\"" << Owner
                  << "\",\"variant\":\"" << Variant << "\",\"round\":" << Round
                  << ",\"order\":\"" << Order << "\",\"concurrency\":" << Concurrency
                  << ",\"trace_version\":\"" << OwnerCompareVersion << "\",\"trace_id\":"
                  << OwnerTraceId << ",\"trace_hash\":" << Trace.Hash
                  << ",\"cid_scale\":" << Trace.AdditionalCids.size()
                  << ",\"cid_alias_count\":" << Trace.AliasCount
                  << ",\"sni_route_count\":" << Trace.SniRoutes.size()
                  << ",\"fixed_uuid\":\"" << FixedUuidText
                  << "\",\"fixed_input_contract\":\"" << JsonString(OwnerInputContract)
                  << "\",\"semantic_model\":\"" << SemanticModel
                  << "\",\"valid\":true,\"window_ns\":" << Measurement.WallNanoseconds
                  << ",\"operations\":" << Measurement.Operations << ",\"errors\":"
                  << Measurement.Errors << ",\"expected_operations\":" << ExpectedOperations
                  << ",\"operation_count_valid\":true,\"drops\":null,\"ops_per_sec\":" << PerSecond
                  << ",\"repeat_cycles\":" << OwnerRepeatCycles
                  << ",\"p50_ns\":" << Percentile(Timings, 0.50)
                  << ",\"p95_ns\":" << Percentile(Timings, 0.95)
                  << ",\"p99_ns\":" << Percentile(Timings, 0.99)
                  << ",\"ordinary_allocation_count\":" << Measurement.Allocations.Count
                  << ",\"ordinary_allocation_bytes\":" << Measurement.Allocations.Bytes
                  << ",\"aligned_allocation_count\":" << Measurement.Allocations.AlignedCount
                  << ",\"aligned_allocation_bytes\":" << Measurement.Allocations.AlignedBytes
                  << ",\"cpu_100ns\":";
        std::cout << JsonOptional(Cpu);
        std::cout << ",\"round_peak_rss_bytes\":" << JsonOptional(Measurement.RoundPeakRssBytes)
                  << ",\"round_peak_commit_bytes\":" << JsonOptional(Measurement.RoundPeakCommitBytes)
                  << ",\"lifetime_peak_rss_bytes\":" << JsonOptional(Measurement.LifetimePeakRssBytes)
                  << ",\"platform_samples\":" << Measurement.PlatformSamples
                  << ",\"platform_sample_interval_ms\":" << OwnerPlatformSampleIntervalMs
                  << ",\"rss_sampled\":"
                  << (Measurement.RoundPeakRssBytes.has_value() ? "true" : "false")
                  << ",\"rss_coverage\":\""
                  << (Measurement.RoundPeakRssBytes.has_value()
                          ? "windows_psapi_1ms_sampler"
                          : "not_sampled_platform_api_unavailable")
                  << "\",\"latency_coverage\":\"worker_operation_steady_clock\""
                  << ",\"throughput_coverage\":\"workers_wall_window\""
                  << ",\"allocation_coverage\":\"ordinary_and_aligned_process_new_requested_bytes\""
                  << ",\"cpu_scope\":\"process_getprocesstimes_delta_observer_included\""
                  << ",\"window_status\":\"workers_ready_to_done_end_clock_boundary_sample_before_join\",\"setup_excluded\":true"
                  << ",\"executor_contract\":\"" << Contract
                  << "\",\"production_entry_gap\":\"" << JsonString(OwnerProductionEntryGap)
                  << "\",\"allocation_boundary\":\"ordinary_and_aligned_process_new_requested_bytes_timed_window\"}\n";
        return Measurement.Errors == 0 && OperationCountValid;
    }


}

namespace Preview::Recognition::Perf
{
    auto JsonString(const std::string_view Value) -> std::string
    {
        return ::JsonString(Value);
    }

    auto PrintOwnerMeasurement(const OwnerMeasurementReport &Report) -> bool
    {
        return ::PrintOwnerMeasurement(Report);
    }
}

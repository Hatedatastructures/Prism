/**
 * @file ValidationCompareReport.cpp
 * @brief 配置校验对照工具的报告格式实现。
 */

#include "ValidationCompareMeasure.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace Prism::Application::Configuration::Perf::Report
{

    using ConfigurationErrorCode = Scenario::ConfigurationErrorCode;
    auto ErrorCodeName(ConfigurationErrorCode Code) -> const char *;

    namespace
    {

        auto Percentile(const std::vector<std::uint64_t> &Samples,
                        const std::size_t Percent) -> std::uint64_t
        {
            if (Samples.empty())
            {
                return 0;
            }
            auto Sorted = Samples;
            std::sort(Sorted.begin(), Sorted.end());
            const auto Rank = (Sorted.size() * Percent + 99U) / 100U;
            return Sorted[(std::max)(std::size_t{1}, Rank) - 1U];
        }

        auto AddAllocationStats(const Allocation::Stats &Left,
                                const Allocation::Stats &Right) -> Allocation::Stats
        {
            return {Left.Count + Right.Count,
                    Left.Bytes + Right.Bytes,
                    Left.AlignedCount + Right.AlignedCount,
                    Left.AlignedBytes + Right.AlignedBytes};
        }

        auto RssDelta(const Measure::RoundMeasurement &Measurement) -> std::string
        {
            if (!Measurement.RssBefore || !Measurement.RssAfter)
            {
                return "unavailable";
            }
            return std::to_string(static_cast<std::int64_t>(*Measurement.RssAfter) -
                                  static_cast<std::int64_t>(*Measurement.RssBefore));
        }

        auto PrintError(const char *Prefix, const Scenario::ErrorView &Error) -> void
        {
            std::printf("%s_code=%s %s_path=%s", Prefix,
                        Error.Present ? ErrorCodeName(Error.Code) : "none", Prefix,
                        Error.Present && !Error.Path.empty() ? Error.Path.c_str() : "-");
        }

    } // namespace

    auto VariantName(const VariantKind Kind) -> const char *
    {
        return Kind == VariantKind::A ? "A" : "B";
    }

    auto ErrorCodeName(const ConfigurationErrorCode Code) -> const char *
    {
        switch (Code)
        {
        case ConfigurationErrorCode::Parse:
            return "Parse";
        case ConfigurationErrorCode::UnknownField:
            return "UnknownField";
        case ConfigurationErrorCode::MissingField:
            return "MissingField";
        case ConfigurationErrorCode::InvalidType:
            return "InvalidType";
        case ConfigurationErrorCode::FileOpen:
            return "FileOpen";
        case ConfigurationErrorCode::UnsupportedSchemaVersion:
            return "UnsupportedSchemaVersion";
        case ConfigurationErrorCode::InvalidValue:
            return "InvalidValue";
        case ConfigurationErrorCode::DuplicateId:
            return "DuplicateId";
        case ConfigurationErrorCode::MissingReference:
            return "MissingReference";
        case ConfigurationErrorCode::UnknownMuxMode:
            return "UnknownMuxMode";
        case ConfigurationErrorCode::InvalidCarrierOptions:
            return "InvalidCarrierOptions";
        case ConfigurationErrorCode::UnresolvedSecret:
            return "UnresolvedSecret";
        case ConfigurationErrorCode::MissingCapability:
            return "MissingCapability";
        case ConfigurationErrorCode::InvalidConfiguration:
            return "InvalidConfiguration";
        case ConfigurationErrorCode::InvalidGeneration:
            return "InvalidGeneration";
        case ConfigurationErrorCode::HotReloadDisabled:
            return "HotReloadDisabled";
        case ConfigurationErrorCode::MissingAcknowledgement:
            return "MissingAcknowledgement";
        case ConfigurationErrorCode::WorkerRejected:
            return "WorkerRejected";
        case ConfigurationErrorCode::PublishConflict:
            return "PublishConflict";
        }
        return "Unknown";
    }

    auto PrintBoundaries() -> void
    {
        std::puts("construction_boundary=generated PreviewConfiguration plus glz JSON serialization; "
                  "--input reports construction_ns=0 and excludes file/decode setup");
        std::puts("parser_boundary=full ConfigurationParser::Parse including required-root precheck, glaze "
                  "decode, secret option setup, and ConfigurationValidator");
        std::puts("validator_boundary=ConfigurationValidator::Validate on the same structured configuration "
                  "with the frozen static builtin snapshot");
        std::puts("execution_boundary=single-threaded cold-start path; Validator mutates no "
                  "shared runtime state, so extra workers would measure scheduling instead "
                  "of startup validation");
        std::puts("memory_boundary=timed process-wide ordinary/aligned C++ operator new calls; "
                  "setup, output formatting, retained input and RSS are excluded from "
                  "allocation counters");
        std::puts("rss_boundary=process working set sampled before construction and after both "
                  "validation paths when the platform exposes it");
        std::puts("correctness_boundary=both paths must match the expected invalid marker and "
                  "exact first Code/Path; any mismatch returns nonzero");
    }

    auto PrintRound(const Options &Settings,
                    const Measure::RoundMeasurement &Measurement) -> void
    {
        const auto ConstructionAndParser =
            Measurement.ConstructionNanoseconds + Measurement.ParserNanoseconds;
        const auto ConstructionAndValidator =
            Measurement.ConstructionNanoseconds + Measurement.ValidatorNanoseconds;
        const auto TotalAllocations = AddAllocationStats(
            AddAllocationStats(Measurement.ConstructionAllocations,
                               Measurement.ParserAllocations),
            Measurement.ValidatorAllocations);
        const auto ExpectedCode = Measurement.Expected.Invalid
                                      ? ErrorCodeName(Measurement.Expected.Code)
                                      : "none";
        const auto ExpectedPath = Measurement.Expected.Invalid
                                      ? Measurement.Expected.Path.data()
                                      : "-";

        std::printf(
            "variant=%s scenario=%s nodes=%zu round=%zu rounds=%zu seed=%llu "
            "trace_hash=%016llx construction_ns=%llu parser_validation_ns=%llu "
            "validator_validation_ns=%llu total_parser_ns=%llu total_validator_ns=%llu "
            "construction_allocations=%llu construction_bytes=%llu "
            "parser_allocations=%llu parser_bytes=%llu validator_allocations=%llu "
            "validator_bytes=%llu allocation_count=%llu allocation_bytes=%llu "
            "aligned_allocation_count=%llu aligned_allocation_bytes=%llu "
            "rss_before_bytes=%s rss_after_bytes=%s rss_delta_bytes=%s "
            "expected_invalid=%d expected_code=%s expected_path=%s correctness_invalid=%d "
            "invalid_reason=%s ",
            VariantName(Settings.Variant), Scenario::ScenarioName(Measurement.Kind),
            Measurement.Nodes, Measurement.Round, Settings.Rounds,
            static_cast<unsigned long long>(Settings.Seed),
            static_cast<unsigned long long>(Measurement.TraceHash),
            static_cast<unsigned long long>(Measurement.ConstructionNanoseconds),
            static_cast<unsigned long long>(Measurement.ParserNanoseconds),
            static_cast<unsigned long long>(Measurement.ValidatorNanoseconds),
            static_cast<unsigned long long>(ConstructionAndParser),
            static_cast<unsigned long long>(ConstructionAndValidator),
            static_cast<unsigned long long>(Measurement.ConstructionAllocations.Count),
            static_cast<unsigned long long>(Measurement.ConstructionAllocations.Bytes),
            static_cast<unsigned long long>(Measurement.ParserAllocations.Count),
            static_cast<unsigned long long>(Measurement.ParserAllocations.Bytes),
            static_cast<unsigned long long>(Measurement.ValidatorAllocations.Count),
            static_cast<unsigned long long>(Measurement.ValidatorAllocations.Bytes),
            static_cast<unsigned long long>(TotalAllocations.Count),
            static_cast<unsigned long long>(TotalAllocations.Bytes),
            static_cast<unsigned long long>(TotalAllocations.AlignedCount),
            static_cast<unsigned long long>(TotalAllocations.AlignedBytes),
            Measurement.RssBefore ? std::to_string(*Measurement.RssBefore).c_str() : "-",
            Measurement.RssAfter ? std::to_string(*Measurement.RssAfter).c_str() : "-",
            RssDelta(Measurement).c_str(), Measurement.Expected.Invalid ? 1 : 0,
            ExpectedCode, ExpectedPath, Measurement.CorrectnessInvalid ? 1 : 0,
            Measurement.InvalidReason.c_str());
        PrintError("parser_first_error", Measurement.ParserError);
        std::putchar(' ');
        PrintError("validator_first_error", Measurement.ValidatorError);
        std::printf(" first_error_source=%s\n",
                    Measurement.ParserError.Present ? "parser"
                    : Measurement.ValidatorError.Present ? "validator"
                                                        : "none");
    }

    auto PrintSummary(const Options &Settings, const ScenarioKind Kind,
                      const std::vector<Measure::RoundMeasurement> &Measurements) -> void
    {
        std::vector<std::uint64_t> Construction;
        std::vector<std::uint64_t> ParserValidation;
        std::vector<std::uint64_t> ValidatorValidation;
        std::vector<std::uint64_t> TotalParser;
        std::vector<std::uint64_t> TotalValidator;
        Construction.reserve(Measurements.size());
        ParserValidation.reserve(Measurements.size());
        ValidatorValidation.reserve(Measurements.size());
        TotalParser.reserve(Measurements.size());
        TotalValidator.reserve(Measurements.size());

        bool Invalid = false;
        std::uint64_t AllocationCount = 0;
        std::uint64_t AllocationBytes = 0;
        for (const auto &Measurement : Measurements)
        {
            Construction.push_back(Measurement.ConstructionNanoseconds);
            ParserValidation.push_back(Measurement.ParserNanoseconds);
            ValidatorValidation.push_back(Measurement.ValidatorNanoseconds);
            TotalParser.push_back(Measurement.ConstructionNanoseconds +
                                  Measurement.ParserNanoseconds);
            TotalValidator.push_back(Measurement.ConstructionNanoseconds +
                                     Measurement.ValidatorNanoseconds);
            Invalid = Invalid || Measurement.CorrectnessInvalid;
            const auto Total = AddAllocationStats(
                AddAllocationStats(Measurement.ConstructionAllocations,
                                   Measurement.ParserAllocations),
                Measurement.ValidatorAllocations);
            AllocationCount += Total.Count;
            AllocationBytes += Total.Bytes;
        }

        const auto &First = Measurements.front();
        std::printf(
            "summary variant=%s scenario=%s nodes=%zu rounds=%zu seed=%llu "
            "trace_hash=%016llx p50_construction_ns=%llu p95_construction_ns=%llu "
            "p99_construction_ns=%llu p50_parser_ns=%llu p95_parser_ns=%llu "
            "p99_parser_ns=%llu p50_validator_ns=%llu p95_validator_ns=%llu "
            "p99_validator_ns=%llu p50_total_parser_ns=%llu p95_total_parser_ns=%llu "
            "p99_total_parser_ns=%llu p50_total_validator_ns=%llu "
            "p95_total_validator_ns=%llu p99_total_validator_ns=%llu "
            "allocation_count_total=%llu allocation_bytes_total=%llu correctness_invalid=%d\n",
            VariantName(Settings.Variant), Scenario::ScenarioName(Kind), First.Nodes,
            Measurements.size(), static_cast<unsigned long long>(Settings.Seed),
            static_cast<unsigned long long>(First.TraceHash),
            static_cast<unsigned long long>(Percentile(Construction, 50)),
            static_cast<unsigned long long>(Percentile(Construction, 95)),
            static_cast<unsigned long long>(Percentile(Construction, 99)),
            static_cast<unsigned long long>(Percentile(ParserValidation, 50)),
            static_cast<unsigned long long>(Percentile(ParserValidation, 95)),
            static_cast<unsigned long long>(Percentile(ParserValidation, 99)),
            static_cast<unsigned long long>(Percentile(ValidatorValidation, 50)),
            static_cast<unsigned long long>(Percentile(ValidatorValidation, 95)),
            static_cast<unsigned long long>(Percentile(ValidatorValidation, 99)),
            static_cast<unsigned long long>(Percentile(TotalParser, 50)),
            static_cast<unsigned long long>(Percentile(TotalParser, 95)),
            static_cast<unsigned long long>(Percentile(TotalParser, 99)),
            static_cast<unsigned long long>(Percentile(TotalValidator, 50)),
            static_cast<unsigned long long>(Percentile(TotalValidator, 95)),
            static_cast<unsigned long long>(Percentile(TotalValidator, 99)),
            static_cast<unsigned long long>(AllocationCount),
            static_cast<unsigned long long>(AllocationBytes), Invalid ? 1 : 0);
    }

} // namespace Prism::Application::Configuration::Perf::Report

/**
 * @file ConfigurationValidationCompareMeasure.cpp
 * @brief 配置校验对照工具的逐轮测量实现。
 */

#include "ConfigurationValidationCompareMeasure.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace Prism::Application::Configuration::Perf
{
    namespace Allocation
    {
        auto Allocate(std::size_t Size) -> void *;
        auto AllocateAligned(std::size_t Size, std::size_t Alignment) -> void *;
        auto ReleaseAligned(void *Memory) noexcept -> void;
    }
    namespace Report
    {
        auto PrintRound(const Options &Settings, const Measure::RoundMeasurement &Measurement) -> void;
        auto PrintSummary(const Options &Settings, ScenarioKind Kind,
                          const std::vector<Measure::RoundMeasurement> &Measurements) -> void;
    }
}

#if defined(_WIN32)
#    if !defined(NOMINMAX)
#        define NOMINMAX
#    endif
#    include <windows.h>
#    include <psapi.h>
#elif defined(__linux__)
#    include <unistd.h>
#endif

namespace Prism::Application::Configuration::Perf::Measure
{

    namespace
    {

        using Clock = std::chrono::steady_clock;

        auto CurrentRssBytes() -> std::optional<std::uint64_t>
        {
#if defined(_WIN32)
            PROCESS_MEMORY_COUNTERS Counters{};
            if (GetProcessMemoryInfo(GetCurrentProcess(), &Counters, sizeof(Counters)) != 0)
            {
                return static_cast<std::uint64_t>(Counters.WorkingSetSize);
            }
#elif defined(__linux__)
            std::FILE *File = std::fopen("/proc/self/statm", "r");
            if (File == nullptr)
            {
                return std::nullopt;
            }
            unsigned long long TotalPages = 0;
            unsigned long long ResidentPages = 0;
            const auto Read = std::fscanf(File, "%llu %llu", &TotalPages, &ResidentPages);
            std::fclose(File);
            if (Read == 2)
            {
                const auto PageSize = sysconf(_SC_PAGESIZE);
                if (PageSize > 0)
                {
                    return static_cast<std::uint64_t>(ResidentPages) *
                           static_cast<std::uint64_t>(PageSize);
                }
            }
#endif
            return std::nullopt;
        }

        auto MarkInvalid(RoundMeasurement &Measurement, const std::string_view Reason) -> void
        {
            if (!Measurement.CorrectnessInvalid)
            {
                Measurement.InvalidReason = Reason;
            }
            Measurement.CorrectnessInvalid = true;
        }

        auto RunRound(const RoundRequest &Request) -> RoundMeasurement
        {
            RoundMeasurement Measurement;
            Measurement.Round = Request.Round;
            Measurement.Kind = Request.Plan.Kind;
            Measurement.Expected = Scenario::MakeExpectedError(Request.Plan.Kind);
            Measurement.RssBefore = CurrentRssBytes();

            std::optional<Scenario::Scenario> Generated;
            const Scenario::Scenario *Active = nullptr;
            {
                Allocation::Window Window;
                const auto Started = Clock::now();
                if (Request.Plan.Input != nullptr)
                {
                    Active = Request.Plan.Input;
                }
                else
                {
                    Generated.emplace(Scenario::MakeScenario(
                        Scenario::ScenarioSpec{Request.Plan.Settings.Nodes,
                                               Request.Plan.Settings.Seed,
                                               Request.Plan.Kind}));
                    Active = &*Generated;
                }
                const auto Finished = Clock::now();
                Measurement.ConstructionNanoseconds = Request.Plan.Input != nullptr
                                                           ? 0
                                                           : static_cast<std::uint64_t>(
                                                                 std::max<std::int64_t>(
                                                                     1,
                                                                     std::chrono::duration_cast<
                                                                         std::chrono::nanoseconds>(
                                                                         Finished - Started)
                                                                         .count()));
                Measurement.ConstructionAllocations = Window.Stop();
            }

            if (Active == nullptr)
            {
                throw std::invalid_argument("scenario was not constructed");
            }
            Measurement.Nodes = Active->Nodes;
            Measurement.TraceHash = Active->TraceHash;
            Measurement.Expected = Active->Expected;

            {
                Allocation::Window Window;
                const auto Started = Clock::now();
                const auto Parsed = Scenario::ConfigurationParser::Parse(
                    {.Json = Active->Json,
                     .Options = Scenario::MakeValidationOptions(Request.Plan.Builtins)});
                const auto Finished = Clock::now();
                Measurement.ParserNanoseconds = static_cast<std::uint64_t>(
                    std::max<std::int64_t>(
                        1,
                        std::chrono::duration_cast<std::chrono::nanoseconds>(Finished - Started)
                            .count()));
                Measurement.ParserAllocations = Window.Stop();
                Measurement.ParserError = Scenario::CaptureError(Parsed);
            }

            {
                Allocation::Window Window;
                const auto Started = Clock::now();
                const auto Validated = Scenario::ConfigurationValidator::Validate(
                    Scenario::ValidationRequest{
                        Active->Configuration,
                        Scenario::MakeValidationOptions(Request.Plan.Builtins)});
                const auto Finished = Clock::now();
                Measurement.ValidatorNanoseconds = static_cast<std::uint64_t>(
                    std::max<std::int64_t>(
                        1,
                        std::chrono::duration_cast<std::chrono::nanoseconds>(Finished - Started)
                            .count()));
                Measurement.ValidatorAllocations = Window.Stop();
                Measurement.ValidatorError = Scenario::CaptureError(Validated);
            }

            Measurement.RssAfter = CurrentRssBytes();
            if (!Scenario::MatchesExpected(Measurement.ParserError, Measurement.Expected))
            {
                MarkInvalid(Measurement, "parser_expected_first_error");
            }
            if (!Scenario::MatchesExpected(Measurement.ValidatorError, Measurement.Expected))
            {
                MarkInvalid(Measurement, "validator_expected_first_error");
            }
            if (!Scenario::SameError(Measurement.ParserError, Measurement.ValidatorError))
            {
                MarkInvalid(Measurement, "parser_validator_first_error_mismatch");
            }
            return Measurement;
        }

    } // namespace

    auto RunValidationOnly(const Options &Settings,
                           const Scenario::SnapshotPointer &Builtins) -> int
    {
        const std::array<std::size_t, 2> NodeCounts{64U, 1024U};
        const std::array<ScenarioKind, 2> Scenarios{
            ScenarioKind::Valid, ScenarioKind::CarrierRouteConflict};
        bool Valid = true;
        if (!Settings.InputPath.empty())
        {
            const auto Input = Scenario::LoadScenario(Settings, Builtins);
            Valid = Scenario::ValidateScenario(Input, Builtins);
            std::printf("semantic_case=input scenario=%s nodes=%zu valid=%d\n",
                        Scenario::ScenarioName(Input.Kind), Input.Nodes, Valid ? 1 : 0);
        }
        else
        {
            const auto &RequestedNodes = Settings.Scenario == ScenarioKind::All
                                             ? NodeCounts
                                             : std::array<std::size_t, 2>{
                                                   Settings.Nodes, Settings.Nodes};
            const auto ScenarioCount = Settings.Scenario == ScenarioKind::All
                                            ? Scenarios.size()
                                            : std::size_t{1};
            for (std::size_t NodeIndex = 0; NodeIndex < 2U; ++NodeIndex)
            {
                if (Settings.Scenario != ScenarioKind::All && NodeIndex > 0U)
                {
                    break;
                }
                for (std::size_t ScenarioIndex = 0; ScenarioIndex < ScenarioCount;
                     ++ScenarioIndex)
                {
                    const auto Kind = Settings.Scenario == ScenarioKind::All
                                           ? Scenarios[ScenarioIndex]
                                           : Settings.Scenario;
                    const auto ScenarioValue = Scenario::MakeScenario(
                        Scenario::ScenarioSpec{RequestedNodes[NodeIndex], Settings.Seed, Kind});
                    const auto CaseValid = Scenario::ValidateScenario(ScenarioValue, Builtins);
                    Valid = Valid && CaseValid;
                    std::printf(
                        "semantic_case=scenario:%s nodes=%zu valid=%d trace_hash=%016llx\n",
                        Scenario::ScenarioName(Kind), ScenarioValue.Nodes, CaseValid ? 1 : 0,
                        static_cast<unsigned long long>(ScenarioValue.TraceHash));
                }
            }
        }
        if (Valid)
        {
            std::puts("semantic_preflight=pass");
            return 0;
        }
        std::puts("semantic_preflight=fail");
        return 1;
    }

    auto RunScenarioPlan(const RunPlan &Plan) -> int
    {
        std::vector<RoundMeasurement> Measurements;
        Measurements.reserve(Plan.Settings.Rounds);
        bool Invalid = false;
        for (std::size_t Round = 1; Round <= Plan.Settings.Rounds; ++Round)
        {
            auto Measurement = RunRound(RoundRequest{Plan, Round});
            Invalid = Invalid || Measurement.CorrectnessInvalid;
            Report::PrintRound(Plan.Settings, Measurement);
            Measurements.push_back(std::move(Measurement));
        }
        Report::PrintSummary(Plan.Settings, Plan.Kind, Measurements);
        return Invalid ? 1 : 0;
    }

} // namespace Prism::Application::Configuration::Perf::Measure

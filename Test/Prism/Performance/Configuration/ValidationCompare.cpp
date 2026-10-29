/**
 * @file ValidationCompare.cpp
 * @brief Preview 配置 Parser/Validator 基线对照 CLI。
 * @details 该工具只测旧生产 ConfigurationParser/ConfigurationValidator 的
 *          构图、JSON 解析和完整校验成本，为后续 A/B 实现提供固定输入基线。
 */

#include "ValidationCompare.hpp"

#include "ValidationMeasure.hpp"
#include "ValidationCompareCase.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>

namespace Prism::Application::Configuration::Perf
{
    auto Run(const Options &Settings) -> int;
    auto PrintUsage() -> void;
    namespace Allocation
    {
        auto Allocate(std::size_t Size) -> void *;
        auto AllocateAligned(std::size_t Size, std::size_t Alignment) -> void *;
        auto ReleaseAligned(void *Memory) noexcept -> void;
    }
    namespace Scenario
    {
        void GenerateScenario(Scenario &Workload);
        auto AddressForVersion(const Scenario &Workload, std::uint32_t Version)
            -> boost::asio::ip::address;
        void ValidateFastSemantics();
        void ValidateSemantics();
    }
    namespace Measure
    {
        auto RunValidationOnly(const Options &Settings, const Scenario::SnapshotPointer &Builtins) -> int;
        auto RunScenarioPlan(const RunPlan &Plan) -> int;
    }
    namespace Report
    {
        auto VariantName(VariantKind Kind) -> const char *;
        auto ErrorCodeName(Scenario::ConfigurationErrorCode Code) -> const char *;
        auto PrintBoundaries() -> void;
        auto PrintRound(const Options &Settings, const Measure::RoundMeasurement &Measurement) -> void;
        auto PrintSummary(const Options &Settings, ScenarioKind Kind,
                          const std::vector<Measure::RoundMeasurement> &Measurements) -> void;
    }
}

namespace Prism::Application::Configuration::Perf
{

    namespace
    {

        auto Require(const bool Condition, const std::string_view Message) -> void
        {
            if (!Condition)
            {
                throw std::invalid_argument(std::string{Message});
            }
        }

        auto ParseUnsigned(const std::string_view Text) -> std::uint64_t
        {
            std::uint64_t Value = 0;
            const auto Result = std::from_chars(Text.data(), Text.data() + Text.size(), Value);
            Require(Result.ec == std::errc{} && Result.ptr == Text.data() + Text.size(),
                    "invalid unsigned integer");
            return Value;
        }

        auto ParseScenario(const std::string_view Text) -> ScenarioKind
        {
            if (Text == "valid")
            {
                return ScenarioKind::Valid;
            }
            if (Text == "carrier-conflict" || Text == "carrier-route-conflict")
            {
                return ScenarioKind::CarrierRouteConflict;
            }
            if (Text == "all")
            {
                return ScenarioKind::All;
            }
            throw std::invalid_argument(
                "scenario must be valid, carrier-route-conflict, or all");
        }

        auto ParseVariant(const std::string_view Text) -> VariantKind
        {
            if (Text == "A" || Text == "a")
            {
                return VariantKind::A;
            }
            if (Text == "B" || Text == "b")
            {
                return VariantKind::B;
            }
            throw std::invalid_argument("variant must be A or B");
        }

        auto ParseOptions(const int Argc, char **Argv, Options &Settings) -> bool
        {
            bool Help = false;
            for (int Index = 1; Index < Argc; ++Index)
            {
                const std::string_view Argument{Argv[Index]};
                if (Argument == "--help" || Argument == "-h")
                {
                    Help = true;
                    continue;
                }
                if (Argument == "--validate-only")
                {
                    Settings.ValidateOnly = true;
                    continue;
                }
                Require(Index + 1 < Argc, "option is missing its value");
                const std::string_view Value{Argv[++Index]};
                if (Argument == "--nodes")
                {
                    Settings.Nodes = static_cast<std::size_t>(ParseUnsigned(Value));
                }
                else if (Argument == "--rounds")
                {
                    Settings.Rounds = static_cast<std::size_t>(ParseUnsigned(Value));
                }
                else if (Argument == "--seed")
                {
                    Settings.Seed = ParseUnsigned(Value);
                }
                else if (Argument == "--scenario")
                {
                    Settings.Scenario = ParseScenario(Value);
                }
                else if (Argument == "--variant")
                {
                    Settings.Variant = ParseVariant(Value);
                }
                else if (Argument == "--input")
                {
                    Settings.InputPath = std::filesystem::path{std::string(Value)};
                }
                else if (Argument == "--emit-input")
                {
                    Settings.EmitInputPath = std::filesystem::path{std::string(Value)};
                }
                else
                {
                    throw std::invalid_argument("unknown option");
                }
            }
            if (Help)
            {
                return false;
            }
            Require(Settings.Nodes == 64U || Settings.Nodes == 1024U,
                    "nodes must be 64 or 1024");
            Require(Settings.Rounds >= 1U && Settings.Rounds <= 100U,
                    "rounds must be between 1 and 100");
            Require(Settings.InputPath.empty() || Settings.EmitInputPath.empty(),
                    "input and emit-input cannot be combined");
            Require(Settings.Scenario != ScenarioKind::All ||
                        (Settings.InputPath.empty() && Settings.EmitInputPath.empty()),
                    "all cannot be combined with input or emit-input");
            Require(Settings.InputPath.empty() || Settings.Scenario != ScenarioKind::All,
                    "input requires an explicit scenario");
            Require(Settings.EmitInputPath.empty() || Settings.Scenario != ScenarioKind::All,
                    "emit-input requires an explicit scenario");
            return true;
        }

    } // namespace

    auto PrintUsage() -> void
    {
        std::puts("ValidationCompare --nodes 64|1024");
        std::puts("  --scenario valid|carrier-route-conflict|all");
        std::puts("  [--rounds N (1..100)] [--seed N] [--variant A|B]");
        std::puts("  [--input path.json | --emit-input path.json]");
        std::puts("ValidationCompare --validate-only");
        std::puts("default: --nodes 64 --scenario all --rounds 5 --seed 3239730925");
        std::puts("A/B method: generate one input, then run both executables with the same");
        std::puts("--input, --nodes, --scenario, --seed and --rounds settings.");
        std::puts("External A/B runner: execute at least five alternating A/B or B/A rounds;");
        std::puts("--rounds 1 is allowed for one externally scheduled round.");
    }

    auto Run(const Options &Settings) -> int
    {
        const auto Builtins = Scenario::MakeStaticBuiltinSnapshot();
        Require(Builtins != nullptr, "cannot freeze static builtin snapshot");

        if (!Settings.EmitInputPath.empty())
        {
            const auto ScenarioValue = Scenario::MakeScenario(
                Scenario::ScenarioSpec{Settings.Nodes, Settings.Seed, Settings.Scenario});
            Scenario::WriteFile(Settings.EmitInputPath, ScenarioValue.Json);
            std::printf("input_written=%s scenario=%s nodes=%zu trace_hash=%016llx\n",
                        Settings.EmitInputPath.string().c_str(),
                        Scenario::ScenarioName(Settings.Scenario), ScenarioValue.Nodes,
                        static_cast<unsigned long long>(ScenarioValue.TraceHash));
        }

        if (Settings.ValidateOnly)
        {
            return Measure::RunValidationOnly(Settings, Builtins);
        }

        Report::PrintBoundaries();

        if (!Settings.InputPath.empty())
        {
            const auto Input = Scenario::LoadScenario(Settings, Builtins);
            return Measure::RunScenarioPlan(
                Measure::RunPlan{Settings, Builtins, Settings.Scenario, &Input});
        }

        if (Settings.Scenario == ScenarioKind::All)
        {
            const auto ValidResult = Measure::RunScenarioPlan(
                Measure::RunPlan{Settings, Builtins, ScenarioKind::Valid, nullptr});
            const auto ConflictResult = Measure::RunScenarioPlan(
                Measure::RunPlan{Settings, Builtins, ScenarioKind::CarrierRouteConflict, nullptr});
            return ValidResult == 0 && ConflictResult == 0 ? 0 : 1;
        }
        return Measure::RunScenarioPlan(
            Measure::RunPlan{Settings, Builtins, Settings.Scenario, nullptr});
    }

} // namespace Prism::Application::Configuration::Perf

auto main(const int Argc, char **Argv) -> int
{
    try
    {
        Prism::Application::Configuration::Perf::Options Settings;
        if (!Prism::Application::Configuration::Perf::ParseOptions(Argc, Argv, Settings))
        {
            Prism::Application::Configuration::Perf::PrintUsage();
            return 0;
        }
        return Prism::Application::Configuration::Perf::Run(Settings);
    }
    catch (const std::exception &Error)
    {
        std::fprintf(stderr, "[FAIL] %s\n", Error.what());
        Prism::Application::Configuration::Perf::PrintUsage();
        return 2;
    }
}

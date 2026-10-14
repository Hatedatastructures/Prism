/**
 * @file SessionRegistryCompare.cpp
 * @brief SessionRegistryCompare CLI entry.
 */

#include "SessionRegistryCompare.hpp"

#include <charconv>
#include <cstdio>
#include <exception>
#include <stdexcept>
#include <string>
#include <string_view>

namespace Preview::Runtime::Perf
{
    auto Run(const Options &Settings) -> int;
}

namespace
{

    using Preview::Runtime::Perf::ModelKind;
    using Preview::Runtime::Perf::Options;
    using Preview::Runtime::Perf::WorkloadKind;

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

    auto ParseModel(const std::string_view Text) -> ModelKind
    {
        if (Text == "A" || Text == "a")
        {
            return ModelKind::CurrentCow;
        }
        if (Text == "B" || Text == "b")
        {
            return ModelKind::ShardedCow;
        }
        if (Text == "C" || Text == "c")
        {
            return ModelKind::ExecutorTable;
        }
        if (Text == "all")
        {
            return ModelKind::All;
        }
        throw std::invalid_argument("variant must be A, B, C, or all");
    }

    auto ParseWorkload(const std::string_view Text) -> WorkloadKind
    {
        if (Text == "read" || Text == "read-heavy")
        {
            return WorkloadKind::ReadHeavy;
        }
        if (Text == "churn")
        {
            return WorkloadKind::Churn;
        }
        throw std::invalid_argument("workload must be read-heavy or churn");
    }

    auto PrintUsage() -> void
    {
        std::puts("SessionRegistryCompare --variant A|B|C|all --active 64|1024|10000");
        std::puts("  --executors 1|2|4 --workload read-heavy|churn");
        std::puts("  [--operations N] [--rounds N] [--seed N]");
        std::puts("SessionRegistryCompare --validate-only");
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
            if (Argument == "--variant")
            {
                Settings.Model = ParseModel(Value);
            }
            else if (Argument == "--active")
            {
                Settings.ActiveSessions = static_cast<std::size_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--executors")
            {
                Settings.Executors = static_cast<std::size_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--workload")
            {
                Settings.Workload = ParseWorkload(Value);
            }
            else if (Argument == "--operations")
            {
                Settings.OperationsPerLane = static_cast<std::size_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--rounds")
            {
                Settings.Rounds = static_cast<std::size_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--seed")
            {
                Settings.Seed = ParseUnsigned(Value);
            }
            else
            {
                throw std::invalid_argument("unknown option");
            }
        }
        if (Help)
        {
            PrintUsage();
            return false;
        }
        Require(Settings.ActiveSessions == 64 || Settings.ActiveSessions == 1024 ||
                    Settings.ActiveSessions == 10000,
                "active must be 64, 1024, or 10000");
        Require(Settings.Executors == 1 || Settings.Executors == 2 || Settings.Executors == 4,
                "executors must be 1, 2, or 4");
        Require(Settings.OperationsPerLane >= 100, "operations must be at least 100");
        Require(Settings.Rounds >= 5, "rounds must be at least five");
        if (!Settings.ValidateOnly)
        {
            Require(Settings.Model != ModelKind::All || Settings.Rounds >= 5,
                    "all variants require at least five rounds");
        }
        return true;
    }

} // namespace

auto main(const int Argc, char **Argv) -> int
{
    try
    {
        Options Settings;
        if (!ParseOptions(Argc, Argv, Settings))
        {
            return 0;
        }
        return Preview::Runtime::Perf::Run(Settings);
    }
    catch (const std::exception &Error)
    {
        std::fprintf(stderr, "[FAIL] %s\n", Error.what());
        PrintUsage();
        return 2;
    }
}

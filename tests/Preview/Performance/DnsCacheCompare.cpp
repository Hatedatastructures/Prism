/**
 * @file DnsCacheCompare.cpp
 * @brief 运行同一预生成 trace 的 DNS cache 对照实验。
 * @details 本文件负责 CLI、计时、结果报告和本 executable 的分配计数 hook。
 */

#include "DnsCacheScenario.hpp"
#include "DnsCacheVariants.hpp"
#include "DnsCacheMeasure.hpp"

namespace Preview::Network::Dns::Compare::Perf
{
    auto ValidateAllocationInstrumentation() -> void;
    auto Run(const Scenario &Workload) -> int;
}

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <latch>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#    if !defined(NOMINMAX)
#        define NOMINMAX
#    endif
#    include <windows.h>
#    include <malloc.h>
#    include <psapi.h>
#endif

namespace Preview::Network::Dns::Compare
{
    auto ValidateSemantics() -> void;
    auto ValidateFastSemantics() -> void;
    auto GenerateScenario(Scenario &Workload) -> void;
    auto ValidateScenario(const Scenario &Workload) -> void;
}
namespace Preview::Network::Dns::Compare::Perf
{
    auto Require(bool Condition, std::string_view Message) -> void;
}
namespace
{
    namespace Compare = Preview::Network::Dns::Compare;
    namespace Dns = Preview::Network::Dns;

    using Preview::Network::Dns::Compare::Perf::Require;
    using Clock = std::chrono::steady_clock;
    using Compare::ClockCache;
    using Compare::CurrentCache;
    using Compare::IntrusiveCache;
    using Compare::Options;
    using Compare::Scenario;
    using Compare::Variant;
    using Compare::WorkloadKind;


    enum class ParseResult
    {
        Run,
        Help,
        ValidateOnly
    };

    auto ParseUnsigned(const std::string_view Text) -> std::uint64_t
    {
        std::uint64_t Value = 0;
        const auto Result = std::from_chars(Text.data(), Text.data() + Text.size(), Value);
        Require(Result.ec == std::errc{} && Result.ptr == Text.data() + Text.size(),
                "invalid unsigned integer argument");
        return Value;
    }

    auto ParseOptions(const int Argc, char **Argv, Options &Settings) -> ParseResult
    {
        bool HasVariant = false;
        bool HasCapacity = false;
        bool HasHitRate = false;
        bool HasDistribution = false;
        bool HasExecutors = false;

        for (int Index = 1; Index < Argc; ++Index)
        {
            const std::string_view Argument{Argv[Index]};
            if (Argument == "--help" || Argument == "-h")
            {
                return ParseResult::Help;
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
                HasVariant = true;
                if (Value == "A" || Value == "a")
                {
                    Settings.Selected = Variant::Current;
                }
                else if (Value == "B" || Value == "b")
                {
                    Settings.Selected = Variant::Intrusive;
                }
                else if (Value == "C" || Value == "c")
                {
                    Settings.Selected = Variant::Clock;
                }
                else
                {
                    throw std::runtime_error("variant must be A, B, or C");
                }
            }
            else if (Argument == "--capacity")
            {
                HasCapacity = true;
                Settings.Capacity = static_cast<std::size_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--hit-rate")
            {
                HasHitRate = true;
                Settings.HitPercent = static_cast<std::uint32_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--distribution")
            {
                HasDistribution = true;
                if (Value == "uniform")
                {
                    Settings.AccessDistribution = Compare::Distribution::Uniform;
                }
                else if (Value == "hotspot")
                {
                    Settings.AccessDistribution = Compare::Distribution::Hotspot;
                }
                else
                {
                    throw std::runtime_error("distribution must be uniform or hotspot");
                }
            }
            else if (Argument == "--workload")
            {
                if (Value == "get" || Value == "get-only")
                {
                    Settings.Workload = WorkloadKind::GetOnly;
                }
                else if (Value == "mixed")
                {
                    Settings.Workload = WorkloadKind::Mixed;
                }
                else
                {
                    throw std::runtime_error("workload must be get-only or mixed");
                }
            }
            else if (Argument == "--executors")
            {
                HasExecutors = true;
                Settings.Executors = static_cast<std::size_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--operations")
            {
                Settings.Operations = static_cast<std::size_t>(ParseUnsigned(Value));
            }
            else if (Argument == "--seed")
            {
                Settings.Seed = ParseUnsigned(Value);
            }
            else
            {
                throw std::runtime_error("unknown option");
            }
        }

        if (Settings.ValidateOnly)
        {
            Require(Argc == 2, "--validate-only cannot be combined with benchmark options");
            return ParseResult::ValidateOnly;
        }
        Require(HasVariant && HasCapacity && HasHitRate && HasDistribution && HasExecutors,
                "benchmark requires --variant, --capacity, --hit-rate, --distribution, and --executors");
        Require(Settings.Capacity == 64 || Settings.Capacity == 1024,
                "capacity must be 64 or 1024");
        Require(Settings.HitPercent == 95 || Settings.HitPercent == 50 || Settings.HitPercent == 5,
                "hit rate must be 95, 50, or 5");
        Require(Settings.Executors == 1 || Settings.Executors == 2 || Settings.Executors == 4,
                "executors must be 1, 2, or 4");
        Require(Settings.Operations >= 100 && Settings.Operations <= 20000000,
                "operations must be between 100 and 20000000");
        Require(Settings.Operations % 100 == 0,
                "operations must be a multiple of 100 for an exact target hit rate");
        return ParseResult::Run;
    }

    void PrintUsage()
    {
        std::puts("DnsCacheCompare --variant A|B|C --capacity 64|1024 --hit-rate 95|50|5");
        std::puts("                --distribution uniform|hotspot --executors 1|2|4");
        std::puts("                [--workload get-only|mixed] [--operations N] [--seed N]");
        std::puts("DnsCacheCompare --validate-only");
    }

} // namespace


auto main(const int Argc, char **Argv) -> int
{
    try
    {
        Options Settings;
        const auto Parse = ParseOptions(Argc, Argv, Settings);
        if (Parse == ParseResult::Help)
        {
            PrintUsage();
            return 0;
        }
        if (Parse == ParseResult::ValidateOnly)
        {
            Preview::Network::Dns::Compare::Perf::ValidateAllocationInstrumentation();
            Compare::ValidateSemantics();
            std::puts("semantic_preflight=pass; tested TTL minimum/maximum and expiry, negative TTL, stale serving, overwrite refresh, capacity, and policy-specific eviction");
            std::puts("clock_note=CLOCK preserves value/TTL/negative/overwrite/capacity contracts; exact LRU victim identity is not guaranteed");
            return 0;
        }

        Preview::Network::Dns::Compare::Perf::ValidateAllocationInstrumentation();
        Compare::ValidateFastSemantics();
        Scenario Workload;
        Workload.Settings = Settings;
        Compare::GenerateScenario(Workload);
        Compare::ValidateScenario(Workload);
        return Preview::Network::Dns::Compare::Perf::Run(Workload);
    }
    catch (const std::exception &Error)
    {
        std::fprintf(stderr, "[FAIL] %s\n", Error.what());
        PrintUsage();
        return 2;
    }
}

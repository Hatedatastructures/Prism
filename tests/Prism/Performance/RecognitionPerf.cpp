/**
 * @file RecognitionPerf.cpp
 * @brief RecognitionPerf 的独立 CLI 入口。
 */

#include "RecognitionPerf.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace
{
    namespace Net = boost::asio;
    namespace Core = Prism::Recognition;
    auto ReadCount(std::string_view Name, std::size_t Default) -> std::size_t
    {
        const auto *Value = std::getenv(Name.data());
        if (Value == nullptr)
        {
            return Default;
        }
        const auto *End = Value + std::char_traits<char>::length(Value);
        std::size_t Parsed = 0;
        const auto [Next, Error] = std::from_chars(Value, End, Parsed);
        if (Error == std::errc{} && Next == End && Parsed > 0)
        {
            return Parsed;
        }
        return Default;
    }


}

auto main(const int Argc, char *Argv[]) -> int
{
    if (!Prism::Recognition::Perf::ValidateAllocationInstrumentation())
    {
        return 1;
    }
    if (Argc > 1 && std::string_view(Argv[1]) == "--owner-compare")
    {
        return Prism::Recognition::Perf::RunOwnerCompare();
    }
    const auto Warmup = ReadCount("PRISM_RECOGNITION_PERF_WARMUP", 1000);
    const auto Samples = ReadCount("PRISM_RECOGNITION_PERF_SAMPLES", 7);
    const auto Trials = ReadCount("PRISM_RECOGNITION_PERF_TRIALS", 10000);
    return Prism::Recognition::Perf::RunConfiguredCompare(Warmup, Samples, Trials);
}

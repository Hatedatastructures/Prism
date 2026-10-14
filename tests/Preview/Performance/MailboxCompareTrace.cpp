/**
 * @file MailboxCompareTrace.cpp
 * @brief Mailbox 基线的确定性命令轨迹实现。
 */

#include "MailboxCompareTrace.hpp"

#include <cstddef>
#include <cstdint>

namespace Preview::Runtime::Perf
{

    namespace
    {

        constexpr std::uint64_t FnvOffset = 14695981039346656037ull;
        constexpr std::uint64_t FnvPrime = 1099511628211ull;
        constexpr std::uint64_t SplitMixIncrement = 0x9E3779B97F4A7C15ull;

        auto Mix(std::uint64_t &Hash, const std::uint64_t Value) -> void
        {
            Hash ^= Value;
            Hash *= FnvPrime;
        }

        auto NextValue(std::uint64_t &State) -> std::uint64_t
        {
            State += SplitMixIncrement;
            auto Value = State;
            Value = (Value ^ (Value >> 30)) * 0xBF58476D1CE4E5B9ull;
            Value = (Value ^ (Value >> 27)) * 0x94D049BB133111EBull;
            return Value ^ (Value >> 31);
        }

    } // namespace

    auto MakeTrace(const Options &Settings) -> Trace
    {
        Trace Result;
        Result.Hash = FnvOffset;
        Result.Commands.reserve(Settings.Commands);
        Mix(Result.Hash, Settings.Commands);
        Mix(Result.Hash, Settings.Seed);

        auto State = Settings.Seed;
        for (std::size_t Index = 0; Index < Settings.Commands; ++Index)
        {
            const auto Payload = NextValue(State);
            Result.Commands.push_back(TraceCommand{Payload});
            Mix(Result.Hash, Index);
            Mix(Result.Hash, Payload);
        }
        return Result;
    }

} // namespace Preview::Runtime::Perf

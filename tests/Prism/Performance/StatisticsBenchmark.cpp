/**
 * @file StatisticsBenchmark.cpp
 * @brief SparseCounters、TrafficDelta 和 EventRing 的独立基准。
 * @details 基准只使用值模型，不启动线程、不创建网络连接，也不改变构建配置。
 */

#include <Prism/Statistics/Statistics.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <utility>

namespace
{

    struct Metrics final
    {
        std::uint64_t Iterations{0};
        std::uint64_t Flushes{0};
        std::uint64_t Events{0};
        std::uint64_t Dropped{0};
        double NanosecondsPerIteration{0};
    };

    auto Run(const std::size_t Iterations) -> Metrics
    {
        Prism::Statistics::SparseCounters Counters;
        Prism::Statistics::EventRing Events(
            Prism::Statistics::EventRing::Options{Iterations, 32});

        Metrics Result;
        const auto Start = std::chrono::steady_clock::now();
        for (std::size_t Index = 0; Index < Iterations; ++Index)
        {
            Prism::Statistics::TrafficDelta Delta(Prism::WorkerId{1});
            Delta.Add({Prism::Statistics::Scope::Account,
                       static_cast<std::uint64_t>(Index % 64 + 1), 1024, 2048});
            if (Delta.Flush(Counters))
            {
                ++Result.Flushes;
            }

            Prism::Statistics::DetailedEvent Event;
            Event.Correlation = Prism::RequestId{static_cast<std::uint64_t>(Index + 1)};
            Event.ScopeValue = Prism::Statistics::Scope::Account;
            Event.Account = Prism::AccountId{static_cast<std::uint64_t>(Index % 64 + 1)};
            Event.Kind = Prism::Statistics::EventKind::Data;
            if (Events.Append(std::move(Event)))
            {
                ++Result.Events;
            }
        }
        const auto Elapsed = std::chrono::duration<double, std::nano>(
            std::chrono::steady_clock::now() - Start);
        Result.Iterations = Iterations;
        Result.Dropped = Events.Counts().Dropped;
        Result.NanosecondsPerIteration =
            Iterations == 0 ? 0.0 : Elapsed.count() / static_cast<double>(Iterations);
        return Result;
    }

} // namespace

auto main() -> int
{
    constexpr std::size_t Iterations{100'000};
    const auto Result = Run(Iterations);
    std::cout << "statistics.iterations=" << Result.Iterations << '\n'
              << "statistics.flushes=" << Result.Flushes << '\n'
              << "statistics.events=" << Result.Events << '\n'
              << "statistics.dropped=" << Result.Dropped << '\n'
              << "statistics.ns_per_iteration=" << Result.NanosecondsPerIteration << '\n';
    return Result.Flushes == Iterations && Result.Events + Result.Dropped == Iterations ? 0 : 1;
}

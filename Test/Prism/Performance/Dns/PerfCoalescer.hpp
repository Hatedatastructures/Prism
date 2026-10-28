/**
 * @file PerfCoalescer.hpp
 * @brief DNS coalescer 的跨编译单元领域契约、round 信号与结果数据。
 */

#pragma once

#include "PerfRuntime.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <string_view>
#include <vector>

namespace DnsPerf
{
    constexpr std::size_t CoalescerRounds = 5;
    constexpr std::size_t CoalescerFlights = 2000;
    constexpr std::size_t CoalescerWaiters = 5;
    constexpr std::string_view CoalescerTraceVersion = "dns-coalescer-v2";
    constexpr std::string_view CoalescerSameDomain = "same-domain.perf.example.com";
    constexpr std::string_view CoalescerIsolatedPrefix = "isolated-";

    struct CoalescerBatch;

    struct CoalescerRoundSignals final
    {
        explicit CoalescerRoundSignals(const Net::any_io_executor Executor)
            : Begin(std::make_shared<GateChannel>(Executor, 1)),
              Ready(std::make_shared<ReadySignal>()), Done(std::make_shared<ReadySignal>())
        {
        }

        auto Fail(ErrorInfo Value) -> void
        {
            if (Error.Category == "none")
            {
                Error = std::move(Value);
            }
        }

        std::shared_ptr<GateChannel> Begin;
        std::shared_ptr<ReadySignal> Ready;
        std::shared_ptr<ReadySignal> Done;
        std::shared_ptr<ReadySignal> Retired;
        std::shared_ptr<CoalescerBatch> ActiveBatch;
        std::atomic<bool> StopRequested{false};
        ErrorInfo Error{};
        std::size_t CompletedOperations{0};
    };

    class CoalescerOwner
    {
    public:
        virtual ~CoalescerOwner() noexcept = default;

        [[nodiscard]] virtual auto Start() -> bool = 0;
        [[nodiscard]] virtual auto Stop() noexcept -> bool = 0;
        [[nodiscard]] virtual auto MakeRoundSignals()
            -> std::shared_ptr<CoalescerRoundSignals> = 0;
        virtual auto PrepareRound() -> void = 0;
        virtual auto LaunchRound(
            std::size_t Flights,
            const std::shared_ptr<CoalescerRoundSignals> &Signals) -> void = 0;
        virtual auto OpenRound(const std::shared_ptr<CoalescerRoundSignals> &Signals) -> void = 0;
        [[nodiscard]] virtual auto QueryDelta() const noexcept -> std::size_t = 0;
        [[nodiscard]] virtual auto ResponseDelta() const noexcept -> std::size_t = 0;
        virtual auto AbortRound() -> void = 0;
        [[nodiscard]] virtual auto Latencies() const noexcept
            -> const std::vector<std::uint64_t> & = 0;
    };

    struct DnsProcessSample final
    {
        std::uint64_t User100ns{0};
        std::uint64_t Kernel100ns{0};
        std::size_t WorkingSet{0};
        std::size_t PrivateUsage{0};
        bool Available{false};
    };

    struct DnsSamplerRuntime;
    using DnsSamplerHandle = std::shared_ptr<DnsSamplerRuntime>;

    struct DnsSamplerMetrics final
    {
        std::size_t SampleCount{0};
        std::size_t PeakWorkingSet{0};
        std::size_t PeakPrivateUsage{0};
        bool Valid{true};
    };

    struct CoalescerRoundMetrics final
    {
        std::uint64_t WallNs{0};
        std::uint64_t Operations{0};
        std::size_t Queries{0};
        std::size_t Responses{0};
        std::size_t ExpectedQueries{0};
        std::size_t SampleCount{0};
        std::size_t PeakWorkingSet{0};
        std::size_t PeakPrivateUsage{0};
        std::uint64_t LatencyP50{0};
        std::uint64_t LatencyP95{0};
        std::uint64_t LatencyP99{0};
        DnsPerfAllocation::Snapshot Allocations{};
        ErrorInfo Error{};
        bool SamplerValid{false};
        bool Valid{false};
#ifdef _WIN32
        DnsProcessSample Before{};
        DnsProcessSample After{};
#endif
    };

} // namespace DnsPerf

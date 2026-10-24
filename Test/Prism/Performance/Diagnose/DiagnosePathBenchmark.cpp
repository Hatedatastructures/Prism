/**
 * @file DiagnosePathBenchmark.cpp
 * @brief Diagnose compact/extended path latency and resource benchmark.
 */
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Prism/Foundation/Utility/Diagnose/RenderMode.hpp>
#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <TestSupport/Prism/DiagnoseTestEnvironment.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <new>
#include <numeric>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <time.h>
#endif

namespace
{

    thread_local std::uint64_t *AllocationCounter = nullptr;

    auto Allocate(const std::size_t Size) -> void *
    {
        if (AllocationCounter != nullptr)
        {
            ++*AllocationCounter;
        }
        if (auto *Memory = std::malloc(Size == 0U ? 1U : Size); Memory != nullptr)
        {
            return Memory;
        }
        throw std::bad_alloc{};
    }

    class AllocationScope final
    {
    public:
        explicit AllocationScope(std::uint64_t &Count) noexcept
            : Previous_(AllocationCounter)
        {
            AllocationCounter = &Count;
        }

        ~AllocationScope() noexcept
        {
            AllocationCounter = Previous_;
        }

        AllocationScope(const AllocationScope &) = delete;
        auto operator=(const AllocationScope &) -> AllocationScope & = delete;

    private:
        std::uint64_t *Previous_;
    };

    using Clock = std::chrono::steady_clock;
    constexpr std::size_t WarmupIterations = 10000U;
    constexpr std::size_t IterationsPerRepetition = 20000U;
    constexpr std::size_t Repetitions = 5U;
    constexpr std::array<std::size_t, 3> PayloadSizes{128U, 512U, 2048U};

    struct RunResult final
    {
        std::string Scenario;
        std::string Mode;
        std::size_t PayloadBytes{0U};
        std::uint64_t SubmitElapsedNs{0U};
        std::uint64_t AverageSubmitNs{0U};
        std::uint64_t P95SubmitNs{0U};
        std::uint64_t P99SubmitNs{0U};
        std::uint64_t ProducerThreadCpuNs{0U};
        std::uint64_t Allocations{0U};
        std::size_t QueueHighWater{0U};
        std::uint64_t DroppedInfo{0U};
        std::uint64_t DrainNs{0U};
    };

    [[nodiscard]] auto ThreadCpuNanoseconds() noexcept -> std::uint64_t
    {
#if defined(_WIN32)
        FILETIME Creation{};
        FILETIME Exit{};
        FILETIME Kernel{};
        FILETIME User{};
        if (GetThreadTimes(GetCurrentThread(), &Creation, &Exit, &Kernel, &User) == 0)
        {
            return 0U;
        }
        ULARGE_INTEGER KernelTicks{};
        KernelTicks.LowPart = Kernel.dwLowDateTime;
        KernelTicks.HighPart = Kernel.dwHighDateTime;
        ULARGE_INTEGER UserTicks{};
        UserTicks.LowPart = User.dwLowDateTime;
        UserTicks.HighPart = User.dwHighDateTime;
        return (KernelTicks.QuadPart + UserTicks.QuadPart) * 100U;
#else
        timespec Time{};
        if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &Time) != 0)
        {
            return 0U;
        }
        return static_cast<std::uint64_t>(Time.tv_sec) * 1000000000ULL +
               static_cast<std::uint64_t>(Time.tv_nsec);
#endif
    }

    [[nodiscard]] auto Percentile(const std::vector<std::uint64_t> &Samples,
                                 const double Quantile) -> std::uint64_t
    {
        if (Samples.empty())
        {
            return 0U;
        }
        auto Ordered = Samples;
        std::sort(Ordered.begin(), Ordered.end());
        const auto Index = static_cast<std::size_t>(
            (Quantile * static_cast<double>(Ordered.size() - 1U)) + 0.5);
        return Ordered[(std::min)(Index, Ordered.size() - 1U)];
    }

    [[nodiscard]] auto ModeName(const Prism::Diagnose::RenderMode Mode) noexcept
        -> std::string_view
    {
        using Prism::Diagnose::RenderMode;
        switch (Mode)
        {
        case RenderMode::CompactHuman: return "CompactHuman";
        case RenderMode::HumanWithFields: return "HumanWithFields";
        case RenderMode::Structured: return "Structured";
        }
        return "CompactHuman";
    }

    struct ScenarioRequest final
    {
        Prism::Application::DiagnoseRuntime &Runtime;
        const Prism::Diagnose::ContextState &Context;
        std::string_view Scenario;
        Prism::Diagnose::RenderMode Mode;
        std::size_t PayloadBytes{0};
    };

    [[nodiscard]] auto RunScenario(ScenarioRequest Request) -> RunResult
    {
        std::string Payload(Request.PayloadBytes, 'x');
        for (std::size_t Index = 0; Index < WarmupIterations; ++Index)
        {
            (void)Prism::Diagnose::Info(
                Request.Context, "event=diagnose_benchmark scenario={} iteration={} payload={}",
                Request.Scenario, Index, Payload);
        }
        if (Request.Runtime.DrainOnControlThread(std::chrono::seconds{60}).Status !=
            Prism::Diagnose::SubmissionStatus::Flushed)
        {
            throw std::runtime_error("Diagnose benchmark warmup drain timed out");
        }
        Request.Runtime.ResetQueueHighWatermark();

        RunResult Result;
        Result.Scenario = Request.Scenario;
        Result.Mode = ModeName(Request.Mode);
        Result.PayloadBytes = Request.PayloadBytes;
        std::vector<std::uint64_t> Samples;
        Samples.reserve(IterationsPerRepetition * Repetitions);

        for (std::size_t Repetition = 0; Repetition < Repetitions; ++Repetition)
        {
            const auto DroppedBefore = Request.Runtime.Dropped(Prism::Diagnose::LogLevel::Info);
            std::uint64_t RepetitionAllocations = 0U;
            const auto CpuBefore = ThreadCpuNanoseconds();
            const auto SubmitStart = Clock::now();
            {
                AllocationScope CountAllocations{RepetitionAllocations};
                for (std::size_t Index = 0; Index < IterationsPerRepetition; ++Index)
                {
                    const auto Start = Clock::now();
                    (void)Prism::Diagnose::Info(
                        Request.Context, "event=diagnose_benchmark scenario={} iteration={} payload={}",
                        Request.Scenario, Index, Payload);
                    const auto Elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                        Clock::now() - Start);
                    Samples.push_back(static_cast<std::uint64_t>(Elapsed.count()));
                }
            }
            const auto SubmitEnd = Clock::now();
            const auto CpuAfter = ThreadCpuNanoseconds();
            Result.SubmitElapsedNs += static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(SubmitEnd - SubmitStart).count());
            Result.ProducerThreadCpuNs += CpuAfter - CpuBefore;
            Result.Allocations += RepetitionAllocations;
            Result.QueueHighWater = (std::max)(Result.QueueHighWater,
                                               Request.Runtime.QueueHighWatermark());
            Result.DroppedInfo += Request.Runtime.Dropped(Prism::Diagnose::LogLevel::Info) -
                                  DroppedBefore;

            const auto DrainStart = Clock::now();
            if (Request.Runtime.DrainOnControlThread(std::chrono::seconds{60}).Status !=
                Prism::Diagnose::SubmissionStatus::Flushed)
            {
                throw std::runtime_error("Diagnose benchmark drain timed out");
            }
            Result.DrainNs += static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    Clock::now() - DrainStart).count());
            Request.Runtime.ResetQueueHighWatermark();
        }

        const auto TotalSampleNs = std::accumulate(
            Samples.begin(), Samples.end(), std::uint64_t{0U});
        Result.AverageSubmitNs = TotalSampleNs / static_cast<std::uint64_t>(Samples.size());
        Result.P95SubmitNs = Percentile(Samples, 0.95);
        Result.P99SubmitNs = Percentile(Samples, 0.99);
        return Result;
    }

    struct JsonWriteRequest final
    {
        std::ostream &Output;
        std::string_view Benchmark;
        const std::vector<RunResult> &Runs;
        std::uint64_t FinalDrainNs{0};
        std::uint64_t ShutdownFlushJoinNs{0};
    };

    auto WriteJson(JsonWriteRequest Request) -> void
    {
        Request.Output << "{\n"
               << "  \"benchmark\": \"" << Request.Benchmark << "\",\n"
               << "  \"warmup_iterations\": " << WarmupIterations << ",\n"
               << "  \"iterations_per_repetition\": " << IterationsPerRepetition << ",\n"
               << "  \"repetitions\": " << Repetitions << ",\n"
               << "  \"runs\": [\n";
        for (std::size_t Index = 0; Index < Request.Runs.size(); ++Index)
        {
            const auto &Run = Request.Runs[Index];
            Request.Output << "    {\"scenario\":\"" << Run.Scenario
                   << "\",\"mode\":\"" << Run.Mode
                   << "\",\"payload_bytes\":" << Run.PayloadBytes
                   << ",\"samples\":" << IterationsPerRepetition * Repetitions
                   << ",\"submit_elapsed_ns\":" << Run.SubmitElapsedNs
                   << ",\"average_submit_ns\":" << Run.AverageSubmitNs
                   << ",\"p95_submit_ns\":" << Run.P95SubmitNs
                   << ",\"p99_submit_ns\":" << Run.P99SubmitNs
                   << ",\"allocations\":" << Run.Allocations
                   << ",\"allocations_per_submit\":"
                   << std::fixed << std::setprecision(4)
                   << static_cast<double>(Run.Allocations) /
                          static_cast<double>(IterationsPerRepetition * Repetitions)
                   << ",\"producer_thread_cpu_ns\":" << Run.ProducerThreadCpuNs
                   << ",\"queue_high_water\":" << Run.QueueHighWater
                   << ",\"dropped_info\":" << Run.DroppedInfo
                   << ",\"drain_ns\":" << Run.DrainNs << "}";
            if (Index + 1U != Request.Runs.size())
            {
                Request.Output << ',';
            }
            Request.Output << '\n';
        }
        Request.Output << "  ],\n"
               << "  \"final_drain_ns\": " << Request.FinalDrainNs << ",\n"
               << "  \"shutdown_flush_join_ns\": " << Request.ShutdownFlushJoinNs << "\n"
               << "}\n";
    }

    auto SaveSample(const std::filesystem::path &LogPath,
                    const std::filesystem::path &OutputPath,
                    const bool Structured) -> void
    {
        if (OutputPath.empty())
        {
            return;
        }
        std::ifstream Input(LogPath, std::ios::binary);
        if (!Input.is_open())
        {
            return;
        }
        std::string Line;
        if (!std::getline(Input, Line))
        {
            return;
        }
        auto SamplePath = OutputPath;
        SamplePath += Structured ? ".sample.jsonl" : ".sample.log";
        std::ofstream Output(SamplePath, std::ios::binary);
        if (Output.is_open())
        {
            Output << Line << '\n';
        }
    }

} // namespace

auto operator new(const std::size_t Size) -> void *
{
    return Allocate(Size);
}

auto operator new[](const std::size_t Size) -> void *
{
    return Allocate(Size);
}

auto operator delete(void *Memory) noexcept -> void
{
    std::free(Memory);
}

auto operator delete[](void *Memory) noexcept -> void
{
    std::free(Memory);
}

auto operator delete(void *Memory, const std::size_t) noexcept -> void
{
    std::free(Memory);
}

auto operator delete[](void *Memory, const std::size_t) noexcept -> void
{
    std::free(Memory);
}

struct FinalizeRequest final
{
    Prism::TestSupport::DiagnoseTestEnvironment &Environment;
    std::string_view BenchmarkName;
    std::vector<RunResult> &Runs;
    std::filesystem::path OutputPath;
    Prism::Diagnose::RenderMode Mode;
};

auto FinalizeBenchmark(FinalizeRequest Request) -> int
{
    const auto FinalDrainStart = Clock::now();
    const auto FinalDrain = Request.Environment.Runtime().DrainOnControlThread(
        std::chrono::seconds{60});
    const auto FinalDrainNs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now() - FinalDrainStart).count());
    if (FinalDrain.Status != Prism::Diagnose::SubmissionStatus::Flushed)
    {
        std::fprintf(stderr, "Diagnose benchmark final drain failed\n");
        return 1;
    }
    const auto ShutdownStart = Clock::now();
    const auto Shutdown = Request.Environment.Runtime().Shutdown();
    const auto ShutdownNs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            Clock::now() - ShutdownStart).count());
    if (Shutdown.Status != Prism::Diagnose::SubmissionStatus::Closed)
    {
        std::fprintf(stderr, "Diagnose benchmark shutdown failed\n");
        return 1;
    }

    std::ofstream File;
    std::ostream *Output = &std::cout;
    if (!Request.OutputPath.empty())
    {
        File.open(Request.OutputPath, std::ios::binary | std::ios::trunc);
        if (!File.is_open())
        {
            std::fprintf(stderr, "cannot open benchmark output\n");
            return 1;
        }
        Output = &File;
    }
    WriteJson(JsonWriteRequest{
        *Output, Request.BenchmarkName, Request.Runs, FinalDrainNs, ShutdownNs});
    SaveSample(Request.Environment.Configuration().Logging.Directory /
                   Request.Environment.Configuration().Logging.FileName,
               Request.OutputPath, Request.Mode == Prism::Diagnose::RenderMode::Structured);
    return 0;
}

auto main(const int Argc, char **Argv) -> int
{
#if defined(PRISM_DIAGNOSE_COMPACT_BENCHMARK)
    constexpr auto BenchmarkName = std::string_view{"CompactPathBenchmark"};
    constexpr auto Mode = Prism::Diagnose::RenderMode::CompactHuman;
    const std::filesystem::path OutputPath = Argc > 1 ? Argv[1] : "";
#else
    constexpr auto BenchmarkName = std::string_view{"ExtendedPathBenchmark"};
    Prism::Diagnose::RenderMode Mode{};
    if (Argc < 2)
    {
        std::fprintf(stderr, "usage: ExtendedPathBenchmark HumanWithFields|Structured [output.json]\n");
        return 2;
    }
    const std::string_view ModeArgument{Argv[1]};
    if (ModeArgument == "HumanWithFields")
    {
        Mode = Prism::Diagnose::RenderMode::HumanWithFields;
    }
    else if (ModeArgument == "Structured")
    {
        Mode = Prism::Diagnose::RenderMode::Structured;
    }
    else
    {
        std::fprintf(stderr, "unknown RenderMode\n");
        return 2;
    }
    const std::filesystem::path OutputPath = Argc > 2 ? Argv[2] : "";
#endif

    Prism::TestSupport::DiagnoseTestEnvironment Environment{
        "diagnose-path-benchmark", 8192U};
    Environment.Configuration().Mode = Mode;
    Environment.Configuration().Logging.RotateBytes = 128ULL * 1024ULL * 1024ULL;
    if (const auto Installed = Environment.Install(); !Installed)
    {
        std::fprintf(stderr, "Diagnose backend install failed: %s\n",
                     Installed.error().Message.c_str());
        return 1;
    }

    std::vector<RunResult> Runs;
    Runs.reserve(6U);
#if defined(PRISM_DIAGNOSE_COMPACT_BENCHMARK)
    const auto WorkerSession = Prism::Diagnose::ContextState::Empty()
                                   .With(Prism::Diagnose::Fields::Worker,
                                         Prism::WorkerId{1})
                                   .With(Prism::Diagnose::Fields::Session,
                                         Prism::SessionId{2});
    const auto Empty = Prism::Diagnose::ContextState::Empty();
    for (const auto PayloadBytes : PayloadSizes)
    {
        Runs.push_back(RunScenario(ScenarioRequest{
            Environment.Runtime(), Empty, "no-context", Mode, PayloadBytes}));
        Runs.push_back(RunScenario(
            ScenarioRequest{Environment.Runtime(), WorkerSession, "worker-session", Mode,
                            PayloadBytes}));
    }
#else
    const auto ExtendedContext = Prism::Diagnose::ContextState::Empty()
                                     .With(Prism::Diagnose::Fields::Worker,
                                           Prism::WorkerId{1})
                                     .With(Prism::Diagnose::Fields::Session,
                                           Prism::SessionId{2})
                                     .With(Prism::Diagnose::Fields::Correlation,
                                           Prism::RequestId{3})
                                     .With(Prism::Diagnose::Fields::Process,
                                           Prism::ProcessId{4})
                                     .With(Prism::Diagnose::Fields::Generation,
                                           Prism::GenerationId{5})
                                     .With(Prism::Diagnose::Fields::Task,
                                           Prism::TaskId{6})
                                     .With(Prism::Diagnose::Fields::Protocol,
                                           std::string_view{"vless"})
                                     .With(Prism::Diagnose::Fields::Route,
                                           std::string_view{"default"})
                                     .With(Prism::Diagnose::Fields::Stream,
                                           Prism::StreamId{7})
                                     .With(Prism::Diagnose::Fields::Carrier,
                                           std::string_view{"native"})
                                     .With(Prism::Diagnose::Fields::Stage,
                                           std::string_view{"relay"})
                                     .With(Prism::Diagnose::Fields::Status,
                                           std::string_view{"active"})
                                     .With(Prism::Diagnose::Fields::FaultCode,
                                           std::string_view{"success"})
                                     .With(Prism::Diagnose::Fields::NativeError,
                                           std::string_view{"password=benchmark-secret"});
    for (const auto PayloadBytes : PayloadSizes)
    {
        Runs.push_back(RunScenario(ScenarioRequest{
            Environment.Runtime(), ExtendedContext, "extended-context", Mode, PayloadBytes}));
    }
#endif

    return FinalizeBenchmark(
        FinalizeRequest{Environment, BenchmarkName, Runs, OutputPath, Mode});
}

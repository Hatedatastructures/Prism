/**
 * @file RecognitionPerf.cpp
 * @brief Preview 多模式识别性能基线
 * @details 使用真实 Preview wire 和 io_context 协程执行识别，输出机器可读
 *          JSON 行。计时不包含 profile 构造和 wire 构造。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <malloc.h>
#endif

#include <preview/Composition/Recognition/CandidateFactory.hpp>
#include <preview/Composition/Recognition/ProfileBuilder.hpp>
#include <preview/Runtime/Recognition/Recognition.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <preview/Transport/Transmission.hpp>

#include "../core/recognition/RecognitionWire.hpp"

namespace
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;
    namespace Composition = Preview::Composition::Recognition;

    std::atomic<std::size_t> AllocationCount{0};
    std::atomic<std::size_t> AllocationBytes{0};

    auto RecordAllocation(void *Pointer, std::size_t Size) -> void *
    {
        if (Pointer != nullptr)
        {
            AllocationCount.fetch_add(1, std::memory_order_relaxed);
            AllocationBytes.fetch_add(Size, std::memory_order_relaxed);
        }
        return Pointer;
    }

    auto AllocateAligned(std::size_t Size, std::size_t Alignment) -> void *
    {
        auto Requested = Size;
        if (Requested == 0)
        {
            Requested = 1;
        }
        const auto Rounded = (Requested + Alignment - 1U) / Alignment * Alignment;
#ifdef _WIN32
        return RecordAllocation(_aligned_malloc(Rounded, Alignment), Size);
#else
        return RecordAllocation(std::aligned_alloc(Alignment, Rounded), Size);
#endif
    }

    auto ReleaseAligned(void *Pointer) noexcept -> void
    {
#ifdef _WIN32
        _aligned_free(Pointer);
#else
        std::free(Pointer);
#endif
    }

    auto ResetAllocationCounters() -> void
    {
        AllocationCount.store(0, std::memory_order_relaxed);
        AllocationBytes.store(0, std::memory_order_relaxed);
    }

    struct AllocationSnapshot
    {
        std::size_t Count{0};
        std::size_t Bytes{0};
    };

    auto ReadAllocationCounters() -> AllocationSnapshot
    {
        return {AllocationCount.load(std::memory_order_relaxed),
                AllocationBytes.load(std::memory_order_relaxed)};
    }

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

    class CountingTransmission final : public Preview::Transmission
    {
    public:
        CountingTransmission(Preview::SharedTransmission Inner, std::size_t &ReadCalls)
            : Inner_(std::move(Inner)), ReadCalls_(&ReadCalls)
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            if (!Inner_)
            {
                return {};
            }
            return Inner_->Executor();
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            ++*ReadCalls_;
            if (!Inner_)
            {
                Error = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            auto Read = Inner_->async_read_some(Buffer, Error);
            co_return co_await std::move(Read);
        }

        [[nodiscard]] auto async_write_some(std::span<const std::byte> Buffer,
                                            std::error_code &Error)
            -> Net::awaitable<std::size_t> override
        {
            if (!Inner_)
            {
                Error = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            auto Write = Inner_->async_write_some(Buffer, Error);
            co_return co_await std::move(Write);
        }

        auto Close() -> void override
        {
            if (Inner_)
            {
                Inner_->Close();
            }
        }

        auto Cancel() -> void override
        {
            if (Inner_)
            {
                Inner_->Cancel();
            }
        }

        auto Shutdown() -> void override
        {
            if (Inner_)
            {
                Inner_->Shutdown();
            }
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Inner_ && Inner_->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return Inner_.get();
        }

        [[nodiscard]] auto NextLayer() const noexcept -> const Preview::Transmission * override
        {
            return Inner_.get();
        }

    private:
        Preview::SharedTransmission Inner_;
        std::size_t *ReadCalls_;
    };

    struct Measurement
    {
        std::uint64_t ElapsedNanoseconds{0};
        std::size_t ReadCalls{0};
        AllocationSnapshot Allocations;
        Core::CandidateId Candidate{Core::InvalidCandidate};
        std::uint16_t CryptoTrials{0};
        bool Success{false};
    };

    struct Scenario
    {
        Core::RecognitionMode Mode{Core::RecognitionMode::Configured};
        std::string_view ModeName;
        std::string_view Protocol;
        std::size_t CandidateCount{0};
        std::vector<std::byte> Wire;
        Core::SharedProfile Profile;
    };

    struct MetricContext
    {
        std::size_t Warmup{0};
        std::size_t TrialsPerSample{0};
    };

    auto Execute(const Scenario &ScenarioValue) -> Measurement
    {
        ResetAllocationCounters();
        Measurement Output;
        Net::io_context Io;
        auto [WriterValue, ReaderValue] = Preview::MakeMemoryPair(Io.get_executor());
        auto Writer = std::make_shared<Preview::MemoryStream>(std::move(WriterValue));
        auto Reader = std::make_shared<Preview::MemoryStream>(std::move(ReaderValue));
        auto Inbound = std::make_shared<CountingTransmission>(Reader, Output.ReadCalls);
        Core::Pipeline Pipeline(ScenarioValue.Profile);
        std::exception_ptr Failure;
        const auto Started = std::chrono::steady_clock::now();

        Net::co_spawn(
            Io,
            [Writer, Inbound, &Pipeline, &Output, &ScenarioValue]() -> Net::awaitable<void>
            {
                std::error_code Error;
                const auto WireSpan = std::span<const std::byte>(ScenarioValue.Wire);
                auto WriteOperation = Writer->async_write_some(WireSpan, Error);
                const auto Written = co_await std::move(WriteOperation);
                if (Error || Written != ScenarioValue.Wire.size())
                {
                    co_return;
                }
                Writer->Shutdown();
                auto Recognition = Pipeline.Recognize(Inbound);
                auto Result = co_await std::move(Recognition);
                Output.Success = Result.success;
                Output.Candidate = Result.Candidate;
                Output.CryptoTrials = Result.CryptoTrials;
                if (Result.transport)
                {
                    Result.transport->Close();
                    Result.transport.reset();
                }
                Writer->Close();
            },
            [&](std::exception_ptr Error)
            {
                Failure = std::move(Error);
                Io.stop();
            });
        Io.run();
        Output.ElapsedNanoseconds = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - Started)
                .count());
        Output.Allocations = ReadAllocationCounters();
        if (Failure)
        {
            Output.Success = false;
            Output.Candidate = Core::InvalidCandidate;
        }
        return Output;
    }

    auto MakeProfile(Core::RecognitionMode Mode, std::string_view Protocol, std::size_t Count)
        -> Core::SharedProfile
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(31);
        std::vector<Composition::CandidateBinding> Bindings;
        auto BindingCount = Count;
        if (Mode == Core::RecognitionMode::Configured)
        {
            BindingCount = 1;
        }
        Bindings.reserve(BindingCount);
        for (std::size_t Index = 0; Index < BindingCount; ++Index)
        {
            const auto Id = static_cast<Core::CandidateId>(100 + Index);
            Composition::CandidateBinding Binding;
            if (Index == 0 && Protocol == "HTTP")
            {
                Binding = Composition::CandidateFactory::MakeHttp(Id);
            }
            else if (Index == 0 && Protocol == "VLESS")
            {
                Binding = Composition::CandidateFactory::MakeVless(
                    Id, Preview::Vless::ServerConfig{Uuid});
            }
            else
            {
                Composition::CandidateOptions Options;
                Options.Id = Id;
                if (Protocol == "VLESS")
                {
                    Options.Name = "http-" + std::to_string(Index);
                }
                else
                {
                    Options.Name = "vmess-" + std::to_string(Index);
                }
                if (Protocol == "VLESS")
                {
                    Binding = Composition::CandidateFactory::MakeHttp(std::move(Options));
                }
                else
                {
                    Binding = Composition::CandidateFactory::MakeVmess(
                        std::move(Options), Preview::Vmess::ServerConfig{Uuid});
                }
            }
            if (Mode == Core::RecognitionMode::DeterministicRoute && Index > 0)
            {
                Binding.Spec.Fallback = false;
                Binding.Spec.FirstBytes = {static_cast<std::uint8_t>(0x80U + Index)};
            }
            Bindings.push_back(std::move(Binding));
        }
        Composition::ProfileBuilderOptions Options;
        Options.Mode = Mode;
        auto Built = Composition::ProfileBuilder::Build(std::move(Bindings), std::move(Options));
        if (!Built)
        {
            std::cerr << "profile build failed: " << Core::ToStringView(Built.error()) << "\n";
            return {};
        }
        return Built->Profile;
    }

    auto Percentile(const std::vector<std::uint64_t> &Values, double Fraction) -> std::uint64_t
    {
        if (Values.empty())
        {
            return 0;
        }
        const auto Position = static_cast<std::size_t>(std::ceil(Fraction * Values.size())) - 1U;
        return Values[(std::min)(Position, Values.size() - 1U)];
    }

    auto MedianAbsoluteDeviation(const std::vector<std::uint64_t> &Values,
                                 std::uint64_t Median) -> std::uint64_t
    {
        std::vector<std::uint64_t> Deviations;
        Deviations.reserve(Values.size());
        for (const auto Value : Values)
        {
            if (Value > Median)
            {
                Deviations.push_back(Value - Median);
            }
            else
            {
                Deviations.push_back(Median - Value);
            }
        }
        std::sort(Deviations.begin(), Deviations.end());
        if (Deviations.empty())
        {
            return 0;
        }
        return Deviations[(Deviations.size() - 1U) / 2U];
    }

    auto PrintMetrics(const Scenario &ScenarioValue, const std::vector<Measurement> &Samples,
                      MetricContext Context) -> bool
    {
        std::vector<std::uint64_t> Timings;
        Timings.reserve(Samples.size());
        std::size_t Failures = 0;
        std::int64_t WinnerIndex = -1;
        std::uint64_t Trials = 0;
        std::uint64_t Reads = 0;
        std::uint64_t Allocations = 0;
        std::uint64_t AllocationBytesValue = 0;
        for (const auto &Sample : Samples)
        {
            Timings.push_back(Sample.ElapsedNanoseconds);
            if (!Sample.Success)
            {
                ++Failures;
            }
            if (Sample.Success && Sample.Candidate != Core::InvalidCandidate)
            {
                WinnerIndex = static_cast<std::int64_t>(Sample.Candidate) - 100;
            }
            Trials += Sample.CryptoTrials;
            Reads += Sample.ReadCalls;
            Allocations += Sample.Allocations.Count;
            AllocationBytesValue += Sample.Allocations.Bytes;
        }
        std::sort(Timings.begin(), Timings.end());
        const auto Median = Percentile(Timings, 0.50);
        std::uint64_t Average = 0;
        std::uint64_t AverageReads = 0;
        std::uint64_t AverageAllocations = 0;
        std::uint64_t AverageAllocationBytes = 0;
        if (!Samples.empty())
        {
            Average = static_cast<std::uint64_t>(Trials / Samples.size());
            AverageReads = static_cast<std::uint64_t>(Reads / Samples.size());
            AverageAllocations = static_cast<std::uint64_t>(Allocations / Samples.size());
            AverageAllocationBytes =
                static_cast<std::uint64_t>(AllocationBytesValue / Samples.size());
        }
        auto SampleCount = Context.TrialsPerSample;
        if (SampleCount == 0)
        {
            SampleCount = 1;
        }
        std::cout << "{\"mode\":\"" << ScenarioValue.ModeName << "\",\"protocol\":\""
                  << ScenarioValue.Protocol << "\",\"wire_size\":" << ScenarioValue.Wire.size()
                  << ",\"candidate_count\":" << ScenarioValue.CandidateCount
                  << ",\"winner_index\":" << WinnerIndex << ",\"trial_count\":" << Average
                  << ",\"read_calls\":" << AverageReads << ",\"allocation_count\":"
                  << AverageAllocations << ",\"allocation_bytes\":" << AverageAllocationBytes
                  << ",\"median_ns\":" << Median << ",\"p95_ns\":" << Percentile(Timings, 0.95)
                  << ",\"p99_ns\":" << Percentile(Timings, 0.99)
                  << ",\"mad_ns\":" << MedianAbsoluteDeviation(Timings, Median)
                  << ",\"failures\":" << Failures << ",\"warmup\":" << Context.Warmup
                  << ",\"samples\":" << Samples.size() / SampleCount
                  << ",\"trials_per_sample\":" << Context.TrialsPerSample << "}\n";
        return Failures == 0;
    }

} // namespace

auto operator new(std::size_t Size) -> void *
{
    auto AllocationSize = Size;
    if (AllocationSize == 0)
    {
        AllocationSize = 1;
    }
    if (auto *Pointer = RecordAllocation(std::malloc(AllocationSize), Size))
    {
        return Pointer;
    }
    throw std::bad_alloc();
}

auto operator new[](std::size_t Size) -> void *
{
    return ::operator new(Size);
}

auto operator new(std::size_t Size, const std::nothrow_t &) noexcept -> void *
{
    auto AllocationSize = Size;
    if (AllocationSize == 0)
    {
        AllocationSize = 1;
    }
    return RecordAllocation(std::malloc(AllocationSize), Size);
}

auto operator new[](std::size_t Size, const std::nothrow_t &Tag) noexcept -> void *
{
    return ::operator new(Size, Tag);
}

auto operator new(std::size_t Size, std::align_val_t Alignment) -> void *
{
    if (auto *Pointer = AllocateAligned(Size, static_cast<std::size_t>(Alignment)))
    {
        return Pointer;
    }
    throw std::bad_alloc();
}

auto operator new[](std::size_t Size, std::align_val_t Alignment) -> void *
{
    return ::operator new(Size, Alignment);
}

auto operator new(
    std::size_t Size,
    std::align_val_t Alignment,
    const std::nothrow_t &) noexcept -> void *
{
    return AllocateAligned(Size, static_cast<std::size_t>(Alignment));
}

auto operator new[](
    std::size_t Size,
    std::align_val_t Alignment,
    const std::nothrow_t &Tag) noexcept -> void *
{
    return ::operator new(Size, Alignment, Tag);
}

auto operator delete(void *Pointer) noexcept -> void
{
    std::free(Pointer);
}

auto operator delete[](void *Pointer) noexcept -> void
{
    std::free(Pointer);
}

auto operator delete(void *Pointer, std::size_t) noexcept -> void
{
    std::free(Pointer);
}

auto operator delete[](void *Pointer, std::size_t) noexcept -> void
{
    std::free(Pointer);
}

auto operator delete(void *Pointer, std::align_val_t) noexcept -> void
{
    ReleaseAligned(Pointer);
}

auto operator delete[](void *Pointer, std::align_val_t) noexcept -> void
{
    ReleaseAligned(Pointer);
}

auto operator delete(void *Pointer, std::size_t, std::align_val_t) noexcept -> void
{
    ReleaseAligned(Pointer);
}

auto operator delete[](void *Pointer, std::size_t, std::align_val_t) noexcept -> void
{
    ReleaseAligned(Pointer);
}

auto main() -> int
{
    const auto Warmup = ReadCount("PRISM_RECOGNITION_PERF_WARMUP", 1000);
    const auto Samples = ReadCount("PRISM_RECOGNITION_PERF_SAMPLES", 7);
    const auto Trials = ReadCount("PRISM_RECOGNITION_PERF_TRIALS", 10000);
    bool AllPassed = true;
    const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(31);
    const std::array<Core::RecognitionMode, 3> Modes{
        Core::RecognitionMode::Configured,
        Core::RecognitionMode::Deterministic,
        Core::RecognitionMode::MixedTrial};
    for (const auto Mode : Modes)
    {
        const auto ModeName = Core::ToStringView(Mode);
        for (const auto Protocol : {std::string_view{"HTTP"}, std::string_view{"VLESS"}})
        {
            std::vector<std::size_t> CandidateCounts;
            if (Mode == Core::RecognitionMode::Configured)
            {
                CandidateCounts = {1};
            }
            else if (Mode == Core::RecognitionMode::DeterministicRoute)
            {
                CandidateCounts = {2};
            }
            else
            {
                CandidateCounts = {2, 4, 8};
            }
            for (const auto CandidateCount : CandidateCounts)
            {
                Scenario ScenarioValue;
                ScenarioValue.Mode = Mode;
                ScenarioValue.ModeName = ModeName;
                ScenarioValue.Protocol = Protocol;
                ScenarioValue.CandidateCount = CandidateCount;
                if (Protocol == "HTTP")
                {
                    ScenarioValue.Wire = Preview::Testing::RecognitionWire::MakeHttp("perf");
                }
                else
                {
                    ScenarioValue.Wire = Preview::Testing::RecognitionWire::MakeVless(Uuid);
                }
                ScenarioValue.Profile = MakeProfile(Mode, Protocol, CandidateCount);
                if (!ScenarioValue.Profile)
                {
                    std::cerr << "profile build failed\n";
                    return 1;
                }
                for (std::size_t Index = 0; Index < Warmup; ++Index)
                {
                    (void)Execute(ScenarioValue);
                }
                std::vector<Measurement> Results;
                Results.reserve(Samples * Trials);
                for (std::size_t Sample = 0; Sample < Samples; ++Sample)
                {
                    for (std::size_t Trial = 0; Trial < Trials; ++Trial)
                    {
                        Results.push_back(Execute(ScenarioValue));
                    }
                }
                AllPassed = PrintMetrics(ScenarioValue, Results, MetricContext{Warmup, Trials}) && AllPassed;
            }
        }
    }
    if (AllPassed)
    {
        return 0;
    }
    return 1;
}

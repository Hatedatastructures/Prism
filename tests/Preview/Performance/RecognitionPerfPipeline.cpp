#include <TestSupport/Preview/ProtocolIngressBindings.hpp>
/**
 * @file RecognitionPerfPipeline.cpp
 * @brief 配置、确定性和混合识别 pipeline 性能 owner。
 */

#include "RecognitionPerf.hpp"

#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Recognition/ProfileBuilder.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <TestSupport/Fixtures/RecognitionWire.hpp>

#include <cmath>

namespace
{
    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;
    namespace Composition = Preview::Composition::Recognition;
    using Preview::Recognition::Perf::Measurement;
    using Preview::Recognition::Perf::MetricContext;
    using Preview::Recognition::Perf::Scenario;
    class CountingTransmission final : public Preview::Transmission
    {
    public:
        CountingTransmission(Preview::SharedTransmission Inner, std::size_t &ReadCalls)
            : Preview::Transmission(Inner->Executor()), Inner_(std::move(Inner)), ReadCalls_(&ReadCalls)
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

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(ReadWork{}, Executor()), Handler,
                ReadInput{std::static_pointer_cast<CountingTransmission>(Preview::Transmission::shared_from_this()), Buffer});
        }

        auto StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Net::async_initiate<Completion, void(Preview::IoResult)>(
                Net::co_composed<void(Preview::IoResult)>(WriteWork{}, Executor()), Handler,
                WriteInput{std::static_pointer_cast<CountingTransmission>(Preview::Transmission::shared_from_this()), Buffer});
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto *Inner = NextLayer())
            {
                Inner->WriteShutdown(std::move(Handler));
                return;
            }
            Preview::Transport::Detail::PostResult(std::move(Handler), {});
        }

        [[nodiscard]] auto OnClose() -> ControlResult override
        {
            if (Inner_)
            {
                (void)Inner_->Close();
            }
            return {};
        }

        [[nodiscard]] auto OnCancel() -> ControlResult override
        {
            if (Inner_)
            {
                (void)Inner_->Cancel();
            }
            return {};
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
        struct ReadInput final
        {
            std::shared_ptr<CountingTransmission> Owner;
            std::span<std::byte> Buffer;
        };
        struct WriteInput final
        {
            std::shared_ptr<CountingTransmission> Owner;
            std::span<const std::byte> Buffer;
        };
        /** @brief 原协程体原位保留，新前门一次性映射正式结果。 */
        struct ReadWork final
        {
            template<class State>
            auto operator()(State Operation, ReadInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Input.Owner->ReadPartial(Input.Buffer, Error);
                co_return std::tuple{Preview::IoResult{Count, Preview::Fault::FromNative(Error)}};
            }
        };
        struct WriteWork final
        {
            template<class State>
            auto operator()(State Operation, WriteInput Input) const -> void
            {
                Preview::Transport::Detail::ConfigureIo(Operation);
                std::error_code Error;
                const auto Count = co_await Input.Owner->WritePartial(Input.Buffer, Error);
                co_return std::tuple{Preview::IoResult{Count, Preview::Fault::FromNative(Error)}};
            }
        };
        [[nodiscard]] auto ReadPartial(std::span<std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t>
        {
            ++*ReadCalls_;
            if (!Inner_)
            {
                Error = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            const auto Read = co_await Inner_->ReadSome(Buffer);
            Error = Preview::Fault::ToNative(Read.Failure);
            co_return Read.Bytes;
        }
        [[nodiscard]] auto WritePartial(std::span<const std::byte> Buffer, std::error_code &Error)
            -> Net::awaitable<std::size_t>
        {
            if (!Inner_)
            {
                Error = std::make_error_code(std::errc::bad_file_descriptor);
                co_return 0;
            }
            const auto Write = co_await Inner_->WriteSome(Buffer);
            Error = Preview::Fault::ToNative(Write.Failure);
            co_return Write.Bytes;
        }
        Preview::SharedTransmission Inner_;
        std::size_t *ReadCalls_;
    };

    struct PipelineExecutionState final
    {
        std::shared_ptr<Preview::MemoryStream> Writer;
        Preview::SharedTransmission Inbound;
        Core::Pipeline Pipeline;
        Measurement &Output;
        const Scenario &ScenarioValue;
    };

    auto RunRecognition(std::shared_ptr<PipelineExecutionState> State)
        -> Net::awaitable<void>
    {
        std::error_code Error;
        const auto WireSpan = std::span<const std::byte>(State->ScenarioValue.Wire);
        const auto Write = co_await State->Writer->WriteSome(WireSpan);
        Error = Preview::Fault::ToNative(Write.Failure);
        const auto Written = Write.Bytes;
        if (Error || Written != State->ScenarioValue.Wire.size())
        {
            co_return;
        }
        (void)co_await State->Writer->WriteShutdown();
        auto Recognition = State->Pipeline.Recognize(State->Inbound);
        auto Result = co_await std::move(Recognition);
        State->Output.Success = Result.success;
        State->Output.Candidate = Result.Candidate;
        State->Output.CryptoTrials = Result.CryptoTrials;
        if (Result.transport)
        {
            (void)Result.transport->Close();
            Result.transport.reset();
        }
        (void)State->Writer->Close();
    }

    auto Execute(const Scenario &ScenarioValue) -> Measurement
    {
        Measurement Output;
        Net::io_context Io;
        auto [WriterValue, ReaderValue] = Preview::MakeMemoryPair(Io.get_executor());
        auto Writer = std::make_shared<Preview::MemoryStream>(std::move(WriterValue));
        auto Reader = std::make_shared<Preview::MemoryStream>(std::move(ReaderValue));
        auto Inbound = std::make_shared<CountingTransmission>(Reader, Output.ReadCalls);
        auto State = std::make_shared<PipelineExecutionState>(PipelineExecutionState{
            Writer,
            Inbound,
            Core::Pipeline(ScenarioValue.Profile),
            Output,
            ScenarioValue});
        Preview::Recognition::Perf::ResetAllocationCounters();
        std::exception_ptr Failure;
        const auto Started = std::chrono::steady_clock::now();

        Net::co_spawn(
            Io,
            RunRecognition(State),
            [&](std::exception_ptr Error)
            {
                Failure = std::move(Error);
                Io.stop();
            });
        Io.run();
        Writer->Close();
        Inbound->Close();
        Output.ElapsedNanoseconds = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - Started)
                .count());
        Output.Allocations = Preview::Recognition::Perf::ReadAllocationCounters();
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
        const auto Uuid = Preview::Recognition::Perf::FixedUuid;
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
                Binding = Composition::CandidateFactory::MakeHttp(Composition::CandidateOptions{Id});
            }
            else if (Index == 0 && Protocol == "VLESS")
            {
                Binding = Preview::Testing::MakeVlessCandidate(Composition::CandidateOptions{Id}, Preview::Vless::ServerConfig{Uuid});
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
                    Binding = Preview::Testing::MakeVmessCandidate(std::move(Options), Preview::Vmess::ServerConfig{Uuid});
                }
            }
            if (Mode == Core::RecognitionMode::Deterministic && Index > 0)
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
        std::size_t CandidateMismatches = 0;
        std::int64_t WinnerIndex = -1;
        std::uint64_t Trials = 0;
        std::uint64_t Reads = 0;
        std::uint64_t Allocations = 0;
        std::uint64_t AllocationBytesValue = 0;
        std::uint64_t AlignedAllocations = 0;
        std::uint64_t AlignedAllocationBytesValue = 0;
        for (const auto &Sample : Samples)
        {
            Timings.push_back(Sample.ElapsedNanoseconds);
            if (!Sample.Success)
            {
                ++Failures;
            }
            else if (Sample.Candidate != ScenarioValue.ExpectedCandidate)
            {
                ++Failures;
                ++CandidateMismatches;
            }
            if (Sample.Success && Sample.Candidate != Core::InvalidCandidate)
            {
                WinnerIndex = static_cast<std::int64_t>(Sample.Candidate) - 100;
            }
            Trials += Sample.CryptoTrials;
            Reads += Sample.ReadCalls;
            Allocations += Sample.Allocations.Count;
            AllocationBytesValue += Sample.Allocations.Bytes;
            AlignedAllocations += Sample.Allocations.AlignedCount;
            AlignedAllocationBytesValue += Sample.Allocations.AlignedBytes;
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
        std::cout << "{\"case\":\"recognition_pipeline\",\"path_model\":\"production_recognition_pipeline\",\"production_entry\":\"Preview::Runtime::Recognition::Pipeline::Recognize\",\"fixed_uuid\":\""
                  << Preview::Recognition::Perf::FixedUuidText << "\",\"mode\":\""
                  << ScenarioValue.ModeName << "\",\"protocol\":\""
                  << ScenarioValue.Protocol << "\",\"wire_size\":" << ScenarioValue.Wire.size()
                  << ",\"candidate_count\":" << ScenarioValue.CandidateCount
                  << ",\"expected_candidate\":"
                  << static_cast<unsigned long long>(ScenarioValue.ExpectedCandidate)
                  << ",\"winner_index\":" << WinnerIndex << ",\"candidate_mismatches\":"
                  << CandidateMismatches << ",\"trial_count\":" << Average
                  << ",\"read_calls\":" << AverageReads << ",\"ordinary_allocation_count\":"
                  << AverageAllocations << ",\"ordinary_allocation_bytes\":" << AverageAllocationBytes
                  << ",\"aligned_allocation_count\":"
                  << (Samples.empty() ? 0U : AlignedAllocations / Samples.size())
                  << ",\"aligned_allocation_bytes\":"
                  << (Samples.empty() ? 0U : AlignedAllocationBytesValue / Samples.size())
                  << ",\"median_ns\":" << Median << ",\"p95_ns\":" << Percentile(Timings, 0.95)
                  << ",\"p99_ns\":" << Percentile(Timings, 0.99)
                  << ",\"mad_ns\":" << MedianAbsoluteDeviation(Timings, Median)
                  << ",\"failures\":" << Failures << ",\"warmup\":" << Context.Warmup
                  << ",\"samples\":" << Samples.size() / SampleCount
                   << ",\"trials_per_sample\":" << Context.TrialsPerSample
                   << ",\"latency_sampled\":true,\"throughput_sampled\":false"
                   << ",\"throughput_coverage\":\"not_sampled_by_this_harness\""
                   << ",\"allocation_sampled\":true,\"rss_sampled\":false"
                   << ",\"rss_coverage\":\"not_sampled_by_this_harness\""
                   << ",\"allocation_boundary\":\"ordinary_and_aligned_process_new_requested_bytes_spawn_and_recognition_window\"}\n";
        return Failures == 0;
    }


    auto RunConfiguredCompareInternal(
        const std::size_t Warmup, const std::size_t Samples, const std::size_t Trials) -> int
    {
        bool AllPassed = true;
        const auto Uuid = Preview::Recognition::Perf::FixedUuid;
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
                else if (Mode == Core::RecognitionMode::Deterministic)
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
                    ScenarioValue.ExpectedCandidate = Core::CandidateId{100};
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
        return AllPassed ? 0 : 1;
    }
}
namespace Preview::Recognition::Perf
{
    auto RunConfiguredCompare(const std::size_t Warmup, const std::size_t Samples,
                              const std::size_t Trials) -> int
    {
        return RunConfiguredCompareInternal(Warmup, Samples, Trials);
    }
}

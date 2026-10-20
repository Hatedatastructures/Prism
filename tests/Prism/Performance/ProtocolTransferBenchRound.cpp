/**
 * @file ProtocolTransferBenchRound.cpp
 * @brief ProtocolTransferBench module owner.
 */

#include "ProtocolTransferBench.hpp"

namespace ProtocolTransferBench
{
    auto RunProtocolRoundIo(ProtocolRoundExecution &Request, LaneRunner Runner)
        -> Net::awaitable<void>
    {
        PrintRoundDiagnostic(Request, "round-start");
        for (std::size_t Index = 0; Index < Request.Executions.size(); ++Index)
        {
            Net::co_spawn(*Request.IoContext, Runner(Request.Executions[Index]), Net::detached);
        }
        for (std::size_t Index = 0; Index < Request.Executions.size() * 2U; ++Index)
        {
            co_await Request.Ready->async_receive(Net::use_awaitable);
        }
        PrintRoundDiagnostic(Request, "ready-complete");
        const auto SamplerState = std::make_shared<ProtocolSamplerState>();
        const auto SamplerStarted = std::make_shared<DoneChannel>(
            Request.IoContext->get_executor(), 1);
        const auto SamplerStart = std::make_shared<DoneChannel>(
            Request.IoContext->get_executor(), 1);
        const auto SamplerDone = std::make_shared<DoneChannel>(
            Request.IoContext->get_executor(), 1);
        Net::co_spawn(
            *Request.IoContext,
            RunProtocolSampler(ProtocolSamplerExecution{
                SamplerState, SamplerStarted, SamplerStart, SamplerDone}),
            Net::detached);
        co_await SamplerStarted->async_receive(Net::use_awaitable);
#ifdef _WIN32
        Request.ProcessBefore = SampleProcess();
#endif
        auto AllocationWindow = std::make_unique<GlobalAllocationWindow>();
        Request.BusinessStart = NowNs();
        (void)SamplerStart->try_send(boost::system::error_code{});
        for (std::size_t Index = 0; Index < Request.Executions.size() * 2U; ++Index)
        {
            (void)Request.StartGate->try_send(boost::system::error_code{});
        }
        PrintRoundDiagnostic(Request, "start-sent");
        for (std::size_t Index = 0; Index < Request.Executions.size(); ++Index)
        {
            co_await Request.Done->async_receive(Net::use_awaitable);
        }
        PrintRoundDiagnostic(Request, "done-complete");
        Request.BusinessEnd = NowNs();
        AllocationWindow->End();
        SamplerState->Stop.store(true, std::memory_order_release);
        co_await SamplerDone->async_receive(Net::use_awaitable);
#ifdef _WIN32
        Request.ProcessAfter = SampleProcess();
#endif
        Request.ProcessSampleCount = SamplerState->Samples;
        Request.SamplePeakWorkingSet = SamplerState->PeakWorkingSet;
        Request.SamplePeakPrivateUsage = SamplerState->PeakPrivateUsage;
        Request.ProcessSamplerValid = SamplerState->Valid;
        Request.GlobalStats = AllocationWindow->Stats();
        for (std::size_t Index = 0; Index < Request.Executions.size(); ++Index)
        {
            (void)Request.End->try_send(boost::system::error_code{});
        }
        PrintRoundDiagnostic(Request, "end-sent");
        for (std::size_t Index = 0; Index < Request.Executions.size(); ++Index)
        {
            co_await Request.Exited->async_receive(Net::use_awaitable);
        }
        PrintRoundDiagnostic(Request, "exited-complete");
    }

    auto AggregateRound(
        const std::vector<std::shared_ptr<LaneMetric>> &Metrics,
        const std::size_t Total,
        const std::int64_t WallNs) -> ProtocolRound
    {
        ProtocolRound Round;
        Round.WallNs = WallNs;
        Round.Completed = true;
        bool HasHash = false;
        for (const auto &Metric : Metrics)
        {
            Round.Sent += Metric->ClientSent;
            Round.Echoed += Metric->ClientEchoed;
            Round.Errors += Metric->Errors;
            Round.PartialIo += Metric->PartialIo;
            Round.BlockSamples.insert(Round.BlockSamples.end(),
                                      Metric->BlockSamples.begin(), Metric->BlockSamples.end());
            Round.Completed = Round.Completed && Metric->ServerComplete &&
                              Metric->ClientComplete && Metric->ServerBytes == Total &&
                              Metric->ExpectedInputHash == Metric->ServerInputHash &&
                              Metric->ExpectedInputHash == Metric->ClientOutputHash;
            if (!HasHash)
            {
                Round.ExpectedInputHash = Metric->ExpectedInputHash;
                Round.ServerInputHash = Metric->ServerInputHash;
                Round.ClientOutputHash = Metric->ClientOutputHash;
                HasHash = true;
            }
            else if (Round.ExpectedInputHash != Metric->ExpectedInputHash ||
                     Round.ServerInputHash != Metric->ServerInputHash ||
                     Round.ClientOutputHash != Metric->ClientOutputHash)
            {
                ++Round.Errors;
            }
        }
        Round.Completed = Round.Completed && Round.Errors == 0 &&
                          Round.Sent == Total * Metrics.size() &&
                          Round.Echoed == Total * Metrics.size();
        return Round;
    }

    [[nodiscard]] auto RunProtocolRound(
        const ProtocolRoundOptions &Options,
        LaneRunner Runner) -> ProtocolRound
    {
        Net::io_context IoContext;
        auto Request = MakeProtocolRoundExecution(IoContext, Options);
        const auto Failure = RunBenchIo(
            IoContext,
            [&Request, Runner]() -> Net::awaitable<void>
            {
                co_await RunProtocolRoundIo(Request, Runner);
            }());
        if (Failure)
        {
            for (const auto &Metric : Request.Metrics)
            {
                ++Metric->Errors;
            }
        }
        auto Round = AggregateRound(
            Request.Metrics, Request.Total, Request.BusinessEnd - Request.BusinessStart);
        Round.GlobalAllocations = Request.GlobalStats;
#ifdef _WIN32
        Round.CpuUser100ns = Request.ProcessAfter.User100ns - Request.ProcessBefore.User100ns;
        Round.CpuKernel100ns = Request.ProcessAfter.Kernel100ns - Request.ProcessBefore.Kernel100ns;
        Round.PeakWorkingSet = (std::max)({
            Request.ProcessBefore.WorkingSet, Request.ProcessAfter.WorkingSet,
            Request.SamplePeakWorkingSet});
        Round.PeakPrivateUsage = (std::max)({
            Request.ProcessBefore.PrivateUsage, Request.ProcessAfter.PrivateUsage,
            Request.SamplePeakPrivateUsage});
        Round.ProcessSampleCount = Request.ProcessSampleCount;
        Round.ProcessAvailable = Request.ProcessBefore.Available &&
                                 Request.ProcessAfter.Available && Request.ProcessSamplerValid &&
                                 Request.ProcessSampleCount > 0;
#endif
        return Round;
    }

    [[nodiscard]] auto RunSocksRound(const ProtocolRoundOptions &Options) -> ProtocolRound
    {
        return RunProtocolRound(Options, RunSocksLane);
    }


}

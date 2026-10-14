/**
 * @file ProtocolTransferBenchSupport.cpp
 * @brief ProtocolTransferBench module owner.
 */

#include "ProtocolTransferBench.hpp"

namespace ProtocolTransferBench
{
    auto NowNs() -> std::int64_t
    {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
    }

    auto PrintLaneDiagnostic(
        const LaneMetric &Metric,
        const char *Side,
        const char *Stage) -> void
    {
        if (!Metric.Diagnose)
        {
            return;
        }
        std::printf(
            "protocol-diagnose timestamp-ns=%lld protocol=%s lane=%zu side=%s stage=%s "
            "server-ready=%s client-ready=%s server-transfer=%s client-transfer=%s "
            "server-cleanup=%s client-cleanup=%s server-bytes=%zu client-sent=%zu "
            "client-echoed=%zu errors=%zu partial=%zu expected-hash=%016llx "
            "server-input-hash=%016llx client-output-hash=%016llx "
            "server-complete=%s client-complete=%s\n",
            static_cast<long long>(NowNs()), Metric.ProtocolName, Metric.LaneIndex, Side, Stage,
            Metric.ServerReadySent ? "yes" : "no", Metric.ClientReadySent ? "yes" : "no",
            Metric.ServerTransferSent ? "yes" : "no", Metric.ClientTransferSent ? "yes" : "no",
            Metric.ServerCleanupSent ? "yes" : "no", Metric.ClientCleanupSent ? "yes" : "no",
            Metric.ServerBytes, Metric.ClientSent, Metric.ClientEchoed, Metric.Errors,
            Metric.PartialIo, static_cast<unsigned long long>(Metric.ExpectedInputHash),
            static_cast<unsigned long long>(Metric.ServerInputHash),
            static_cast<unsigned long long>(Metric.ClientOutputHash),
            Metric.ServerComplete ? "yes" : "no", Metric.ClientComplete ? "yes" : "no");
        std::fflush(stdout);
    }

    auto SignalLaneReady(LaneMetric &Metric, const bool Server,
                         const std::shared_ptr<DoneChannel> &Ready) -> void
    {
        auto &Sent = Server ? Metric.ServerReadySent : Metric.ClientReadySent;
        if (!Sent)
        {
            Sent = true;
            (void)Ready->try_send(boost::system::error_code{});
            PrintLaneDiagnostic(Metric, Server ? "server" : "client", "ready");
        }
    }

    auto SignalLaneTransfer(LaneMetric &Metric, const bool Server,
                            const std::shared_ptr<DoneChannel> &TransferDone) -> void
    {
        auto &Sent = Server ? Metric.ServerTransferSent : Metric.ClientTransferSent;
        if (!Sent)
        {
            Sent = true;
            (void)TransferDone->try_send(boost::system::error_code{});
            PrintLaneDiagnostic(Metric, Server ? "server" : "client", "transfer-done");
        }
    }

    auto SignalLaneCleanup(LaneMetric &Metric, const bool Server,
                           const std::shared_ptr<DoneChannel> &CleanupDone) -> void
    {
        auto &Sent = Server ? Metric.ServerCleanupSent : Metric.ClientCleanupSent;
        if (!Sent)
        {
            Sent = true;
            (void)CleanupDone->try_send(boost::system::error_code{});
            PrintLaneDiagnostic(Metric, Server ? "server" : "client", "cleanup-done");
        }
    }

    [[nodiscard]] auto WaitLaneEnd(
        const LaneExecution &Request,
        const bool Server) -> Net::awaitable<void>
    {
        co_await Request.End->async_receive(Net::use_awaitable);
        PrintLaneDiagnostic(*Request.Metric, Server ? "server" : "client", "end");
    }

    auto ReleaseLaneMetric(LaneMetric &Metric, const bool Server) -> void
    {
        auto &Owner = Server ? Metric.ServerOwner : Metric.ClientOwner;
        if (Owner)
        {
            (void)Owner->Close();
            Owner.reset();
        }
        if (Server)
        {
            Metric.ServerBuffer.reset();
        }
        else
        {
            Metric.ClientChunks.reset();
            Metric.ClientEcho.reset();
        }
    }

    auto MakeProtocolRoundExecution(
        Net::io_context &IoContext,
        const ProtocolRoundOptions &Options) -> ProtocolRoundExecution
    {
        ProtocolRoundExecution Request;
        Request.IoContext = &IoContext;
        Request.Total = Options.Total;
        Request.BlockSize = Options.BlockSize;
        Request.ProtocolName = Options.ProtocolName;
        Request.Diagnose = Options.Diagnose;
        Request.Acceptors.reserve(Options.LaneCount);
        Request.Metrics.reserve(Options.LaneCount);
        for (std::size_t Index = 0; Index < Options.LaneCount; ++Index)
        {
            Request.Acceptors.push_back(std::make_shared<Net::ip::tcp::acceptor>(
                IoContext, Net::ip::tcp::endpoint(Net::ip::tcp::v4(), 0)));
            auto Metric = std::make_shared<LaneMetric>();
            Metric->LaneIndex = Index;
            Metric->ExpectedInputHash = Options.ExpectedInputHash;
            Metric->ProtocolName = Options.ProtocolName;
            Metric->Diagnose = Options.Diagnose;
            Request.Metrics.push_back(std::move(Metric));
        }
        Request.Ready = std::make_shared<DoneChannel>(
            IoContext.get_executor(), Options.LaneCount * 2U);
        Request.StartGate = std::make_shared<DoneChannel>(
            IoContext.get_executor(), Options.LaneCount * 2U);
        Request.Done = std::make_shared<DoneChannel>(IoContext.get_executor(), Options.LaneCount);
        Request.End = std::make_shared<DoneChannel>(IoContext.get_executor(), Options.LaneCount);
        Request.Exited = std::make_shared<DoneChannel>(IoContext.get_executor(), Options.LaneCount);
        Request.Executions.reserve(Options.LaneCount);
        for (std::size_t Index = 0; Index < Options.LaneCount; ++Index)
        {
            Request.Executions.push_back(LaneExecution{
                Request.Acceptors[Index], Options.Total, Options.BlockSize, Request.Metrics[Index], Request.Ready,
                Request.StartGate, std::make_shared<DoneChannel>(IoContext.get_executor(), 2),
                std::make_shared<DoneChannel>(IoContext.get_executor(), 2), Request.End,
                Request.Done, Request.Exited, Index, Options.ProtocolName, Options.Diagnose});
        }
        return Request;
    }

    auto PrintRoundDiagnostic(
        const ProtocolRoundExecution &Request,
        const char *Stage) -> void
    {
        if (!Request.Diagnose)
        {
            return;
        }
        std::printf(
            "protocol-diagnose timestamp-ns=%lld protocol=%s lane-count=%zu stage=%s\n",
            static_cast<long long>(NowNs()), Request.ProtocolName,
            Request.Executions.size(), Stage);
        std::fflush(stdout);
    }

    auto RunProtocolSampler(ProtocolSamplerExecution Request) -> Net::awaitable<void>
    {
        const auto &State = Request.State;
        (void)Request.Started->try_send(boost::system::error_code{});
        try
        {
            boost::system::error_code StartError;
            co_await Request.StartSampling->async_receive(
                Net::redirect_error(Net::use_awaitable, StartError));
            if (StartError)
            {
                State->Valid = false;
            }
#ifdef _WIN32
            if (!StartError)
            {
                const auto Executor = co_await Net::this_coro::executor;
                Net::steady_timer Timer(Executor);
                while (!State->Stop.load(std::memory_order_acquire))
                {
                    const auto Sample = SampleProcess();
                    ++State->Samples;
                    if (!Sample.Available)
                    {
                        State->Valid = false;
                    }
                    else
                    {
                        State->PeakWorkingSet =
                            (std::max)(State->PeakWorkingSet, Sample.WorkingSet);
                        State->PeakPrivateUsage =
                            (std::max)(State->PeakPrivateUsage, Sample.PrivateUsage);
                    }
                    Timer.expires_after(std::chrono::milliseconds(1));
                    boost::system::error_code TimerError;
                    co_await Timer.async_wait(
                        Net::redirect_error(Net::use_awaitable, TimerError));
                    if (TimerError && !State->Stop.load(std::memory_order_acquire))
                    {
                        State->Valid = false;
                        break;
                    }
                }
            }
#endif
        }
        catch (...)
        {
            State->Valid = false;
        }
        (void)Request.Done->try_send(boost::system::error_code{});
        co_return;
    }

    [[nodiscard]] auto AsBytes(std::vector<std::uint8_t> &Buffer) -> std::span<std::byte>
    {
        return {reinterpret_cast<std::byte *>(Buffer.data()), Buffer.size()};
    }

    [[nodiscard]] auto AsConstBytes(const std::vector<std::uint8_t> &Buffer)
        -> std::span<const std::byte>
    {
        return {reinterpret_cast<const std::byte *>(Buffer.data()), Buffer.size()};
    }

    auto HashBytes(std::uint64_t &Hash, std::span<const std::byte> Data) -> void
    {
        for (const auto Byte : Data)
        {
            Hash ^= std::to_integer<std::uint8_t>(Byte);
            Hash *= 1099511628211ULL;
        }
    }

    auto FillPayload(std::span<std::byte> Buffer, const std::size_t Offset) -> void
    {
        for (std::size_t Index = 0; Index < Buffer.size(); ++Index)
        {
            Buffer[Index] = std::byte{
                static_cast<unsigned char>((Offset + Index) & 0xFFU)};
        }
    }

    [[nodiscard]] auto PayloadHash(const std::size_t Total) -> std::uint64_t
    {
        std::uint64_t Hash = InitialHash;
        for (std::size_t Offset = 0; Offset < Total; ++Offset)
        {
            Hash ^= static_cast<std::uint8_t>(Offset & 0xFFU);
            Hash *= 1099511628211ULL;
        }
        return Hash;
    }


}


/**
 * @file ProtocolTransferBench.hpp
 * @brief 协议传输基准共享的 lane、round、allocator 和入口契约。
 */

#pragma once

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <functional>
#include <memory>
#include <span>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

#include <Prism/Transport/Reliable.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Vmess/Vmess.hpp>

namespace Net = boost::asio;
namespace Socks5 = Prism::Socks5;
namespace Transport = Prism::Transport;
namespace Vmess = Prism::Vmess;
using Prism::Error;

namespace ProtocolBenchAllocation
{
    struct Snapshot final
    {
        std::size_t OrdinaryAllocations{0};
        std::size_t AlignedAllocations{0};
        std::size_t OrdinaryBytes{0};
        std::size_t AlignedBytes{0};
    };
    inline std::atomic<bool> Active{false};
    inline std::atomic<std::size_t> OrdinaryAllocations{0}, AlignedAllocations{0};
    inline std::atomic<std::size_t> OrdinaryBytes{0}, AlignedBytes{0};
    inline auto Start() noexcept -> void
    {
        OrdinaryAllocations.store(0, std::memory_order_relaxed);
        AlignedAllocations.store(0, std::memory_order_relaxed);
        OrdinaryBytes.store(0, std::memory_order_relaxed);
        AlignedBytes.store(0, std::memory_order_relaxed);
        Active.store(true, std::memory_order_release);
    }
    inline auto Stop() noexcept -> void { Active.store(false, std::memory_order_release); }
    [[nodiscard]] inline auto Read() noexcept -> Snapshot
    {
        return {OrdinaryAllocations.load(std::memory_order_relaxed),
                AlignedAllocations.load(std::memory_order_relaxed),
                OrdinaryBytes.load(std::memory_order_relaxed),
                AlignedBytes.load(std::memory_order_relaxed)};
    }
}
namespace ProtocolTransferBench
{
    using Clock = std::chrono::steady_clock;
    inline constexpr std::uint64_t InitialHash = 1469598103934665603ULL;
    inline constexpr std::size_t ProtocolRoundCount = 5;
    inline constexpr std::size_t DefaultProtocolMatrixGroups = 30;
    using LaneRunner = Net::awaitable<void> (*)(struct LaneExecution Request);
    struct Result
    {
        std::array<std::int64_t, 5> Samples{};
        auto Median() const -> std::int64_t
        {
            auto Sorted = Samples;
            std::sort(Sorted.begin(), Sorted.end());
            return Sorted[2];
        }
    };

    struct ChunkRun final
    {
        std::int64_t ElapsedNanoseconds{0};
        std::uint64_t OutputHash{InitialHash};
        std::size_t OutputBytes{0};
        bool Valid{false};
    };

    struct alignas(64) AlignedPayload final
    {
        std::array<std::byte, 64> Bytes{};
    };

    struct LaneMetric final
    {
        std::size_t ServerBytes{0};
        std::size_t ClientSent{0};
        std::size_t ClientEchoed{0};
        std::size_t Errors{0};
        std::uint64_t ExpectedInputHash{InitialHash};
        std::uint64_t ServerInputHash{InitialHash};
        std::uint64_t ClientOutputHash{InitialHash};
        std::size_t PartialIo{0};
        std::vector<std::int64_t> BlockSamples;
        Prism::SharedTransmission ClientOwner;
        Prism::SharedTransmission ServerOwner;
        std::shared_ptr<std::vector<AlignedPayload>> ClientChunks;
        std::shared_ptr<std::vector<std::uint8_t>> ClientEcho;
        std::shared_ptr<std::vector<std::uint8_t>> ServerBuffer;
        bool ServerReadySent{false};
        bool ClientReadySent{false};
        bool ServerTransferSent{false};
        bool ClientTransferSent{false};
        bool ServerCleanupSent{false};
        bool ClientCleanupSent{false};
        bool ServerComplete{false};
        bool ClientComplete{false};
        std::size_t LaneIndex{0};
        const char *ProtocolName{"protocol"};
        bool Diagnose{false};
    };

    struct ProtocolRound final
    {
        std::int64_t WallNs{0};
        std::size_t Sent{0};
        std::size_t Echoed{0};
        std::size_t Errors{0};
        std::uint64_t ExpectedInputHash{InitialHash};
        std::uint64_t ServerInputHash{InitialHash};
        std::uint64_t ClientOutputHash{InitialHash};
        std::size_t PartialIo{0};
        std::vector<std::int64_t> BlockSamples;
        std::uint64_t CpuUser100ns{0};
        std::uint64_t CpuKernel100ns{0};
        std::size_t PeakWorkingSet{0};
        std::size_t PeakPrivateUsage{0};
        std::size_t ProcessSampleCount{0};
        bool ProcessAvailable{false};
        ProtocolBenchAllocation::Snapshot GlobalAllocations{};
        bool Completed{false};
    };

    struct ProtocolSeries final
    {
        std::array<ProtocolRound, ProtocolRoundCount> Rounds;
    };

    using DoneChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct LaneExecution final
    {
        std::shared_ptr<Net::ip::tcp::acceptor> Acceptor;
        std::size_t Total{0};
        std::size_t BlockSize{0};
        std::shared_ptr<LaneMetric> Metric;
        std::shared_ptr<DoneChannel> Ready;
        std::shared_ptr<DoneChannel> Start;
        std::shared_ptr<DoneChannel> TransferDone;
        std::shared_ptr<DoneChannel> CleanupDone;
        std::shared_ptr<DoneChannel> End;
        std::shared_ptr<DoneChannel> Done;
        std::shared_ptr<DoneChannel> Exited;
        std::size_t LaneIndex{0};
        const char *ProtocolName{"protocol"};
        bool Diagnose{false};
    };

#ifdef _WIN32
    struct ProcessSample final
    {
        std::uint64_t User100ns{0};
        std::uint64_t Kernel100ns{0};
        std::size_t WorkingSet{0};
        std::size_t PrivateUsage{0};
        bool Available{false};
    };

    [[nodiscard]] inline auto SampleProcess() -> ProcessSample
    {
        ProcessSample Result;
        FILETIME CreateTime{}, ExitTime{}, KernelTime{}, UserTime{};
        const auto TimesAvailable = GetProcessTimes(
            GetCurrentProcess(), &CreateTime, &ExitTime, &KernelTime, &UserTime) != FALSE;
        if (TimesAvailable)
        {
            ULARGE_INTEGER User{}, Kernel{};
            User.LowPart = UserTime.dwLowDateTime;
            User.HighPart = UserTime.dwHighDateTime;
            Kernel.LowPart = KernelTime.dwLowDateTime;
            Kernel.HighPart = KernelTime.dwHighDateTime;
            Result.User100ns = User.QuadPart;
            Result.Kernel100ns = Kernel.QuadPart;
        }
        PROCESS_MEMORY_COUNTERS_EX Counters{};
        Counters.cb = sizeof(Counters);
        const auto MemoryAvailable = K32GetProcessMemoryInfo(
            GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&Counters),
            sizeof(Counters)) != FALSE;
        if (MemoryAvailable)
        {
            Result.WorkingSet = Counters.WorkingSetSize;
            Result.PrivateUsage = Counters.PrivateUsage;
        }
        Result.Available = TimesAvailable && MemoryAvailable;
        return Result;
    }
#endif

    class GlobalAllocationWindow final
    {
    public:
        GlobalAllocationWindow()
        {
            ProtocolBenchAllocation::Start();
        }

        ~GlobalAllocationWindow()
        {
            End();
        }

        auto End() noexcept -> void
        {
            if (!Active_)
            {
                return;
            }
            ProtocolBenchAllocation::Stop();
            Snapshot_ = ProtocolBenchAllocation::Read();
            Active_ = false;
        }

        [[nodiscard]] auto Stats() const noexcept -> ProtocolBenchAllocation::Snapshot
        {
            return Snapshot_;
        }

    private:
        bool Active_{true};
        ProtocolBenchAllocation::Snapshot Snapshot_{};
    };

    struct ProtocolSamplerState final
    {
        std::atomic<bool> Stop{false};
        std::size_t Samples{0};
        std::size_t PeakWorkingSet{0};
        std::size_t PeakPrivateUsage{0};
        bool Valid{true};
    };

    struct ProtocolSamplerExecution final
    {
        std::shared_ptr<ProtocolSamplerState> State;
        std::shared_ptr<DoneChannel> Started;
        std::shared_ptr<DoneChannel> StartSampling;
        std::shared_ptr<DoneChannel> Done;
    };

    struct ProtocolRoundOptions final
    {
        std::size_t Total{0};
        std::size_t BlockSize{0};
        std::size_t LaneCount{0};
        std::uint64_t ExpectedInputHash{InitialHash};
        const char *ProtocolName{"protocol"};
        bool Diagnose{false};
    };

    struct ProtocolRoundExecution final
    {
        Net::io_context *IoContext{nullptr};
        std::size_t Total{0};
        std::size_t BlockSize{0};
        std::vector<std::shared_ptr<Net::ip::tcp::acceptor>> Acceptors;
        std::vector<std::shared_ptr<LaneMetric>> Metrics;
        std::vector<LaneExecution> Executions;
        std::shared_ptr<DoneChannel> Ready;
        std::shared_ptr<DoneChannel> StartGate;
        std::shared_ptr<DoneChannel> Done;
        std::shared_ptr<DoneChannel> End;
        std::shared_ptr<DoneChannel> Exited;
        std::int64_t BusinessStart{0};
        std::int64_t BusinessEnd{0};
        ProtocolBenchAllocation::Snapshot GlobalStats{};
        std::size_t ProcessSampleCount{0};
        std::size_t SamplePeakWorkingSet{0};
        std::size_t SamplePeakPrivateUsage{0};
        bool ProcessSamplerValid{true};
        const char *ProtocolName{"protocol"};
        bool Diagnose{false};
#ifdef _WIN32
        ProcessSample ProcessBefore;
        ProcessSample ProcessAfter;
#endif
    };

    struct ProtocolSeriesPrintRequest final
    {
        const char *Name{nullptr};
        std::size_t Total{0};
        std::size_t LaneCount{0};
        const ProtocolSeries *Series{nullptr};
    };

    /** @brief 共享基准时钟、哈希、lane 生命周期与 round 编排契约。 */
    auto NowNs() -> std::int64_t;
    auto HashBytes(std::uint64_t &Hash, std::span<const std::byte> Data) -> void;
    auto FillPayload(std::span<std::byte> Buffer, std::size_t Offset) -> void;
    [[nodiscard]] auto PayloadHash(std::size_t Total) -> std::uint64_t;
    auto PrintLaneDiagnostic(const LaneMetric &Metric, const char *Side,
                             const char *Stage) -> void;
    auto SignalLaneReady(LaneMetric &Metric, bool Server,
                         const std::shared_ptr<DoneChannel> &Ready) -> void;
    auto SignalLaneTransfer(LaneMetric &Metric, bool Server,
                            const std::shared_ptr<DoneChannel> &TransferDone) -> void;
    auto SignalLaneCleanup(LaneMetric &Metric, bool Server,
                           const std::shared_ptr<DoneChannel> &CleanupDone) -> void;
    auto WaitLaneEnd(const LaneExecution &Request, bool Server) -> Net::awaitable<void>;
    auto ReleaseLaneMetric(LaneMetric &Metric, bool Server) -> void;
    auto MakeProtocolRoundExecution(Net::io_context &IoContext,
                                    const ProtocolRoundOptions &Options) -> ProtocolRoundExecution;
    auto PrintRoundDiagnostic(const ProtocolRoundExecution &Request,
                              const char *Stage) -> void;
    auto RunProtocolSampler(ProtocolSamplerExecution Request) -> Net::awaitable<void>;
    [[nodiscard]] auto AsBytes(std::vector<std::uint8_t> &Buffer) -> std::span<std::byte>;
    [[nodiscard]] auto AsConstBytes(const std::vector<std::uint8_t> &Buffer)
        -> std::span<const std::byte>;
    [[nodiscard]] auto WriteAll(
        const Prism::SharedTransmission &Conn,
        std::span<const std::byte> Data,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;
    [[nodiscard]] auto ReadExact(
        const Prism::SharedTransmission &Conn,
        std::span<std::byte> Data,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>;
    auto RunBenchIo(Net::io_context &IoContext, Net::awaitable<void> Coroutine)
        -> std::exception_ptr;
    [[nodiscard]] auto RunProtocolRound(const ProtocolRoundOptions &Options,
                                        LaneRunner Runner) -> ProtocolRound;
    [[nodiscard]] auto RunSocksRound(std::size_t Total, std::size_t BlockSize,
                                     std::size_t LaneCount,
                                     std::uint64_t ExpectedInputHash) -> ProtocolRound;
    [[nodiscard]] auto RunVmessRound(std::size_t Total, std::size_t BlockSize,
                                     std::size_t LaneCount,
                                     std::uint64_t ExpectedInputHash) -> ProtocolRound;
    auto RunSocksLane(LaneExecution Request) -> Net::awaitable<void>;
    auto RunVmessLane(LaneExecution Request) -> Net::awaitable<void>;
    auto RunProtocolDiagnosis(std::size_t Total, std::size_t BlockSize) -> int;
    auto RunPreflightDiagnosis() -> int;
    [[nodiscard]] auto RunAllocationPreflight(bool Diagnose = false) -> bool;
    [[nodiscard]] auto RunFailurePreflightCase(bool Diagnose = false) -> bool;
    [[nodiscard]] auto BenchVmessChunk(bool Reuse) -> ChunkRun;
    [[nodiscard]] auto PrintProtocolSeries(const ProtocolSeriesPrintRequest &Request) -> bool;
    [[nodiscard]] auto Gate(const char *Name, std::size_t Bytes,
                            const Result &Statistics) -> bool;

}

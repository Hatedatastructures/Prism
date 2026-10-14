/**
 * @file TransferPerf.hpp
 * @brief TransferPerf 的 endpoint、round、allocation 与 CLI owner 契约。
 */

#pragma once

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
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
#include <memory_resource>
#include <limits>
#include <span>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

#include <Preview/Transport/Connector.hpp>
#include <Preview/Transport/Reliable.hpp>
#include <Preview/Transport/Transmission.hpp>

namespace Net = boost::asio;
namespace Transport = Preview::Transport;

namespace TransferPerfAllocation
{
    struct Counters final
    {
        std::atomic<bool> Active{false};
        std::atomic<std::size_t> OrdinaryAllocations{0}, AlignedAllocations{0};
        std::atomic<std::size_t> OrdinaryBytes{0}, AlignedBytes{0};
        std::atomic<std::size_t> OrdinaryFrees{0}, AlignedFrees{0};
    };
    inline Counters State;
    struct Snapshot final
    {
        std::size_t OrdinaryAllocations{0};
        std::size_t AlignedAllocations{0};
        std::size_t OrdinaryBytes{0};
        std::size_t AlignedBytes{0};
        std::size_t OrdinaryFrees{0};
        std::size_t AlignedFrees{0};
    };
    inline auto Start() noexcept -> void
    {
        State.OrdinaryAllocations.store(0, std::memory_order_relaxed);
        State.AlignedAllocations.store(0, std::memory_order_relaxed);
        State.OrdinaryBytes.store(0, std::memory_order_relaxed);
        State.AlignedBytes.store(0, std::memory_order_relaxed);
        State.OrdinaryFrees.store(0, std::memory_order_relaxed);
        State.AlignedFrees.store(0, std::memory_order_relaxed);
        State.Active.store(true, std::memory_order_release);
    }
    inline auto Stop() noexcept -> void { State.Active.store(false, std::memory_order_release); }
    [[nodiscard]] inline auto ReadSnapshot() noexcept -> Snapshot
    {
        return {State.OrdinaryAllocations.load(std::memory_order_relaxed),
                State.AlignedAllocations.load(std::memory_order_relaxed),
                State.OrdinaryBytes.load(std::memory_order_relaxed),
                State.AlignedBytes.load(std::memory_order_relaxed),
                State.OrdinaryFrees.load(std::memory_order_relaxed),
                State.AlignedFrees.load(std::memory_order_relaxed)};
    }
}

namespace TransferPerf
{
    inline constexpr std::uint64_t InitialHash = 1469598103934665603ULL;
    inline constexpr std::size_t DeterministicFragmentBytes = 4096;
    inline constexpr std::size_t CompareRoundCount = 5;
    inline constexpr std::size_t ExpectedCompareGroups = 45;
    inline constexpr std::size_t ExpectedCompareLanes = 105;
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code, bool)>;
    using IoCompletion = Net::experimental::channel<void(boost::system::error_code, std::size_t)>;
    using GateChannel = Net::experimental::channel<void(boost::system::error_code)>;
    using LaneSignalChannel = Net::experimental::channel<void(boost::system::error_code, std::size_t)>;
    enum class IoMode : std::uint8_t { Direct, AwaitableBridge, ScatterGather };
    class AwaitableBridge;
    struct IoEndpoint final
    {
        std::shared_ptr<Preview::Transport::Reliable> Reliable;
        std::shared_ptr<AwaitableBridge> Bridge;
        std::unique_ptr<Preview::Transport::Connector> Scatter;
        std::size_t FragmentBytes{DeterministicFragmentBytes};
    };
    struct ErrorProjection final
    {
        std::string RawCategory;
        std::string RawMessage;
        int RawValue{0};
    };

    struct EndpointReadRequest final
    {
        IoEndpoint &Endpoint;
        IoMode Mode;
        std::span<std::byte> Buffer;
        ErrorProjection *Diagnostic{nullptr};
    };
    struct IoCompareResult final
    {
        std::int64_t WallNs{0};
        std::size_t Sent{0};
        std::size_t Received{0};
        std::size_t Partial{0};
        std::size_t Errors{0};
        std::uint64_t ExpectedInputHash{InitialHash};
        std::uint64_t ServerInputHash{InitialHash};
        std::uint64_t ClientOutputHash{InitialHash};
        std::vector<std::int64_t> BlockSamples;
        std::size_t OrdinaryAllocations{0};
        std::size_t AlignedAllocations{0};
        std::size_t OrdinaryBytes{0};
        std::size_t AlignedBytes{0};
        std::uint64_t CpuUser100ns{0};
        std::uint64_t CpuKernel100ns{0};
        std::size_t PeakWorkingSet{0};
        std::size_t PeakPrivateUsage{0};
        std::size_t ProcessSampleCount{0};
        TransferPerfAllocation::Snapshot GlobalAllocations{};
        bool ProcessAvailable{false};
        std::size_t LaneId{(std::numeric_limits<std::size_t>::max)()};
        bool ServerCompleted{false};
        bool Completed{false};
    };
    using IoCompareResultChannel = Net::experimental::channel<void(boost::system::error_code, IoCompareResult)>;
    struct AllocationStats final
    {
        std::size_t OrdinaryAllocations{0};
        std::size_t AlignedAllocations{0};
        std::size_t OrdinaryBytes{0};
        std::size_t AlignedBytes{0};
    };
    struct ProcessMetrics final
    {
        std::array<std::uint64_t, 5> CpuUser100ns{};
        std::array<std::uint64_t, 5> CpuKernel100ns{};
        std::array<std::size_t, 5> WorkingSet{};
        std::array<std::size_t, 5> PrivateUsage{};
        std::array<std::size_t, 5> SampleCount{};
        std::array<TransferPerfAllocation::Snapshot, 5> GlobalAllocations{};
        std::array<bool, 5> Available{};
    };
    struct ProcessSamplerState final
    {
        std::atomic<bool> Stop{false};
        std::size_t SampleCount{0};
        std::size_t PeakWorkingSet{0};
        std::size_t PeakPrivateUsage{0};
        bool Valid{true};
    };

    struct LaneReadyRequest final
    {
        const std::shared_ptr<LaneSignalChannel> &Ready;
        const std::shared_ptr<std::atomic_bool> &Signaled;
        std::size_t LaneIndex{0};
        bool Success{false};
    };

    struct ProcessSamplerRequest final
    {
        std::shared_ptr<ProcessSamplerState> State;
        std::shared_ptr<GateChannel> Started;
        std::shared_ptr<GateChannel> StartSampling;
        std::shared_ptr<GateChannel> Done;
    };

    struct CompareRoundRequest final
    {
        IoMode Mode{IoMode::Direct};
        std::size_t LaneCount{1};
        std::size_t TotalBytes{0};
        std::size_t BlockSize{0};
        std::size_t Round{0};
        std::uint64_t ExpectedInputHash{InitialHash};
        bool InjectStartupFailure{false};
    };

    struct CompareMetricsRequest final
    {
        const char *Name{nullptr};
        std::size_t LaneCount{0};
        const std::array<std::int64_t, 5> &WallSamples;
        const std::vector<std::int64_t> &BlockSamples;
        const AllocationStats &Allocation;
        const ProcessMetrics &Process;
        std::size_t ConfirmedBytesPerRound{0};
        std::size_t Partial{0};
        std::uint64_t ExpectedInputHash{InitialHash};
        std::uint64_t ServerInputHash{InitialHash};
        std::uint64_t ClientOutputHash{InitialHash};
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
    struct alignas(64) AlignedPayload final { std::array<std::byte, 64> Bytes{}; };
    struct ComparePlan final
    {
        std::size_t TotalBytes{256ULL * 1024 * 1024};
        std::size_t BlockSize{64ULL * 1024};
        std::array<std::size_t, 3> LaneCounts{1, 2, 4};
        std::size_t Rounds{CompareRoundCount};
        std::size_t ExpectedGroups{ExpectedCompareGroups};
        std::size_t ExpectedLanes{ExpectedCompareLanes};
        std::size_t FragmentBytes{DeterministicFragmentBytes};
    };
    auto HashBytes(std::uint64_t &Hash, std::span<const std::byte> Data) -> void;
    auto FillPayload(std::span<std::byte> Buffer, std::size_t Offset) -> void;
    [[nodiscard]] auto PayloadHash(std::size_t Total) -> std::uint64_t;
    class CountingResource final : public std::pmr::memory_resource
    {
    public:
        explicit CountingResource(AllocationStats &Stats) : Stats_(Stats) {}
    private:
        void *do_allocate(std::size_t Bytes, std::size_t Alignment) override
        {
            if (Alignment <= alignof(std::max_align_t)) { ++Stats_.OrdinaryAllocations; Stats_.OrdinaryBytes += Bytes; }
            else { ++Stats_.AlignedAllocations; Stats_.AlignedBytes += Bytes; }
            return std::pmr::new_delete_resource()->allocate(Bytes, Alignment);
        }
        void do_deallocate(void *Pointer, std::size_t Bytes, std::size_t Alignment) override
        { std::pmr::new_delete_resource()->deallocate(Pointer, Bytes, Alignment); }
        [[nodiscard]] auto do_is_equal(const std::pmr::memory_resource &Other) const noexcept -> bool override
        { return this == &Other; }
        AllocationStats &Stats_;
    };
    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &IoContext, Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
            [&Exception, &IoContext](std::exception_ptr ErrorValue)
            { Exception = std::move(ErrorValue); IoContext.stop(); });
        IoContext.run();
        if (Exception) std::rethrow_exception(Exception);
    }
    struct ServerState;
    struct Result final
    {
        std::array<std::int64_t, 3> Samples{};
        [[nodiscard]] auto Median() const -> std::int64_t
        { auto Sorted = Samples; std::sort(Sorted.begin(), Sorted.end()); return Sorted[1]; }
    };
}


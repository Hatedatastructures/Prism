/**
 * @file ManagementModels.hpp
 * @brief 运行概览、代理入口、用户组和追踪查询的 owning JSON 数据模型。
 */
#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Operations/Metrics.hpp>
#include <Prism/Operations/QueryPage.hpp>
#include <Prism/Statistics/TrafficHistory.hpp>
#include <Prism/Statistics/Snapshots.hpp>
#include <Prism/Statistics/Types.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace Prism::Operations
{

    struct LatencySummary final
    {
        std::string Name;
        bool Available{false};
        std::uint64_t SampleCount{0};
        std::optional<std::uint64_t> P50Milliseconds{};
        std::optional<std::uint64_t> P95Milliseconds{};
        std::optional<std::uint64_t> P99Milliseconds{};
        std::optional<std::uint64_t> MaximumMilliseconds{};
        std::optional<Prism::WorkerId> Worker{};
        std::string Protocol{};
    };

    struct MemoryAllocationSnapshot final
    {
        bool Available{false};
        std::uint64_t CurrentBytes{0};
        std::uint64_t PeakBytes{0};
        std::uint64_t AllocationCount{0};
        std::uint64_t ReleaseCount{0};
        std::string Coverage{};
    };

    struct MemoryPoolSnapshot final
    {
        bool Available{false};
        std::uint64_t UsedBytes{0};
        std::uint64_t CapacityBytes{0};
        std::uint64_t AvailableBlocks{0};
        std::uint64_t BlockSize{0};
        std::uint64_t PeakUsedBytes{0};
        std::uint64_t AllocationCount{0};
        std::uint64_t ReleaseCount{0};
    };

    struct WorkerMemorySnapshot final
    {
        Prism::WorkerId Id{};
        MemoryAllocationSnapshot Allocations{};
    };

    struct MemorySnapshot final
    {
        bool ProcessAvailable{false};
        std::uint64_t ResidentBytes{0};
        std::uint64_t PeakResidentBytes{0};
        MemoryPoolSnapshot ProcessPool{};
        MemoryAllocationSnapshot ProcessAllocations{};
        std::vector<WorkerMemorySnapshot> WorkerAllocations{};
    };

    struct IngressSnapshot final
    {
        std::string Id;
        std::string Transport;
        std::string ConfiguredAddress;
        std::optional<std::string> BoundAddress{};
        bool Ready{false};
        std::vector<std::string> Protocols{};
        std::vector<std::string> Carriers{};
        std::optional<std::uint64_t> ActiveConnections{};
    };

    struct ProtocolSnapshot final
    {
        std::string Id;
        std::string Name;
        std::uint64_t ConfiguredBindings{0};
        std::optional<std::uint64_t> ActiveSessions{};
        std::optional<Prism::Statistics::TrafficValue> Traffic{};
        std::optional<LatencySummary> Latency{};
        std::string Coverage;
    };

    struct GroupSnapshot final
    {
        std::string Id;
        std::string Name;
        std::uint64_t ConfiguredAccounts{0};
        std::uint64_t ActiveAccounts{0};
        std::optional<std::uint64_t> ActiveSessions{};
        std::optional<Prism::Statistics::TrafficValue> Traffic{};
    };

    struct OperationSnapshot final
    {
        std::uint64_t Id{0};
        std::string Command;
        std::string Status;
        Prism::RequestId Correlation{};
        std::optional<std::uint64_t> AcceptedAt{};
        std::optional<std::uint64_t> UpdatedAt{};
        std::string Message;
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::WorkerId Worker{};
        Prism::AccountId Account{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::TaskId Task{};
    };

    struct TraceSpanSnapshot final
    {
        std::string SpanId;
        std::optional<std::string> ParentSpanId{};
        std::uint64_t Sequence{0};
        std::string Name;
        std::uint64_t StartTimeUnixNanoseconds{0};
        std::optional<std::uint64_t> DurationMilliseconds{};
        std::string Status;
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        Prism::SessionId Session{};
        std::optional<Prism::WorkerId> Worker{};
        Prism::AccountId Account{};
        Prism::TaskId Task{};
        Prism::TaskId ParentTask{};
        Prism::StreamId Stream{};
        std::string Stage;
        std::string Outcome;
        std::optional<std::int32_t> FailureCode{};
        std::uint64_t ElapsedNanoseconds{0};
    };

    struct TraceCursorSnapshot final
    {
        Prism::WorkerId Worker{};
        std::uint64_t Sequence{0};
    };

    struct TraceLossSnapshot final
    {
        Prism::WorkerId Worker{};
        std::uint64_t Overwritten{0};
        std::uint64_t LostSinceCursor{0};
        std::uint64_t ConcurrentReadSkips{0};
    };

    struct TracePageSnapshot final
    {
        std::vector<TraceSpanSnapshot> Items;
        std::vector<TraceCursorSnapshot> Cursors;
        std::vector<TraceLossSnapshot> Loss;
        bool HasMore{false};
        std::string NextCursor;
    };

    struct OverviewSnapshot final
    {
        Prism::ProcessId Process{};
        Prism::GenerationId Generation{};
        std::string Phase;
        std::uint64_t SampledAt{0};
        Prism::Statistics::HealthSnapshot Health{};
        std::uint64_t ConfiguredAccounts{0};
        std::uint64_t ActiveAccounts{0};
        std::uint64_t UngroupedAccounts{0};
        std::uint64_t TcpSessions{0};
        std::optional<std::uint64_t> UdpConnections{};
        std::optional<std::uint64_t> QuicConnections{};
        std::uint64_t WorkersTotal{0};
        std::uint64_t WorkersAccepting{0};
        std::optional<Prism::Statistics::TrafficValue> Traffic{};
        std::optional<std::uint64_t> UploadBytesPerSecond{};
        std::optional<std::uint64_t> DownloadBytesPerSecond{};
        std::uint64_t SampleIntervalMilliseconds{0};
        LatencySummary RecognitionAdmission{};
        std::vector<LatencySummary> LatencyStages{};
        MemorySnapshot Memory{};
        std::uint64_t AcceptedObservations{0};
        std::uint64_t ConsumedObservations{0};
        std::uint64_t DroppedObservations{0};
        std::uint64_t AggregationFailures{0};
        std::vector<Prism::Statistics::TrafficSample> History{};
        std::vector<ProtocolSnapshot> Protocols{};
    };

    struct OverviewRead final {};
    struct IngressesRead final { PageRequest Page{}; };
    struct GroupsRead final { PageRequest Page{}; };
    struct ProtocolsRead final { PageRequest Page{}; };
    struct OperationsRead final { PageRequest Page{}; };
    struct SessionTraceRead final
    {
        PageRequest Page{};
        Prism::ProcessId Process{};
        Prism::SessionId Session{};
        std::vector<TraceCursorSnapshot> Cursors;
    };
    struct EventsRead final
    {
        PageRequest Page{};
        bool IncludeDetails{true};
        std::optional<Prism::ProcessId> Process{};
        std::optional<Prism::WorkerId> Worker{};
        std::optional<Prism::AccountId> Account{};
        std::optional<Prism::SessionId> Session{};
        std::optional<Prism::Statistics::EventSeverity> Severity{};
    };

    using ManagementQueryValue = std::variant<OverviewRead,
                                             IngressesRead,
                                             GroupsRead,
                                             ProtocolsRead,
                                             OperationsRead,
                                             SessionTraceRead,
                                             EventsRead>;

    struct ManagementQuery final
    {
        Prism::RequestId Correlation{};
        ManagementQueryValue Value{};
    };

    using ManagementPayload = std::variant<OverviewSnapshot,
                                           Page<IngressSnapshot>,
                                           Page<GroupSnapshot>,
                                           Page<ProtocolSnapshot>,
                                           Page<OperationSnapshot>,
                                           TracePageSnapshot>;

} // namespace Prism::Operations

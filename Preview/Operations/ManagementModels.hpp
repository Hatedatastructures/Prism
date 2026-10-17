/**
 * @file ManagementModels.hpp
 * @brief 运行概览、代理入口、用户组和追踪查询的 owning JSON 数据模型。
 */
#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Operations/Metrics.hpp>
#include <Preview/Operations/QueryPage.hpp>
#include <Preview/Statistics/History.hpp>
#include <Preview/Statistics/Snapshots.hpp>
#include <Preview/Statistics/Types.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace Preview::Operations
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
        std::optional<Preview::WorkerId> Worker{};
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
        Preview::WorkerId Id{};
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
        std::optional<Preview::Statistics::TrafficValue> Traffic{};
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
        std::optional<Preview::Statistics::TrafficValue> Traffic{};
    };

    struct OperationSnapshot final
    {
        std::uint64_t Id{0};
        std::string Command;
        std::string Status;
        Preview::RequestId Correlation{};
        std::optional<std::uint64_t> AcceptedAt{};
        std::optional<std::uint64_t> UpdatedAt{};
        std::string Message;
        Preview::ProcessId Process{};
        Preview::GenerationId Generation{};
        Preview::WorkerId Worker{};
        Preview::AccountId Account{};
        Preview::SessionId Session{};
        Preview::StreamId Stream{};
        Preview::TaskId Task{};
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
        Preview::ProcessId Process{};
        Preview::GenerationId Generation{};
        Preview::SessionId Session{};
        std::optional<Preview::WorkerId> Worker{};
        Preview::AccountId Account{};
        Preview::TaskId Task{};
        Preview::TaskId ParentTask{};
        Preview::StreamId Stream{};
        std::string Stage;
        std::string Outcome;
        std::optional<std::int32_t> FailureCode{};
        std::uint64_t ElapsedNanoseconds{0};
    };

    struct TraceCursorSnapshot final
    {
        Preview::WorkerId Worker{};
        std::uint64_t Sequence{0};
    };

    struct TraceLossSnapshot final
    {
        Preview::WorkerId Worker{};
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
        Preview::ProcessId Process{};
        Preview::GenerationId Generation{};
        std::string Phase;
        std::uint64_t SampledAt{0};
        Preview::Statistics::HealthSnapshot Health{};
        std::uint64_t ConfiguredAccounts{0};
        std::uint64_t ActiveAccounts{0};
        std::uint64_t UngroupedAccounts{0};
        std::uint64_t TcpSessions{0};
        std::optional<std::uint64_t> UdpConnections{};
        std::optional<std::uint64_t> QuicConnections{};
        std::uint64_t WorkersTotal{0};
        std::uint64_t WorkersAccepting{0};
        std::optional<Preview::Statistics::TrafficValue> Traffic{};
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
        std::vector<Preview::Statistics::TrafficSample> History{};
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
        Preview::ProcessId Process{};
        Preview::SessionId Session{};
        std::vector<TraceCursorSnapshot> Cursors;
    };
    struct EventsRead final
    {
        PageRequest Page{};
        bool IncludeDetails{true};
        std::optional<Preview::ProcessId> Process{};
        std::optional<Preview::WorkerId> Worker{};
        std::optional<Preview::AccountId> Account{};
        std::optional<Preview::SessionId> Session{};
        std::optional<Preview::Statistics::EventSeverity> Severity{};
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
        Preview::RequestId Correlation{};
        ManagementQueryValue Value{};
    };

    using ManagementPayload = std::variant<OverviewSnapshot,
                                           Page<IngressSnapshot>,
                                           Page<GroupSnapshot>,
                                           Page<ProtocolSnapshot>,
                                           Page<OperationSnapshot>,
                                           TracePageSnapshot>;

} // namespace Preview::Operations

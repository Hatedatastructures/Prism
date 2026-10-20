/**
 * @file Snapshots.hpp
 * @brief 统计层资源值快照。
 */

#pragma once

#include <Prism/Statistics/Types.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace Prism::Statistics
{

    enum class HealthStatus : std::uint8_t
    {
        Unknown,
        Healthy,
        Degraded,
        Unhealthy,
        Draining,
    };

    /**
     * @brief 进程级动态范围统计退休失败计数。
     * @details 计数来自 TrafficCounter 的 Session、Stream、Task 类型事实；失败只表示统计键未退休，不改变业务关闭结果。
     */
    struct RetirementFailureSnapshot final
    {
        std::uint64_t Session{0};
        std::uint64_t Stream{0};
        std::uint64_t Task{0};
    };

    /** @brief 单一代次 recognition admission 实际样本与近似分布。 */
    struct RecognitionLatencySnapshot final
    {
        Prism::GenerationId Generation{};
        std::uint64_t SampleCount{0};
        std::uint64_t TracerWrittenCount{0};
        std::uint64_t TracerDroppedCount{0};
        std::uint64_t HistogramRangeExceeded{0};
        std::array<std::uint64_t, 8> RecentMicroseconds{};
        std::size_t RecentCount{0};
        std::optional<std::uint64_t> P50BucketLowerBoundMicroseconds{};
        std::optional<std::uint64_t> P95BucketLowerBoundMicroseconds{};
        std::optional<std::uint64_t> P99BucketLowerBoundMicroseconds{};
        std::optional<std::uint64_t> MaximumObservedMicroseconds{};
    };

    struct HealthSnapshot final
    {
        HealthStatus Status{HealthStatus::Unknown};
        std::uint64_t CheckedAt{0};
        std::uint64_t Active{0};
        std::uint64_t Errors{0};
        bool Ready{false};
        bool TcpReady{false};
        bool UdpReady{false};
        bool QuicReady{false};
        bool UdpSocketReady{false};
        bool QuicSocketReady{false};
        bool QuicHandshakeReady{false};
        bool QuicProtocolReady{false};
        /** @brief 进程级统计退休失败观察计数；不参与健康状态和就绪判定。 */
        RetirementFailureSnapshot ProcessRetirementFailures{};
    };

    struct GenerationSnapshot final
    {
        Prism::GenerationId Id{};
        std::uint64_t CreatedAt{0};
        bool Active{false};
        bool Retiring{false};
        HealthSnapshot Health{};
    };

    struct ProcessSnapshot final
    {
        Prism::ProcessId Id{};
        Prism::GenerationId Generation{};
        HealthSnapshot Health{};
        TrafficValue Traffic{};
        std::uint64_t WorkerCount{0};
        std::uint64_t AccountCount{0};
        std::uint64_t SessionCount{0};
        std::uint64_t DroppedEvents{0};
    };

    struct WorkerSnapshot final
    {
        Prism::ProcessId Process{};
        Prism::WorkerId Id{};
        Prism::GenerationId Generation{};
        HealthSnapshot Health{};
        std::optional<TrafficValue> Traffic{};
        bool Running{false};
        bool Accepting{false};
        std::uint64_t ActiveTasks{0};
        std::uint64_t DroppedEvents{0};
        std::uint64_t MailboxDepth{0};
        std::uint64_t MailboxCapacity{0};
        std::uint64_t StartedTasks{0};
        std::uint64_t CompletedTasks{0};
        std::uint64_t CancelledTasks{0};
        std::uint64_t DispatchAccepted{0};
        std::uint64_t DispatchFull{0};
        std::uint64_t DispatchClosed{0};
        std::uint64_t DispatchUnavailable{0};
        std::uint64_t DispatchGenerationRejected{0};
        std::uint64_t CommandsExecuted{0};
        std::uint64_t CommandsFailed{0};
    };

    struct AccountSnapshot final
    {
        Prism::AccountId Id{};
        Prism::GenerationId Generation{};
        std::optional<TrafficValue> Traffic{};
        std::uint64_t ActiveSessions{0};
        std::string Label{};
        std::optional<std::string> GroupId{};
        bool Revoked{false};
    };

    struct SessionSnapshot final
    {
        Prism::SessionId Id{};
        Prism::ProcessId Process{};
        Prism::WorkerId Worker{};
        Prism::AccountId Account{};
        Prism::GenerationId Generation{};
        std::optional<TrafficValue> Traffic{};
        std::uint64_t StartedAt{0};
        std::string Identity{};
        std::string SourceAddress{};
        std::string Transport{"tcp"};
        std::string Protocol{};
        std::string Target{};
        bool Active{false};
        bool Draining{false};
        std::optional<std::uint64_t> ActiveTasks{};
    };

    struct StreamSnapshot final
    {
        Prism::StreamId Id{};
        Prism::TaskId Task{};
        Prism::TaskId ParentTask{};
        Prism::ProcessId Process{};
        Prism::SessionId Session{};
        Prism::AccountId Account{};
        Prism::WorkerId Worker{};
        Prism::GenerationId Generation{};
        std::optional<TrafficValue> Traffic{};
        std::string Protocol{};
        bool Active{false};
    };

    enum class TaskStatus : std::uint8_t
    {
        Pending,
        Running,
        Succeeded,
        Failed,
        Canceled,
        Quarantined,
    };

    struct TaskSnapshot final
    {
        Prism::TaskId Id{};
        Prism::ProcessId Process{};
        Prism::WorkerId Worker{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::GenerationId Generation{};
        Prism::TaskId ParentTask{};
        TaskStatus Status{TaskStatus::Pending};
        std::uint64_t StartedAt{0};
        std::uint64_t CompletedAt{0};
        bool CancelRequested{false};
        bool Cancellable{false};
        bool DrainBlocked{false};
        Prism::Fault::Failure Failure{};
        Prism::Fault::Failure DrainFailure{};
    };

} // namespace Prism::Statistics

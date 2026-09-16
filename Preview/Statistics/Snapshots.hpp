/**
 * @file Snapshots.hpp
 * @brief 统计层资源值快照。
 */

#pragma once

#include <Preview/Statistics/Types.hpp>

#include <cstdint>
#include <string>

namespace Preview::Statistics
{

    enum class HealthStatus : std::uint8_t
    {
        Unknown,
        Healthy,
        Degraded,
        Unhealthy,
        Draining,
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
    };

    struct GenerationSnapshot final
    {
        Preview::GenerationId Id{};
        std::uint64_t CreatedAt{0};
        bool Active{false};
        bool Retiring{false};
        HealthSnapshot Health{};
    };

    struct ProcessSnapshot final
    {
        Preview::ProcessId Id{};
        Preview::GenerationId Generation{};
        HealthSnapshot Health{};
        TrafficValue Traffic{};
        std::uint64_t WorkerCount{0};
        std::uint64_t AccountCount{0};
        std::uint64_t SessionCount{0};
        std::uint64_t DroppedEvents{0};
    };

    struct WorkerSnapshot final
    {
        Preview::ProcessId Process{};
        Preview::WorkerId Id{};
        Preview::GenerationId Generation{};
        HealthSnapshot Health{};
        TrafficValue Traffic{};
        bool Running{false};
        bool Accepting{false};
        std::uint64_t ActiveTasks{0};
        std::uint64_t DroppedEvents{0};
    };

    struct AccountSnapshot final
    {
        Preview::AccountId Id{};
        Preview::GenerationId Generation{};
        TrafficValue Traffic{};
        std::uint64_t ActiveSessions{0};
        std::string Label{};
        bool Enabled{false};
    };

    struct SessionSnapshot final
    {
        Preview::SessionId Id{};
        Preview::ProcessId Process{};
        Preview::WorkerId Worker{};
        Preview::AccountId Account{};
        Preview::GenerationId Generation{};
        TrafficValue Traffic{};
        std::uint64_t StartedAt{0};
        std::string Protocol{};
        std::string Target{};
        bool Active{false};
        bool Draining{false};
    };

    struct StreamSnapshot final
    {
        Preview::StreamId Id{};
        Preview::SessionId Session{};
        Preview::AccountId Account{};
        Preview::WorkerId Worker{};
        Preview::GenerationId Generation{};
        TrafficValue Traffic{};
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
        Preview::TaskId Id{};
        Preview::WorkerId Worker{};
        Preview::SessionId Session{};
        Preview::GenerationId Generation{};
        TaskStatus Status{TaskStatus::Pending};
        std::uint64_t StartedAt{0};
        std::uint64_t CompletedAt{0};
        bool CancelRequested{false};
        bool DrainBlocked{false};
    };

} // namespace Preview::Statistics

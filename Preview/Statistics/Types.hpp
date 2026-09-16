/**
 * @file Types.hpp
 * @brief Preview 统计 API 的数值键、指标和详细事件值类型。
 */

#pragma once

#include <Preview/Foundation/Identifier/Id.hpp>

#include <cstdint>
#include <string>

namespace Preview::Statistics
{

    using NumericId = std::uint64_t;

    enum class Scope : std::uint8_t
    {
        Process,
        Worker,
        Account,
        Session,
        Stream,
        Task,
    };

    enum class Metric : std::uint32_t
    {
        UpBytes = 1,
        DownBytes = 2,
        Events = 3,
        Errors = 4,
        Active = 5,
        Started = 6,
        Completed = 7,
        Canceled = 8,
    };

    struct CounterKey final
    {
        Scope ScopeValue{Scope::Process};
        NumericId Id{0};
        Metric MetricValue{Metric::Events};

        friend constexpr auto operator==(const CounterKey &, const CounterKey &) noexcept -> bool = default;
    };

    struct CounterEntry final
    {
        CounterKey Key{};
        std::uint64_t Value{0};
    };

    struct TrafficValue final
    {
        std::uint64_t UpBytes{0};
        std::uint64_t DownBytes{0};
        std::uint64_t Events{0};
        std::uint64_t Errors{0};

        auto operator+=(const TrafficValue &Other) noexcept -> TrafficValue &
        {
            UpBytes += Other.UpBytes;
            DownBytes += Other.DownBytes;
            Events += Other.Events;
            Errors += Other.Errors;
            return *this;
        }

        friend auto operator+(TrafficValue Left, const TrafficValue &Right) noexcept -> TrafficValue
        {
            Left += Right;
            return Left;
        }
    };

    enum class EventKind : std::uint8_t
    {
        Data,
        Started,
        Failed,
        SessionClosed,
        StreamClosed,
        TaskCompleted,
        TaskCanceled,
        WorkerDrained,
        GenerationReloaded,
    };

    enum class EventSeverity : std::uint8_t
    {
        Debug,
        Info,
        Warning,
        Error,
    };

    /**
     * @struct DetailedEvent
     * @brief 只包含值和数值 ID 的详细事件。
     */
    struct DetailedEvent final
    {
        std::uint64_t Sequence{0};
        std::uint64_t Timestamp{0};
        Preview::RequestId Correlation{};
        Preview::GenerationId Generation{};
        Preview::ProcessId Process{};
        Preview::WorkerId Worker{};
        Preview::AccountId Account{};
        Preview::SessionId Session{};
        Preview::StreamId Stream{};
        Preview::TaskId Task{};
        Scope ScopeValue{Scope::Process};
        EventKind Kind{EventKind::Data};
        EventSeverity Severity{EventSeverity::Info};
        bool Terminal{false};
        std::string Detail{};
    };

    using EventRecord = DetailedEvent;

} // namespace Preview::Statistics

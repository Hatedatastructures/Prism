/**
 * @file Types.hpp
 * @brief Prism 统计 API 的数值键、指标和详细事件值类型。
 */

#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>

#include <cstdint>
#include <string>

namespace Prism::Statistics
{

    using NumericId = std::uint64_t;

    /**
     * @brief 统计值的归属范围。
     * @details Worker 表示 Prism::WorkerId 对应的逻辑 worker 维度，不保存操作系统线程号。
     */
    enum class Scope : std::uint8_t
    {
        Process,
        Worker,
        Account,
        Protocol,
        Session,
        Stream,
        Task,
        ProtocolInstance,
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
        NumericId Id{0}; ///< 归属 ID；Worker 范围使用 Prism::WorkerId::Value()。
        Metric MetricValue{Metric::Events};
        Prism::SessionId ParentSession{}; ///< Stream 的 wire ID 只在父 session 内唯一；其余范围为空。
        Prism::GenerationId Generation{}; ///< 协议实例数值下标由 Generation 限定，其余范围为空。

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
        OperationAccepted,
        OperationCompleted,
        OperationFailed,
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
        Prism::RequestId Correlation{};
        Prism::GenerationId Generation{};
        Prism::ProcessId Process{};
        Prism::WorkerId Worker{}; ///< 事件所属的逻辑 worker，用于按 Worker 维度查询统计。
        Prism::AccountId Account{};
        Prism::SessionId Session{};
        Prism::StreamId Stream{};
        Prism::TaskId Task{};
        Scope ScopeValue{Scope::Process};
        EventKind Kind{EventKind::Data};
        EventSeverity Severity{EventSeverity::Info};
        bool Terminal{false};
        bool Truncated{false}; ///< 正文在拥有入口有界截断，原 UTF-8 边界和 marker 保留。
        std::string Detail{};
        Prism::TaskId ParentTask{}; ///< Stream/Task 的父任务身份；其他事件保持零值。
        NumericId Operation{0}; ///< 管理操作 ID；非 operation 事件保持零值。
    };

    using EventRecord = DetailedEvent;

} // namespace Prism::Statistics

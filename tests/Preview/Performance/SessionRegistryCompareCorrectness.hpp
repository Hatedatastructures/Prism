/**
 * @file SessionRegistryCompareCorrectness.hpp
 * @brief 注册表 trace 回放与 quiescent 合同检查。
 */

#pragma once

#include "SessionRegistryCompareModels.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>

namespace Preview::Runtime::Perf
{

    inline constexpr std::size_t CompareLaneCount = 4;

    enum class InvalidReason : std::size_t
    {
        RegisterResult,
        FindResult,
        SizeExceeded,
        SnapshotValue,
        CancelResult,
        ResetResult,
        SnapshotIsolation,
        RetireResult,
        HookShape,
        HookInstallFailure,
        StaleHook,
        InFlightHook,
        PendingResult,
        FinalSnapshot,
        FinalSize,
        FinalPending,
        FinalLifecycle,
        TokenState,
        Count
    };

    inline constexpr auto InvalidReasonCount = static_cast<std::size_t>(InvalidReason::Count);

    struct Statistics final
    {
        std::uint64_t Operations{0};
        std::uint64_t Finds{0};
        std::uint64_t FindHits{0};
        std::uint64_t Registers{0};
        std::uint64_t Resets{0};
        std::uint64_t Cancels{0};
        std::uint64_t Snapshots{0};
        std::uint64_t Invalid{0};
        std::uint64_t Checksum{14695981039346656037ull};
        std::uint64_t SnapshotChecksum{14695981039346656037ull};
        std::array<std::uint64_t, InvalidReasonCount> InvalidReasons{};
    };

    struct LaneState final
    {
        std::unordered_map<std::uint64_t, Token> Active;
        std::unordered_map<std::uint64_t, Token> Stale;
        std::unordered_map<std::uint64_t, SessionInfo> Expected;
        bool Shutdown{false};
    };

    struct ExecutionContext final
    {
        IModel &Model;
        LaneState &Lane;
        Statistics &Stats;
        std::atomic<bool> &Invalid;
        std::size_t MaxSessions{0};
        std::optional<SnapshotMap> CapturedSnapshot;
    };

    /** @brief 回放一个 trace 操作并更新执行统计及错误合同。 */
    auto Apply(const TraceOperation &Operation, ExecutionContext &Context) -> void;

    struct ProbeResult final
    {
        bool Valid{true};
        HookCounts Hooks;
        std::array<std::uint64_t, InvalidReasonCount> InvalidReasons{};
    };

} // namespace Preview::Runtime::Perf

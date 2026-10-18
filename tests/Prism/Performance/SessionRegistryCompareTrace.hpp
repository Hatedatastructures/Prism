/**
 * @file SessionRegistryCompareTrace.hpp
 * @brief 会话注册表对照实验的 trace 与值语义。
 */

#pragma once

#include "SessionRegistryCompare.hpp"

#include <Prism/Runtime/SessionRegistry.hpp>

#include <cstdint>
#include <map>
#include <vector>

namespace Prism::Runtime::Perf
{

    using SnapshotMap = std::map<std::uint64_t, SessionInfo>;

    struct TraceOperation final
    {
        enum class Kind
        {
            Register,
            Find,
            Size,
            Snapshot,
            Cancel,
            Reset,
            RetireForReuse,
            EmitStale,
            EmitActive,
            FailCompaction,
            ObservePending,
            Shutdown
        };

        Kind Operation{Kind::Find};
        std::uint64_t Id{0};
        std::uint64_t Value{0};
        std::size_t Lane{0};
        bool CheckResult{false};
        bool ExpectedResult{false};
    };

    struct Trace final
    {
        std::vector<TraceOperation> Probe;
        std::vector<TraceOperation> Work;
        std::uint64_t Hash{14695981039346656037ull};
    };

    /** @brief 构造固定字段的会话值，供 trace 与执行校验共享。 */
    auto MakeInfo(std::uint64_t Id, std::uint64_t Value) -> SessionInfo;

    /** @brief 比较会话值的所有可观测字段。 */
    [[nodiscard]] auto SameInfo(const SessionInfo &Left, const SessionInfo &Right) -> bool;

    /** @brief 对 trace/结果使用唯一 FNV-1a 混合实现。 */
    auto Mix(std::uint64_t &Hash, std::uint64_t Value) -> void;

    /** @brief 对有序快照计算稳定值 hash。 */
    [[nodiscard]] auto HashSnapshot(const SnapshotMap &Snapshot) -> std::uint64_t;

} // namespace Prism::Runtime::Perf

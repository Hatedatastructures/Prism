/**
 * @file SessionRegistryCompare.hpp
 * @brief Preview 会话注册表候选结构的同 trace 对照入口。
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace Preview::Runtime::Perf
{

    enum class ModelKind
    {
        CurrentCow,
        ShardedCow,
        ExecutorTable,
        All
    };

    enum class WorkloadKind
    {
        ReadHeavy,
        Churn
    };

    struct Options final
    {
        ModelKind Model{ModelKind::All};
        WorkloadKind Workload{WorkloadKind::ReadHeavy};
        std::size_t ActiveSessions{64};
        std::size_t Executors{1};
        std::size_t OperationsPerLane{1000};
        std::size_t Rounds{5};
        std::uint64_t Seed{0xB01Full};
        bool ValidateOnly{false};
    };

} // namespace Preview::Runtime::Perf

/**
 * @file TrafficDelta.hpp
 * @brief worker-local 流量增量及 exactly-once flush。
 */

#pragma once

#include <Prism/Statistics/SparseCounters.hpp>

#include <Prism/Foundation/Identifier/Id.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace Prism::Statistics
{

    struct TrafficDeltaEntry final
    {
        Scope ScopeValue{Scope::Account};
        NumericId Id{0};
        std::uint64_t UpBytes{0};
        std::uint64_t DownBytes{0};
    };

    class TrafficDelta final
    {
    public:
        explicit TrafficDelta(const Prism::WorkerId WorkerValue = {}) noexcept : Worker_(WorkerValue) {}

        [[nodiscard]] auto Worker() const noexcept -> Prism::WorkerId
        {
            return Worker_;
        }

        /** @brief 按值拥有最多 64 个范围的字节增量；先检查溢出和容量，拒绝不改变已有 batch。 */
        [[nodiscard]] auto Add(TrafficDeltaEntry Entry) noexcept -> bool;

        [[nodiscard]] auto Flush(SparseCounters &Counters) noexcept -> bool;

        [[nodiscard]] auto IsFlushed() const noexcept -> bool
        {
            return Flushed_;
        }

        [[nodiscard]] auto Entries() const -> std::vector<TrafficDeltaEntry>;

    private:
        [[nodiscard]] auto Find(const Scope ScopeValue, const NumericId IdValue)
            -> std::array<TrafficDeltaEntry, 64>::iterator;

        Prism::WorkerId Worker_{};
        std::array<TrafficDeltaEntry, 64> Entries_{};
        std::size_t Size_{0};
        bool Flushed_{false};
    };

} // namespace Prism::Statistics

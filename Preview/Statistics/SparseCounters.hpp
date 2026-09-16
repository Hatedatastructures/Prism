/**
 * @file SparseCounters.hpp
 * @brief 数值键稀疏计数器。
 */

#pragma once

#include <Preview/Statistics/Types.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace Preview::Statistics
{

    struct CounterKeyLess final
    {
        [[nodiscard]] auto operator()(const CounterKey &Left, const CounterKey &Right) const noexcept -> bool
        {
            if (Left.ScopeValue != Right.ScopeValue)
            {
                return static_cast<std::uint8_t>(Left.ScopeValue) <
                       static_cast<std::uint8_t>(Right.ScopeValue);
            }
            if (Left.Id != Right.Id)
            {
                return Left.Id < Right.Id;
            }
            return static_cast<std::uint32_t>(Left.MetricValue) <
                   static_cast<std::uint32_t>(Right.MetricValue);
        }
    };

    class SparseCounters final
    {
    public:
        struct Options final
        {
            std::size_t MaxEntries{0};
        };

        SparseCounters() = default;

        explicit SparseCounters(Options Value) noexcept : MaxEntries_(Value.MaxEntries) {}

        [[nodiscard]] auto Add(const Scope ScopeValue, const NumericId Id,
                               const Metric MetricValue, const std::uint64_t Delta) -> bool
        {
            return Add(CounterKey{ScopeValue, Id, MetricValue}, Delta);
        }

        [[nodiscard]] auto Add(const NumericId Id, const Metric MetricValue,
                               const std::uint64_t Delta) -> bool
        {
            return Add(Scope::Process, Id, MetricValue, Delta);
        }

        [[nodiscard]] auto Add(const NumericId Id, const std::uint64_t Delta) -> bool
        {
            return Add(Scope::Process, Id, Metric::Events, Delta);
        }

        [[nodiscard]] auto Add(const CounterKey Key, const std::uint64_t Delta) -> bool
        {
            const auto It = Values_.find(Key);
            if (It != Values_.end())
            {
                It->second += Delta;
                return true;
            }
            if (MaxEntries_ != 0 && Values_.size() >= MaxEntries_)
            {
                ++Dropped_;
                return false;
            }
            Values_.emplace(Key, Delta);
            return true;
        }

        [[nodiscard]] auto Set(const CounterKey Key, const std::uint64_t Value) -> bool
        {
            const auto It = Values_.find(Key);
            if (It != Values_.end())
            {
                It->second = Value;
                return true;
            }
            if (MaxEntries_ != 0 && Values_.size() >= MaxEntries_)
            {
                ++Dropped_;
                return false;
            }
            Values_.emplace(Key, Value);
            return true;
        }

        [[nodiscard]] auto Get(const CounterKey Key) const noexcept -> std::uint64_t
        {
            const auto It = Values_.find(Key);
            return It == Values_.end() ? 0 : It->second;
        }

        [[nodiscard]] auto Get(const Scope ScopeValue, const NumericId Id,
                               const Metric MetricValue) const noexcept -> std::uint64_t
        {
            return Get(CounterKey{ScopeValue, Id, MetricValue});
        }

        [[nodiscard]] auto Get(const NumericId Id, const Metric MetricValue) const noexcept
            -> std::uint64_t
        {
            return Get(Scope::Process, Id, MetricValue);
        }

        [[nodiscard]] auto Snapshot() const -> std::vector<CounterEntry>
        {
            std::vector<CounterEntry> Result;
            Result.reserve(Values_.size());
            for (const auto &[Key, Value] : Values_)
            {
                Result.push_back(CounterEntry{Key, Value});
            }
            return Result;
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Values_.size();
        }

        [[nodiscard]] auto Dropped() const noexcept -> std::uint64_t
        {
            return Dropped_;
        }

        auto Clear() noexcept -> void
        {
            Values_.clear();
            Dropped_ = 0;
        }

    private:
        std::size_t MaxEntries_{0};
        std::map<CounterKey, std::uint64_t, CounterKeyLess> Values_;
        std::uint64_t Dropped_{0};
    };

} // namespace Preview::Statistics

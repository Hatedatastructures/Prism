/**
 * @file TrafficDelta.hpp
 * @brief worker-local 流量增量及 exactly-once flush。
 */

#pragma once

#include <Prism/Statistics/SparseCounters.hpp>

#include <Prism/Foundation/Identifier/Id.hpp>

#include <algorithm>
#include <array>
#include <limits>
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
        [[nodiscard]] auto Add(TrafficDeltaEntry Entry) noexcept -> bool
        {
            if (Flushed_) return false;
            auto It = Find(Entry.ScopeValue, Entry.Id);
            if (It == Entries_.begin() + Size_)
            {
                if (Size_ == Entries_.size()) return false;
                Entries_[Size_++] = Entry;
                return true;
            }
            if (Entry.UpBytes > std::numeric_limits<std::uint64_t>::max() - It->UpBytes ||
                Entry.DownBytes > std::numeric_limits<std::uint64_t>::max() - It->DownBytes) return false;
            It->UpBytes += Entry.UpBytes;
            It->DownBytes += Entry.DownBytes;
            return true;
        }

        [[nodiscard]] auto Flush(SparseCounters &Counters) noexcept -> bool
        {
            if (Flushed_) return false;
            Flushed_ = true;
            std::array<CounterKey, 128> Keys;
            std::array<std::uint64_t, 128> Deltas;
            std::size_t Count = 0;
            for (std::size_t Index = 0; Index < Size_; ++Index)
            {
                const auto& Entry = Entries_[Index];
                if (Entry.UpBytes != 0U)
                { Keys[Count] = {Entry.ScopeValue, Entry.Id, Metric::UpBytes}; Deltas[Count++] = Entry.UpBytes; }
                if (Entry.DownBytes != 0U)
                { Keys[Count] = {Entry.ScopeValue, Entry.Id, Metric::DownBytes}; Deltas[Count++] = Entry.DownBytes; }
            }
            if (!Counters.Prepare(std::span(Keys).first(Count))) return false;
            for (std::size_t Index = 0; Index < Count; ++Index)
                if (!Counters.CanAdd(Keys[Index], Deltas[Index])) return false;
            for (std::size_t Index = 0; Index < Count; ++Index)
                if (!Counters.Add(Keys[Index], Deltas[Index])) return false;
            return true;
        }

        [[nodiscard]] auto IsFlushed() const noexcept -> bool
        {
            return Flushed_;
        }

        [[nodiscard]] auto Entries() const -> std::vector<TrafficDeltaEntry>
        {
            return {Entries_.begin(), Entries_.begin() + Size_};
        }

    private:
        [[nodiscard]] auto Find(const Scope ScopeValue, const NumericId IdValue)
            -> std::array<TrafficDeltaEntry, 64>::iterator
        {
            return std::find_if(Entries_.begin(), Entries_.begin() + Size_,
                                [ScopeValue, IdValue](const TrafficDeltaEntry &Entry)
                                {
                                    return Entry.ScopeValue == ScopeValue && Entry.Id == IdValue;
                                });
        }

        Prism::WorkerId Worker_{};
        std::array<TrafficDeltaEntry, 64> Entries_{};
        std::size_t Size_{0};
        bool Flushed_{false};
    };

} // namespace Prism::Statistics

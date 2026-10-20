/** @file TrafficDelta.cpp @brief worker-local流量增量校验及 exactly-once flush 实现。 */
#include <Prism/Statistics/TrafficDelta.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace Prism::Statistics
{
    auto TrafficDelta::Add(TrafficDeltaEntry Entry) noexcept -> bool
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

    auto TrafficDelta::Flush(SparseCounters& Counters) noexcept -> bool
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
            {
                Keys[Count] = {Entry.ScopeValue, Entry.Id, Metric::UpBytes};
                Deltas[Count++] = Entry.UpBytes;
            }
            if (Entry.DownBytes != 0U)
            {
                Keys[Count] = {Entry.ScopeValue, Entry.Id, Metric::DownBytes};
                Deltas[Count++] = Entry.DownBytes;
            }
        }
        if (!Counters.Prepare(std::span(Keys).first(Count))) return false;
        for (std::size_t Index = 0; Index < Count; ++Index)
            if (!Counters.CanAdd(Keys[Index], Deltas[Index])) return false;
        for (std::size_t Index = 0; Index < Count; ++Index)
            if (!Counters.Add(Keys[Index], Deltas[Index])) return false;
        return true;
    }

    auto TrafficDelta::Entries() const -> std::vector<TrafficDeltaEntry>
    {
        return {Entries_.begin(), Entries_.begin() + Size_};
    }

    auto TrafficDelta::Find(const Scope ScopeValue, const NumericId IdValue)
        -> std::array<TrafficDeltaEntry, 64>::iterator
    {
        return std::find_if(Entries_.begin(), Entries_.begin() + Size_,
            [ScopeValue, IdValue](const TrafficDeltaEntry &Entry)
            { return Entry.ScopeValue == ScopeValue && Entry.Id == IdValue; });
    }
}

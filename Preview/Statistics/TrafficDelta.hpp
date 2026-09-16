/**
 * @file TrafficDelta.hpp
 * @brief worker-local 流量增量及 exactly-once flush。
 */

#pragma once

#include <Preview/Statistics/SparseCounters.hpp>

#include <Preview/Foundation/Identifier/Id.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace Preview::Statistics
{

    struct TrafficDeltaEntry final
    {
        CounterKey Key{};
        std::uint64_t UpBytes{0};
        std::uint64_t DownBytes{0};
    };

    class TrafficDelta final
    {
    public:
        explicit TrafficDelta(const Preview::WorkerId WorkerValue = {}) noexcept : Worker_(WorkerValue) {}

        [[nodiscard]] auto Worker() const noexcept -> Preview::WorkerId
        {
            return Worker_;
        }

        template <typename Id>
        auto Add(const Scope ScopeValue, const Id IdValue, const std::uint64_t UpBytes,
                 const std::uint64_t DownBytes) -> void
        {
            Add(ScopeValue, IdValue.Value(), UpBytes, DownBytes);
        }

        template <typename Id>
        auto Add(const Id IdValue, const std::uint64_t UpBytes, const std::uint64_t DownBytes) -> void
        {
            Add(Scope::Account, IdValue, UpBytes, DownBytes);
        }

        auto Add(const NumericId IdValue, const std::uint64_t UpBytes,
                 const std::uint64_t DownBytes) -> void
        {
            Add(Scope::Account, IdValue, UpBytes, DownBytes);
        }

        auto Add(const Scope ScopeValue, const NumericId IdValue, const std::uint64_t UpBytes,
                 const std::uint64_t DownBytes) -> void
        {
            auto It = Find(ScopeValue, IdValue);
            if (It == Entries_.end())
            {
                Entries_.push_back(TrafficDeltaEntry{
                    CounterKey{ScopeValue, IdValue, Metric::UpBytes}, UpBytes, DownBytes});
                return;
            }
            It->UpBytes += UpBytes;
            It->DownBytes += DownBytes;
        }

        [[nodiscard]] auto Flush(SparseCounters &Counters) noexcept -> bool
        {
            if (Flushed_)
            {
                return false;
            }
            for (const auto &Entry : Entries_)
            {
                if (Entry.UpBytes != 0)
                {
                    (void)Counters.Add(Entry.Key, Entry.UpBytes);
                }
                if (Entry.DownBytes != 0)
                {
                    (void)Counters.Add(
                        CounterKey{Entry.Key.ScopeValue, Entry.Key.Id, Metric::DownBytes},
                        Entry.DownBytes);
                }
            }
            Flushed_ = true;
            return true;
        }

        [[nodiscard]] auto FlushInto(SparseCounters &Counters) noexcept -> bool
        {
            return Flush(Counters);
        }

        [[nodiscard]] auto IsFlushed() const noexcept -> bool
        {
            return Flushed_;
        }

        [[nodiscard]] auto Entries() const -> std::vector<TrafficDeltaEntry>
        {
            return Entries_;
        }

    private:
        [[nodiscard]] auto Find(const Scope ScopeValue, const NumericId IdValue)
            -> std::vector<TrafficDeltaEntry>::iterator
        {
            return std::find_if(Entries_.begin(), Entries_.end(),
                                [ScopeValue, IdValue](const TrafficDeltaEntry &Entry)
                                {
                                    return Entry.Key.ScopeValue == ScopeValue && Entry.Key.Id == IdValue;
                                });
        }

        Preview::WorkerId Worker_{};
        std::vector<TrafficDeltaEntry> Entries_;
        bool Flushed_{false};
    };

} // namespace Preview::Statistics

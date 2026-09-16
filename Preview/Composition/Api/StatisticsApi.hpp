/**
 * @file StatisticsApi.hpp
 * @brief Preview 统计值快照组合 API。
 */

#pragma once

#include <Preview/Statistics/Statistics.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace Preview::Composition::Api
{

    struct StatisticsSnapshot final
    {
        std::vector<Preview::Statistics::CounterEntry> Counters;
        Preview::Statistics::EventCounts Events{};
    };

    class StatisticsApi final
    {
    public:
        struct Options final
        {
            Preview::Statistics::SparseCounters::Options Counters{};
            Preview::Statistics::EventRing::Options Events{};
        };

        StatisticsApi() = default;

        explicit StatisticsApi(Options Value)
            : Counters_(Value.Counters), Events_(Value.Events)
        {
        }

        [[nodiscard]] auto Add(const Preview::Statistics::CounterKey Key,
                               const std::uint64_t Delta) -> bool
        {
            return Counters_.Add(Key, Delta);
        }

        [[nodiscard]] auto Flush(Preview::Statistics::TrafficDelta &Delta) noexcept -> bool
        {
            return Delta.Flush(Counters_);
        }

        [[nodiscard]] auto Append(Preview::Statistics::DetailedEvent EventValue)
            -> Preview::Statistics::EventAppendResult
        {
            return Events_.Append(std::move(EventValue));
        }

        [[nodiscard]] auto Counters() const -> std::vector<Preview::Statistics::CounterEntry>
        {
            return Counters_.Snapshot();
        }

        [[nodiscard]] auto Events(std::uint64_t Cursor, std::size_t Limit) const
            -> Preview::Statistics::EventPage
        {
            return Events_.Page(Cursor, Limit);
        }

        [[nodiscard]] auto Snapshot() const -> StatisticsSnapshot
        {
            return StatisticsSnapshot{Counters_.Snapshot(), Events_.Counts()};
        }

    private:
        Preview::Statistics::SparseCounters Counters_;
        Preview::Statistics::EventRing Events_;
    };

} // namespace Preview::Composition::Api

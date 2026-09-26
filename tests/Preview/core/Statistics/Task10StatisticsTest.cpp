/**
 * @file Task10StatisticsTest.cpp
 * @brief Task 10 稀疏统计、流量增量和详细事件环测试。
 */

#include <gtest/gtest.h>

#include <Preview/Statistics/Statistics.hpp>

#include <cstdint>
namespace
{

    TEST(Task10SparseCounters, WorkerTrafficFlushIsExactlyOnce)
    {
        Preview::Statistics::SparseCounters Counters;
        Preview::Statistics::TrafficDelta Delta(Preview::WorkerId{7});
        Delta.Add(Preview::Statistics::Scope::Account, Preview::AccountId{11}, 100, 40);
        Delta.Add(Preview::Statistics::Scope::Session, Preview::SessionId{22}, 5, 8);

        EXPECT_TRUE(Delta.Flush(Counters));
        EXPECT_FALSE(Delta.Flush(Counters));
        EXPECT_EQ(Counters.Get({Preview::Statistics::Scope::Account,
                                11,
                                Preview::Statistics::Metric::UpBytes}),
                  100U);
        EXPECT_EQ(Counters.Get({Preview::Statistics::Scope::Account,
                                11,
                                Preview::Statistics::Metric::DownBytes}),
                  40U);
        EXPECT_EQ(Counters.Get({Preview::Statistics::Scope::Session,
                                22,
                                Preview::Statistics::Metric::UpBytes}),
                  5U);
        EXPECT_EQ(Counters.Get({Preview::Statistics::Scope::Session,
                                22,
                                Preview::Statistics::Metric::DownBytes}),
                  8U);
        EXPECT_EQ(Counters.Size(), 4U);
    }

    TEST(Task10SparseCounters, NumericSnapshotIsAValueCopy)
    {
        Preview::Statistics::SparseCounters Counters;
        (void)Counters.Add({Preview::Statistics::Scope::Worker,
                             3,
                             Preview::Statistics::Metric::Events},
                            9);

        const auto First = Counters.Snapshot();
        (void)Counters.Add({Preview::Statistics::Scope::Worker,
                             3,
                             Preview::Statistics::Metric::Events},
                            1);

        ASSERT_EQ(First.size(), 1U);
        EXPECT_EQ(First.front().Value, 9U);
        EXPECT_EQ(Counters.Get({Preview::Statistics::Scope::Worker,
                                3,
                                Preview::Statistics::Metric::Events}),
                  10U);
    }

    TEST(Task10EventRing, TerminalReservationAndDropCountsAreBounded)
    {
        Preview::Statistics::EventRing Ring({.Capacity = 3, .TerminalReservation = 1});

        Preview::Statistics::DetailedEvent Ordinary;
        Ordinary.ScopeValue = Preview::Statistics::Scope::Session;
        Ordinary.Session = Preview::SessionId{4};
        Ordinary.Kind = Preview::Statistics::EventKind::Data;
        EXPECT_EQ(Ring.Append(Ordinary).Status,
                  Preview::Statistics::EventAppendStatus::Accepted);
        EXPECT_EQ(Ring.Append(Ordinary).Status,
                  Preview::Statistics::EventAppendStatus::Accepted);
        EXPECT_EQ(Ring.Append(Ordinary).Status,
                  Preview::Statistics::EventAppendStatus::Dropped);

        Preview::Statistics::DetailedEvent Terminal = Ordinary;
        Terminal.Kind = Preview::Statistics::EventKind::SessionClosed;
        Terminal.Terminal = true;
        const auto TerminalResult = Ring.Append(Terminal);
        EXPECT_EQ(TerminalResult.Status,
                  Preview::Statistics::EventAppendStatus::Accepted);
        EXPECT_TRUE(TerminalResult.UsedReservation);
        EXPECT_EQ(Ring.Append(Terminal).Status,
                  Preview::Statistics::EventAppendStatus::TerminalDropped);

        const auto Counts = Ring.Counts();
        EXPECT_EQ(Counts.Size, 3U);
        EXPECT_EQ(Counts.Dropped, 1U);
        EXPECT_EQ(Counts.TerminalReserved, 1U);
        EXPECT_EQ(Counts.TerminalDropped, 1U);
    }

    TEST(Task10EventRing, EventsPageByNumericCursor)
    {
        Preview::Statistics::EventRing Ring({.Capacity = 8, .TerminalReservation = 1});
        for (std::uint64_t Index = 1; Index <= 3; ++Index)
        {
            Preview::Statistics::DetailedEvent Event;
            Event.Correlation = Preview::RequestId{Index};
            Event.Kind = Preview::Statistics::EventKind::Data;
            Event.ScopeValue = Preview::Statistics::Scope::Stream;
            Event.Stream = Preview::StreamId{Index};
            ASSERT_EQ(Ring.Append(Event).Status,
                      Preview::Statistics::EventAppendStatus::Accepted);
        }

        const auto First = Ring.Page(0, 2);
        ASSERT_EQ(First.Items.size(), 2U);
        EXPECT_TRUE(First.HasMore);
        EXPECT_EQ(First.Items[0].Sequence, 1U);
        EXPECT_EQ(First.Items[1].Sequence, 2U);

        const auto Second = Ring.Page(First.NextCursor, 2);
        ASSERT_EQ(Second.Items.size(), 1U);
        EXPECT_FALSE(Second.HasMore);
        EXPECT_EQ(Second.Items[0].Sequence, 3U);
        EXPECT_EQ(Second.Items[0].Stream, Preview::StreamId{3});
    }

} // namespace

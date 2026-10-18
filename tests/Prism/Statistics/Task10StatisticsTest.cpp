/**
 * @file Task10StatisticsTest.cpp
 * @brief Task 10 稀疏统计、流量增量和详细事件环测试。
 */

#include <gtest/gtest.h>

#include <Prism/Statistics/Statistics.hpp>

#include <cstdint>
namespace
{

    TEST(Task10SparseCounters, WorkerTrafficFlushIsExactlyOnce)
    {
        Prism::Statistics::SparseCounters Counters;
        Prism::Statistics::TrafficDelta Delta(Prism::WorkerId{7});
        (void)Delta.Add({Prism::Statistics::Scope::Account, 11, 100, 40});
        (void)Delta.Add({Prism::Statistics::Scope::Session, 22, 5, 8});

        EXPECT_TRUE(Delta.Flush(Counters));
        EXPECT_FALSE(Delta.Flush(Counters));
        EXPECT_EQ(Counters.Get({Prism::Statistics::Scope::Account,
                                11,
                                Prism::Statistics::Metric::UpBytes}),
                  100U);
        EXPECT_EQ(Counters.Get({Prism::Statistics::Scope::Account,
                                11,
                                Prism::Statistics::Metric::DownBytes}),
                  40U);
        EXPECT_EQ(Counters.Get({Prism::Statistics::Scope::Session,
                                22,
                                Prism::Statistics::Metric::UpBytes}),
                  5U);
        EXPECT_EQ(Counters.Get({Prism::Statistics::Scope::Session,
                                22,
                                Prism::Statistics::Metric::DownBytes}),
                  8U);
        EXPECT_EQ(Counters.Size(), 4U);
    }

    TEST(Task10SparseCounters, NumericSnapshotIsAValueCopy)
    {
        Prism::Statistics::SparseCounters Counters;
        (void)Counters.Add({Prism::Statistics::Scope::Worker,
                             3,
                             Prism::Statistics::Metric::Events},
                            9);

        const auto First = Counters.Snapshot();
        (void)Counters.Add({Prism::Statistics::Scope::Worker,
                             3,
                             Prism::Statistics::Metric::Events},
                            1);

        ASSERT_EQ(First.size(), 1U);
        EXPECT_EQ(First.front().Value, 9U);
        EXPECT_EQ(Counters.Get({Prism::Statistics::Scope::Worker,
                                3,
                                Prism::Statistics::Metric::Events}),
                  10U);
    }

    TEST(Task10SparseCounters, CapacityFailureLeavesNoPartialTrafficAndCannotReplay)
    {
        Prism::Statistics::SparseCounters Counters({.MaxEntries = 1});
        Prism::Statistics::TrafficDelta Delta(Prism::WorkerId{7});
        (void)Delta.Add({Prism::Statistics::Scope::Account, 11, 100, 40});
        EXPECT_FALSE(Delta.Flush(Counters));
        EXPECT_TRUE(Delta.IsFlushed());
        EXPECT_EQ(Counters.Size(), 0U);
        EXPECT_EQ(Counters.Dropped(), 1U);
        EXPECT_FALSE(Delta.Flush(Counters));
        EXPECT_EQ(Counters.Size(), 0U);
        EXPECT_EQ(Counters.Dropped(), 1U);
    }

    TEST(Task10EventRing, TerminalReservationAndDropCountsAreBounded)
    {
        Prism::Statistics::EventRing Ring({.Capacity = 3, .TerminalReservation = 1});

        Prism::Statistics::DetailedEvent Ordinary;
        Ordinary.ScopeValue = Prism::Statistics::Scope::Session;
        Ordinary.Session = Prism::SessionId{4};
        Ordinary.Kind = Prism::Statistics::EventKind::Data;
        EXPECT_EQ(Ring.Append(Ordinary).Status,
                  Prism::Statistics::EventAppendStatus::Accepted);
        EXPECT_EQ(Ring.Append(Ordinary).Status,
                  Prism::Statistics::EventAppendStatus::Accepted);
        EXPECT_EQ(Ring.Append(Ordinary).Status,
                  Prism::Statistics::EventAppendStatus::Accepted);

        Prism::Statistics::DetailedEvent Terminal = Ordinary;
        Terminal.Kind = Prism::Statistics::EventKind::SessionClosed;
        Terminal.Terminal = true;
        const auto TerminalResult = Ring.Append(Terminal);
        EXPECT_EQ(TerminalResult.Status,
                  Prism::Statistics::EventAppendStatus::Accepted);
        EXPECT_TRUE(TerminalResult.UsedReservation);
        EXPECT_EQ(Ring.Append(Terminal).Status,
                  Prism::Statistics::EventAppendStatus::Accepted);

        const auto Counts = Ring.Counts();
        EXPECT_EQ(Counts.Size, 3U);
        EXPECT_EQ(Counts.Dropped, 0U);
        EXPECT_EQ(Counts.TerminalReserved, 1U);
        EXPECT_EQ(Counts.TerminalDropped, 0U);
    }

    TEST(Task10EventRing, EventsPageByNumericCursor)
    {
        Prism::Statistics::EventRing Ring({.Capacity = 8, .TerminalReservation = 1});
        for (std::uint64_t Index = 1; Index <= 3; ++Index)
        {
            Prism::Statistics::DetailedEvent Event;
            Event.Correlation = Prism::RequestId{Index};
            Event.Kind = Prism::Statistics::EventKind::Data;
            Event.ScopeValue = Prism::Statistics::Scope::Stream;
            Event.Stream = Prism::StreamId{Index};
            ASSERT_EQ(Ring.Append(Event).Status,
                      Prism::Statistics::EventAppendStatus::Accepted);
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
        EXPECT_EQ(Second.Items[0].Stream, Prism::StreamId{3});
    }

} // namespace

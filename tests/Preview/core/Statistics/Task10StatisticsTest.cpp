/**
 * @file Task10StatisticsTest.cpp
 * @brief Task 10 稀疏统计、流量增量和详细事件环测试。
 */

#include <gtest/gtest.h>

#include <Preview/Foundation/Utility/Diagnose/Context.hpp>
#include <Preview/Foundation/Utility/Diagnose/Log.hpp>
#include <Preview/Foundation/Utility/Diagnose/Logger.hpp>
#include <Preview/Statistics/Statistics.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
namespace
{

    auto MakeLoggingTestDirectory() -> std::filesystem::path
    {
        const auto Stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        return std::filesystem::temp_directory_path() /
               ("prism-preview-logging-" + std::to_string(Stamp));
    }

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

    TEST(Task10TraceContext, SnapshotOwnsSelectedIdentifiersAfterOwnerRelease)
    {
        auto Context = std::make_shared<Preview::Diagnose::TraceContext>();
        Context->SetCorrelation(Preview::RequestId{11});
        Context->SetWorker(Preview::WorkerId{22});
        Context->SetSession(Preview::SessionId{33});
        Context->SetStream(Preview::StreamId{44});

        const auto Snapshot = Context->Snapshot();
        Context.reset();

        ASSERT_TRUE(Snapshot.Correlation.has_value());
        ASSERT_TRUE(Snapshot.Worker.has_value());
        ASSERT_TRUE(Snapshot.Session.has_value());
        EXPECT_EQ(Snapshot.Correlation->Value(), 11U);
        EXPECT_EQ(Snapshot.Worker->Value(), 22U);
        EXPECT_EQ(Snapshot.Session->Value(), 33U);
        EXPECT_FALSE(Snapshot.Stream.has_value());
    }

    TEST(Task10TraceContext, IncludeStreamCanBeEnabledExplicitly)
    {
        Preview::Statistics::TraceSelection Selection;
        Selection.IncludeStream = true;
        auto Context = std::make_shared<Preview::Diagnose::TraceContext>(Selection);
        Context->SetStream(Preview::StreamId{44});

        const auto Snapshot = Context->Snapshot();

        ASSERT_TRUE(Snapshot.Stream.has_value());
        EXPECT_EQ(Snapshot.Stream->Value(), 44U);
    }

    TEST(Task10Logger, WritesOwnedTraceRecordsDuringOwnerShutdown)
    {
        const auto Directory = MakeLoggingTestDirectory();
        std::error_code CleanupError;
        std::filesystem::remove_all(Directory, CleanupError);

        Preview::Diagnose::LoggerOptions Options;
        Options.Directory = Directory;
        Options.FileName = "preview.log";
        Options.Console = false;
        auto Created = Preview::Diagnose::Logger::Create(std::move(Options));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        auto Context = std::make_shared<Preview::Diagnose::TraceContext>();
        Context->SetCorrelation(Preview::RequestId{101});
        Context->SetWorker(Preview::WorkerId{202});
        Context->SetSession(Preview::SessionId{303});
        ASSERT_EQ(Preview::Diagnose::Info(Logger, Context, "owned message"),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        Context.reset();

        Logger->Stop();
        std::ifstream Input(Directory / "preview.log");
        ASSERT_TRUE(Input.is_open());
        const std::string Contents((std::istreambuf_iterator<char>(Input)),
                                   std::istreambuf_iterator<char>());
        EXPECT_NE(Contents.find("owned message"), std::string::npos);
        EXPECT_NE(Contents.find("Correlation=101"), std::string::npos);
        EXPECT_NE(Contents.find("Worker=202"), std::string::npos);
        EXPECT_NE(Contents.find("Session=303"), std::string::npos);
        EXPECT_EQ(Contents.find("Stream="), std::string::npos);

        Input.close();
        Logger.reset();
        std::filesystem::remove_all(Directory, CleanupError);
        EXPECT_FALSE(CleanupError);
    }

    TEST(Task10Logger, FiltersBelowConfiguredLevelWithoutWriting)
    {
        const auto Directory = MakeLoggingTestDirectory();
        std::error_code CleanupError;
        std::filesystem::remove_all(Directory, CleanupError);

        Preview::Diagnose::LoggerOptions Options;
        Options.Directory = Directory;
        Options.Level = Preview::Diagnose::LogLevel::Warn;
        auto Created = Preview::Diagnose::Logger::Create(std::move(Options));
        ASSERT_TRUE(Created.has_value()) << Created.error().Message;
        auto Logger = std::move(*Created);

        EXPECT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Info, "filtered", {}),
                  Preview::Diagnose::EnqueueStatus::Filtered);
        EXPECT_EQ(Logger->TryWrite(Preview::Diagnose::LogLevel::Warn, "written", {}),
                  Preview::Diagnose::EnqueueStatus::Accepted);
        Logger->Stop();

        std::ifstream Input(Directory / "preview.log");
        ASSERT_TRUE(Input.is_open());
        const std::string Contents((std::istreambuf_iterator<char>(Input)),
                                   std::istreambuf_iterator<char>());
        EXPECT_EQ(Contents.find("filtered"), std::string::npos);
        EXPECT_NE(Contents.find("written"), std::string::npos);

        Input.close();
        Logger.reset();
        std::filesystem::remove_all(Directory, CleanupError);
        EXPECT_FALSE(CleanupError);
    }

} // namespace

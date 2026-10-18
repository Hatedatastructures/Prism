/**
 * @file AsyncBackendShutdownTest.cpp
 * @brief Drain、重复 Shutdown 和 stopped receipt 测试。
 */

#include <gtest/gtest.h>

#include <TestSupport/Prism/DiagnoseTestEnvironment.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <thread>

namespace Prism::Diagnose::Detail
{
    struct BackendLifecycleTestAccess final
    {
        [[nodiscard]] static auto RetainState(const BackendLifecycle &Lifecycle)
            -> std::shared_ptr<AsyncBackendState>
        {
            return Lifecycle.SnapshotState();
        }
    };
}

namespace Prism::Application
{
    struct DiagnoseRuntimeTestAccess final
    {
        [[nodiscard]] static auto RetainState(const DiagnoseRuntime &Runtime)
            -> std::shared_ptr<Prism::Diagnose::Detail::AsyncBackendState>
        {
            return Prism::Diagnose::Detail::BackendLifecycleTestAccess::RetainState(Runtime.Lifecycle_);
        }
    };
}

namespace
{

    TEST(PrismLogger, BeginShutdownStopsSubmissionsAndControlThreadFinalizationJoins)
    {
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"shutdown", 128U};
        ASSERT_TRUE(Environment.Install().has_value());
        const auto State = Prism::Application::DiagnoseRuntimeTestAccess::RetainState(Environment.Runtime());
        ASSERT_TRUE(State);
        const auto Context = Prism::Diagnose::ContextState::Empty()
                                 .WithRenderEpoch(Environment.Runtime().CurrentEpoch())
                                 .With(Prism::Diagnose::Fields::Worker, Prism::WorkerId{5});
        const auto Submitted = Environment.Runtime().Submit(
            Prism::Diagnose::LogLevel::Info, Context, "before shutdown");
        EXPECT_EQ(Submitted.Status, Prism::Diagnose::SubmissionStatus::Accepted);

        Environment.Runtime().BeginShutdown();
        EXPECT_FALSE(Environment.Runtime().IsInstalled());
        const auto Closed = Environment.Runtime().FinalizeShutdown();
        EXPECT_EQ(Closed.Status, Prism::Diagnose::SubmissionStatus::Closed);
        EXPECT_FALSE(Closed.Accepted());
        EXPECT_EQ(Closed.Sequence, Submitted.Sequence);
        EXPECT_TRUE(Context.RenderEpoch()->CloseState()->Closed.load(std::memory_order_acquire));
        EXPECT_FALSE(Context.RenderEpoch()->CloseState()->Failed.load(std::memory_order_acquire));
        EXPECT_FALSE(Context.RenderEpoch()->Value().Sinks.load(std::memory_order_acquire));
        EXPECT_TRUE(State);
        const auto RepeatedClose = Environment.Runtime().FinalizeShutdown();
        EXPECT_EQ(RepeatedClose.Status, Prism::Diagnose::SubmissionStatus::Closed);
        const auto LogPath = Environment.Configuration().Logging.Directory /
            Environment.Configuration().Logging.FileName;
        const auto RenamedPath = std::filesystem::path(LogPath.string() + ".closed");
        std::error_code RenameError;
        std::filesystem::rename(LogPath, RenamedPath, RenameError);
        EXPECT_FALSE(RenameError);
        EXPECT_EQ(Environment.Runtime()
                      .Submit(Prism::Diagnose::LogLevel::Info, Context, "after shutdown")
                      .Status,
                  Prism::Diagnose::SubmissionStatus::Stopped);
        EXPECT_FALSE(Environment.Runtime().IsInstalled());
    }

    TEST(PrismLogger, ExpiredDrainDeadlineLeavesAcceptedRecordForLaterFlush)
    {
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"drain-deadline"};
        ASSERT_TRUE(Environment.Install().has_value());
        const auto Context = Prism::Diagnose::ContextState::Empty();
        const auto Submitted = Environment.Runtime().Submit(
            Prism::Diagnose::LogLevel::Info, Context, "DeadlinePayload=17");
        ASSERT_EQ(Submitted.Status, Prism::Diagnose::SubmissionStatus::Accepted);

        const auto Expired = Environment.Runtime().DrainOnControlThread(std::chrono::milliseconds::zero());
        EXPECT_EQ(Expired.Status, Prism::Diagnose::SubmissionStatus::TimedOut);
        EXPECT_EQ(Expired.Failure.Code, Prism::Fault::Code::Timeout);
        EXPECT_TRUE(Environment.Runtime().IsInstalled());

        const auto Flushed = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2});
        EXPECT_EQ(Flushed.Status, Prism::Diagnose::SubmissionStatus::Flushed);
        EXPECT_EQ(Flushed.Sequence, Submitted.Sequence);
        EXPECT_EQ(Environment.Runtime().Written(), 1U);
        const auto Closed = Environment.Runtime().Shutdown();
        EXPECT_EQ(Closed.Status, Prism::Diagnose::SubmissionStatus::Closed);
    }

    TEST(PrismLogger, DrainReceiptKeepsBarrierSequenceDuringConcurrentSubmission)
    {
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"barrier-sequence", 128U};
        ASSERT_TRUE(Environment.Install().has_value());
        const auto Context = Prism::Diagnose::ContextState::Empty();
        std::atomic<bool> DrainFinished{false};
        Prism::Diagnose::SubmissionReceipt ConcurrentDrain;
        std::thread DrainThread([&Environment, &DrainFinished, &ConcurrentDrain]
        {
            ConcurrentDrain = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2});
            DrainFinished.store(true, std::memory_order_release);
        });

        const auto PublishDeadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        bool BarrierPublished = false;
        while (std::chrono::steady_clock::now() < PublishDeadline && !DrainFinished.load(std::memory_order_acquire))
        {
            if (Environment.Runtime().QueueHighWatermark() != 0U)
            {
                BarrierPublished = true;
                break;
            }
            std::this_thread::yield();
        }
        if (!BarrierPublished && Environment.Runtime().QueueHighWatermark() != 0U)
        {
            BarrierPublished = true;
        }
        Prism::Diagnose::SubmissionReceipt After;
        if (BarrierPublished)
        {
            After = Environment.Runtime().Submit(
                Prism::Diagnose::LogLevel::Info, Context, "after concurrent barrier");
        }
        DrainThread.join();

        ASSERT_TRUE(BarrierPublished);
        ASSERT_EQ(After.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_EQ(ConcurrentDrain.Status, Prism::Diagnose::SubmissionStatus::Flushed);
        EXPECT_LT(ConcurrentDrain.Sequence, After.Sequence);
        const auto FinalDrain = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2});
        EXPECT_EQ(FinalDrain.Status, Prism::Diagnose::SubmissionStatus::Flushed);
        EXPECT_EQ(FinalDrain.Sequence, After.Sequence);
        EXPECT_EQ(Environment.Runtime().Shutdown().Status, Prism::Diagnose::SubmissionStatus::Closed);
    }

} // namespace

/**
 * @file BackendShutdownTest.cpp
 * @brief Drain、重复 Shutdown 和 stopped receipt 测试。
 */

#include <gtest/gtest.h>

#include <TestSupport/Prism/Diagnose/Environment.hpp>
#include <Prism/Foundation/Utility/Diagnose/BackendLifecycle.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/BackendLifecycleOwner.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace Prism::Diagnose::Detail
{
    struct BackendLifecycleTestAccess final
    {
        [[nodiscard]] static auto RetainState(const BackendLifecycle &Lifecycle)
            -> std::shared_ptr<AsyncBackendState>
        {
            return Lifecycle.Owner_->SnapshotState();
        }

        [[nodiscard]] static auto LockEpochGate(AsyncBackendState &State)
            -> std::unique_lock<EpochGate>
        {
            return std::unique_lock<EpochGate>(State.EpochGate_);
        }

        /**
         * @brief 在队首放入一个会阻塞在 EpochGate 的 barrier，让 worker 暂停消费。
         * @details 调用者必须先持有 EpochGate；worker 消费该 barrier 时停在 FlushOutputs，
         *          之后的普通提交可确定性累积直到队列真正填满。
         */
        [[nodiscard]] static auto PublishBlockedBarrier(AsyncBackendState &State) noexcept
            -> std::uint64_t
        {
            class GateGuard final
            {
            public:
                explicit GateGuard(std::atomic_flag &Gate) noexcept
                    : Gate_(Gate),
                      Acquired_(!Gate_.test_and_set(std::memory_order_acquire))
                {
                }

                ~GateGuard()
                {
                    if (Acquired_)
                    {
                        Gate_.clear(std::memory_order_release);
                        Gate_.notify_all();
                    }
                }

                [[nodiscard]] auto Acquired() const noexcept -> bool
                {
                    return Acquired_;
                }
            private:
                std::atomic_flag &Gate_;
                bool Acquired_{false};
            };

            GateGuard Gate(State.EnqueueGate_);
            if (!Gate.Acquired())
            {
                return 0U;
            }
            const auto Write = State.Write_.load(std::memory_order_relaxed);
            if (Write - State.Read_.load(std::memory_order_acquire) >=
                State.Settings_.Logging.QueueCapacity)
            {
                return 0U;
            }
            const auto Id = State.NextBarrier_.fetch_add(1U, std::memory_order_relaxed);
            auto &Record = State.Queue_[Write % State.Settings_.Logging.QueueCapacity];
            Record.Command = QueueCommand::Barrier;
            Record.Sequence = 0U;
            Record.BarrierId = Id;
            Record.TimestampMilliseconds = 0U;
            Record.Epoch.reset();
            Record.Message.Reset();
            State.Write_.store(Write + 1U, std::memory_order_release);
            State.ObserveQueueHighWatermark(State.QueueSize());
            State.Wake_->Notify();
            return Id;
        }

        [[nodiscard]] static auto QueueSize(const AsyncBackendState &State) noexcept
            -> std::size_t
        {
            return State.QueueSize();
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
        const auto State = Prism::Application::DiagnoseRuntimeTestAccess::RetainState(
            Environment.Runtime());
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
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"barrier-sequence", 1U};
        ASSERT_TRUE(Environment.Install().has_value());
        const auto State = Prism::Application::DiagnoseRuntimeTestAccess::RetainState(
            Environment.Runtime());
        ASSERT_TRUE(State);
        const auto Context = Prism::Diagnose::ContextState::Empty();
        auto Pause = Prism::Diagnose::Detail::BackendLifecycleTestAccess::LockEpochGate(*State);
        const auto BlockingBarrier =
            Prism::Diagnose::Detail::BackendLifecycleTestAccess::PublishBlockedBarrier(*State);
        ASSERT_EQ(BlockingBarrier, 1U);
        EXPECT_EQ(Prism::Diagnose::Detail::BackendLifecycleTestAccess::QueueSize(*State), 1U);
        EXPECT_EQ(Environment.Runtime()
                      .Submit(Prism::Diagnose::LogLevel::Info, Context, "capacity held")
                      .Status,
            Prism::Diagnose::SubmissionStatus::Dropped);
        Prism::Diagnose::SubmissionReceipt BlockedDrain;
        std::thread DrainThread([&Environment, &BlockedDrain]
        {
            BlockedDrain = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{1});
        });
        DrainThread.join();
        EXPECT_EQ(BlockedDrain.Status, Prism::Diagnose::SubmissionStatus::TimedOut);
        EXPECT_EQ(BlockedDrain.Failure.Code, Prism::Fault::Code::Timeout);

        Pause.unlock();
        const auto ConcurrentDrain =
            Environment.Runtime().DrainOnControlThread(std::chrono::seconds{5});
        ASSERT_EQ(ConcurrentDrain.Status, Prism::Diagnose::SubmissionStatus::Flushed);
        const auto After = Environment.Runtime().Submit(
            Prism::Diagnose::LogLevel::Info, Context, "after concurrent barrier");
        ASSERT_EQ(After.Status, Prism::Diagnose::SubmissionStatus::Accepted);
        EXPECT_LT(ConcurrentDrain.Sequence, After.Sequence);
        const auto FinalDrain = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{2});
        EXPECT_EQ(FinalDrain.Status, Prism::Diagnose::SubmissionStatus::Flushed);
        EXPECT_EQ(FinalDrain.Sequence, After.Sequence);
        EXPECT_EQ(Environment.Runtime().Shutdown().Status, Prism::Diagnose::SubmissionStatus::Closed);
    }

    TEST(PrismLogger, FullQueueBarrierPreservesEveryAcceptedSequence)
    {
        Prism::TestSupport::DiagnoseTestEnvironment Environment{"full-queue-barrier", 129U};
        ASSERT_TRUE(Environment.Install().has_value());
        const auto Context = Prism::Diagnose::ContextState::Empty();
        const auto State = Prism::Application::DiagnoseRuntimeTestAccess::RetainState(
            Environment.Runtime());
        ASSERT_TRUE(State);
        auto Pause = Prism::Diagnose::Detail::BackendLifecycleTestAccess::LockEpochGate(*State);
        const auto BlockingBarrier =
            Prism::Diagnose::Detail::BackendLifecycleTestAccess::PublishBlockedBarrier(*State);
        ASSERT_EQ(BlockingBarrier, 1U);
        ASSERT_EQ(Prism::Diagnose::Detail::BackendLifecycleTestAccess::QueueSize(*State), 1U);
        ASSERT_EQ(State->QueueHighWatermark(), 1U);
        std::vector<std::uint64_t> Sequences;
        Sequences.reserve(129U);
        for (std::size_t Index = 0U; Index < 129U; ++Index)
        {
            const auto Submitted = Environment.Runtime().Submit(
                Prism::Diagnose::LogLevel::Info, Context,
                Index + 1U == 129U ? "queue full"
                                   : "FullQueuePayload=" + std::to_string(Index));
            if (Index + 1U == 129U)
            {
                ASSERT_EQ(Submitted.Status, Prism::Diagnose::SubmissionStatus::Dropped);
                continue;
            }
            ASSERT_EQ(Submitted.Status, Prism::Diagnose::SubmissionStatus::Accepted);
            Sequences.push_back(Submitted.Sequence);
        }
        Pause.unlock();
        EXPECT_EQ(State->QueueHighWatermark(), 129U);

        const auto Flushed = Environment.Runtime().DrainOnControlThread(std::chrono::seconds{5});
        ASSERT_EQ(Flushed.Status, Prism::Diagnose::SubmissionStatus::Flushed);
        ASSERT_EQ(Flushed.Sequence, Sequences.back());
        EXPECT_TRUE(std::is_sorted(Sequences.begin(), Sequences.end()));
        EXPECT_EQ(Sequences.front(), 1U);
        EXPECT_EQ(Sequences.size(), 128U);
        EXPECT_EQ(Environment.Runtime().Written(), 128U);
        EXPECT_EQ(Environment.Runtime().Shutdown().Status,
            Prism::Diagnose::SubmissionStatus::Closed);

        const auto LogPath = Environment.Configuration().Logging.Directory /
            Environment.Configuration().Logging.FileName;
        std::ifstream Input(LogPath, std::ios::binary);
        ASSERT_TRUE(Input.is_open());
        const std::string Contents{std::istreambuf_iterator<char>{Input},
                                   std::istreambuf_iterator<char>{}};
        for (std::size_t Index = 0U; Index < 128U; ++Index)
        {
            EXPECT_NE(Contents.find("FullQueuePayload=" + std::to_string(Index) + "\n"),
                std::string::npos);
        }
    }

} // namespace

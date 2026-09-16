#include <gtest/gtest.h>

#include <Preview/Runtime/Process.hpp>
#include <Preview/Runtime/SessionControl.hpp>
#include <Preview/Runtime/Worker.hpp>
#include <Preview/Runtime/WorkerGroup.hpp>

#include <type_traits>
#include <vector>

namespace
{

    using Preview::GenerationId;
    using Preview::ProcessId;
    using Preview::WorkerId;
    using Preview::Runtime::Mailbox;
    using Preview::Runtime::Process;
    using Preview::Runtime::Worker;

    static_assert(!std::is_copy_constructible_v<Process>);
    static_assert(!std::is_copy_constructible_v<Worker>);

    TEST(WorkerGroup, OwnsWorkersAndDispatchesOnWorkerExecutor)
    {
        Process::Options Options;
        Options.Id = ProcessId{3};
        Options.Generation = GenerationId{9};
        Options.WorkerCount = 2;
        Options.MailboxCapacity = 2;
        Process ProcessValue(Options);

        auto &Group = ProcessValue.Workers();
        ASSERT_EQ(Group.Size(), 2U);
        auto *WorkerValue = Group.Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);

        bool OnExecutor = false;
        EXPECT_EQ(Group.Dispatch(WorkerId{1}, GenerationId{9}, [&OnExecutor, WorkerValue]
                                 { OnExecutor = WorkerValue->IsOnExecutor(); }),
                  Mailbox::Result::Accepted);
        EXPECT_GE(WorkerValue->Pump(), 1U);
        EXPECT_TRUE(OnExecutor);
    }

    TEST(WorkerGroup, RejectsStaleGenerationAndStoppedWorker)
    {
        Process::Options Options;
        Options.Id = ProcessId{4};
        Options.Generation = GenerationId{12};
        Options.WorkerCount = 1;
        Process ProcessValue(Options);

        auto *WorkerValue = ProcessValue.Workers().Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        EXPECT_EQ(ProcessValue.Workers().Dispatch(WorkerId{1}, GenerationId{13}, [] {}),
                  Mailbox::Result::GenerationRejected);

        WorkerValue->Stop();
        EXPECT_EQ(ProcessValue.Workers().Dispatch(WorkerId{1}, GenerationId{12}, [] {}),
                  Mailbox::Result::WorkerUnavailable);
    }

    TEST(WorkerGroup, PublishesWorkerSnapshot)
    {
        Process::Options Options;
        Options.Id = ProcessId{5};
        Options.Generation = GenerationId{15};
        Options.WorkerCount = 1;
        Options.MailboxCapacity = 3;
        Process ProcessValue(Options);

        auto *WorkerValue = ProcessValue.Workers().Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        EXPECT_EQ(WorkerValue->Dispatch(GenerationId{15}, [] {}), Mailbox::Result::Accepted);
        EXPECT_GE(WorkerValue->Pump(), 1U);

        const auto Snapshot = WorkerValue->Snapshot();
        EXPECT_EQ(Snapshot.Id, WorkerId{1});
        EXPECT_EQ(Snapshot.Generation, GenerationId{15});
        EXPECT_EQ(Snapshot.MailboxCapacity, 3U);
        EXPECT_EQ(Snapshot.MailboxSize, 0U);
        EXPECT_EQ(Snapshot.DispatchAccepted, 1U);
        EXPECT_EQ(Snapshot.CommandsExecuted, 1U);

        const auto GroupSnapshot = ProcessValue.Workers().Snapshot();
        ASSERT_EQ(GroupSnapshot.size(), 1U);
        EXPECT_EQ(GroupSnapshot.front().Id, WorkerId{1});
    }

    TEST(WorkerGroup, PreservesBoundedMailboxAdmissionResults)
    {
        Process::Options Options;
        Options.Id = ProcessId{6};
        Options.Generation = GenerationId{18};
        Options.WorkerCount = 1;
        Options.MailboxCapacity = 1;
        Process ProcessValue(Options);

        auto *WorkerValue = ProcessValue.Workers().Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);

        EXPECT_EQ(WorkerValue->Dispatch(GenerationId{18}, [] {}), Mailbox::Result::Accepted);
        EXPECT_EQ(WorkerValue->Dispatch(GenerationId{18}, [] {}), Mailbox::Result::Full);

        WorkerValue->MailboxRef().Close();
        EXPECT_EQ(WorkerValue->Dispatch(GenerationId{18}, [] {}), Mailbox::Result::Closed);

        WorkerValue->Stop();
        EXPECT_EQ(WorkerValue->Dispatch(GenerationId{18}, [] {}),
                  Mailbox::Result::WorkerUnavailable);
    }

    TEST(WorkerGroup, SessionControlObservesWorkerRegistryCancellation)
    {
        Process::Options Options;
        Options.Id = ProcessId{8};
        Options.Generation = GenerationId{24};
        Options.WorkerCount = 1;
        Process ProcessValue(Options);

        auto *WorkerValue = ProcessValue.Workers().Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        Preview::Runtime::SessionControl Control;
        ASSERT_TRUE(Control.Bind(WorkerValue->Executor(), WorkerValue->TaskRegistry()));
        EXPECT_FALSE(Control.IsCancelled());

        WorkerValue->Stop();
        EXPECT_TRUE(Control.IsCancelled());
        Preview::Lifecycle::TaskRequest FollowUp;
        EXPECT_FALSE(Control.Start(
            std::move(FollowUp),
            []() -> boost::asio::awaitable<void> { co_return; }()));
    }

    TEST(WorkerGroup, SessionScopesIsolateCancelAndShareWorkerShutdown)
    {
        Process::Options Options;
        Options.Id = ProcessId{7};
        Options.Generation = GenerationId{21};
        Options.WorkerCount = 1;
        Process ProcessValue(Options);

        auto *WorkerValue = ProcessValue.Workers().Find(WorkerId{1});
        ASSERT_NE(WorkerValue, nullptr);
        EXPECT_EQ(&WorkerValue->TaskRegistry(), &WorkerValue->Resources().Tasks);
        Preview::Runtime::SessionControl FirstControl;
        Preview::Runtime::SessionControl SecondControl;
        ASSERT_TRUE(FirstControl.Bind(WorkerValue->Executor(), WorkerValue->TaskRegistry()));
        ASSERT_TRUE(SecondControl.Bind(WorkerValue->Executor(), WorkerValue->TaskRegistry()));

        Preview::Lifecycle::TaskRequest FirstRequest;
        FirstRequest.Identity.SessionId = Preview::SessionId{101};
        FirstRequest.Identity.WorkerId = WorkerId{1};
        FirstRequest.Identity.Generation = GenerationId{21};
        Preview::Lifecycle::TaskRequest SecondRequest = FirstRequest;
        SecondRequest.Identity.SessionId = Preview::SessionId{102};

        EXPECT_TRUE(FirstControl.Start(
            std::move(FirstRequest),
            []() -> boost::asio::awaitable<void> { co_return; }()));
        EXPECT_TRUE(SecondControl.Start(
            std::move(SecondRequest),
            []() -> boost::asio::awaitable<void> { co_return; }()));
        EXPECT_NE(FirstControl.CurrentIdentity().TaskId, SecondControl.CurrentIdentity().TaskId);

        FirstControl.Cancel();
        EXPECT_TRUE(FirstControl.IsCancelled());
        EXPECT_FALSE(SecondControl.IsCancelled());

        Preview::Lifecycle::TaskRequest FollowUp;
        FollowUp.Identity.SessionId = Preview::SessionId{103};
        FollowUp.Identity.WorkerId = WorkerId{1};
        FollowUp.Identity.Generation = GenerationId{21};
        EXPECT_TRUE(SecondControl.Start(
            std::move(FollowUp),
            []() -> boost::asio::awaitable<void> { co_return; }()));

        WorkerValue->Stop();
        EXPECT_TRUE(SecondControl.IsCancelled());
    }

} // namespace

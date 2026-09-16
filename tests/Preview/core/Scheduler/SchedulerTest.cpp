/**
 * @file SchedulerTest.cpp
 * @brief Preview scheduler 的确定性公平性与边界契约测试
 */

#include <gtest/gtest.h>

#include <Preview/Scheduler/Scheduler.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>

namespace
{

    namespace Scheduler = Preview::Scheduler;

    auto MakeRequest(const std::uint64_t IdValue,
                     const std::uint64_t AccountValue,
                     const std::uint64_t StreamValue) -> Scheduler::Request
    {
        Scheduler::Request RequestValue;
        RequestValue.RequestId = Preview::RequestId{IdValue};
        RequestValue.AccountId = Preview::AccountId{AccountValue};
        RequestValue.StreamId = Preview::StreamId{StreamValue};
        RequestValue.WorkerId = Preview::WorkerId{7};
        RequestValue.RemainingBytes = 1000;
        RequestValue.QuantumBytes = 10;
        RequestValue.MaxBurstBytes = 100;
        RequestValue.MaxConsecutiveTurns = 1;
        RequestValue.Priority = Scheduler::PriorityBand::Bulk;
        return RequestValue;
    }

    auto Requeue(Scheduler::FairScheduler &SchedulerValue, Scheduler::Result ResultValue)
        -> Scheduler::Result
    {
        return SchedulerValue.Requeue(std::move(ResultValue));
    }

    TEST(FairScheduler, WeightedShareUsesAccountWeight)
    {
        Scheduler::Budget BudgetValue;
        BudgetValue.WorkerId = Preview::WorkerId{7};
        BudgetValue.MaxQueueSize = 8;
        BudgetValue.AccountQuantumBytes = 10;

        Scheduler::FairScheduler SchedulerValue(BudgetValue);
        auto AccountOne = MakeRequest(1, 11, 101);
        auto AccountTwo = MakeRequest(2, 22, 202);
        AccountOne.Weight = 1;
        AccountTwo.Weight = 2;

        EXPECT_EQ(SchedulerValue.Submit(AccountOne).Status, Scheduler::ResultStatus::Accepted);
        EXPECT_EQ(SchedulerValue.Submit(AccountTwo).Status, Scheduler::ResultStatus::Accepted);

        const auto First = SchedulerValue.Next(0);
        ASSERT_EQ(First.Status, Scheduler::ResultStatus::Ready);
        EXPECT_EQ(First.RequestId, AccountOne.RequestId);
        EXPECT_EQ(First.GrantedBytes, 10U);
        EXPECT_EQ(Requeue(SchedulerValue, First).Status, Scheduler::ResultStatus::Accepted);

        const auto Second = SchedulerValue.Next(0);
        ASSERT_EQ(Second.Status, Scheduler::ResultStatus::Ready);
        EXPECT_EQ(Second.RequestId, AccountTwo.RequestId);
        EXPECT_EQ(Second.GrantedBytes, 20U);
        EXPECT_EQ(Requeue(SchedulerValue, Second).Status, Scheduler::ResultStatus::Accepted);

        const auto Third = SchedulerValue.Next(0);
        ASSERT_EQ(Third.Status, Scheduler::ResultStatus::Ready);
        EXPECT_EQ(Third.RequestId, AccountOne.RequestId);
        EXPECT_EQ(Third.GrantedBytes, 10U);
        EXPECT_EQ(Requeue(SchedulerValue, Third).Status, Scheduler::ResultStatus::Accepted);

        const auto Fourth = SchedulerValue.Next(0);
        ASSERT_EQ(Fourth.Status, Scheduler::ResultStatus::Ready);
        EXPECT_EQ(Fourth.RequestId, AccountTwo.RequestId);
        EXPECT_EQ(Fourth.GrantedBytes, 20U);
    }

    TEST(FairScheduler, AccountFanOutDoesNotMultiplyAccountShare)
    {
        Scheduler::Budget BudgetValue;
        BudgetValue.WorkerId = Preview::WorkerId{7};
        BudgetValue.MaxQueueSize = 8;
        BudgetValue.AccountQuantumBytes = 10;

        Scheduler::FairScheduler SchedulerValue(BudgetValue);
        auto FirstStream = MakeRequest(1, 11, 101);
        auto SecondStream = MakeRequest(2, 11, 102);
        auto OtherAccount = MakeRequest(3, 22, 201);
        ASSERT_EQ(SchedulerValue.Submit(FirstStream).Status, Scheduler::ResultStatus::Accepted);
        ASSERT_EQ(SchedulerValue.Submit(SecondStream).Status, Scheduler::ResultStatus::Accepted);
        ASSERT_EQ(SchedulerValue.Submit(OtherAccount).Status, Scheduler::ResultStatus::Accepted);

        std::uint64_t FirstAccountBytes = 0;
        std::uint64_t OtherAccountBytes = 0;
        bool FirstStreamServed = false;
        bool SecondStreamServed = false;
        for (std::size_t Index = 0; Index < 6; ++Index)
        {
            auto ResultValue = SchedulerValue.Next(0);
            ASSERT_EQ(ResultValue.Status, Scheduler::ResultStatus::Ready);
            if (ResultValue.AccountId == FirstStream.AccountId)
            {
                FirstAccountBytes += ResultValue.GrantedBytes;
                FirstStreamServed = FirstStreamServed || ResultValue.RequestId == FirstStream.RequestId;
                SecondStreamServed = SecondStreamServed || ResultValue.RequestId == SecondStream.RequestId;
            }
            else
            {
                OtherAccountBytes += ResultValue.GrantedBytes;
            }
            ASSERT_EQ(Requeue(SchedulerValue, ResultValue).Status, Scheduler::ResultStatus::Accepted);
        }

        EXPECT_EQ(FirstAccountBytes, 30U);
        EXPECT_EQ(OtherAccountBytes, 30U);
        EXPECT_TRUE(FirstStreamServed);
        EXPECT_TRUE(SecondStreamServed);
    }

    TEST(FairScheduler, CancellationRemovesInFlightRequest)
    {
        Scheduler::FairScheduler SchedulerValue(Scheduler::Budget{.WorkerId = Preview::WorkerId{7}});
        auto RequestValue = MakeRequest(1, 11, 101);
        ASSERT_EQ(SchedulerValue.Submit(RequestValue).Status, Scheduler::ResultStatus::Accepted);
        ASSERT_EQ(SchedulerValue.Next(0).Status, Scheduler::ResultStatus::Ready);

        EXPECT_EQ(SchedulerValue.Cancel(RequestValue.RequestId).Status, Scheduler::ResultStatus::Cancelled);
        EXPECT_EQ(SchedulerValue.Next(0).Status, Scheduler::ResultStatus::Empty);
        EXPECT_EQ(SchedulerValue.Cancel(RequestValue.RequestId).Status, Scheduler::ResultStatus::NotFound);
    }

    TEST(FairScheduler, RateBlockedRequestLeavesReadySetAndRequeuesOnce)
    {
        Scheduler::FairScheduler SchedulerValue(Scheduler::Budget{.WorkerId = Preview::WorkerId{7}});
        auto RequestValue = MakeRequest(1, 11, 101);
        RequestValue.RateBlocked = true;
        EXPECT_EQ(SchedulerValue.Submit(RequestValue).Status, Scheduler::ResultStatus::RateBlocked);
        EXPECT_EQ(SchedulerValue.ReadyCount(), 0U);
        EXPECT_EQ(SchedulerValue.Next(0).Status, Scheduler::ResultStatus::Empty);

        EXPECT_EQ(SchedulerValue.Unblock(RequestValue.RequestId).Status, Scheduler::ResultStatus::Accepted);
        EXPECT_EQ(SchedulerValue.Unblock(RequestValue.RequestId).Status, Scheduler::ResultStatus::Updated);
        EXPECT_EQ(SchedulerValue.ReadyCount(), 1U);

        auto ResultValue = SchedulerValue.Next(0);
        ASSERT_EQ(ResultValue.Status, Scheduler::ResultStatus::Ready);
        ResultValue.RateBlocked = true;
        EXPECT_EQ(SchedulerValue.Requeue(ResultValue).Status, Scheduler::ResultStatus::RateBlocked);
        EXPECT_EQ(SchedulerValue.ReadyCount(), 0U);
        EXPECT_EQ(SchedulerValue.BlockedCount(), 1U);
        EXPECT_EQ(SchedulerValue.Next(0).Status, Scheduler::ResultStatus::Empty);

        EXPECT_EQ(SchedulerValue.Unblock(RequestValue.RequestId).Status, Scheduler::ResultStatus::Accepted);
        ResultValue = SchedulerValue.Next(0);
        ASSERT_EQ(ResultValue.Status, Scheduler::ResultStatus::Ready);
        ResultValue.Cancelled = true;
        EXPECT_EQ(SchedulerValue.Requeue(ResultValue).Status, Scheduler::ResultStatus::Cancelled);
    }

    TEST(FairScheduler, QueueFullDoesNotCreateAHiddenReadyNode)
    {
        Scheduler::Budget BudgetValue;
        BudgetValue.WorkerId = Preview::WorkerId{7};
        BudgetValue.MaxQueueSize = 2;
        Scheduler::FairScheduler SchedulerValue(BudgetValue);

        EXPECT_EQ(SchedulerValue.Submit(MakeRequest(1, 11, 101)).Status,
                  Scheduler::ResultStatus::Accepted);
        EXPECT_EQ(SchedulerValue.Submit(MakeRequest(2, 22, 202)).Status,
                  Scheduler::ResultStatus::Accepted);
        EXPECT_EQ(SchedulerValue.Submit(MakeRequest(3, 33, 303)).Status,
                  Scheduler::ResultStatus::QueueFull);
        EXPECT_EQ(SchedulerValue.Size(), 2U);

        EXPECT_EQ(SchedulerValue.Cancel(Preview::RequestId{1}).Status,
                  Scheduler::ResultStatus::Cancelled);
        EXPECT_EQ(SchedulerValue.Submit(MakeRequest(3, 33, 303)).Status,
                  Scheduler::ResultStatus::Accepted);
        EXPECT_EQ(SchedulerValue.Size(), 2U);
    }

    TEST(PriorityScheduler, AgingPromotesBackgroundBeforeFreshBulk)
    {
        Scheduler::Budget BudgetValue;
        BudgetValue.WorkerId = Preview::WorkerId{7};
        BudgetValue.AgingInterval = 10;
        BudgetValue.StarvationDeadline = 100;
        BudgetValue.MinimumServiceBytes = 5;
        BudgetValue.MaxBurstBytes = 8;

        Scheduler::PriorityScheduler SchedulerValue(BudgetValue);
        auto Background = MakeRequest(1, 11, 101);
        auto FreshBulk = MakeRequest(2, 22, 202);
        Background.Priority = Scheduler::PriorityBand::Background;
        Background.EnqueuedAt = 0;
        FreshBulk.Priority = Scheduler::PriorityBand::Bulk;
        FreshBulk.EnqueuedAt = 20;
        ASSERT_EQ(SchedulerValue.Submit(Background).Status, Scheduler::ResultStatus::Accepted);
        ASSERT_EQ(SchedulerValue.Submit(FreshBulk).Status, Scheduler::ResultStatus::Accepted);

        const auto ResultValue = SchedulerValue.Next(20);
        ASSERT_EQ(ResultValue.Status, Scheduler::ResultStatus::Ready);
        EXPECT_EQ(ResultValue.RequestId, Background.RequestId);
        EXPECT_GE(ResultValue.GrantedBytes, 5U);
        EXPECT_LE(ResultValue.GrantedBytes, 8U);
    }

    TEST(PriorityScheduler, MinimumServiceKeepsAccountsRoundRobin)
    {
        Scheduler::Budget BudgetValue;
        BudgetValue.WorkerId = Preview::WorkerId{7};
        BudgetValue.MinimumServiceBytes = 5;
        BudgetValue.MaxBurstBytes = 8;
        Scheduler::PriorityScheduler SchedulerValue(BudgetValue);

        auto FirstStream = MakeRequest(1, 11, 101);
        auto SecondStream = MakeRequest(2, 11, 102);
        auto OtherAccount = MakeRequest(3, 22, 201);
        FirstStream.Priority = Scheduler::PriorityBand::Interactive;
        SecondStream.Priority = Scheduler::PriorityBand::Interactive;
        OtherAccount.Priority = Scheduler::PriorityBand::Interactive;
        ASSERT_EQ(SchedulerValue.Submit(FirstStream).Status, Scheduler::ResultStatus::Accepted);
        ASSERT_EQ(SchedulerValue.Submit(SecondStream).Status, Scheduler::ResultStatus::Accepted);
        ASSERT_EQ(SchedulerValue.Submit(OtherAccount).Status, Scheduler::ResultStatus::Accepted);

        const auto First = SchedulerValue.Next(0);
        ASSERT_EQ(First.Status, Scheduler::ResultStatus::Ready);
        EXPECT_EQ(First.AccountId, FirstStream.AccountId);
        EXPECT_GE(First.GrantedBytes, 5U);
        ASSERT_EQ(SchedulerValue.Requeue(First).Status, Scheduler::ResultStatus::Accepted);

        const auto Second = SchedulerValue.Next(0);
        ASSERT_EQ(Second.Status, Scheduler::ResultStatus::Ready);
        EXPECT_EQ(Second.AccountId, OtherAccount.AccountId);
        EXPECT_GE(Second.GrantedBytes, 5U);
        ASSERT_EQ(SchedulerValue.Requeue(Second).Status, Scheduler::ResultStatus::Accepted);

        const auto Third = SchedulerValue.Next(0);
        ASSERT_EQ(Third.Status, Scheduler::ResultStatus::Ready);
        EXPECT_EQ(Third.AccountId, FirstStream.AccountId);
    }

    TEST(PriorityScheduler, QueueFullAndWorkerAffinityAreExplicit)
    {
        Scheduler::Budget BudgetValue;
        BudgetValue.WorkerId = Preview::WorkerId{7};
        BudgetValue.MaxQueueSize = 1;
        Scheduler::PriorityScheduler SchedulerValue(BudgetValue);

        auto Accepted = MakeRequest(1, 11, 101);
        EXPECT_EQ(SchedulerValue.Submit(Accepted).Status, Scheduler::ResultStatus::Accepted);

        auto WrongWorker = MakeRequest(2, 22, 202);
        WrongWorker.WorkerId = Preview::WorkerId{8};
        EXPECT_EQ(SchedulerValue.Submit(WrongWorker).Status, Scheduler::ResultStatus::WorkerMismatch);

        EXPECT_EQ(SchedulerValue.Submit(MakeRequest(3, 33, 303)).Status,
                  Scheduler::ResultStatus::QueueFull);
    }

} // namespace

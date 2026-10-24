/**
 * @file MuxRealRootLifecycleTest.cpp
 * @brief 真实 Mux Root 认证失败、failure-before-drain 和收口测试。
 */

#include "MuxRealRootFixture.hpp"
#include "MuxRealRootMatrixControl.hpp"
#include "MuxRealRootMeasurement.hpp"

namespace Prism::Testing::MuxRealRoot
{
TEST(MuxPerf, RealRootBadAuthPublishesFailureBeforeDrain)
{
    Net::io_context IoContext;
    auto State = MakeRealRootState(RealRootMode::Smux, IoContext.get_executor());
    State->InvalidPassword = true;
    State->Window = std::make_shared<RealMeasureWindow>(1U);
    bool FailurePublishedBeforeDrain = false;
    std::exception_ptr Failure;
    Net::co_spawn(IoContext, RunRealScenario(State),
                  RealMatrixCompletion{State, &Failure});
    Net::co_spawn(IoContext,
                  ObserveRealFailureBeforeDrain(State, FailurePublishedBeforeDrain),
                  Net::detached);
    Net::co_spawn(IoContext, RootFixture::Watchdog(State->Harness), Net::detached);
    IoContext.run();

    EXPECT_FALSE(Failure);
    EXPECT_FALSE(State->Harness->TimedOut);
    EXPECT_FALSE(State->Authenticated);
    EXPECT_FALSE(State->RootFinished);
    EXPECT_TRUE(State->Drained);
    EXPECT_TRUE(FailurePublishedBeforeDrain);
    EXPECT_EQ(State->Window->MeasureCompleted.load(std::memory_order_acquire), 0U);
    EXPECT_EQ(State->Window->MeasureFailed.load(std::memory_order_acquire), 1U);
}

TEST(MuxPerf, RealRootMatrixFailureInjectionClosesEveryGate)
{
    constexpr std::array<RealMatrixFailurePoint, 5> FailurePoints{
        RealMatrixFailurePoint::BeforeReady,
        RealMatrixFailurePoint::Start,
        RealMatrixFailurePoint::Transfer,
        RealMatrixFailurePoint::End,
        RealMatrixFailurePoint::Close};
    for (const auto FailurePoint : FailurePoints)
    {
        const auto Result = RunRealMatrix(RealMatrixRequest{
            .Mode = RealRootMode::Smux, .Lanes = 1U, .Round = 1U,
            .FailurePoint = FailurePoint});
        ASSERT_TRUE(Result.Prepared);
        ASSERT_FALSE(Result.CloseTimedOut);
        ASSERT_EQ(Result.StartedLanes, 1U);
        ASSERT_EQ(Result.ExitedLanes, 1U);
        ASSERT_EQ(Result.Lanes.size(), 1U);
        const auto &Lane = Result.Lanes.front();
        EXPECT_TRUE(Lane.Failure);
        EXPECT_FALSE(Lane.FailureMessage.empty());
        EXPECT_TRUE(Lane.ScenarioCompleted);
        EXPECT_TRUE(Lane.Exited);
        EXPECT_TRUE(Lane.Drained);
        EXPECT_TRUE(Lane.QuotaZero);
        EXPECT_TRUE(Lane.WeakExpired);
        EXPECT_EQ(Lane.ReadyOrFailed, 1U);
        EXPECT_EQ(Lane.MeasureCompleted + Lane.MeasureFailed, 1U);
        if (FailurePoint == RealMatrixFailurePoint::BeforeReady)
        {
            EXPECT_FALSE(Lane.Ready);
        }
        else
        {
            EXPECT_TRUE(Lane.Ready);
        }
    }
}

TEST(MuxPerf, RealRootMatrixPartialThreadCreationCleansStartedLanes)
{
    const auto Result = RunRealMatrix(RealMatrixRequest{
        .Mode = RealRootMode::Smux, .Lanes = 2U, .Round = 1U,
        .FailurePoint = RealMatrixFailurePoint::ThreadCreation, .FailureLane = 1U});
    ASSERT_FALSE(Result.Prepared);
    ASSERT_TRUE(Result.ThreadCreationFailed);
    ASSERT_FALSE(Result.CloseTimedOut);
    ASSERT_EQ(Result.StartedLanes, 1U);
    ASSERT_EQ(Result.ExitedLanes, 1U);
    ASSERT_EQ(Result.Lanes.size(), 2U);
    EXPECT_TRUE(Result.Lanes[0].Exited);
    EXPECT_TRUE(Result.Lanes[0].ScenarioCompleted);
    EXPECT_TRUE(Result.Lanes[0].Failure);
    EXPECT_FALSE(Result.Lanes[1].Exited);
    EXPECT_FALSE(Result.Lanes[1].ScenarioCompleted);
    EXPECT_TRUE(Result.Lanes[1].Failure);
    EXPECT_EQ(Result.Lanes[1].ReadyOrFailed, 2U);
    EXPECT_EQ(Result.Lanes[1].MeasureCompleted + Result.Lanes[1].MeasureFailed, 2U);
}
} // namespace Prism::Testing::MuxRealRoot

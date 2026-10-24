/** @file AccountUsageScheduleTest.cpp @brief 账户用量周期调度状态转换回归。 */
#include <Prism/Account/UsageCalendar.hpp>
#include <Prism/Foundation/Fault/Code.hpp>
#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>

namespace
{
    namespace Account = Prism::Account;
    constexpr std::int64_t DayMilliseconds{86'400'000};

    TEST(AccountUsageSchedule, InitializesWithoutPreviousSchedule)
    {
        const Account::UsageCycleRequest Request{"schedule-account", {Account::CycleKind::Week, 0},
            6 * DayMilliseconds};
        const auto Result = Account::AdvanceUsageSchedule(std::nullopt, Request);
        ASSERT_TRUE(Result);
        EXPECT_EQ(Result->Current.Start, 4 * DayMilliseconds);
        ASSERT_TRUE(Result->Current.End);
        EXPECT_EQ(*Result->Current.End, 11 * DayMilliseconds);
        EXPECT_EQ(Result->Active, Request.Desired);
        EXPECT_EQ(Result->Pending, Request.Desired);
    }

    TEST(AccountUsageSchedule, KeepsActiveCycleBeforeBoundary)
    {
        const Account::UsageSchedule Previous{{3 * DayMilliseconds, 5 * DayMilliseconds},
            {Account::CycleKind::Day, 0}, {Account::CycleKind::Day, 0}};
        const Account::UsageCycleRequest Request{"schedule-account", {Account::CycleKind::Week, 0},
            5 * DayMilliseconds - 1};
        const auto Result = Account::AdvanceUsageSchedule(Previous, Request);
        ASSERT_TRUE(Result);
        EXPECT_EQ(Result->Current, Previous.Current);
        EXPECT_EQ(Result->Active, Previous.Active);
        EXPECT_EQ(Result->Pending, Request.Desired);
    }

    TEST(AccountUsageSchedule, ActivatesAtBoundaryAndClampsCurrentStart)
    {
        const Account::UsageSchedule Previous{{0, 5 * DayMilliseconds},
            {Account::CycleKind::Day, 0}, {Account::CycleKind::Day, 0}};
        const Account::UsageCycleRequest Request{"schedule-account", {Account::CycleKind::Week, 0},
            5 * DayMilliseconds};
        const auto Result = Account::AdvanceUsageSchedule(Previous, Request);
        ASSERT_TRUE(Result);
        EXPECT_EQ(Result->Current.Start, 5 * DayMilliseconds);
        ASSERT_TRUE(Result->Current.End);
        EXPECT_EQ(*Result->Current.End, 11 * DayMilliseconds);
        EXPECT_EQ(Result->Active, Request.Desired);
        EXPECT_EQ(Result->Pending, Request.Desired);
    }

    TEST(AccountUsageSchedule, ClampsCurrentStartWhenActivationIsDelayed)
    {
        const Account::UsageSchedule Previous{{0, 5 * DayMilliseconds},
            {Account::CycleKind::Day, 0}, {Account::CycleKind::Day, 0}};
        const Account::UsageCycleRequest Request{"schedule-account", {Account::CycleKind::Week, 0},
            7 * DayMilliseconds};
        const auto Result = Account::AdvanceUsageSchedule(Previous, Request);
        ASSERT_TRUE(Result);
        EXPECT_EQ(Result->Current.Start, 5 * DayMilliseconds);
        ASSERT_TRUE(Result->Current.End);
        EXPECT_EQ(*Result->Current.End, 11 * DayMilliseconds);
        EXPECT_EQ(Result->Active, Request.Desired);
        EXPECT_EQ(Result->Pending, Request.Desired);
    }

    TEST(AccountUsageSchedule, SetsNextBoundaryWhenLeavingNoneCycle)
    {
        const Account::UsageSchedule Previous{{0, std::nullopt},
            {Account::CycleKind::None, 0}, {Account::CycleKind::None, 0}};
        const Account::UsageCycleRequest Request{"schedule-account", {Account::CycleKind::Day, 0},
            6 * DayMilliseconds + 123};
        const auto Result = Account::AdvanceUsageSchedule(Previous, Request);
        ASSERT_TRUE(Result);
        EXPECT_EQ(Result->Current.Start, 0);
        ASSERT_TRUE(Result->Current.End);
        EXPECT_EQ(*Result->Current.End, 7 * DayMilliseconds);
        EXPECT_EQ(Result->Active, Previous.Active);
        EXPECT_EQ(Result->Pending, Request.Desired);
    }

    TEST(AccountUsageSchedule, RejectsInvalidDesiredCycle)
    {
        const Account::UsageCycleRequest Request{"schedule-account", {Account::CycleKind::Day, 841},
            6 * DayMilliseconds};
        const auto Result = Account::AdvanceUsageSchedule(std::nullopt, Request);
        ASSERT_FALSE(Result);
        EXPECT_EQ(Result.error().Code, Prism::Fault::Code::InvalidArgument);
    }
}

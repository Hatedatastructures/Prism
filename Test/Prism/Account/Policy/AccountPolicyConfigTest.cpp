/** @file AccountPolicyConfigTest.cpp @brief 继承、不限、零额度及自然周期领域测试。 */
#include <Prism/Account/PolicyConfiguration.hpp>
#include <Prism/Account/UsageCalendar.hpp>
#include <gtest/gtest.h>
#include <chrono>

namespace
{
    using namespace Prism::Account;

    TEST(AccountPolicyConfiguration, InheritsGroupAndRetainsFiniteZero)
    {
        PolicyConfiguration Group;
        Group.TrafficBytes = {LimitMode::Finite, 4096};
        Group.Connections = {LimitMode::Finite, 3};
        PolicyConfiguration Account;
        Account.TrafficBytes = {LimitMode::Finite, 0};
        Account.Connections.Mode = LimitMode::Unlimited;
        const auto Policy = CompilePolicy(Account, Group);
        ASSERT_TRUE(Policy);
        ASSERT_TRUE(Policy->TrafficBytes);
        EXPECT_EQ(*Policy->TrafficBytes, 0U);
        EXPECT_FALSE(Policy->Connections);
        EXPECT_EQ(Policy->Cycle.OffsetMinutes, 480);
    }

    TEST(AccountPolicyConfiguration, RejectsInvalidLimitsWithoutDiscardingGroupError)
    {
        PolicyConfiguration Group;
        Group.Connections = {LimitMode::Finite, UINT64_MAX};
        PolicyConfiguration Account;
        Account.Connections.Mode = LimitMode::Unlimited;
        EXPECT_FALSE(CompilePolicy(Account, Group));
        Group.Connections = {};
        Account.Streams = {LimitMode::Inherit, 1};
        EXPECT_FALSE(CompilePolicy(Account, Group));
    }

    TEST(AccountPolicyConfiguration, FebruaryLeapMonthUsesLocalOffset)
    {
        using namespace std::chrono;
        const auto Now = duration_cast<milliseconds>(
            (sys_days{year{2024}/February/29} + hours{20}).time_since_epoch()).count();
        const auto Cycle = ResolveUsageCycle({}, Now);
        ASSERT_TRUE(Cycle);
        EXPECT_EQ(Cycle->Start, duration_cast<milliseconds>(
            (sys_days{year{2024}/March/1} - hours{8}).time_since_epoch()).count());
        ASSERT_TRUE(Cycle->End);
        EXPECT_EQ(*Cycle->End, duration_cast<milliseconds>(
            (sys_days{year{2024}/April/1} - hours{8}).time_since_epoch()).count());
    }

    TEST(AccountPolicyConfiguration, WeekStartsMondayAndNoneNeverResets)
    {
        using namespace std::chrono;
        const auto Now = duration_cast<milliseconds>(sys_days{year{2026}/October/18}.time_since_epoch()).count();
        const auto Week = ResolveUsageCycle({CycleKind::Week, 0}, Now);
        ASSERT_TRUE(Week);
        EXPECT_EQ(Week->Start, duration_cast<milliseconds>(sys_days{year{2026}/October/12}.time_since_epoch()).count());
        const auto Forever = ResolveUsageCycle({CycleKind::None, 0}, Now);
        ASSERT_TRUE(Forever);
        EXPECT_EQ(Forever->Start, 0);
        EXPECT_FALSE(Forever->End);
    }
}

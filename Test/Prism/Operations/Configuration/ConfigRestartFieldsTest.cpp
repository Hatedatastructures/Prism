/** @file ConfigRestartFieldsTest.cpp @brief 真实差异列表既判重启又保留每个变更字段。 */
#include <Prism/Application/Reload/RestartPolicy.hpp>
#include <gtest/gtest.h>
#include <algorithm>
#include <string>
#include <vector>

TEST(ConfigurationRestartFields, ReportsEveryChangedColdFieldWithoutUnchangedFields)
{
    Prism::Application::Configuration::PrismConfiguration Current;
    auto Candidate=Current;
    ++Candidate.Runtime.WorkerCount;
    Candidate.Operations.Endpoint="127.0.0.1:19090";
    const auto Fields=Prism::Application::Reload::RestartPolicy::RestartRequiredFields(
        {Current,Candidate});
    EXPECT_EQ(Fields,(std::vector<std::string>{"Runtime.WorkerCount","Operations.Endpoint"}));
}

TEST(ConfigurationRestartFields, StatisticsEnabledTransitionsRequireProcessRestart)
{
    Prism::Application::Configuration::PrismConfiguration Current;
    Current.Statistics.Enabled=false;
    auto Candidate=Current;
    Candidate.Statistics.Enabled=true;
    Candidate.Statistics.Interval=17;
    EXPECT_EQ(Prism::Application::Reload::RestartPolicy::RestartRequiredFields(
        {Current,Candidate}), (std::vector<std::string>{"Statistics.Enabled"}));

    Current.Statistics.Enabled=true;
    Candidate=Current;
    Candidate.Statistics.Enabled=false;
    EXPECT_EQ(Prism::Application::Reload::RestartPolicy::RestartRequiredFields(
        {Current,Candidate}), (std::vector<std::string>{"Statistics.Enabled"}));
}

TEST(ConfigurationRestartFields, LoggingEpochAndTimerIntervalRemainHotChanges)
{
    Prism::Application::Configuration::PrismConfiguration Current;
    auto Candidate=Current;
    Candidate.Logging.RenderMode="StructuredJson";
    Candidate.Logging.Level="Debug";
    Candidate.Statistics.Interval=29;
    const auto Fields=Prism::Application::Reload::RestartPolicy::RestartRequiredFields(
        {Current,Candidate});
    EXPECT_TRUE(Fields.empty());
}

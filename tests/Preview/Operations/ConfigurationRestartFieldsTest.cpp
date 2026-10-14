/** @file ConfigurationRestartFieldsTest.cpp @brief 真实差异列表既判重启又保留每个变更字段。 */
#include <Preview/Application/Reload/ConfigurationDifference.hpp>
#include <gtest/gtest.h>
#include <algorithm>
#include <string>
#include <vector>

TEST(ConfigurationRestartFields, ReportsEveryChangedColdFieldWithoutUnchangedFields)
{
    Preview::Application::Configuration::PreviewConfiguration Current;
    auto Candidate=Current;
    ++Candidate.Runtime.WorkerCount;
    Candidate.Operations.Endpoint="127.0.0.1:19090";
    const auto Fields=Preview::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current,Candidate});
    EXPECT_EQ(Fields,(std::vector<std::string>{"Runtime.WorkerCount","Operations.Endpoint"}));
}

TEST(ConfigurationRestartFields, StatisticsEnabledTransitionsRequireProcessRestart)
{
    Preview::Application::Configuration::PreviewConfiguration Current;
    Current.Statistics.Enabled=false;
    auto Candidate=Current;
    Candidate.Statistics.Enabled=true;
    Candidate.Statistics.Interval=17;
    EXPECT_EQ(Preview::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current,Candidate}), (std::vector<std::string>{"Statistics.Enabled"}));

    Current.Statistics.Enabled=true;
    Candidate=Current;
    Candidate.Statistics.Enabled=false;
    EXPECT_EQ(Preview::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current,Candidate}), (std::vector<std::string>{"Statistics.Enabled"}));
}

TEST(ConfigurationRestartFields, LoggingEpochAndTimerIntervalRemainHotChanges)
{
    Preview::Application::Configuration::PreviewConfiguration Current;
    auto Candidate=Current;
    Candidate.Logging.RenderMode="StructuredJson";
    Candidate.Logging.Level="Debug";
    Candidate.Statistics.Interval=29;
    const auto Fields=Preview::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current,Candidate});
    EXPECT_TRUE(Fields.empty());
}

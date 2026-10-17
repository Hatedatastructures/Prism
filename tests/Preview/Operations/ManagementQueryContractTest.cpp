/** @file ManagementQueryContractTest.cpp @brief 管理面真实游标、过滤与安全配置往返契约。 */
#include <gtest/gtest.h>
#include <Preview/Application/OperationsConfiguration.hpp>
#include <Preview/Operations/Routes/RouteDispatch.hpp>
#include <Preview/Operations/Routes/ManagementJson.hpp>
#include <atomic>
#include <string>
#include <variant>

TEST(ManagementQueryContract, CollectionCursorIsNotDiscarded)
{
    Preview::Operations::HttpRequest Request;
    Request.Method = "GET";
    Request.Target = "/Operations/Groups?cursor=17&limit=2";
    std::atomic<std::uint64_t> Next{1};
    const auto Route = Preview::Operations::RouteDispatch::BuildRoute(Request, Next);
    ASSERT_TRUE(Route.has_value());
    const auto *Query = std::get_if<Preview::Operations::Query>(&*Route);
    ASSERT_NE(Query, nullptr);
    const auto *Management = std::get_if<Preview::Operations::ManagementQuery>(&Query->Value);
    ASSERT_NE(Management, nullptr);
    const auto *Groups = std::get_if<Preview::Operations::GroupsRead>(&Management->Value);
    ASSERT_NE(Groups, nullptr);
    EXPECT_EQ(Groups->Page.Cursor, 17U);
    EXPECT_EQ(Groups->Page.Limit, 2U);
}

TEST(ManagementQueryContract, TraceRetainsIndependentWorkerCursors)
{
    Preview::Operations::HttpRequest Request;
    Request.Method = "GET";
    Request.Target = "/Operations/Processes/1/Sessions/9/Trace?cursor=1:7,2:11&limit=3";
    std::atomic<std::uint64_t> Next{1};
    const auto Route = Preview::Operations::RouteDispatch::BuildRoute(Request, Next);
    ASSERT_TRUE(Route.has_value());
    const auto *Query = std::get_if<Preview::Operations::Query>(&*Route);
    ASSERT_NE(Query, nullptr);
    const auto *Management = std::get_if<Preview::Operations::ManagementQuery>(&Query->Value);
    ASSERT_NE(Management, nullptr);
    const auto *Trace = std::get_if<Preview::Operations::SessionTraceRead>(&Management->Value);
    ASSERT_NE(Trace, nullptr);
    ASSERT_EQ(Trace->Cursors.size(), 2U);
    EXPECT_EQ(Trace->Cursors[0].Sequence, 7U);
    EXPECT_EQ(Trace->Cursors[1].Sequence, 11U);
}

TEST(ManagementQueryContract, EventsAcceptProcessAndSeverityTogether)
{
    Preview::Operations::HttpRequest Request;
    Request.Method = "GET";
    Request.Target = "/Operations/Events?process_id=5&severity=warning";
    std::atomic<std::uint64_t> Next{1};
    const auto Route = Preview::Operations::RouteDispatch::BuildRoute(Request, Next);
    ASSERT_TRUE(Route.has_value());
    const auto *Query = std::get_if<Preview::Operations::Query>(&*Route);
    ASSERT_NE(Query, nullptr);
    const auto *Management = std::get_if<Preview::Operations::ManagementQuery>(&Query->Value);
    ASSERT_NE(Management, nullptr);
    const auto *Events = std::get_if<Preview::Operations::EventsRead>(&Management->Value);
    ASSERT_NE(Events, nullptr);
    ASSERT_TRUE(Events->Process.has_value());
    EXPECT_EQ(*Events->Process, Preview::ProcessId{5});
    EXPECT_EQ(Events->Severity, Preview::Statistics::EventSeverity::Warning);
}

TEST(ManagementQueryContract, SafeConfigurationPreservesGroupMembership)
{
    Preview::Application::Configuration::PreviewConfiguration Source;
    Source.AccountGroups.push_back({"team-a", "研发"});
    Preview::Application::Configuration::AccountConfiguration Account;
    Account.Id = "alice";
    Account.GroupId = "team-a";
    Account.Credential = "must-never-appear";
    Source.Accounts.push_back(std::move(Account));
    const auto Serialized = Preview::Application::OperationsConfiguration::SerializePublicConfiguration(Source);
    ASSERT_TRUE(Serialized.has_value());
    EXPECT_NE(Serialized->find("\"AccountGroups\""), std::string::npos);
    EXPECT_NE(Serialized->find("\"GroupId\":\"team-a\""), std::string::npos);
    EXPECT_EQ(Serialized->find("must-never-appear"), std::string::npos);
}

TEST(ManagementQueryContract, OverviewSerializesRealSampleInterval)
{
    Preview::Operations::OverviewSnapshot Snapshot;
    Snapshot.SampleIntervalMilliseconds = 1000U;
    Preview::Operations::HttpDetail::JsonWriter Writer(65536U);
    EXPECT_TRUE(Preview::Operations::HttpDetail::AppendOverview(Writer, Snapshot));
    EXPECT_NE(std::move(Writer).Take().find("\"sample_interval_ms\":\"1000\""), std::string::npos);
}

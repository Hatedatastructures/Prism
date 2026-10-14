/**
 * @file OperationsMetadataTest.cpp
 * @brief 管理面安全配置与真实作用域元数据契约。
 */

#include <gtest/gtest.h>

#include <Preview/Application/OperationsConfiguration.hpp>
#include <Preview/Application/OperationsEventProducer.hpp>
#include <Preview/Application/OperationsMetrics.hpp>
#include <Preview/Application/OperationsReload.hpp>
#include <Preview/Application/Reload/ConfigurationDifference.hpp>
#include <Preview/Operations/Metrics.hpp>
#include <Preview/Operations/Routes/RouteDispatch.hpp>
#include <Preview/Runtime/Session/RecognitionLatencyScope.hpp>
#include <Preview/Statistics/Statistics.hpp>

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <variant>

namespace
{
    class RecognitionLatencyCapture final : public Preview::Foundation::RecognitionLatencySink
    {
    public:
        auto ReportRecognitionLatency(
            Preview::Foundation::RecognitionLatencySample Value) noexcept -> void override
        {
            Sample = Value;
            ++Count;
        }

        std::optional<Preview::Foundation::RecognitionLatencySample> Sample{};
        std::size_t Count{0};
    };
}

TEST(OperationsMetadataRoutes, ConfigurationAndChildListsRequireTypedScope)
{
    Preview::Operations::HttpRequest Request;
    Request.Method = "GET";
    std::atomic<std::uint64_t> NextCorrelation{1};

    Request.Target = "/Operations/Configuration";
    const auto ConfigurationRoute =
        Preview::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_TRUE(ConfigurationRoute.has_value());
    const auto *Configuration =
        std::get_if<Preview::Operations::Query>(&*ConfigurationRoute);
    ASSERT_NE(Configuration, nullptr);
    EXPECT_TRUE(std::holds_alternative<Preview::Operations::ConfigurationQuery>(
        Configuration->Value));

    Request.Target =
        "/Operations/Processes/11/Sessions/33/Streams?generation=5&worker=7&cursor=8&limit=2";
    const auto StreamRoute =
        Preview::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_TRUE(StreamRoute.has_value());
    const auto *StreamQueryRoute = std::get_if<Preview::Operations::Query>(&*StreamRoute);
    ASSERT_NE(StreamQueryRoute, nullptr);
    const auto *StreamList =
        std::get_if<Preview::Operations::StreamListQuery>(&StreamQueryRoute->Value);
    ASSERT_NE(StreamList, nullptr);
    EXPECT_EQ(StreamList->Process, Preview::ProcessId{11});
    EXPECT_EQ(StreamList->Generation, Preview::GenerationId{5});
    EXPECT_EQ(StreamList->Worker, Preview::WorkerId{7});
    EXPECT_EQ(StreamList->Session, Preview::SessionId{33});
    EXPECT_EQ(StreamList->Page.Cursor, 8U);
    EXPECT_EQ(StreamList->Page.Limit, 2U);

    Request.Target =
        "/Operations/Processes/11/Workers/7/Sessions/33/Tasks?generation=5&cursor=9&limit=3";
    const auto TaskRoute =
        Preview::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_TRUE(TaskRoute.has_value());
    const auto *TaskQueryRoute = std::get_if<Preview::Operations::Query>(&*TaskRoute);
    ASSERT_NE(TaskQueryRoute, nullptr);
    const auto *TaskList =
        std::get_if<Preview::Operations::TaskListQuery>(&TaskQueryRoute->Value);
    ASSERT_NE(TaskList, nullptr);
    EXPECT_EQ(TaskList->Process, Preview::ProcessId{11});
    EXPECT_EQ(TaskList->Generation, Preview::GenerationId{5});
    EXPECT_EQ(TaskList->Worker, Preview::WorkerId{7});
    EXPECT_EQ(TaskList->Session, Preview::SessionId{33});
    EXPECT_EQ(TaskList->Page.Cursor, 9U);
    EXPECT_EQ(TaskList->Page.Limit, 3U);

    Request.Target = "/Operations/Metrics?correlation=19";
    const auto MetricsRoute =
        Preview::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_TRUE(MetricsRoute.has_value());
    const auto *MetricsQueryRoute = std::get_if<Preview::Operations::Query>(&*MetricsRoute);
    ASSERT_NE(MetricsQueryRoute, nullptr);
    const auto *Metrics = std::get_if<Preview::Operations::MetricsQuery>(
        &MetricsQueryRoute->Value);
    ASSERT_NE(Metrics, nullptr);
    EXPECT_EQ(Metrics->Correlation, Preview::RequestId{19});

    Request.Target = "/Operations/Metrics?format=raw";
    const auto InvalidMetricsRoute =
        Preview::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_FALSE(InvalidMetricsRoute.has_value());
    EXPECT_EQ(InvalidMetricsRoute.error().Status, 400);

    Request.Target = "/Operations/Tasks";
    const auto UnscopedRoute =
        Preview::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_FALSE(UnscopedRoute.has_value());
    EXPECT_EQ(UnscopedRoute.error().Message, "parent_identity_required");

    Request.Target = "/Operations/Events?severity=warning";
    const auto UnsupportedSeverityRoute =
        Preview::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_FALSE(UnsupportedSeverityRoute.has_value());
    EXPECT_EQ(UnsupportedSeverityRoute.error().Status, 400);
}

TEST(OperationsMetadataJson, OmitsSecretValuesAndReportsRealOwnerFacts)
{
    Preview::Application::Configuration::PreviewConfiguration Configuration;
    Configuration.Secrets.emplace("global", "global-secret-value");
    Preview::Application::Configuration::AccountConfiguration Account;
    Account.Id = "alice";
    Account.SecretRef = "secret://alice";
    Account.Credential = "account-secret-value";
    Account.Credentials.emplace("Vless", "protocol-secret-value");
    Configuration.Accounts.push_back(std::move(Account));
    Preview::Contract::ProtocolConfiguration Protocol;
    Protocol.Id = "quic";
    Protocol.Quic = Preview::Contract::ProtocolConfiguration::QuicOptions{};
    Protocol.Quic->CredentialSecretRef = "secret://quic";
    Protocol.Quic->Uuid = "quic-secret-value";
    Configuration.Protocols.push_back(std::move(Protocol));

    const auto PublicJson =
        Preview::Application::OperationsConfiguration::SerializePublicConfiguration(Configuration);
    ASSERT_TRUE(PublicJson.has_value());
    EXPECT_NE(PublicJson->find("secret://alice"), std::string::npos);
    EXPECT_NE(PublicJson->find("secret://quic"), std::string::npos);
    EXPECT_EQ(PublicJson->find("global-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("account-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("protocol-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("quic-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("Credential\""), std::string::npos);

    Preview::Operations::ConfigurationSnapshot ConfigurationValue;
    ConfigurationValue.Generation = Preview::GenerationId{21};
    ConfigurationValue.Reloadable = true;
    ConfigurationValue.Json = *PublicJson;
    const auto ConfigurationJson = Preview::Operations::HttpDetail::SerializeQuery(
        Preview::Operations::QueryResult::Configuration(
            Preview::RequestId{1}, std::move(ConfigurationValue)), true);
    ASSERT_TRUE(ConfigurationJson.has_value());
    EXPECT_NE(ConfigurationJson->find("\"generation\":\"21\""), std::string::npos);
    EXPECT_NE(ConfigurationJson->find("\"reloadable\":true"), std::string::npos);

    Preview::Operations::MetricsSnapshot EmptyMetrics;
    EmptyMetrics.Process = Preview::ProcessId{12};
    EmptyMetrics.Generation = Preview::GenerationId{21};
    EmptyMetrics.AcceptedObservations = 4U;
    EmptyMetrics.ConsumedObservations = 3U;
    EmptyMetrics.DroppedObservations = 1U;
    EmptyMetrics.AggregationFailures = 2U;
    EmptyMetrics.RecognitionLatencyQueueDrops = 1U;
    EmptyMetrics.RecognitionLatencyAggregationFailures = 1U;
    EmptyMetrics.RecognitionLatency.Generation = EmptyMetrics.Generation;
    EmptyMetrics.SampleIntervalMilliseconds = 1000U;
    const auto EmptyMetricsJson = Preview::Operations::HttpDetail::SerializeQuery(
        Preview::Operations::QueryResult::Metrics(
            Preview::RequestId{6}, std::move(EmptyMetrics)), true);
    ASSERT_TRUE(EmptyMetricsJson.has_value());
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("accepted":"4")METRIC"), std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("consumed":"3")METRIC"), std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("dropped":"1")METRIC"), std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("history_ready":false)METRIC"), std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("history":[])METRIC"), std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("recognition_latency_queue_dropped":"1")METRIC"),
        std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("recognition_latency_aggregation_failures":"1")METRIC"),
        std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("sample_boundary":"recognition_admission")METRIC"),
        std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("unit":"microseconds")METRIC"), std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("ready":false)METRIC"), std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("recent_us":[])METRIC"), std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("p50_bucket_lower_bound_us":null)METRIC"),
        std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("p95_bucket_lower_bound_us":null)METRIC"),
        std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("p99_bucket_lower_bound_us":null)METRIC"),
        std::string::npos);
    EXPECT_NE(EmptyMetricsJson->find(R"METRIC("max_observed_us":null)METRIC"),
        std::string::npos);

    Preview::Operations::MetricsSnapshot SampledMetrics;
    SampledMetrics.Generation = Preview::GenerationId{21};
    SampledMetrics.History.push_back({
        1234U, Preview::Statistics::TrafficValue{10U, 20U, 2U, 1U}});
    SampledMetrics.RecognitionLatency.Generation = SampledMetrics.Generation;
    SampledMetrics.RecognitionLatency.SampleCount = 3U;
    SampledMetrics.RecognitionLatency.TracerWrittenCount = 3U;
    SampledMetrics.RecognitionLatency.HistogramRangeExceeded = 1U;
    SampledMetrics.RecognitionLatency.RecentMicroseconds = {300'000'001U, 49U, 52U};
    SampledMetrics.RecognitionLatency.RecentCount = 3U;
    SampledMetrics.RecognitionLatency.P50BucketLowerBoundMicroseconds = 32U;
    SampledMetrics.RecognitionLatency.P95BucketLowerBoundMicroseconds = 134'217'728U;
    SampledMetrics.RecognitionLatency.P99BucketLowerBoundMicroseconds = 134'217'728U;
    SampledMetrics.RecognitionLatency.MaximumObservedMicroseconds = 300'000'001U;
    const auto SampledMetricsJson = Preview::Operations::HttpDetail::SerializeQuery(
        Preview::Operations::QueryResult::Metrics(
            Preview::RequestId{7}, std::move(SampledMetrics)), true);
    ASSERT_TRUE(SampledMetricsJson.has_value());
    EXPECT_NE(SampledMetricsJson->find(R"METRIC("history_ready":true)METRIC"), std::string::npos);
    EXPECT_NE(SampledMetricsJson->find(R"METRIC("timestamp":"1234")METRIC"), std::string::npos);
    EXPECT_NE(SampledMetricsJson->find(R"METRIC("generation":"21")METRIC"), std::string::npos);
    EXPECT_NE(SampledMetricsJson->find(R"METRIC("ready":true)METRIC"), std::string::npos);
    EXPECT_NE(SampledMetricsJson->find(R"METRIC("sample_count":"3")METRIC"), std::string::npos);
    EXPECT_NE(SampledMetricsJson->find(R"METRIC("histogram_range_exceeded":"1")METRIC"),
        std::string::npos);
    EXPECT_NE(SampledMetricsJson->find(
        R"METRIC("recent_us":["300000001","49","52"])METRIC"),
        std::string::npos);
    EXPECT_NE(SampledMetricsJson->find(R"METRIC("p50_bucket_lower_bound_us":"32")METRIC"),
        std::string::npos);
    EXPECT_NE(SampledMetricsJson->find(
        R"METRIC("p99_bucket_lower_bound_us":"134217728")METRIC"),
        std::string::npos);
    EXPECT_NE(SampledMetricsJson->find(R"METRIC("max_observed_us":"300000001")METRIC"),
        std::string::npos);

    Preview::Operations::Page<Preview::Operations::WorkerSnapshot> Workers;
    Workers.Items.push_back(Preview::Operations::WorkerSnapshot{});
    const auto WorkerJson = Preview::Operations::HttpDetail::SerializeQuery(
        Preview::Operations::QueryResult::Workers(Preview::RequestId{8}, std::move(Workers)), true);
    ASSERT_TRUE(WorkerJson.has_value());
    EXPECT_NE(WorkerJson->find(R"METRIC("traffic":null)METRIC"), std::string::npos);

    Preview::Operations::Page<Preview::Operations::AccountSnapshot> Accounts;
    Preview::Operations::AccountSnapshot AccountValue;
    AccountValue.Id = Preview::AccountId{7};
    AccountValue.Generation = Preview::GenerationId{21};
    AccountValue.Revoked = true;
    Accounts.Items.push_back(AccountValue);
    const auto AccountJson = Preview::Operations::HttpDetail::SerializeQuery(
        Preview::Operations::QueryResult::Accounts(
            Preview::RequestId{2}, std::move(Accounts)), true);
    ASSERT_TRUE(AccountJson.has_value());
    EXPECT_NE(AccountJson->find("\"revoked\":true"), std::string::npos);
    EXPECT_NE(AccountJson->find(R"METRIC("traffic":null)METRIC"), std::string::npos);
    EXPECT_EQ(AccountJson->find("\"enabled\":"), std::string::npos);

    Preview::Operations::Page<Preview::Operations::SessionSnapshot> Sessions;
    Preview::Operations::SessionSnapshot SessionValue;
    SessionValue.ActiveTasks = 3U;
    Sessions.Items.push_back(SessionValue);
    Sessions.Items.push_back(Preview::Operations::SessionSnapshot{});
    const auto SessionJson = Preview::Operations::HttpDetail::SerializeQuery(
        Preview::Operations::QueryResult::Sessions(
            Preview::RequestId{3}, std::move(Sessions)), true);
    ASSERT_TRUE(SessionJson.has_value());
    EXPECT_NE(SessionJson->find("\"active_tasks\":3"), std::string::npos);
    EXPECT_NE(SessionJson->find("\"active_tasks\":null"), std::string::npos);
    EXPECT_NE(SessionJson->find(R"METRIC("traffic":null)METRIC"), std::string::npos);

    Preview::Operations::Page<Preview::Operations::TaskSnapshot> Tasks;
    Preview::Operations::TaskSnapshot TaskValue;
    TaskValue.Id = Preview::TaskId{9};
    TaskValue.Cancellable = true;
    Tasks.Items.push_back(TaskValue);
    const auto TaskJson = Preview::Operations::HttpDetail::SerializeQuery(
        Preview::Operations::QueryResult::Tasks(
            Preview::RequestId{4}, std::move(Tasks)), true);
    ASSERT_TRUE(TaskJson.has_value());
    EXPECT_NE(TaskJson->find("\"cancellable\":true"), std::string::npos);

    Preview::Statistics::EventPage Events;
    Preview::Statistics::DetailedEvent Event;
    Event.Kind = Preview::Statistics::EventKind::GenerationReloaded;
    Event.Severity = Preview::Statistics::EventSeverity::Info;
    Events.Items.push_back(Event);
    Preview::Statistics::DetailedEvent FailureEvent;
    FailureEvent.Kind = Preview::Statistics::EventKind::Failed;
    FailureEvent.Severity = Preview::Statistics::EventSeverity::Error;
    FailureEvent.Terminal = true;
    Events.Items.push_back(FailureEvent);
    const auto EventJson = Preview::Operations::HttpDetail::SerializeQuery(
        Preview::Operations::QueryResult::Events(
            Preview::RequestId{5}, std::move(Events)), true);
    ASSERT_TRUE(EventJson.has_value());
    EXPECT_NE(EventJson->find(R"METRIC("severity":"info")METRIC"), std::string::npos);
    EXPECT_NE(EventJson->find(R"METRIC("severity":"error")METRIC"), std::string::npos);
    EXPECT_NE(EventJson->find(R"METRIC("severity_filter_supported":false)METRIC"), std::string::npos);
}

TEST(OperationsMetadataBootstrap, AdvertisesImplementedReadAndCommandRoutes)
{
    Preview::Operations::BootstrapIdentity::Options Options;
    Options.Process = Preview::ProcessId{12};
    const Preview::Operations::BootstrapIdentity Bootstrap{std::move(Options)};

    const auto Json = Preview::Operations::HttpDetail::SerializeBootstrap(Bootstrap);
    ASSERT_TRUE(Json.has_value());
    EXPECT_NE(Json->find("\"api_version\":\"1\""), std::string::npos);
    EXPECT_NE(Json->find("\"configuration.read\""), std::string::npos);
    EXPECT_NE(Json->find("\"configuration.reload.validate\""), std::string::npos);
    EXPECT_NE(Json->find("\"configuration.reload.apply\""), std::string::npos);
    EXPECT_NE(Json->find("\"streams.reset\""), std::string::npos);
    EXPECT_NE(Json->find("\"metrics.read\""), std::string::npos);
}

TEST(OperationsMetadataMetrics, ReportsUnavailableWithoutARealCollector)
{
    Preview::Operations::MetricsQuery Request;
    Request.Correlation = Preview::RequestId{18};
    const auto Result = Preview::Application::OperationsMetrics::Query(nullptr, Request);
    EXPECT_EQ(Result.Correlation, Request.Correlation);
    EXPECT_EQ(Result.Status, Preview::Operations::QueryStatus::Unavailable);
}

TEST(OperationsMetadataLatency, ReportsOnceWithoutChangingAdmissionException)
{
    const auto Capture = std::make_shared<RecognitionLatencyCapture>();
    const auto Expected = std::make_error_code(std::errc::permission_denied);
    std::error_code Actual;

    try
    {
        Preview::Runtime::Detail::RecognitionLatencyScope Measure(
            Capture, Preview::Foundation::RecognitionLatencySample{
                .Generation = Preview::GenerationId{4},
                .Worker = Preview::WorkerId{2},
                .Session = Preview::SessionId{8}});
        throw std::system_error(Expected);
    }
    catch (const std::system_error &Error)
    {
        Actual = Error.code();
    }

    EXPECT_EQ(Actual, Expected);
    ASSERT_EQ(Capture->Count, 1U);
    ASSERT_TRUE(Capture->Sample.has_value());
    EXPECT_EQ(Capture->Sample->Generation, Preview::GenerationId{4});
    EXPECT_EQ(Capture->Sample->Worker, Preview::WorkerId{2});
    EXPECT_EQ(Capture->Sample->Session, Preview::SessionId{8});
}

TEST(OperationsMetadataEvents, AcceptedAndTerminalKeepOneTypedTargetIdentity)
{
    using Preview::Operations::CommandTargetScope;
    const std::array<CommandTargetScope, 6> Targets{
        Preview::Operations::ProcessTargetScope{Preview::ProcessId{3}},
        Preview::Operations::WorkerTargetScope{
            Preview::ProcessId{3}, Preview::GenerationId{5}, Preview::WorkerId{7}},
        Preview::Operations::AccountTargetScope{
            Preview::GenerationId{5}, Preview::AccountId{11}},
        Preview::Operations::SessionTargetScope{
            Preview::ProcessId{3}, Preview::GenerationId{5}, Preview::WorkerId{7},
            Preview::SessionId{13}},
        Preview::Operations::StreamTargetScope{
            Preview::ProcessId{3}, Preview::GenerationId{5}, Preview::WorkerId{7},
            Preview::SessionId{13}, Preview::StreamId{17}, Preview::TaskId{19},
            Preview::TaskId{23}},
        Preview::Operations::TaskTargetScope{
            Preview::ProcessId{3}, Preview::GenerationId{5}, Preview::WorkerId{7},
            Preview::SessionId{13}, Preview::StreamId{17}, Preview::TaskId{19},
            Preview::TaskId{23}}};

    for (const auto &Target : Targets)
    {
        const Preview::Application::OperationsEventProducer::Identity Identity{
            Preview::ProcessId{3}, Preview::GenerationId{5},
            Preview::Operations::OperationId{29}, Preview::RequestId{31}, Target};
        const auto Accepted =
            Preview::Application::OperationsEventProducer::MakeAccepted(Identity);
        const auto Terminal =
            Preview::Application::OperationsEventProducer::MakeTerminal(Identity, false);

        EXPECT_EQ(Accepted.Kind, Preview::Statistics::EventKind::OperationAccepted);
        EXPECT_FALSE(Accepted.Terminal);
        EXPECT_EQ(Terminal.Kind, Preview::Statistics::EventKind::OperationFailed);
        EXPECT_TRUE(Terminal.Terminal);
        EXPECT_EQ(Accepted.Operation, Terminal.Operation);
        EXPECT_EQ(Accepted.Correlation, Terminal.Correlation);
        EXPECT_EQ(Accepted.Process, Terminal.Process);
        EXPECT_EQ(Accepted.Generation, Terminal.Generation);
        EXPECT_EQ(Accepted.Worker, Terminal.Worker);
        EXPECT_EQ(Accepted.Account, Terminal.Account);
        EXPECT_EQ(Accepted.Session, Terminal.Session);
        EXPECT_EQ(Accepted.Stream, Terminal.Stream);
        EXPECT_EQ(Accepted.ParentTask, Terminal.ParentTask);
        EXPECT_EQ(Accepted.Task, Terminal.Task);
        EXPECT_EQ(Accepted.ScopeValue, Terminal.ScopeValue);
    }

    auto Runtime = std::make_shared<Preview::Application::Application::RuntimeState>(
        1, Preview::GenerationId{5}, Preview::Network::Dns::Config{});
    const Preview::Application::OperationsEventProducer::ProcessDrainIdentityInput Request{
        Preview::Operations::OperationId{37}, Preview::RequestId{41},
        Preview::Operations::CommandTargetScope{
            Preview::Operations::ProcessTargetScope{Runtime->Process->Id()}}};
    const auto Identity =
        Preview::Application::OperationsEventProducer::MakeProcessDrainIdentity(Runtime, Request);
    Preview::Application::OperationsEventProducer::AppendAccepted(Runtime, Identity);
    Preview::Application::OperationsEventProducer::AppendTerminal(Runtime, Identity, true);
    const auto Page = Runtime->Events->Page(0U, 2U);
    ASSERT_EQ(Page.Items.size(), 2U);
    EXPECT_EQ(Page.Items[0].Kind, Preview::Statistics::EventKind::OperationAccepted);
    EXPECT_EQ(Page.Items[1].Kind, Preview::Statistics::EventKind::OperationCompleted);
    EXPECT_EQ(Page.Items[0].Operation, Page.Items[1].Operation);
    EXPECT_EQ(Page.Items[0].Correlation, Page.Items[1].Correlation);
    EXPECT_EQ(Page.Items[0].Process, Page.Items[1].Process);
    EXPECT_EQ(Page.Items[0].ScopeValue, Preview::Statistics::Scope::Process);
}

TEST(OperationsMetadataReload, StatisticsEnabledIsProcessScopedButIntervalRemainsHot)
{
    Preview::Application::Configuration::PreviewConfiguration Current;
    Current.Statistics.Enabled = false;
    auto Candidate = Current;
    Candidate.Statistics.Enabled = true;
    EXPECT_EQ(Preview::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current, Candidate}), (std::vector<std::string>{"Statistics.Enabled"}));

    Candidate = Current;
    ++Candidate.Statistics.Interval;
    EXPECT_TRUE(Preview::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current, Candidate}).empty());

    Current.Statistics.Enabled = true;
    Candidate = Current;
    Candidate.Statistics.Enabled = false;
    EXPECT_EQ(Preview::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current, Candidate}), (std::vector<std::string>{"Statistics.Enabled"}));
    Candidate = Current;
    Candidate.Logging.Level = "debug";
    EXPECT_TRUE(Preview::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current, Candidate}).empty());
}

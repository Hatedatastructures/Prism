/**
 * @file OperationsMetadataTest.cpp
 * @brief 管理面安全配置与真实作用域元数据契约。
 */

#include <gtest/gtest.h>

#include <Prism/Application/OperationsConfiguration.hpp>
#include <Prism/Application/OperationsEventProducer.hpp>
#include <Prism/Application/OperationsMetrics.hpp>
#include <Prism/Application/OperationsReload.hpp>
#include <Prism/Application/Reload/ConfigurationDifference.hpp>
#include <Prism/Operations/Metrics.hpp>
#include <Prism/Operations/Routes/RouteDispatch.hpp>
#include <Prism/Runtime/Session/RecognitionLatencyScope.hpp>
#include <Prism/Statistics/Statistics.hpp>

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
    class RecognitionLatencyCapture final : public Prism::Foundation::RecognitionLatencySink
    {
    public:
        auto ReportRecognitionLatency(
            Prism::Foundation::RecognitionLatencySample Value) noexcept -> void override
        {
            Sample = Value;
            ++Count;
        }

        std::optional<Prism::Foundation::RecognitionLatencySample> Sample{};
        std::size_t Count{0};
    };
}

TEST(OperationsMetadataRoutes, ConfigurationAndChildListsRequireTypedScope)
{
    Prism::Operations::HttpRequest Request;
    Request.Method = "GET";
    std::atomic<std::uint64_t> NextCorrelation{1};

    Request.Target = "/Operations/Configuration";
    const auto ConfigurationRoute =
        Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_TRUE(ConfigurationRoute.has_value());
    const auto *Configuration =
        std::get_if<Prism::Operations::Query>(&*ConfigurationRoute);
    ASSERT_NE(Configuration, nullptr);
    EXPECT_TRUE(std::holds_alternative<Prism::Operations::ConfigurationQuery>(
        Configuration->Value));

    Request.Target =
        "/Operations/Processes/11/Sessions/33/Streams?generation=5&worker=7&cursor=8&limit=2";
    const auto StreamRoute =
        Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_TRUE(StreamRoute.has_value());
    const auto *StreamQueryRoute = std::get_if<Prism::Operations::Query>(&*StreamRoute);
    ASSERT_NE(StreamQueryRoute, nullptr);
    const auto *StreamList =
        std::get_if<Prism::Operations::StreamListQuery>(&StreamQueryRoute->Value);
    ASSERT_NE(StreamList, nullptr);
    EXPECT_EQ(StreamList->Process, Prism::ProcessId{11});
    EXPECT_EQ(StreamList->Generation, Prism::GenerationId{5});
    EXPECT_EQ(StreamList->Worker, Prism::WorkerId{7});
    EXPECT_EQ(StreamList->Session, Prism::SessionId{33});
    EXPECT_EQ(StreamList->Page.Cursor, 8U);
    EXPECT_EQ(StreamList->Page.Limit, 2U);

    Request.Target =
        "/Operations/Processes/11/Workers/7/Sessions/33/Tasks?generation=5&cursor=9&limit=3";
    const auto TaskRoute =
        Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_TRUE(TaskRoute.has_value());
    const auto *TaskQueryRoute = std::get_if<Prism::Operations::Query>(&*TaskRoute);
    ASSERT_NE(TaskQueryRoute, nullptr);
    const auto *TaskList =
        std::get_if<Prism::Operations::TaskListQuery>(&TaskQueryRoute->Value);
    ASSERT_NE(TaskList, nullptr);
    EXPECT_EQ(TaskList->Process, Prism::ProcessId{11});
    EXPECT_EQ(TaskList->Generation, Prism::GenerationId{5});
    EXPECT_EQ(TaskList->Worker, Prism::WorkerId{7});
    EXPECT_EQ(TaskList->Session, Prism::SessionId{33});
    EXPECT_EQ(TaskList->Page.Cursor, 9U);
    EXPECT_EQ(TaskList->Page.Limit, 3U);

    Request.Target = "/Operations/Metrics?correlation=19";
    const auto MetricsRoute =
        Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_TRUE(MetricsRoute.has_value());
    const auto *MetricsQueryRoute = std::get_if<Prism::Operations::Query>(&*MetricsRoute);
    ASSERT_NE(MetricsQueryRoute, nullptr);
    const auto *Metrics = std::get_if<Prism::Operations::MetricsQuery>(
        &MetricsQueryRoute->Value);
    ASSERT_NE(Metrics, nullptr);
    EXPECT_EQ(Metrics->Correlation, Prism::RequestId{19});

    Request.Target = "/Operations/Metrics?format=raw";
    const auto InvalidMetricsRoute =
        Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_FALSE(InvalidMetricsRoute.has_value());
    EXPECT_EQ(InvalidMetricsRoute.error().Status, 400);

    Request.Target = "/Operations/Tasks";
    const auto UnscopedRoute =
        Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_FALSE(UnscopedRoute.has_value());
    EXPECT_EQ(UnscopedRoute.error().Message, "parent_identity_required");

    Request.Target = "/Operations/Events?severity=warning";
    const auto UnsupportedSeverityRoute =
        Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_FALSE(UnsupportedSeverityRoute.has_value());
    EXPECT_EQ(UnsupportedSeverityRoute.error().Status, 400);
}

TEST(OperationsMetadataJson, OmitsSecretValuesAndReportsRealOwnerFacts)
{
    Prism::Application::Configuration::PrismConfiguration Configuration;
    Configuration.Secrets.emplace("global", "global-secret-value");
    Prism::Application::Configuration::AccountConfiguration Account;
    Account.Id = "alice";
    Account.SecretRef = "secret://alice";
    Account.Credential = "account-secret-value";
    Account.Credentials.emplace("Vless", "protocol-secret-value");
    Configuration.Accounts.push_back(std::move(Account));
    Prism::Contract::ProtocolConfiguration Protocol;
    Protocol.Id = "quic";
    Protocol.Quic = Prism::Contract::ProtocolConfiguration::QuicOptions{};
    Protocol.Quic->CredentialSecretRef = "secret://quic";
    Protocol.Quic->Uuid = "quic-secret-value";
    Configuration.Protocols.push_back(std::move(Protocol));

    const auto PublicJson =
        Prism::Application::OperationsConfiguration::SerializePublicConfiguration(Configuration);
    ASSERT_TRUE(PublicJson.has_value());
    EXPECT_NE(PublicJson->find("secret://alice"), std::string::npos);
    EXPECT_NE(PublicJson->find("secret://quic"), std::string::npos);
    EXPECT_EQ(PublicJson->find("global-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("account-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("protocol-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("quic-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("Credential\""), std::string::npos);

    Prism::Operations::ConfigurationSnapshot ConfigurationValue;
    ConfigurationValue.Generation = Prism::GenerationId{21};
    ConfigurationValue.Reloadable = true;
    ConfigurationValue.Json = *PublicJson;
    const auto ConfigurationJson = Prism::Operations::HttpDetail::SerializeQuery(
        Prism::Operations::QueryResult::Configuration(
            Prism::RequestId{1}, std::move(ConfigurationValue)), true);
    ASSERT_TRUE(ConfigurationJson.has_value());
    EXPECT_NE(ConfigurationJson->find("\"generation\":\"21\""), std::string::npos);
    EXPECT_NE(ConfigurationJson->find("\"reloadable\":true"), std::string::npos);

    Prism::Operations::MetricsSnapshot EmptyMetrics;
    EmptyMetrics.Process = Prism::ProcessId{12};
    EmptyMetrics.Generation = Prism::GenerationId{21};
    EmptyMetrics.AcceptedObservations = 4U;
    EmptyMetrics.ConsumedObservations = 3U;
    EmptyMetrics.DroppedObservations = 1U;
    EmptyMetrics.AggregationFailures = 2U;
    EmptyMetrics.RecognitionLatencyQueueDrops = 1U;
    EmptyMetrics.RecognitionLatencyAggregationFailures = 1U;
    EmptyMetrics.RecognitionLatency.Generation = EmptyMetrics.Generation;
    EmptyMetrics.SampleIntervalMilliseconds = 1000U;
    const auto EmptyMetricsJson = Prism::Operations::HttpDetail::SerializeQuery(
        Prism::Operations::QueryResult::Metrics(
            Prism::RequestId{6}, std::move(EmptyMetrics)), true);
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

    Prism::Operations::MetricsSnapshot SampledMetrics;
    SampledMetrics.Generation = Prism::GenerationId{21};
    SampledMetrics.History.push_back({
        1234U, Prism::Statistics::TrafficValue{10U, 20U, 2U, 1U}});
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
    const auto SampledMetricsJson = Prism::Operations::HttpDetail::SerializeQuery(
        Prism::Operations::QueryResult::Metrics(
            Prism::RequestId{7}, std::move(SampledMetrics)), true);
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

    Prism::Operations::Page<Prism::Operations::WorkerSnapshot> Workers;
    Workers.Items.push_back(Prism::Operations::WorkerSnapshot{});
    const auto WorkerJson = Prism::Operations::HttpDetail::SerializeQuery(
        Prism::Operations::QueryResult::Workers(Prism::RequestId{8}, std::move(Workers)), true);
    ASSERT_TRUE(WorkerJson.has_value());
    EXPECT_NE(WorkerJson->find(R"METRIC("traffic":null)METRIC"), std::string::npos);

    Prism::Operations::Page<Prism::Operations::AccountSnapshot> Accounts;
    Prism::Operations::AccountSnapshot AccountValue;
    AccountValue.Id = Prism::AccountId{7};
    AccountValue.Generation = Prism::GenerationId{21};
    AccountValue.Revoked = true;
    Accounts.Items.push_back(AccountValue);
    const auto AccountJson = Prism::Operations::HttpDetail::SerializeQuery(
        Prism::Operations::QueryResult::Accounts(
            Prism::RequestId{2}, std::move(Accounts)), true);
    ASSERT_TRUE(AccountJson.has_value());
    EXPECT_NE(AccountJson->find("\"revoked\":true"), std::string::npos);
    EXPECT_NE(AccountJson->find(R"METRIC("traffic":null)METRIC"), std::string::npos);
    EXPECT_EQ(AccountJson->find("\"enabled\":"), std::string::npos);

    Prism::Operations::Page<Prism::Operations::SessionSnapshot> Sessions;
    Prism::Operations::SessionSnapshot SessionValue;
    SessionValue.ActiveTasks = 3U;
    Sessions.Items.push_back(SessionValue);
    Sessions.Items.push_back(Prism::Operations::SessionSnapshot{});
    const auto SessionJson = Prism::Operations::HttpDetail::SerializeQuery(
        Prism::Operations::QueryResult::Sessions(
            Prism::RequestId{3}, std::move(Sessions)), true);
    ASSERT_TRUE(SessionJson.has_value());
    EXPECT_NE(SessionJson->find("\"active_tasks\":3"), std::string::npos);
    EXPECT_NE(SessionJson->find("\"active_tasks\":null"), std::string::npos);
    EXPECT_NE(SessionJson->find(R"METRIC("traffic":null)METRIC"), std::string::npos);

    Prism::Operations::Page<Prism::Operations::TaskSnapshot> Tasks;
    Prism::Operations::TaskSnapshot TaskValue;
    TaskValue.Id = Prism::TaskId{9};
    TaskValue.Cancellable = true;
    Tasks.Items.push_back(TaskValue);
    const auto TaskJson = Prism::Operations::HttpDetail::SerializeQuery(
        Prism::Operations::QueryResult::Tasks(
            Prism::RequestId{4}, std::move(Tasks)), true);
    ASSERT_TRUE(TaskJson.has_value());
    EXPECT_NE(TaskJson->find("\"cancellable\":true"), std::string::npos);

    Prism::Statistics::EventPage Events;
    Prism::Statistics::DetailedEvent Event;
    Event.Kind = Prism::Statistics::EventKind::GenerationReloaded;
    Event.Severity = Prism::Statistics::EventSeverity::Info;
    Events.Items.push_back(Event);
    Prism::Statistics::DetailedEvent FailureEvent;
    FailureEvent.Kind = Prism::Statistics::EventKind::Failed;
    FailureEvent.Severity = Prism::Statistics::EventSeverity::Error;
    FailureEvent.Terminal = true;
    Events.Items.push_back(FailureEvent);
    const auto EventJson = Prism::Operations::HttpDetail::SerializeQuery(
        Prism::Operations::QueryResult::Events(
            Prism::RequestId{5}, std::move(Events)), true);
    ASSERT_TRUE(EventJson.has_value());
    EXPECT_NE(EventJson->find(R"METRIC("severity":"info")METRIC"), std::string::npos);
    EXPECT_NE(EventJson->find(R"METRIC("severity":"error")METRIC"), std::string::npos);
    EXPECT_NE(EventJson->find(R"METRIC("severity_filter_supported":false)METRIC"), std::string::npos);
}

TEST(OperationsMetadataBootstrap, AdvertisesImplementedReadAndCommandRoutes)
{
    Prism::Operations::BootstrapIdentity::Options Options;
    Options.Process = Prism::ProcessId{12};
    const Prism::Operations::BootstrapIdentity Bootstrap{std::move(Options)};

    const auto Json = Prism::Operations::HttpDetail::SerializeBootstrap(Bootstrap);
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
    Prism::Operations::MetricsQuery Request;
    Request.Correlation = Prism::RequestId{18};
    const auto Result = Prism::Application::OperationsMetrics::Query(nullptr, Request);
    EXPECT_EQ(Result.Correlation, Request.Correlation);
    EXPECT_EQ(Result.Status, Prism::Operations::QueryStatus::Unavailable);
}

TEST(OperationsMetadataLatency, ReportsOnceWithoutChangingAdmissionException)
{
    const auto Capture = std::make_shared<RecognitionLatencyCapture>();
    const auto Expected = std::make_error_code(std::errc::permission_denied);
    std::error_code Actual;

    try
    {
        Prism::Runtime::Detail::RecognitionLatencyScope Measure(
            Capture, Prism::Foundation::RecognitionLatencySample{
                .Generation = Prism::GenerationId{4},
                .Worker = Prism::WorkerId{2},
                .Session = Prism::SessionId{8}});
        throw std::system_error(Expected);
    }
    catch (const std::system_error &Error)
    {
        Actual = Error.code();
    }

    EXPECT_EQ(Actual, Expected);
    ASSERT_EQ(Capture->Count, 1U);
    ASSERT_TRUE(Capture->Sample.has_value());
    EXPECT_EQ(Capture->Sample->Generation, Prism::GenerationId{4});
    EXPECT_EQ(Capture->Sample->Worker, Prism::WorkerId{2});
    EXPECT_EQ(Capture->Sample->Session, Prism::SessionId{8});
}

TEST(OperationsMetadataEvents, AcceptedAndTerminalKeepOneTypedTargetIdentity)
{
    using Prism::Operations::CommandTargetScope;
    const std::array<CommandTargetScope, 6> Targets{
        Prism::Operations::ProcessTargetScope{Prism::ProcessId{3}},
        Prism::Operations::WorkerTargetScope{
            Prism::ProcessId{3}, Prism::GenerationId{5}, Prism::WorkerId{7}},
        Prism::Operations::AccountTargetScope{
            Prism::GenerationId{5}, Prism::AccountId{11}},
        Prism::Operations::SessionTargetScope{
            Prism::ProcessId{3}, Prism::GenerationId{5}, Prism::WorkerId{7},
            Prism::SessionId{13}},
        Prism::Operations::StreamTargetScope{
            Prism::ProcessId{3}, Prism::GenerationId{5}, Prism::WorkerId{7},
            Prism::SessionId{13}, Prism::StreamId{17}, Prism::TaskId{19},
            Prism::TaskId{23}},
        Prism::Operations::TaskTargetScope{
            Prism::ProcessId{3}, Prism::GenerationId{5}, Prism::WorkerId{7},
            Prism::SessionId{13}, Prism::StreamId{17}, Prism::TaskId{19},
            Prism::TaskId{23}}};

    for (const auto &Target : Targets)
    {
        const Prism::Application::OperationsEventProducer::Identity Identity{
            Prism::ProcessId{3}, Prism::GenerationId{5},
            Prism::Operations::OperationId{29}, Prism::RequestId{31}, Target};
        const auto Accepted =
            Prism::Application::OperationsEventProducer::MakeAccepted(Identity);
        const auto Terminal =
            Prism::Application::OperationsEventProducer::MakeTerminal(Identity, false);

        EXPECT_EQ(Accepted.Kind, Prism::Statistics::EventKind::OperationAccepted);
        EXPECT_FALSE(Accepted.Terminal);
        EXPECT_EQ(Terminal.Kind, Prism::Statistics::EventKind::OperationFailed);
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

    auto Runtime = std::make_shared<Prism::Application::Application::RuntimeState>(
        1, Prism::GenerationId{5}, Prism::Network::Dns::Config{});
    const Prism::Application::OperationsEventProducer::ProcessDrainIdentityInput Request{
        Prism::Operations::OperationId{37}, Prism::RequestId{41},
        Prism::Operations::CommandTargetScope{
            Prism::Operations::ProcessTargetScope{Runtime->Process->Id()}}};
    const auto Identity =
        Prism::Application::OperationsEventProducer::MakeProcessDrainIdentity(Runtime, Request);
    Prism::Application::OperationsEventProducer::AppendAccepted(Runtime, Identity);
    Prism::Application::OperationsEventProducer::AppendTerminal(Runtime, Identity, true);
    const auto Page = Runtime->Events->Page(0U, 2U);
    ASSERT_EQ(Page.Items.size(), 2U);
    EXPECT_EQ(Page.Items[0].Kind, Prism::Statistics::EventKind::OperationAccepted);
    EXPECT_EQ(Page.Items[1].Kind, Prism::Statistics::EventKind::OperationCompleted);
    EXPECT_EQ(Page.Items[0].Operation, Page.Items[1].Operation);
    EXPECT_EQ(Page.Items[0].Correlation, Page.Items[1].Correlation);
    EXPECT_EQ(Page.Items[0].Process, Page.Items[1].Process);
    EXPECT_EQ(Page.Items[0].ScopeValue, Prism::Statistics::Scope::Process);
}

TEST(OperationsMetadataReload, StatisticsEnabledIsProcessScopedButIntervalRemainsHot)
{
    Prism::Application::Configuration::PrismConfiguration Current;
    Current.Statistics.Enabled = false;
    auto Candidate = Current;
    Candidate.Statistics.Enabled = true;
    EXPECT_EQ(Prism::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current, Candidate}), (std::vector<std::string>{"Statistics.Enabled"}));

    Candidate = Current;
    ++Candidate.Statistics.Interval;
    EXPECT_TRUE(Prism::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current, Candidate}).empty());

    Current.Statistics.Enabled = true;
    Candidate = Current;
    Candidate.Statistics.Enabled = false;
    EXPECT_EQ(Prism::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current, Candidate}), (std::vector<std::string>{"Statistics.Enabled"}));
    Candidate = Current;
    Candidate.Logging.Level = "debug";
    EXPECT_TRUE(Prism::Application::Reload::ConfigurationDifference::RestartRequiredFields(
        {Current, Candidate}).empty());
}

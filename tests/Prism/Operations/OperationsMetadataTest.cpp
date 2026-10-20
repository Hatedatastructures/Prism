/**
 * @file OperationsMetadataTest.cpp
 * @brief 管理面安全配置与真实作用域元数据契约。
 */

#include <gtest/gtest.h>

#include <Prism/Application/OperationsConfiguration.hpp>
#include <Prism/Application/OperationsEventProducer.hpp>
#include <Prism/Application/OperationsMetrics.hpp>
#include <Prism/Application/OperationsReload.hpp>
#include <Prism/Application/Reload/RestartPolicy.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Operations/HttpRequest.hpp>
#include <Prism/Operations/ManagementModels.hpp>
#include <Prism/Operations/Metrics.hpp>
#include <Prism/Operations/Routes/BootstrapJson.hpp>
#include <Prism/Operations/Routes/HttpJson.hpp>
#include <Prism/Operations/Routes/RouteDispatch.hpp>
#include <Prism/Runtime/Session.hpp>
#include <Prism/Statistics/Statistics.hpp>

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
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

    /** @brief 构造用于验证敏感配置值脱敏的公开配置 JSON。 */
    [[nodiscard]] auto MakePublicConfigurationJson()
        -> std::expected<std::string, Prism::Fault::Failure>
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
        return Prism::Application::OperationsConfiguration::SerializePublicConfiguration(Configuration);
    }

    /** @brief 将公开配置装入带代次与热重载标记的查询 JSON。 */
    [[nodiscard]] auto MakeConfigurationSnapshotJson(const std::string &Json)
        -> std::optional<std::string>
    {
        Prism::Operations::ConfigurationSnapshot Value;
        Value.Generation = Prism::GenerationId{21};
        Value.Reloadable = true;
        Value.Json = Json;
        return Prism::Operations::HttpDetail::SerializeQuery(
            Prism::Operations::QueryResult::Configuration(
                Prism::RequestId{1}, std::move(Value)), true);
    }

    /** @brief 构造空历史下仍带计数与识别延迟指标的查询 JSON。 */
    [[nodiscard]] auto MakeEmptyMetricsJson() -> std::optional<std::string>
    {
        Prism::Operations::MetricsSnapshot Metrics;
        Metrics.Process = Prism::ProcessId{12};
        Metrics.Generation = Prism::GenerationId{21};
        Metrics.AcceptedObservations = 4U;
        Metrics.ConsumedObservations = 3U;
        Metrics.DroppedObservations = 1U;
        Metrics.AggregationFailures = 2U;
        Metrics.RecognitionLatencyQueueDrops = 1U;
        Metrics.RecognitionLatencyAggregationFailures = 1U;
        Metrics.RecognitionLatency.Generation = Metrics.Generation;
        Metrics.SampleIntervalMilliseconds = 1000U;
        return Prism::Operations::HttpDetail::SerializeQuery(
            Prism::Operations::QueryResult::Metrics(
                Prism::RequestId{6}, std::move(Metrics)), true);
    }

    /** @brief 构造包含历史与识别延迟样本的指标查询 JSON。 */
    [[nodiscard]] auto MakeSampledMetricsJson() -> std::optional<std::string>
    {
        Prism::Operations::MetricsSnapshot Metrics;
        Metrics.Generation = Prism::GenerationId{21};
        Metrics.History.push_back({
            1234U, Prism::Statistics::TrafficValue{10U, 20U, 2U, 1U}});
        Metrics.RecognitionLatency.Generation = Metrics.Generation;
        Metrics.RecognitionLatency.SampleCount = 3U;
        Metrics.RecognitionLatency.TracerWrittenCount = 3U;
        Metrics.RecognitionLatency.HistogramRangeExceeded = 1U;
        Metrics.RecognitionLatency.RecentMicroseconds = {300'000'001U, 49U, 52U};
        Metrics.RecognitionLatency.RecentCount = 3U;
        Metrics.RecognitionLatency.P50BucketLowerBoundMicroseconds = 32U;
        Metrics.RecognitionLatency.P95BucketLowerBoundMicroseconds = 134'217'728U;
        Metrics.RecognitionLatency.P99BucketLowerBoundMicroseconds = 134'217'728U;
        Metrics.RecognitionLatency.MaximumObservedMicroseconds = 300'000'001U;
        return Prism::Operations::HttpDetail::SerializeQuery(
            Prism::Operations::QueryResult::Metrics(
                Prism::RequestId{7}, std::move(Metrics)), true);
    }

    /** @brief 构造空流量字段的 worker 查询 JSON。 */
    [[nodiscard]] auto MakeWorkerJson() -> std::optional<std::string>
    {
        Prism::Operations::Page<Prism::Operations::WorkerSnapshot> Workers;
        Workers.Items.push_back(Prism::Operations::WorkerSnapshot{});
        return Prism::Operations::HttpDetail::SerializeQuery(
            Prism::Operations::QueryResult::Workers(Prism::RequestId{8}, std::move(Workers)), true);
    }

    /** @brief 构造撤销账户与空流量字段的账户查询 JSON。 */
    [[nodiscard]] auto MakeAccountJson() -> std::optional<std::string>
    {
        Prism::Operations::Page<Prism::Operations::AccountSnapshot> Accounts;
        Prism::Operations::AccountSnapshot Account;
        Account.Id = Prism::AccountId{7};
        Account.Generation = Prism::GenerationId{21};
        Account.Revoked = true;
        Accounts.Items.push_back(Account);
        return Prism::Operations::HttpDetail::SerializeQuery(
            Prism::Operations::QueryResult::Accounts(
                Prism::RequestId{2}, std::move(Accounts)), true);
    }

    /** @brief 构造含活动任务数和空值记录的 session 查询 JSON。 */
    [[nodiscard]] auto MakeSessionJson() -> std::optional<std::string>
    {
        Prism::Operations::Page<Prism::Operations::SessionSnapshot> Sessions;
        Prism::Operations::SessionSnapshot Session;
        Session.ActiveTasks = 3U;
        Sessions.Items.push_back(Session);
        Sessions.Items.push_back(Prism::Operations::SessionSnapshot{});
        return Prism::Operations::HttpDetail::SerializeQuery(
            Prism::Operations::QueryResult::Sessions(
                Prism::RequestId{3}, std::move(Sessions)), true);
    }

    /** @brief 构造可取消 task 的查询 JSON。 */
    [[nodiscard]] auto MakeTaskJson() -> std::optional<std::string>
    {
        Prism::Operations::Page<Prism::Operations::TaskSnapshot> Tasks;
        Prism::Operations::TaskSnapshot Task;
        Task.Id = Prism::TaskId{9};
        Task.Cancellable = true;
        Tasks.Items.push_back(Task);
        return Prism::Operations::HttpDetail::SerializeQuery(
            Prism::Operations::QueryResult::Tasks(
                Prism::RequestId{4}, std::move(Tasks)), true);
    }

    /** @brief 构造包含普通与终态事件的事件查询 JSON。 */
    [[nodiscard]] auto MakeEventJson() -> std::optional<std::string>
    {
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
        return Prism::Operations::HttpDetail::SerializeQuery(
            Prism::Operations::QueryResult::Events(
                Prism::RequestId{5}, std::move(Events)), true);
    }
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
    const auto WarningSeverityRoute =
        Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_TRUE(WarningSeverityRoute.has_value());
    const auto *WarningQuery = std::get_if<Prism::Operations::Query>(&*WarningSeverityRoute);
    ASSERT_NE(WarningQuery, nullptr);
    const auto *ManagementQuery =
        std::get_if<Prism::Operations::ManagementQuery>(&WarningQuery->Value);
    ASSERT_NE(ManagementQuery, nullptr);
    const auto *Events = std::get_if<Prism::Operations::EventsRead>(&ManagementQuery->Value);
    ASSERT_NE(Events, nullptr);
    ASSERT_TRUE(Events->Severity.has_value());
    EXPECT_EQ(*Events->Severity, Prism::Statistics::EventSeverity::Warning);
}

TEST(OperationsMetadataJson, OmitsSecretValuesAndReportsRealOwnerFacts)
{
    const auto PublicJson = MakePublicConfigurationJson();
    ASSERT_TRUE(PublicJson.has_value());
    EXPECT_NE(PublicJson->find("secret://alice"), std::string::npos);
    EXPECT_NE(PublicJson->find("secret://quic"), std::string::npos);
    EXPECT_EQ(PublicJson->find("global-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("account-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("protocol-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("quic-secret-value"), std::string::npos);
    EXPECT_EQ(PublicJson->find("Credential\""), std::string::npos);

    const auto ConfigurationJson = MakeConfigurationSnapshotJson(*PublicJson);
    ASSERT_TRUE(ConfigurationJson.has_value());
    EXPECT_NE(ConfigurationJson->find("\"generation\":\"21\""), std::string::npos);
    EXPECT_NE(ConfigurationJson->find("\"reloadable\":true"), std::string::npos);

    const auto EmptyMetricsJson = MakeEmptyMetricsJson();
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

    const auto SampledMetricsJson = MakeSampledMetricsJson();
    ASSERT_TRUE(SampledMetricsJson.has_value());
    EXPECT_NE(SampledMetricsJson->find(R"METRIC("history_ready":true)METRIC"), std::string::npos);
    EXPECT_NE(SampledMetricsJson->find(
        R"METRIC("timestamp":"1970-01-01T00:00:01.234Z")METRIC"), std::string::npos);
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

    const auto WorkerJson = MakeWorkerJson();
    ASSERT_TRUE(WorkerJson.has_value());
    EXPECT_NE(WorkerJson->find(R"METRIC("traffic":null)METRIC"), std::string::npos);

    const auto AccountJson = MakeAccountJson();
    ASSERT_TRUE(AccountJson.has_value());
    EXPECT_NE(AccountJson->find("\"revoked\":true"), std::string::npos);
    EXPECT_NE(AccountJson->find(R"METRIC("traffic":null)METRIC"), std::string::npos);
    EXPECT_EQ(AccountJson->find("\"enabled\":"), std::string::npos);

    const auto SessionJson = MakeSessionJson();
    ASSERT_TRUE(SessionJson.has_value());
    EXPECT_NE(SessionJson->find("\"active_tasks\":\"3\""), std::string::npos);
    EXPECT_NE(SessionJson->find("\"active_tasks\":null"), std::string::npos);
    EXPECT_NE(SessionJson->find(R"METRIC("traffic":null)METRIC"), std::string::npos);

    const auto TaskJson = MakeTaskJson();
    ASSERT_TRUE(TaskJson.has_value());
    EXPECT_NE(TaskJson->find("\"cancellable\":true"), std::string::npos);

    const auto EventJson = MakeEventJson();
    ASSERT_TRUE(EventJson.has_value());
    EXPECT_NE(EventJson->find(R"METRIC("severity":"info")METRIC"), std::string::npos);
    EXPECT_NE(EventJson->find(R"METRIC("severity":"error")METRIC"), std::string::npos);
    EXPECT_NE(EventJson->find(R"METRIC("severity_filter_supported":true)METRIC"), std::string::npos);
}

TEST(OperationsMetadataBootstrap, AdvertisesImplementedReadAndCommandRoutes)
{
    Prism::Operations::BootstrapIdentity::Options Options;
    Options.Process = Prism::ProcessId{12};
    const Prism::Operations::BootstrapIdentity Bootstrap{std::move(Options)};

    const auto Json = Prism::Operations::HttpDetail::SerializeBootstrap(Bootstrap);
    ASSERT_TRUE(Json.has_value());
    EXPECT_NE(Json->find("\"api_version\":\"2\""), std::string::npos);
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
    EXPECT_EQ(Prism::Application::Reload::RestartPolicy::RestartRequiredFields(
        {Current, Candidate}), (std::vector<std::string>{"Statistics.Enabled"}));

    Candidate = Current;
    ++Candidate.Statistics.Interval;
    EXPECT_TRUE(Prism::Application::Reload::RestartPolicy::RestartRequiredFields(
        {Current, Candidate}).empty());

    Current.Statistics.Enabled = true;
    Candidate = Current;
    Candidate.Statistics.Enabled = false;
    EXPECT_EQ(Prism::Application::Reload::RestartPolicy::RestartRequiredFields(
        {Current, Candidate}), (std::vector<std::string>{"Statistics.Enabled"}));
    Candidate = Current;
    Candidate.Logging.Level = "debug";
    EXPECT_TRUE(Prism::Application::Reload::RestartPolicy::RestartRequiredFields(
        {Current, Candidate}).empty());
}

/**
 * @file Task10OperationsTest.cpp
 * @brief Task 10 操作模型、关联、分页和脱敏测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>

#include <Preview/Operations/Operations.hpp>
#include <Preview/Operations/Routes/HttpJson.hpp>
#include <Preview/Operations/Routes/RequestParser.hpp>
#include <Preview/Operations/Router.hpp>
#include "OperationsHttpAuthTestSupport.hpp"

#include <exception>
#include <array>
#include <atomic>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>

namespace
{

    namespace Net = boost::asio;

    template <typename Value>
    auto RunAwaitable(Net::io_context &Io, Net::awaitable<Value> Operation) -> Value
    {
        Io.restart();
        std::optional<Value> Result;
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
                      [&](std::exception_ptr Error, Value ValueObject)
                      {
                          Failure = Error;
                          if (!Error)
                          {
                              Result = std::move(ValueObject);
                          }
                      });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
        return std::move(*Result);
    }

    auto ExecuteCommand(Preview::Operations::Router &RouterValue,
                        Preview::Operations::Command CommandValue)
        -> Net::awaitable<Preview::Operations::CommandResult>
    {
        const auto Executor = co_await Net::this_coro::executor;
        auto Delivery = Preview::Operations::ResponseDeliveryReceipt::Create(Executor);
        co_return co_await RouterValue.ExecuteAsync(std::move(CommandValue), std::move(Delivery));
    }

    /** @brief 在 handler 返回 Accepted 前经真实 Completion 提交 operation 终态。 */
    auto CompleteBeforeAcceptedReturns(
        Preview::Operations::Command CommandValue,
        Preview::Operations::OperationCompletion Completion)
        -> Net::awaitable<Preview::Operations::CommandResult>
    {
        const auto Correlation = Preview::Operations::CorrelationOf(CommandValue);
        const auto Published = co_await Completion.CompleteAsync(
            Preview::Operations::CommandResult::Completed(Correlation));
        if (!Published)
            co_return Preview::Operations::CommandResult::FromFailure(
                Correlation, Published.error());
        co_return Preview::Operations::CommandResult::Accepted(Correlation);
    }

    auto MakePagedSessionResult(Preview::Operations::Query QueryValue)
        -> Net::awaitable<Preview::Operations::QueryResult>
    {
        const auto &QueryData = std::get<Preview::Operations::SessionQuery>(QueryValue.Value);
        Preview::Operations::Page<Preview::Operations::SessionSnapshot> Page;
        for (std::uint64_t Id = 1; Id <= 3; ++Id)
        {
            Preview::Operations::SessionSnapshot Session;
            Session.Id = Preview::SessionId{Id};
            Page.Items.push_back(std::move(Session));
        }
        Page.NextCursor = 3;
        Page.HasMore = false;
        co_return Preview::Operations::QueryResult::Sessions(QueryData.Correlation, std::move(Page));
    }

    TEST(Task10Operations, CommandResultPreservesCorrelationAndIsValueOnly)
    {
        Net::io_context Io;
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{{},
                [](Preview::Operations::Command CommandValue,
                   Preview::Operations::OperationCompletion) -> Net::awaitable<Preview::Operations::CommandResult>
                {
                    const auto Correlation = Preview::Operations::CorrelationOf(CommandValue);
                    co_return Preview::Operations::CommandResult::Completed(Correlation, Preview::WorkerId{3},
                        Preview::GenerationId{9});
                }});

        Preview::Operations::CancelCommand CommandValue;
        CommandValue.Correlation = Preview::RequestId{91};
        CommandValue.Session = Preview::SessionId{44};
        const auto Result = RunAwaitable(
            Io, ExecuteCommand(Router, Preview::Operations::Command{CommandValue}));

        EXPECT_EQ(Result.Status, Preview::Operations::CommandStatus::Completed);
        EXPECT_EQ(Result.Correlation, Preview::RequestId{91});
        EXPECT_EQ(Result.Worker, Preview::WorkerId{3});
        EXPECT_EQ(Result.Generation, Preview::GenerationId{9});
        static_assert(!std::is_pointer_v<decltype(Result) >);
    }

    TEST(Task10OperationsRouter, RetainsTerminalPublishedBeforeHandlerReturnsAccepted)
    {
        Net::io_context Io;
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{{}, CompleteBeforeAcceptedReturns});

        Preview::Operations::CancelCommand CommandValue;
        CommandValue.Correlation = Preview::RequestId{93};
        const auto Accepted = RunAwaitable(
            Io, ExecuteCommand(Router, Preview::Operations::Command{CommandValue}));

        ASSERT_EQ(Accepted.Status, Preview::Operations::CommandStatus::Accepted);
        ASSERT_TRUE(static_cast<bool>(Accepted.Operation));
        const auto Terminal = RunAwaitable(Io, Router.StatusAsync(Accepted.Operation));
        EXPECT_EQ(Terminal.Status, Preview::Operations::CommandStatus::Completed);
        EXPECT_EQ(Terminal.Operation, Accepted.Operation);
        EXPECT_EQ(Terminal.Correlation, CommandValue.Correlation);
    }

    TEST(Task10Operations, QueryPaginationIsSeparateFromCommands)
    {
        static_assert(!std::is_same_v<Preview::Operations::Command,
                                      Preview::Operations::Query>);

        Net::io_context Io;
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{
                [](Preview::Operations::Query QueryValue) -> Net::awaitable<Preview::Operations::QueryResult>
                {
                    const auto& QueryData = std::get<Preview::Operations::SessionQuery>(QueryValue.Value);
                    Preview::Operations::SessionSnapshot Session;
                    Session.Id = Preview::SessionId{17};
                    Session.Account = Preview::AccountId{8};
                    co_return Preview::Operations::QueryResult::Sessions(QueryData.Correlation,
                        Preview::Operations::Page<Preview::Operations::SessionSnapshot>{{Session}, 17,
                            false});
                },
                {}});

        Preview::Operations::SessionQuery QueryData;
        QueryData.Correlation = Preview::RequestId{92};
        QueryData.Page = {.Cursor = 10, .Limit = 5};
        const auto Result = RunAwaitable(
            Io, Router.QueryAsync(Preview::Operations::Query{QueryData}));

        ASSERT_EQ(Result.Status, Preview::Operations::QueryStatus::Ok);
        EXPECT_EQ(Result.Correlation, Preview::RequestId{92});
        const auto *Sessions = std::get_if<Preview::Operations::Page<
            Preview::Operations::SessionSnapshot>>(&Result.Value);
        ASSERT_NE(Sessions, nullptr);
        ASSERT_EQ(Sessions->Items.size(), 1U);
        EXPECT_EQ(Sessions->Items.front().Id, Preview::SessionId{17});
        EXPECT_EQ(Sessions->NextCursor, 17U);
    }

    TEST(Task10Operations, EventDetailsAreRedactedAtTheBoundary)
    {
        Preview::Statistics::DetailedEvent Event;
        Event.Detail = "user=alice token=abc123 password=plain-secret target=example.com";
        Event.Correlation = Preview::RequestId{93};

        const auto Safe = Preview::Operations::Redact(Event);
        EXPECT_EQ(Safe.Detail,
                  "user=alice token=<redacted> password=<redacted> target=example.com");
        EXPECT_EQ(Safe.Correlation, Preview::RequestId{93});
    }

    TEST(Task10Operations, RedactionCoversManagementCredentialAliasesAndBearerTail)
    {
        const auto Safe = Preview::Text::RedactSensitiveText(
            "access_token=access-secret refresh_token=refresh-secret api_key=api-secret "
            "client_secret=client-secret secret_key=secret-secret "
            "Authorization: Bearer bearer-secret authorization=Bearer equals-secret");

        EXPECT_NE(Safe.find("access_token=<redacted>"), std::string::npos);
        EXPECT_NE(Safe.find("refresh_token=<redacted>"), std::string::npos);
        EXPECT_NE(Safe.find("api_key=<redacted>"), std::string::npos);
        EXPECT_NE(Safe.find("client_secret=<redacted>"), std::string::npos);
        EXPECT_NE(Safe.find("secret_key=<redacted>"), std::string::npos);
        EXPECT_NE(Safe.find("Authorization"), std::string::npos);
        EXPECT_EQ(Safe.find("access-secret"), std::string::npos);
        EXPECT_EQ(Safe.find("refresh-secret"), std::string::npos);
        EXPECT_EQ(Safe.find("api-secret"), std::string::npos);
        EXPECT_EQ(Safe.find("client-secret"), std::string::npos);
        EXPECT_EQ(Safe.find("secret-secret"), std::string::npos);
        EXPECT_EQ(Safe.find("bearer-secret"), std::string::npos);
        EXPECT_EQ(Safe.find("equals-secret"), std::string::npos);
    }

    TEST(Task10Operations, ModelFamilyContainsHealthGenerationAndResourceSnapshots)
    {
        Preview::Operations::HealthSnapshot Health;
        Health.Status = Preview::Operations::HealthStatus::Healthy;

        Preview::Operations::GenerationSnapshot Generation;
        Generation.Id = Preview::GenerationId{5};
        Generation.Health = Health;

        Preview::Operations::ProcessSnapshot Process;
        Process.Id = Preview::ProcessId{1};
        Process.Generation = Generation.Id;
        Process.Health = Health;

        Preview::Operations::WorkerSnapshot Worker;
        Worker.Id = Preview::WorkerId{2};
        Worker.Process = Process.Id;
        Worker.Generation = Generation.Id;

        Preview::Operations::AccountSnapshot Account;
        Account.Id = Preview::AccountId{3};
        Account.Generation = Generation.Id;

        Preview::Operations::StreamSnapshot Stream;
        Stream.Id = Preview::StreamId{6};
        Stream.Session = Preview::SessionId{7};

        Preview::Operations::TaskSnapshot Task;
        Task.Id = Preview::TaskId{8};
        Task.Process = Process.Id;
        Task.Worker = Worker.Id;
        Task.Session = Preview::SessionId{7};
        Task.Stream = Preview::StreamId{6};
        Task.Generation = Generation.Id;
        Task.ParentTask = Preview::TaskId{4};
        Task.Status = Preview::Operations::TaskStatus::Failed;
        Task.StartedAt = 10U;
        Task.CompletedAt = 11U;
        Task.DrainBlocked = true;
        Task.Failure = Preview::Fault::Failure{
            Preview::Fault::Code::IoError,
            std::make_error_code(std::errc::connection_reset)};
        Task.DrainFailure = Preview::Fault::Failure{
            Preview::Fault::Code::IoError, std::make_error_code(std::errc::io_error)};

        EXPECT_EQ(Process.Generation, Generation.Id);
        EXPECT_EQ(Worker.Process, Process.Id);
        EXPECT_EQ(Account.Generation, Generation.Id);
        EXPECT_EQ(Stream.Session, Preview::SessionId{7});
        EXPECT_EQ(Task.Process, Process.Id);
        EXPECT_EQ(Task.Worker, Worker.Id);
        EXPECT_EQ(Task.Session, Preview::SessionId{7});
        EXPECT_EQ(Task.Stream, Preview::StreamId{6});
        EXPECT_EQ(Task.Generation, Generation.Id);
        EXPECT_EQ(Task.ParentTask, Preview::TaskId{4});
        EXPECT_EQ(Task.Status, Preview::Operations::TaskStatus::Failed);
        EXPECT_TRUE(Task.DrainBlocked);
        EXPECT_TRUE(Task.Failure.Failed());
        EXPECT_TRUE(Task.DrainFailure.Failed());

        Preview::Operations::Page<Preview::Operations::TaskSnapshot> Tasks;
        Tasks.Items.push_back(Task);
        const auto Json = Preview::Operations::HttpDetail::SerializeQuery(
            Preview::Operations::QueryResult::Tasks(Preview::RequestId{82}, std::move(Tasks)),
            false);
        ASSERT_TRUE(Json.has_value());
        EXPECT_NE(Json->find("\"parent_task\":\"4\""), std::string::npos);
        EXPECT_NE(Json->find("\"failure\":{"), std::string::npos);
        EXPECT_NE(Json->find("\"drain_failure\""), std::string::npos);
        EXPECT_NE(Json->find("\"native_category\""), std::string::npos);

        const auto ErrorJson = Preview::Operations::HttpDetail::SerializeQuery(
            Preview::Operations::QueryResult::Failed(Preview::RequestId{83}, Task.Failure), false);
        ASSERT_TRUE(ErrorJson.has_value());
        EXPECT_NE(ErrorJson->find("\"status\":\"failed\""), std::string::npos);
        EXPECT_NE(ErrorJson->find("\"failure\":{"), std::string::npos);
        EXPECT_NE(ErrorJson->find("\"native_value\""), std::string::npos);
    }

    TEST(Task10Operations, RouterCreatesValueRouterOnTheGivenExecutor)
    {
        Net::io_context Io;
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{
                [](Preview::Operations::Query QueryValue) -> Net::awaitable<Preview::Operations::QueryResult>
                {
                    const auto& QueryData = std::get<Preview::Operations::HealthQuery>(QueryValue.Value);
                    Preview::Operations::HealthSnapshot Health;
                    Health.Status = Preview::Operations::HealthStatus::Healthy;
                    Health.Ready = true;
                    co_return Preview::Operations::QueryResult::Health(QueryData.Correlation, std::move(Health));
                },
                {}});
        Preview::Operations::HealthQuery QueryData;
        QueryData.Correlation = Preview::RequestId{206};
        const auto Result =
            RunAwaitable(Io, Router.QueryAsync(Preview::Operations::Query{QueryData}));

        EXPECT_EQ(Result.Status, Preview::Operations::QueryStatus::Ok);
        EXPECT_EQ(Result.Correlation, Preview::RequestId{206});
        const auto *Health = std::get_if<Preview::Operations::HealthSnapshot>(&Result.Value);
        ASSERT_NE(Health, nullptr);
        EXPECT_TRUE(Health->Ready);
        static_assert(!std::is_pointer_v<decltype(Router)>);
    }

    TEST(Task10OperationsRouter, AppliesCursorPaginationAndPreservesCorrelation)
    {
        Net::io_context Io;
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{
                [](Preview::Operations::Query QueryValue)
                { return MakePagedSessionResult(std::move(QueryValue)); },
                {}});

        Preview::Operations::SessionQuery QueryData;
        QueryData.Correlation = Preview::RequestId{201};
        QueryData.Page = {.Cursor = 1, .Limit = 1};
        const auto Result =
            RunAwaitable(Io, Router.QueryAsync(Preview::Operations::Query{QueryData}));

        ASSERT_EQ(Result.Status, Preview::Operations::QueryStatus::Ok);
        EXPECT_EQ(Result.Correlation, Preview::RequestId{201});
        const auto *Sessions = std::get_if<Preview::Operations::Page<
            Preview::Operations::SessionSnapshot>>(&Result.Value);
        ASSERT_NE(Sessions, nullptr);
        ASSERT_EQ(Sessions->Items.size(), 1U);
        EXPECT_EQ(Sessions->Items.front().Id, Preview::SessionId{2});
        EXPECT_EQ(Sessions->NextCursor, 2U);
        EXPECT_TRUE(Sessions->HasMore);
    }

    TEST(Task10OperationsRouter, PreservesHealthReadinessAndUsesLoopbackDefaults)
    {
        Net::io_context Io;
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{
                [](Preview::Operations::Query QueryValue) -> Net::awaitable<Preview::Operations::QueryResult>
                {
                    const auto& QueryData = std::get<Preview::Operations::HealthQuery>(QueryValue.Value);
                    Preview::Operations::HealthSnapshot Health;
                    Health.Status = Preview::Operations::HealthStatus::Healthy;
                    Health.Ready = true;
                    Health.CheckedAt = 1234;
                    co_return Preview::Operations::QueryResult::Health(QueryData.Correlation, std::move(Health));
                },
                {}});

        Preview::Operations::HealthQuery QueryData;
        QueryData.Correlation = Preview::RequestId{202};
        const auto Result =
            RunAwaitable(Io, Router.QueryAsync(Preview::Operations::Query{QueryData}));

        ASSERT_EQ(Result.Status, Preview::Operations::QueryStatus::Ok);
        EXPECT_EQ(Result.Correlation, Preview::RequestId{202});
        const auto *Health = std::get_if<Preview::Operations::HealthSnapshot>(&Result.Value);
        ASSERT_NE(Health, nullptr);
        EXPECT_TRUE(Health->Ready);
        EXPECT_EQ(Health->Status, Preview::Operations::HealthStatus::Healthy);
        EXPECT_EQ(Router.Endpoint().Address, "127.0.0.1");
        EXPECT_EQ(Router.Endpoint().Port, 9090U);
    }

    TEST(Task10OperationsRouter, RedactsSnapshotAndCommandSecretsAtTheBoundary)
    {
        Net::io_context Io;
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{
                [](Preview::Operations::Query QueryValue) -> Net::awaitable<Preview::Operations::QueryResult>
                {
                    const auto& QueryData = std::get<Preview::Operations::SessionQuery>(QueryValue.Value);
                    Preview::Operations::SessionSnapshot Session;
                    Session.Id = Preview::SessionId{7};
                    Session.Target = "example.test token=secret-value";
                    co_return Preview::Operations::QueryResult::Sessions(QueryData.Correlation,
                        Preview::Operations::Page<Preview::Operations::SessionSnapshot>{{Session}, 7, false});
                },
                [](Preview::Operations::Command CommandValue,
                   Preview::Operations::OperationCompletion) -> Net::awaitable<Preview::Operations::CommandResult>
                {
                    auto Result = Preview::Operations::CommandResult::Completed(
                        Preview::Operations::CorrelationOf(CommandValue));
                    Result.Message = "authorization=bearer token=secret-value";
                    co_return Result;
                }});

        Preview::Operations::SessionQuery QueryData;
        QueryData.Correlation = Preview::RequestId{203};
        const auto QueryResult =
            RunAwaitable(Io, Router.QueryAsync(Preview::Operations::Query{QueryData}));
        const auto *Sessions = std::get_if<Preview::Operations::Page<
            Preview::Operations::SessionSnapshot>>(&QueryResult.Value);
        ASSERT_NE(Sessions, nullptr);
        EXPECT_EQ(Sessions->Items.front().Target, "example.test token=<redacted>");

        Preview::Operations::ProcessDrainCommand Drain;
        Drain.Correlation = Preview::RequestId{204};
        const auto CommandResult =
            RunAwaitable(Io, ExecuteCommand(Router, Preview::Operations::Command{Drain}));
        EXPECT_EQ(CommandResult.Correlation, Preview::RequestId{204});
        EXPECT_EQ(CommandResult.Message, "authorization=<redacted> token=<redacted>");
    }

    TEST(Task10OperationsRouter, TracksAcceptedCommandUntilCompletionByOperationId)
    {
        Net::io_context Io;
        std::optional<Preview::Operations::OperationCompletion> Completion;
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{{},
                [&Completion](Preview::Operations::Command CommandValue,
                              Preview::Operations::OperationCompletion Owner) -> Net::awaitable<Preview::Operations::CommandResult>
                {
                    Completion = Owner;
                    co_return Preview::Operations::CommandResult::Accepted(
                        Preview::Operations::CorrelationOf(CommandValue));
                }});

        Preview::Operations::ReloadCommand Reload;
        Reload.Correlation = Preview::RequestId{205};
        Reload.BaseGeneration = Preview::GenerationId{1};
        Reload.Mode = Preview::Operations::ReloadMode::Apply;
        Reload.ConfigurationJson = "{}";
        const auto Accepted =
            RunAwaitable(Io, ExecuteCommand(Router, Preview::Operations::Command{Reload}));

        EXPECT_EQ(Accepted.Status, Preview::Operations::CommandStatus::Accepted);
        EXPECT_EQ(Accepted.Correlation, Preview::RequestId{205});
        EXPECT_TRUE(static_cast<bool>(Accepted.Operation));
        static_assert(!std::is_pointer_v<decltype(Accepted.Operation)>);

        const auto Pending = RunAwaitable(Io, Router.StatusAsync(Accepted.Operation));
        EXPECT_EQ(Pending.Status, Preview::Operations::CommandStatus::Accepted);
        EXPECT_EQ(Pending.Correlation, Preview::RequestId{205});
        EXPECT_EQ(Pending.Operation, Accepted.Operation);

        auto Completed = Preview::Operations::CommandResult::Completed(Preview::RequestId{999});
        Completed.Message = "password=secret-value";
        ASSERT_TRUE(Completion.has_value());
        EXPECT_TRUE(
            RunAwaitable(Io, Completion->CompleteAsync(std::move(Completed))));

        const auto Finished = RunAwaitable(Io, Router.StatusAsync(Accepted.Operation));
        EXPECT_EQ(Finished.Status, Preview::Operations::CommandStatus::Completed);
        EXPECT_EQ(Finished.Correlation, Preview::RequestId{205});
        EXPECT_EQ(Finished.Operation, Accepted.Operation);
        EXPECT_EQ(Finished.Message, "password=<redacted>");
    }

    TEST(Task10OperationsRouter, CarriesStreamResetScopeThroughOperationCompletion)
    {
        Net::io_context Io;
        std::optional<Preview::Operations::OperationCompletion> Completion;
        const Preview::Operations::CommandTargetScope Scope{
            Preview::Operations::StreamTargetScope{
                Preview::ProcessId{1}, Preview::GenerationId{3}, Preview::WorkerId{2},
                Preview::SessionId{44}, Preview::StreamId{7}, Preview::TaskId{6},
                Preview::TaskId{8}}};
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{{},
                [&Completion, Scope](Preview::Operations::Command CommandValue,
                    Preview::Operations::OperationCompletion Owner)
                    -> Net::awaitable<Preview::Operations::CommandResult>
                {
                    Completion = Owner;
                    auto Result = Preview::Operations::CommandResult::Accepted(
                        Preview::Operations::CorrelationOf(CommandValue), Owner.Id());
                    Preview::Operations::ApplyCommandTarget(Result, Scope);
                    co_return Result;
                }});
        Preview::Operations::StreamResetCommand Reset;
        Reset.Correlation = Preview::RequestId{215};

        const auto Accepted = RunAwaitable(
            Io, ExecuteCommand(Router, Preview::Operations::Command{Reset}));

        ASSERT_EQ(Accepted.Status, Preview::Operations::CommandStatus::Accepted);
        ASSERT_TRUE(Completion.has_value());
        auto Terminal = Preview::Operations::CommandResult::Completed(Preview::RequestId{999});
        Preview::Operations::ApplyCommandTarget(Terminal, Scope);
        ASSERT_TRUE(RunAwaitable(Io, Completion->CompleteAsync(std::move(Terminal))));
        const auto Finished = RunAwaitable(Io, Router.StatusAsync(Accepted.Operation));
        EXPECT_EQ(Finished.Status, Preview::Operations::CommandStatus::Completed);
        EXPECT_EQ(Finished.Process, Preview::ProcessId{1});
        EXPECT_EQ(Finished.Generation, Preview::GenerationId{3});
        EXPECT_EQ(Finished.Worker, Preview::WorkerId{2});
        EXPECT_EQ(Finished.Session, Preview::SessionId{44});
        EXPECT_EQ(Finished.Stream, Preview::StreamId{7});
        EXPECT_EQ(Finished.ParentTask, Preview::TaskId{6});
        EXPECT_EQ(Finished.Task, Preview::TaskId{8});
    }

    TEST(Task10OperationsRouter, RejectsBeforeCallingHandlerWhenOperationCapacityIsFull)
    {
        Net::io_context Io;
        std::size_t HandlerCalls = 0;
        Preview::Operations::RouterOptions Options;
        Options.MaxOperations = 1;
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{{},
                [&HandlerCalls](Preview::Operations::Command CommandValue,
                    Preview::Operations::OperationCompletion) -> Net::awaitable<Preview::Operations::CommandResult>
                {
                    ++HandlerCalls;
                    co_return Preview::Operations::CommandResult::Accepted(
                        Preview::Operations::CorrelationOf(CommandValue));
                }},
            Options);

        Preview::Operations::ReloadCommand First;
        First.Correlation = Preview::RequestId{212};
        First.BaseGeneration = Preview::GenerationId{1};
        First.Mode = Preview::Operations::ReloadMode::Apply;
        First.ConfigurationJson = "{}";
        const auto Accepted =
            RunAwaitable(Io, ExecuteCommand(Router, Preview::Operations::Command{First}));
        ASSERT_EQ(Accepted.Status, Preview::Operations::CommandStatus::Accepted);

        Preview::Operations::ReloadCommand Second;
        Second.Correlation = Preview::RequestId{213};
        Second.BaseGeneration = Preview::GenerationId{1};
        Second.Mode = Preview::Operations::ReloadMode::Apply;
        Second.ConfigurationJson = "{}";
        const auto Rejected =
            RunAwaitable(Io, ExecuteCommand(Router, Preview::Operations::Command{Second}));

        EXPECT_EQ(Rejected.Status, Preview::Operations::CommandStatus::Rejected);
        EXPECT_EQ(Rejected.Message, "operation_limit");
        EXPECT_EQ(HandlerCalls, 1U);
    }

    TEST(Task10OperationsRouter, AcceptsAllTypedManagementCommands)
    {
        Net::io_context Io;
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{{},
                [](Preview::Operations::Command CommandValue,
                   Preview::Operations::OperationCompletion) -> Net::awaitable<Preview::Operations::CommandResult>
                {
                    co_return Preview::Operations::CommandResult::Accepted(
                        Preview::Operations::CorrelationOf(CommandValue));
                }});

        Preview::Operations::ReloadCommand Reload;
        Reload.Correlation = Preview::RequestId{207};
        Reload.BaseGeneration = Preview::GenerationId{1};
        Reload.Mode = Preview::Operations::ReloadMode::Apply;
        Reload.ConfigurationJson = "{}";
        Preview::Operations::RevokeCommand Revoke;
        Revoke.Correlation = Preview::RequestId{208};
        Preview::Operations::CancelCommand Cancel;
        Cancel.Correlation = Preview::RequestId{209};
        Preview::Operations::StreamResetCommand StreamReset;
        StreamReset.Correlation = Preview::RequestId{211};
        Preview::Operations::ProcessDrainCommand Drain;
        Drain.Correlation = Preview::RequestId{210};

        const std::array Commands{
            Preview::Operations::Command{Reload},
            Preview::Operations::Command{Revoke},
            Preview::Operations::Command{Cancel},
            Preview::Operations::Command{StreamReset},
            Preview::Operations::Command{Drain}};
        for (const auto &CommandValue : Commands)
        {
            const auto Result = RunAwaitable(Io, ExecuteCommand(Router, CommandValue));
            EXPECT_EQ(Result.Status, Preview::Operations::CommandStatus::Accepted);
            EXPECT_TRUE(static_cast<bool>(Result.Operation));
        }
    }

    TEST(Task10OperationsRouter, ServesRedactedEventRingPagesAsValues)
    {
        Net::io_context Io;
        Preview::Statistics::EventRing Ring;
        Preview::Statistics::DetailedEvent First;
        First.Detail = "token=first";
        ASSERT_TRUE(static_cast<bool>(Ring.Append(std::move(First))));
        Preview::Statistics::DetailedEvent Second;
        Second.Detail = "password=second";
        ASSERT_TRUE(static_cast<bool>(Ring.Append(std::move(Second))));

        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{
                [&Ring](Preview::Operations::Query QueryValue) -> Net::awaitable<Preview::Operations::QueryResult>
                {
                    const auto& QueryData = std::get<Preview::Operations::EventQuery>(QueryValue.Value);
                    const auto Source = Ring.Page(QueryData.Page.Cursor, QueryData.Page.BoundedLimit());
                    co_return Preview::Operations::QueryResult::Events(QueryData.Correlation,
                        Preview::Statistics::EventPage{Source.Items,
                            Source.NextCursor, Source.HasMore});
                },
                {}});

        Preview::Operations::EventQuery QueryData;
        QueryData.Correlation = Preview::RequestId{211};
        QueryData.Page = {.Cursor = 0, .Limit = 1};
        const auto Result =
            RunAwaitable(Io, Router.QueryAsync(Preview::Operations::Query{QueryData}));

        ASSERT_EQ(Result.Status, Preview::Operations::QueryStatus::Ok);
        const auto *Events = std::get_if<Preview::Statistics::EventPage>(&Result.Value);
        ASSERT_NE(Events, nullptr);
        ASSERT_EQ(Events->Items.size(), 1U);
        EXPECT_EQ(Events->Items.front().Detail, "token=<redacted>");
        EXPECT_EQ(Events->NextCursor, 1U);
        EXPECT_TRUE(Events->HasMore);
    }

    TEST(Task10Operations, DistinguishesRetiredStreamsFromUnavailableCatalogs)
    {
        const auto Retired = Preview::Operations::QueryResult::NotFound(Preview::RequestId{212});
        auto Unsupported = Preview::Operations::QueryResult::Unavailable(Preview::RequestId{213});
        Unsupported.Message = "stream_catalog_unavailable";

        EXPECT_EQ(Retired.Status, Preview::Operations::QueryStatus::NotFound);
        EXPECT_EQ(Retired.Message, "stream_not_found");
        EXPECT_EQ(Preview::Operations::HttpDetail::QueryStatusName(Retired.Status), "not_found");
        EXPECT_EQ(Preview::Operations::HttpDetail::StatusFor(Retired.Status), 404);
        EXPECT_EQ(Unsupported.Status, Preview::Operations::QueryStatus::Unavailable);
        EXPECT_EQ(Unsupported.Message, "stream_catalog_unavailable");
        EXPECT_EQ(Preview::Operations::HttpDetail::QueryStatusName(Unsupported.Status), "unavailable");
        EXPECT_EQ(Preview::Operations::HttpDetail::StatusFor(Unsupported.Status), 503);
    }

    TEST(Task10Operations, ScopedStreamResetTargetSurvivesAcceptedAndTerminalResults)
    {
        const Preview::Operations::CommandTargetScope Scope{
            Preview::Operations::StreamTargetScope{
                Preview::ProcessId{1}, Preview::GenerationId{3}, Preview::WorkerId{2},
                Preview::SessionId{44}, Preview::StreamId{7}, Preview::TaskId{6},
                Preview::TaskId{8}}};
        auto Accepted = Preview::Operations::CommandResult::Accepted(
            Preview::RequestId{214}, Preview::Operations::OperationId{15});
        Preview::Operations::ApplyCommandTarget(Accepted, Scope);
        auto Terminal = Preview::Operations::CommandResult::Completed(Preview::RequestId{214});
        Preview::Operations::ApplyCommandTarget(Terminal, Scope);

        const auto AcceptedJson = Preview::Operations::HttpDetail::SerializeCommand(Accepted);
        const auto TerminalJson = Preview::Operations::HttpDetail::SerializeCommand(Terminal);

        ASSERT_TRUE(AcceptedJson.has_value());
        ASSERT_TRUE(TerminalJson.has_value());
        EXPECT_NE(AcceptedJson->find("\"process\":\"1\""), std::string::npos);
        EXPECT_NE(AcceptedJson->find("\"generation\":\"3\""), std::string::npos);
        EXPECT_NE(AcceptedJson->find("\"worker\":\"2\""), std::string::npos);
        EXPECT_NE(AcceptedJson->find("\"session\":\"44\""), std::string::npos);
        EXPECT_NE(AcceptedJson->find("\"stream\":\"7\""), std::string::npos);
        EXPECT_NE(AcceptedJson->find("\"task\":\"8\""), std::string::npos);
        EXPECT_NE(AcceptedJson->find("\"parent_task\":\"6\""), std::string::npos);
        EXPECT_NE(TerminalJson->find("\"process\":\"1\""), std::string::npos);
        EXPECT_NE(TerminalJson->find("\"generation\":\"3\""), std::string::npos);
        EXPECT_NE(TerminalJson->find("\"worker\":\"2\""), std::string::npos);
        EXPECT_NE(TerminalJson->find("\"session\":\"44\""), std::string::npos);
        EXPECT_NE(TerminalJson->find("\"stream\":\"7\""), std::string::npos);
        EXPECT_NE(TerminalJson->find("\"task\":\"8\""), std::string::npos);
        EXPECT_NE(TerminalJson->find("\"parent_task\":\"6\""), std::string::npos);
    }

    TEST(Task10OperationsHttpParser, RejectsRepeatedSecurityHeaders)
    {
        Preview::Operations::HttpRequest Request;
        EXPECT_EQ(Preview::Operations::RequestParserDetail::ParseRequest(
            "GET /Operations/Health HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n"
            "Host: 127.0.0.1:9090\r\n\r\n", Request), Preview::Operations::RequestParserDetail::ParseStatus::Malformed);
        EXPECT_EQ(Preview::Operations::RequestParserDetail::ParseRequest(
            "GET /Operations/Health HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n"
            "Origin: http://127.0.0.1:9090\r\nOrigin: http://127.0.0.1:9090\r\n\r\n",
            Request), Preview::Operations::RequestParserDetail::ParseStatus::Malformed);
        EXPECT_EQ(Preview::Operations::RequestParserDetail::ParseRequest(
            "POST /Operations/Reload HTTP/1.1\r\nHost: 127.0.0.1:9090\r\n"
            "Authorization: Bearer one\r\nAuthorization: Bearer two\r\n"
            "Content-Length: 0\r\n\r\n", Request), Preview::Operations::RequestParserDetail::ParseStatus::Malformed);
    }

    TEST(Task10OperationsHttp, PublishesVersionedNoStoreBootstrap)
    {
        Net::io_context Io;
        auto Server = Preview::Testing::OperationsHttp::MakeServer(
            Preview::Operations::Router(Io.get_executor()), Io);
        const auto Exchange = Preview::Testing::OperationsHttp::RunExchange(
            Io, Server,
            "GET /Operations/Bootstrap HTTP/1.1\r\nHost: localhost\r\n\r\n");

        EXPECT_FALSE(Exchange.Error);
        EXPECT_NE(Exchange.Response.find("HTTP/1.1 200"), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\r\nCache-Control: no-store\r\n"), std::string::npos);
        EXPECT_EQ(Exchange.Response.find("Access-Control-Allow-Origin"), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"api_version\":\"1\""), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"process_id\":\"1\""), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"capabilities\":["), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"workers.drain\""), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"process.drain\""), std::string::npos);
        EXPECT_EQ(Exchange.Response.find("\"streams.reset\""), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"configuration.reload\""), std::string::npos);
        const auto Incarnation = Exchange.Response.find("\"process_incarnation\":\"");
        ASSERT_NE(Incarnation, std::string::npos);
        const auto IncarnationBegin = Incarnation + std::string_view{"\"process_incarnation\":\""}.size();
        const auto IncarnationEnd = Exchange.Response.find('"', IncarnationBegin);
        ASSERT_NE(IncarnationEnd, std::string::npos);
        EXPECT_EQ(IncarnationEnd - IncarnationBegin, 32U);
        constexpr std::string_view TokenKey{"\"command_token\":\""};
        const auto Token = Exchange.Response.find(TokenKey);
        ASSERT_NE(Token, std::string::npos);
        const auto TokenBegin = Token + TokenKey.size();
        const auto TokenEnd = Exchange.Response.find('"', TokenBegin);
        ASSERT_NE(TokenEnd, std::string::npos);
        EXPECT_EQ(TokenEnd - TokenBegin, 64U);
    }

    TEST(Task10OperationsHttp, RejectsInvalidCommandTokenBeforeOperationDispatch)
    {
        Net::io_context Io;
        std::atomic<bool> HandlerCalled{false};
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{{},
                [&HandlerCalled](Preview::Operations::Command CommandValue,
                    Preview::Operations::OperationCompletion) -> Net::awaitable<Preview::Operations::CommandResult>
                {
                    HandlerCalled.store(true, std::memory_order_release);
                    co_return Preview::Operations::CommandResult::Accepted(
                        Preview::Operations::CorrelationOf(CommandValue));
                }});
        auto Server = Preview::Testing::OperationsHttp::MakeServer(std::move(Router), Io);
        const auto Exchange = Preview::Testing::OperationsHttp::RunExchange(
            Io, Server,
            "POST /Operations/Reload HTTP/1.1\r\n"
            "Host: localhost\r\nAuthorization: Bearer invalid\r\n"
            "Content-Length: 0\r\n\r\n");

        EXPECT_FALSE(Exchange.Error);
        EXPECT_NE(Exchange.Response.find("HTTP/1.1 403"), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"error\":\"forbidden\""), std::string::npos);
        EXPECT_EQ(Exchange.Response.find("\"operation\":"), std::string::npos);
        EXPECT_EQ(Exchange.Response.find("invalid"), std::string::npos);
        EXPECT_FALSE(HandlerCalled.load(std::memory_order_acquire));
    }

    TEST(Task10OperationsHttp, RejectsMissingCommandTokenBeforeOperationDispatch)
    {
        Net::io_context Io;
        std::atomic<bool> HandlerCalled{false};
        Preview::Operations::Router Router(Io.get_executor(),
            Preview::Operations::RouterHandlers{{},
                [&HandlerCalled](Preview::Operations::Command CommandValue,
                    Preview::Operations::OperationCompletion) -> Net::awaitable<Preview::Operations::CommandResult>
                {
                    HandlerCalled.store(true, std::memory_order_release);
                    co_return Preview::Operations::CommandResult::Accepted(
                        Preview::Operations::CorrelationOf(CommandValue));
                }});
        auto Server = Preview::Testing::OperationsHttp::MakeServer(std::move(Router), Io);
        const auto Exchange = Preview::Testing::OperationsHttp::RunExchangeWithoutToken(
            Io, Server,
            "POST /Operations/Reload HTTP/1.1\r\n"
            "Host: localhost\r\nContent-Length: 0\r\n\r\n");

        EXPECT_FALSE(Exchange.Error);
        EXPECT_NE(Exchange.Response.find("HTTP/1.1 403"), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"error\":\"forbidden\""), std::string::npos);
        EXPECT_EQ(Exchange.Response.find("\"operation\":"), std::string::npos);
        EXPECT_FALSE(HandlerCalled.load(std::memory_order_acquire));
    }

    TEST(Task10OperationsHttp, RejectsRebindingHostAndCrossSiteOrigin)
    {
        Net::io_context HostIo;
        auto HostServer = Preview::Testing::OperationsHttp::MakeServer(
            Preview::Operations::Router(HostIo.get_executor()), HostIo);
        const auto HostExchange = Preview::Testing::OperationsHttp::RunExchange(
            HostIo, HostServer,
            "GET /Operations/Bootstrap HTTP/1.1\r\nHost: attacker.example\r\n\r\n");
        EXPECT_FALSE(HostExchange.Error);
        EXPECT_NE(HostExchange.Response.find("HTTP/1.1 403"), std::string::npos);
        EXPECT_EQ(HostExchange.Response.find("\"command_token\":"), std::string::npos);

        Net::io_context OriginIo;
        auto OriginServer = Preview::Testing::OperationsHttp::MakeServer(
            Preview::Operations::Router(OriginIo.get_executor()), OriginIo);
        const auto OriginExchange = Preview::Testing::OperationsHttp::RunExchange(
            OriginIo, OriginServer,
            "GET /Operations/Bootstrap HTTP/1.1\r\n"
            "Host: localhost\r\nOrigin: http://attacker.example\r\n\r\n");
        EXPECT_FALSE(OriginExchange.Error);
        EXPECT_NE(OriginExchange.Response.find("HTTP/1.1 403"), std::string::npos);
        EXPECT_EQ(OriginExchange.Response.find("\"command_token\":"), std::string::npos);
    }

} // namespace

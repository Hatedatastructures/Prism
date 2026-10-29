/**
 * @file ManagementTest.cpp
 * @brief Task 10 操作模型、关联、分页和脱敏测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>

#include <Prism/Operations/Operations.hpp>
#include <Prism/Operations/ManagementModels.hpp>
#include <Prism/Operations/Routes/HttpJson.hpp>
#include <Prism/Operations/Router.hpp>
#include <Prism/Statistics/EventRing.hpp>
#include <Prism/Foundation/Utility/Text/Redaction.hpp>
#include "../Http/AuthSupport.hpp"

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

    auto ExecuteCommand(Prism::Operations::Router &RouterValue,
                        Prism::Operations::Command CommandValue)
        -> Net::awaitable<Prism::Operations::CommandResult>
    {
        const auto Executor = co_await Net::this_coro::executor;
        auto Delivery = Prism::Operations::ResponseDeliveryReceipt::Create(Executor);
        co_return co_await RouterValue.ExecuteAsync(std::move(CommandValue), std::move(Delivery));
    }

    /** @brief 在 handler 返回 Accepted 前经真实 Completion 提交 operation 终态。 */
    auto CompleteBeforeAcceptedReturns(
        Prism::Operations::Command CommandValue,
        Prism::Operations::OperationCompletion Completion)
        -> Net::awaitable<Prism::Operations::CommandResult>
    {
        const auto Correlation = Prism::Operations::CorrelationOf(CommandValue);
        const auto Published = co_await Completion.CompleteAsync(
            Prism::Operations::CommandResult::Completed(Correlation));
        if (!Published)
            co_return Prism::Operations::CommandResult::FromFailure(
                Correlation, Published.error());
        co_return Prism::Operations::CommandResult::Accepted(Correlation);
    }

    auto MakePagedSessionResult(Prism::Operations::Query QueryValue)
        -> Net::awaitable<Prism::Operations::QueryResult>
    {
        const auto &QueryData = std::get<Prism::Operations::SessionQuery>(QueryValue.Value);
        Prism::Operations::Page<Prism::Operations::SessionSnapshot> Page;
        for (std::uint64_t Id = 1; Id <= 3; ++Id)
        {
            Prism::Operations::SessionSnapshot Session;
            Session.Id = Prism::SessionId{Id};
            Page.Items.push_back(std::move(Session));
        }
        Page.NextCursor = 3;
        Page.HasMore = false;
        co_return Prism::Operations::QueryResult::Sessions(QueryData.Correlation, std::move(Page));
    }

    TEST(Task10Operations, CommandResultPreservesCorrelationAndIsValueOnly)
    {
        Net::io_context Io;
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{{},
                [](Prism::Operations::Command CommandValue,
                   Prism::Operations::OperationCompletion) -> Net::awaitable<Prism::Operations::CommandResult>
                {
                    const auto Correlation = Prism::Operations::CorrelationOf(CommandValue);
                    co_return Prism::Operations::CommandResult::Completed(Correlation, Prism::WorkerId{3},
                        Prism::GenerationId{9});
                }});

        Prism::Operations::CancelCommand CommandValue;
        CommandValue.Correlation = Prism::RequestId{91};
        CommandValue.Session = Prism::SessionId{44};
        const auto Result = RunAwaitable(
            Io, ExecuteCommand(Router, Prism::Operations::Command{CommandValue}));

        EXPECT_EQ(Result.Status, Prism::Operations::CommandStatus::Completed);
        EXPECT_EQ(Result.Correlation, Prism::RequestId{91});
        EXPECT_EQ(Result.Worker, Prism::WorkerId{3});
        EXPECT_EQ(Result.Generation, Prism::GenerationId{9});
        static_assert(!std::is_pointer_v<decltype(Result) >);
    }

    TEST(Task10OperationsRouter, RetainsTerminalPublishedBeforeHandlerReturnsAccepted)
    {
        Net::io_context Io;
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{{}, CompleteBeforeAcceptedReturns});

        Prism::Operations::CancelCommand CommandValue;
        CommandValue.Correlation = Prism::RequestId{93};
        const auto Accepted = RunAwaitable(
            Io, ExecuteCommand(Router, Prism::Operations::Command{CommandValue}));

        ASSERT_EQ(Accepted.Status, Prism::Operations::CommandStatus::Accepted);
        ASSERT_TRUE(static_cast<bool>(Accepted.Operation));
        const auto Terminal = RunAwaitable(Io, Router.StatusAsync(Accepted.Operation));
        EXPECT_EQ(Terminal.Status, Prism::Operations::CommandStatus::Completed);
        EXPECT_EQ(Terminal.Operation, Accepted.Operation);
        EXPECT_EQ(Terminal.Correlation, CommandValue.Correlation);
    }

    TEST(Task10Operations, QueryPaginationIsSeparateFromCommands)
    {
        static_assert(!std::is_same_v<Prism::Operations::Command,
                                      Prism::Operations::Query>);

        Net::io_context Io;
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{
                [](Prism::Operations::Query QueryValue) -> Net::awaitable<Prism::Operations::QueryResult>
                {
                    const auto& QueryData = std::get<Prism::Operations::SessionQuery>(QueryValue.Value);
                    Prism::Operations::SessionSnapshot Session;
                    Session.Id = Prism::SessionId{17};
                    Session.Account = Prism::AccountId{8};
                    co_return Prism::Operations::QueryResult::Sessions(QueryData.Correlation,
                        Prism::Operations::Page<Prism::Operations::SessionSnapshot>{{Session}, 17,
                            false});
                },
                {}});

        Prism::Operations::SessionQuery QueryData;
        QueryData.Correlation = Prism::RequestId{92};
        QueryData.Page = {.Cursor = 10, .Limit = 5};
        const auto Result = RunAwaitable(
            Io, Router.QueryAsync(Prism::Operations::Query{QueryData}));

        ASSERT_EQ(Result.Status, Prism::Operations::QueryStatus::Ok);
        EXPECT_EQ(Result.Correlation, Prism::RequestId{92});
        const auto *Sessions = std::get_if<Prism::Operations::Page<
            Prism::Operations::SessionSnapshot>>(&Result.Value);
        ASSERT_NE(Sessions, nullptr);
        ASSERT_EQ(Sessions->Items.size(), 1U);
        EXPECT_EQ(Sessions->Items.front().Id, Prism::SessionId{17});
        EXPECT_EQ(Sessions->NextCursor, 17U);
    }

    TEST(Task10Operations, EventDetailsAreRedactedAtTheBoundary)
    {
        Prism::Statistics::DetailedEvent Event;
        Event.Detail = "user=alice token=abc123 password=plain-secret target=example.com";
        Event.Correlation = Prism::RequestId{93};

        const auto Safe = Prism::Operations::Redact(Event);
        EXPECT_EQ(Safe.Detail,
                  "user=alice token=<redacted> password=<redacted> target=example.com");
        EXPECT_EQ(Safe.Correlation, Prism::RequestId{93});
    }

    TEST(Task10Operations, RedactionCoversManagementCredentialAliasesAndBearerTail)
    {
        const auto Safe = Prism::Text::RedactSensitiveText(
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
        Prism::Operations::HealthSnapshot Health;
        Health.Status = Prism::Operations::HealthStatus::Healthy;

        Prism::Operations::GenerationSnapshot Generation;
        Generation.Id = Prism::GenerationId{5};
        Generation.Health = Health;

        Prism::Operations::ProcessSnapshot Process;
        Process.Id = Prism::ProcessId{1};
        Process.Generation = Generation.Id;
        Process.Health = Health;

        Prism::Operations::WorkerSnapshot Worker;
        Worker.Id = Prism::WorkerId{2};
        Worker.Process = Process.Id;
        Worker.Generation = Generation.Id;

        Prism::Operations::AccountSnapshot Account;
        Account.Id = Prism::AccountId{3};
        Account.Generation = Generation.Id;

        Prism::Operations::StreamSnapshot Stream;
        Stream.Id = Prism::StreamId{6};
        Stream.Session = Prism::SessionId{7};

        Prism::Operations::TaskSnapshot Task;
        Task.Id = Prism::TaskId{8};
        Task.Process = Process.Id;
        Task.Worker = Worker.Id;
        Task.Session = Prism::SessionId{7};
        Task.Stream = Prism::StreamId{6};
        Task.Generation = Generation.Id;
        Task.ParentTask = Prism::TaskId{4};
        Task.Status = Prism::Operations::TaskStatus::Failed;
        Task.StartedAt = 10U;
        Task.CompletedAt = 11U;
        Task.DrainBlocked = true;
        Task.Failure = Prism::Fault::Failure{
            Prism::Fault::Code::IoError,
            std::make_error_code(std::errc::connection_reset)};
        Task.DrainFailure = Prism::Fault::Failure{
            Prism::Fault::Code::IoError, std::make_error_code(std::errc::io_error)};

        EXPECT_EQ(Process.Generation, Generation.Id);
        EXPECT_EQ(Worker.Process, Process.Id);
        EXPECT_EQ(Account.Generation, Generation.Id);
        EXPECT_EQ(Stream.Session, Prism::SessionId{7});
        EXPECT_EQ(Task.Process, Process.Id);
        EXPECT_EQ(Task.Worker, Worker.Id);
        EXPECT_EQ(Task.Session, Prism::SessionId{7});
        EXPECT_EQ(Task.Stream, Prism::StreamId{6});
        EXPECT_EQ(Task.Generation, Generation.Id);
        EXPECT_EQ(Task.ParentTask, Prism::TaskId{4});
        EXPECT_EQ(Task.Status, Prism::Operations::TaskStatus::Failed);
        EXPECT_TRUE(Task.DrainBlocked);
        EXPECT_TRUE(Task.Failure.Failed());
        EXPECT_TRUE(Task.DrainFailure.Failed());

        Prism::Operations::Page<Prism::Operations::TaskSnapshot> Tasks;
        Tasks.Items.push_back(Task);
        const auto Json = Prism::Operations::HttpDetail::SerializeQuery(
            Prism::Operations::QueryResult::Tasks(Prism::RequestId{82}, std::move(Tasks)),
            false);
        ASSERT_TRUE(Json.has_value());
        EXPECT_NE(Json->find("\"parent_task\":\"4\""), std::string::npos);
        EXPECT_NE(Json->find("\"failure\":{"), std::string::npos);
        EXPECT_NE(Json->find("\"drain_failure\""), std::string::npos);
        EXPECT_NE(Json->find("\"native_category\""), std::string::npos);

        const auto ErrorJson = Prism::Operations::HttpDetail::SerializeQuery(
            Prism::Operations::QueryResult::Failed(Prism::RequestId{83}, Task.Failure), false);
        ASSERT_TRUE(ErrorJson.has_value());
        EXPECT_NE(ErrorJson->find("\"status\":\"failed\""), std::string::npos);
        EXPECT_NE(ErrorJson->find("\"failure\":{"), std::string::npos);
        EXPECT_NE(ErrorJson->find("\"native_value\""), std::string::npos);
    }

    TEST(Task10Operations, RouterCreatesValueRouterOnTheGivenExecutor)
    {
        Net::io_context Io;
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{
                [](Prism::Operations::Query QueryValue) -> Net::awaitable<Prism::Operations::QueryResult>
                {
                    const auto& QueryData = std::get<Prism::Operations::HealthQuery>(QueryValue.Value);
                    Prism::Operations::HealthSnapshot Health;
                    Health.Status = Prism::Operations::HealthStatus::Healthy;
                    Health.Ready = true;
                    co_return Prism::Operations::QueryResult::Health(QueryData.Correlation, std::move(Health));
                },
                {}});
        Prism::Operations::HealthQuery QueryData;
        QueryData.Correlation = Prism::RequestId{206};
        const auto Result =
            RunAwaitable(Io, Router.QueryAsync(Prism::Operations::Query{QueryData}));

        EXPECT_EQ(Result.Status, Prism::Operations::QueryStatus::Ok);
        EXPECT_EQ(Result.Correlation, Prism::RequestId{206});
        const auto *Health = std::get_if<Prism::Operations::HealthSnapshot>(&Result.Value);
        ASSERT_NE(Health, nullptr);
        EXPECT_TRUE(Health->Ready);
        static_assert(!std::is_pointer_v<decltype(Router)>);
    }

    TEST(Task10OperationsRouter, AppliesCursorPaginationAndPreservesCorrelation)
    {
        Net::io_context Io;
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{
                [](Prism::Operations::Query QueryValue)
                { return MakePagedSessionResult(std::move(QueryValue)); },
                {}});

        Prism::Operations::SessionQuery QueryData;
        QueryData.Correlation = Prism::RequestId{201};
        QueryData.Page = {.Cursor = 1, .Limit = 1};
        const auto Result =
            RunAwaitable(Io, Router.QueryAsync(Prism::Operations::Query{QueryData}));

        ASSERT_EQ(Result.Status, Prism::Operations::QueryStatus::Ok);
        EXPECT_EQ(Result.Correlation, Prism::RequestId{201});
        const auto *Sessions = std::get_if<Prism::Operations::Page<
            Prism::Operations::SessionSnapshot>>(&Result.Value);
        ASSERT_NE(Sessions, nullptr);
        ASSERT_EQ(Sessions->Items.size(), 1U);
        EXPECT_EQ(Sessions->Items.front().Id, Prism::SessionId{2});
        EXPECT_EQ(Sessions->NextCursor, 2U);
        EXPECT_TRUE(Sessions->HasMore);
    }

    TEST(Task10OperationsRouter, PreservesHealthReadinessAndUsesLoopbackDefaults)
    {
        Net::io_context Io;
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{
                [](Prism::Operations::Query QueryValue) -> Net::awaitable<Prism::Operations::QueryResult>
                {
                    const auto& QueryData = std::get<Prism::Operations::HealthQuery>(QueryValue.Value);
                    Prism::Operations::HealthSnapshot Health;
                    Health.Status = Prism::Operations::HealthStatus::Healthy;
                    Health.Ready = true;
                    Health.CheckedAt = 1234;
                    co_return Prism::Operations::QueryResult::Health(QueryData.Correlation, std::move(Health));
                },
                {}});

        Prism::Operations::HealthQuery QueryData;
        QueryData.Correlation = Prism::RequestId{202};
        const auto Result =
            RunAwaitable(Io, Router.QueryAsync(Prism::Operations::Query{QueryData}));

        ASSERT_EQ(Result.Status, Prism::Operations::QueryStatus::Ok);
        EXPECT_EQ(Result.Correlation, Prism::RequestId{202});
        const auto *Health = std::get_if<Prism::Operations::HealthSnapshot>(&Result.Value);
        ASSERT_NE(Health, nullptr);
        EXPECT_TRUE(Health->Ready);
        EXPECT_EQ(Health->Status, Prism::Operations::HealthStatus::Healthy);
        EXPECT_EQ(Router.Endpoint().Address, "127.0.0.1");
        EXPECT_EQ(Router.Endpoint().Port, 9090U);
    }

    TEST(Task10OperationsRouter, RedactsSnapshotAndCommandSecretsAtTheBoundary)
    {
        Net::io_context Io;
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{
                [](Prism::Operations::Query QueryValue) -> Net::awaitable<Prism::Operations::QueryResult>
                {
                    const auto& QueryData = std::get<Prism::Operations::SessionQuery>(QueryValue.Value);
                    Prism::Operations::SessionSnapshot Session;
                    Session.Id = Prism::SessionId{7};
                    Session.Target = "example.test token=secret-value";
                    co_return Prism::Operations::QueryResult::Sessions(QueryData.Correlation,
                        Prism::Operations::Page<Prism::Operations::SessionSnapshot>{{Session}, 7, false});
                },
                [](Prism::Operations::Command CommandValue,
                   Prism::Operations::OperationCompletion) -> Net::awaitable<Prism::Operations::CommandResult>
                {
                    auto Result = Prism::Operations::CommandResult::Completed(
                        Prism::Operations::CorrelationOf(CommandValue));
                    Result.Message = "authorization=bearer token=secret-value";
                    co_return Result;
                }});

        Prism::Operations::SessionQuery QueryData;
        QueryData.Correlation = Prism::RequestId{203};
        const auto QueryResult =
            RunAwaitable(Io, Router.QueryAsync(Prism::Operations::Query{QueryData}));
        const auto *Sessions = std::get_if<Prism::Operations::Page<
            Prism::Operations::SessionSnapshot>>(&QueryResult.Value);
        ASSERT_NE(Sessions, nullptr);
        EXPECT_EQ(Sessions->Items.front().Target, "example.test token=<redacted>");

        Prism::Operations::ProcessDrainCommand Drain;
        Drain.Correlation = Prism::RequestId{204};
        const auto CommandResult =
            RunAwaitable(Io, ExecuteCommand(Router, Prism::Operations::Command{Drain}));
        EXPECT_EQ(CommandResult.Correlation, Prism::RequestId{204});
        EXPECT_EQ(CommandResult.Message, "authorization=<redacted> token=<redacted>");
    }

    TEST(Task10OperationsRouter, TracksAcceptedCommandUntilCompletionByOperationId)
    {
        Net::io_context Io;
        std::optional<Prism::Operations::OperationCompletion> Completion;
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{{},
                [&Completion](Prism::Operations::Command CommandValue,
                              Prism::Operations::OperationCompletion Owner) -> Net::awaitable<Prism::Operations::CommandResult>
                {
                    Completion = Owner;
                    co_return Prism::Operations::CommandResult::Accepted(
                        Prism::Operations::CorrelationOf(CommandValue));
                }});

        Prism::Operations::ReloadCommand Reload;
        Reload.Correlation = Prism::RequestId{205};
        Reload.BaseGeneration = Prism::GenerationId{1};
        Reload.Mode = Prism::Operations::ReloadMode::Apply;
        Reload.ConfigurationJson = "{}";
        const auto Accepted =
            RunAwaitable(Io, ExecuteCommand(Router, Prism::Operations::Command{Reload}));

        EXPECT_EQ(Accepted.Status, Prism::Operations::CommandStatus::Accepted);
        EXPECT_EQ(Accepted.Correlation, Prism::RequestId{205});
        EXPECT_TRUE(static_cast<bool>(Accepted.Operation));
        static_assert(!std::is_pointer_v<decltype(Accepted.Operation)>);

        const auto Pending = RunAwaitable(Io, Router.StatusAsync(Accepted.Operation));
        EXPECT_EQ(Pending.Status, Prism::Operations::CommandStatus::Accepted);
        EXPECT_EQ(Pending.Correlation, Prism::RequestId{205});
        EXPECT_EQ(Pending.Operation, Accepted.Operation);

        auto Completed = Prism::Operations::CommandResult::Completed(Prism::RequestId{999});
        Completed.Message = "password=secret-value";
        ASSERT_TRUE(Completion.has_value());
        EXPECT_TRUE(
            RunAwaitable(Io, Completion->CompleteAsync(std::move(Completed))));

        const auto Finished = RunAwaitable(Io, Router.StatusAsync(Accepted.Operation));
        EXPECT_EQ(Finished.Status, Prism::Operations::CommandStatus::Completed);
        EXPECT_EQ(Finished.Correlation, Prism::RequestId{205});
        EXPECT_EQ(Finished.Operation, Accepted.Operation);
        EXPECT_EQ(Finished.Message, "password=<redacted>");
    }

    TEST(Task10OperationsRouter, CarriesStreamResetScopeThroughOperationCompletion)
    {
        Net::io_context Io;
        std::optional<Prism::Operations::OperationCompletion> Completion;
        const Prism::Operations::CommandTargetScope Scope{
            Prism::Operations::StreamTargetScope{
                Prism::ProcessId{1}, Prism::GenerationId{3}, Prism::WorkerId{2},
                Prism::SessionId{44}, Prism::StreamId{7}, Prism::TaskId{6},
                Prism::TaskId{8}}};
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{{},
                [&Completion, Scope](Prism::Operations::Command CommandValue,
                    Prism::Operations::OperationCompletion Owner)
                    -> Net::awaitable<Prism::Operations::CommandResult>
                {
                    Completion = Owner;
                    auto Result = Prism::Operations::CommandResult::Accepted(
                        Prism::Operations::CorrelationOf(CommandValue), Owner.Id());
                    Prism::Operations::ApplyCommandTarget(Result, Scope);
                    co_return Result;
                }});
        Prism::Operations::StreamResetCommand Reset;
        Reset.Correlation = Prism::RequestId{215};

        const auto Accepted = RunAwaitable(
            Io, ExecuteCommand(Router, Prism::Operations::Command{Reset}));

        ASSERT_EQ(Accepted.Status, Prism::Operations::CommandStatus::Accepted);
        ASSERT_TRUE(Completion.has_value());
        auto Terminal = Prism::Operations::CommandResult::Completed(Prism::RequestId{999});
        Prism::Operations::ApplyCommandTarget(Terminal, Scope);
        ASSERT_TRUE(RunAwaitable(Io, Completion->CompleteAsync(std::move(Terminal))));
        const auto Finished = RunAwaitable(Io, Router.StatusAsync(Accepted.Operation));
        EXPECT_EQ(Finished.Status, Prism::Operations::CommandStatus::Completed);
        EXPECT_EQ(Finished.Process, Prism::ProcessId{1});
        EXPECT_EQ(Finished.Generation, Prism::GenerationId{3});
        EXPECT_EQ(Finished.Worker, Prism::WorkerId{2});
        EXPECT_EQ(Finished.Session, Prism::SessionId{44});
        EXPECT_EQ(Finished.Stream, Prism::StreamId{7});
        EXPECT_EQ(Finished.ParentTask, Prism::TaskId{6});
        EXPECT_EQ(Finished.Task, Prism::TaskId{8});
    }

    TEST(Task10OperationsRouter, RejectsBeforeCallingHandlerWhenOperationCapacityIsFull)
    {
        Net::io_context Io;
        std::size_t HandlerCalls = 0;
        Prism::Operations::RouterOptions Options;
        Options.MaxOperations = 1;
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{{},
                [&HandlerCalls](Prism::Operations::Command CommandValue,
                    Prism::Operations::OperationCompletion) -> Net::awaitable<Prism::Operations::CommandResult>
                {
                    ++HandlerCalls;
                    co_return Prism::Operations::CommandResult::Accepted(
                        Prism::Operations::CorrelationOf(CommandValue));
                }},
            Options);

        Prism::Operations::ReloadCommand First;
        First.Correlation = Prism::RequestId{212};
        First.BaseGeneration = Prism::GenerationId{1};
        First.Mode = Prism::Operations::ReloadMode::Apply;
        First.ConfigurationJson = "{}";
        const auto Accepted =
            RunAwaitable(Io, ExecuteCommand(Router, Prism::Operations::Command{First}));
        ASSERT_EQ(Accepted.Status, Prism::Operations::CommandStatus::Accepted);

        Prism::Operations::ReloadCommand Second;
        Second.Correlation = Prism::RequestId{213};
        Second.BaseGeneration = Prism::GenerationId{1};
        Second.Mode = Prism::Operations::ReloadMode::Apply;
        Second.ConfigurationJson = "{}";
        const auto Rejected =
            RunAwaitable(Io, ExecuteCommand(Router, Prism::Operations::Command{Second}));

        EXPECT_EQ(Rejected.Status, Prism::Operations::CommandStatus::Rejected);
        EXPECT_EQ(Rejected.Message, "operation_limit");
        EXPECT_EQ(HandlerCalls, 1U);
    }

    TEST(Task10OperationsRouter, AcceptsAllTypedManagementCommands)
    {
        Net::io_context Io;
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{{},
                [](Prism::Operations::Command CommandValue,
                   Prism::Operations::OperationCompletion) -> Net::awaitable<Prism::Operations::CommandResult>
                {
                    co_return Prism::Operations::CommandResult::Accepted(
                        Prism::Operations::CorrelationOf(CommandValue));
                }});

        Prism::Operations::ReloadCommand Reload;
        Reload.Correlation = Prism::RequestId{207};
        Reload.BaseGeneration = Prism::GenerationId{1};
        Reload.Mode = Prism::Operations::ReloadMode::Apply;
        Reload.ConfigurationJson = "{}";
        Prism::Operations::RevokeCommand Revoke;
        Revoke.Correlation = Prism::RequestId{208};
        Prism::Operations::CancelCommand Cancel;
        Cancel.Correlation = Prism::RequestId{209};
        Prism::Operations::StreamResetCommand StreamReset;
        StreamReset.Correlation = Prism::RequestId{211};
        Prism::Operations::ProcessDrainCommand Drain;
        Drain.Correlation = Prism::RequestId{210};

        const std::array Commands{
            Prism::Operations::Command{Reload},
            Prism::Operations::Command{Revoke},
            Prism::Operations::Command{Cancel},
            Prism::Operations::Command{StreamReset},
            Prism::Operations::Command{Drain}};
        for (const auto &CommandValue : Commands)
        {
            const auto Result = RunAwaitable(Io, ExecuteCommand(Router, CommandValue));
            EXPECT_EQ(Result.Status, Prism::Operations::CommandStatus::Accepted);
            EXPECT_TRUE(static_cast<bool>(Result.Operation));
        }
    }

    TEST(Task10OperationsRouter, ServesRedactedEventRingPagesAsValues)
    {
        Net::io_context Io;
        Prism::Statistics::EventRing Ring;
        Prism::Statistics::DetailedEvent First;
        First.Detail = "token=first";
        ASSERT_TRUE(static_cast<bool>(Ring.Append(std::move(First))));
        Prism::Statistics::DetailedEvent Second;
        Second.Detail = "password=second";
        ASSERT_TRUE(static_cast<bool>(Ring.Append(std::move(Second))));

        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{
                [&Ring](Prism::Operations::Query QueryValue) -> Net::awaitable<Prism::Operations::QueryResult>
                {
                    const auto &QueryData = std::get<Prism::Operations::ManagementQuery>(QueryValue.Value);
                    const auto &EventsRead = std::get<Prism::Operations::EventsRead>(QueryData.Value);
                    const auto Source = Ring.Page(EventsRead.Page.Cursor, EventsRead.Page.BoundedLimit());
                    co_return Prism::Operations::QueryResult::Events(QueryData.Correlation,
                        Prism::Statistics::EventPage{Source.Items,
                            Source.NextCursor, Source.HasMore});
                },
                {}});

        Prism::Operations::ManagementQuery QueryData{Prism::RequestId{211},
            Prism::Operations::EventsRead{.Page = {.Cursor = 0, .Limit = 1}}};
        const auto Result =
            RunAwaitable(Io, Router.QueryAsync(Prism::Operations::Query{QueryData}));

        ASSERT_EQ(Result.Status, Prism::Operations::QueryStatus::Ok);
        const auto *Events = std::get_if<Prism::Statistics::EventPage>(&Result.Value);
        ASSERT_NE(Events, nullptr);
        ASSERT_EQ(Events->Items.size(), 1U);
        EXPECT_EQ(Events->Items.front().Detail, "token=<redacted>");
        EXPECT_EQ(Events->NextCursor, 1U);
        EXPECT_TRUE(Events->HasMore);
    }

    TEST(Task10Operations, DistinguishesRetiredStreamsFromUnavailableCatalogs)
    {
        const auto Retired = Prism::Operations::QueryResult::NotFound(Prism::RequestId{212});
        auto Unsupported = Prism::Operations::QueryResult::Unavailable(Prism::RequestId{213});
        Unsupported.Message = "stream_catalog_unavailable";

        EXPECT_EQ(Retired.Status, Prism::Operations::QueryStatus::NotFound);
        EXPECT_EQ(Retired.Message, "stream_not_found");
        EXPECT_EQ(Prism::Operations::HttpDetail::QueryStatusName(Retired.Status), "not_found");
        EXPECT_EQ(Prism::Operations::HttpDetail::StatusFor(Retired.Status), 404);
        EXPECT_EQ(Unsupported.Status, Prism::Operations::QueryStatus::Unavailable);
        EXPECT_EQ(Unsupported.Message, "stream_catalog_unavailable");
        EXPECT_EQ(Prism::Operations::HttpDetail::QueryStatusName(Unsupported.Status), "unavailable");
        EXPECT_EQ(Prism::Operations::HttpDetail::StatusFor(Unsupported.Status), 503);
    }

    TEST(Task10Operations, ScopedStreamResetTargetSurvivesAcceptedAndTerminalResults)
    {
        const Prism::Operations::CommandTargetScope Scope{
            Prism::Operations::StreamTargetScope{
                Prism::ProcessId{1}, Prism::GenerationId{3}, Prism::WorkerId{2},
                Prism::SessionId{44}, Prism::StreamId{7}, Prism::TaskId{6},
                Prism::TaskId{8}}};
        auto Accepted = Prism::Operations::CommandResult::Accepted(
            Prism::RequestId{214}, Prism::Operations::OperationId{15});
        Prism::Operations::ApplyCommandTarget(Accepted, Scope);
        auto Terminal = Prism::Operations::CommandResult::Completed(Prism::RequestId{214});
        Prism::Operations::ApplyCommandTarget(Terminal, Scope);

        const auto AcceptedJson = Prism::Operations::HttpDetail::SerializeCommand(Accepted);
        const auto TerminalJson = Prism::Operations::HttpDetail::SerializeCommand(Terminal);

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

    TEST(Task10OperationsHttp, PublishesVersionedNoStoreBootstrap)
    {
        Net::io_context Io;
        auto Server = Prism::Testing::OperationsHttp::MakeServer(
            Prism::Operations::Router(Io.get_executor()), Io);
        const auto Exchange = Prism::Testing::OperationsHttp::RunExchange(
            Io, Server,
            "GET /Operations/Bootstrap HTTP/1.1\r\nHost: localhost\r\n\r\n");

        EXPECT_FALSE(Exchange.Error);
        EXPECT_NE(Exchange.Response.find("HTTP/1.1 200"), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\r\nCache-Control: no-store\r\n"), std::string::npos);
        EXPECT_EQ(Exchange.Response.find("Access-Control-Allow-Origin"), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"api_version\":\"2\""), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"process_id\":\"1\""), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"capabilities\":["), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"workers.drain\""), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"process.drain\""), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"streams.reset\""), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"configuration.reload.validate\""), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"configuration.reload.apply\""), std::string::npos);
        EXPECT_NE(Exchange.Response.find("\"configuration.reload.persist\""), std::string::npos);
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
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{{},
                [&HandlerCalled](Prism::Operations::Command CommandValue,
                    Prism::Operations::OperationCompletion) -> Net::awaitable<Prism::Operations::CommandResult>
                {
                    HandlerCalled.store(true, std::memory_order_release);
                    co_return Prism::Operations::CommandResult::Accepted(
                        Prism::Operations::CorrelationOf(CommandValue));
                }});
        auto Server = Prism::Testing::OperationsHttp::MakeServer(std::move(Router), Io);
        const auto Exchange = Prism::Testing::OperationsHttp::RunExchange(
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
        Prism::Operations::Router Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{{},
                [&HandlerCalled](Prism::Operations::Command CommandValue,
                    Prism::Operations::OperationCompletion) -> Net::awaitable<Prism::Operations::CommandResult>
                {
                    HandlerCalled.store(true, std::memory_order_release);
                    co_return Prism::Operations::CommandResult::Accepted(
                        Prism::Operations::CorrelationOf(CommandValue));
                }});
        auto Server = Prism::Testing::OperationsHttp::MakeServer(std::move(Router), Io);
        const auto Exchange = Prism::Testing::OperationsHttp::RunExchangeWithoutToken(
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
        auto HostServer = Prism::Testing::OperationsHttp::MakeServer(
            Prism::Operations::Router(HostIo.get_executor()), HostIo);
        const auto HostExchange = Prism::Testing::OperationsHttp::RunExchange(
            HostIo, HostServer,
            "GET /Operations/Bootstrap HTTP/1.1\r\nHost: attacker.example\r\n\r\n");
        EXPECT_FALSE(HostExchange.Error);
        EXPECT_NE(HostExchange.Response.find("HTTP/1.1 403"), std::string::npos);
        EXPECT_EQ(HostExchange.Response.find("\"command_token\":"), std::string::npos);

        Net::io_context OriginIo;
        auto OriginServer = Prism::Testing::OperationsHttp::MakeServer(
            Prism::Operations::Router(OriginIo.get_executor()), OriginIo);
        const auto OriginExchange = Prism::Testing::OperationsHttp::RunExchange(
            OriginIo, OriginServer,
            "GET /Operations/Bootstrap HTTP/1.1\r\n"
            "Host: localhost\r\nOrigin: http://attacker.example\r\n\r\n");
        EXPECT_FALSE(OriginExchange.Error);
        EXPECT_NE(OriginExchange.Response.find("HTTP/1.1 403"), std::string::npos);
        EXPECT_EQ(OriginExchange.Response.find("\"command_token\":"), std::string::npos);
    }

} // namespace

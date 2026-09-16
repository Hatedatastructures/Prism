/**
 * @file Task10OperationsTest.cpp
 * @brief Task 10 操作模型、关联、分页和脱敏测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <Preview/Composition/Api/OperationsApi.hpp>
#include <Preview/Operations/Operations.hpp>
#include <Preview/Operations/Router.hpp>

#include <exception>
#include <array>
#include <optional>
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

    TEST(Task10Operations, CommandResultPreservesCorrelationAndIsValueOnly)
    {
        Preview::Composition::Api::OperationsApi Api;
        Api.SetCommandHandler([](const Preview::Operations::Command &CommandValue)
                                  -> Preview::Operations::CommandResult
                              {
                                  const auto Correlation =
                                      Preview::Operations::CorrelationOf(CommandValue);
                                  return Preview::Operations::CommandResult::Completed(
                                      Correlation,
                                      Preview::WorkerId{3},
                                      Preview::GenerationId{9});
                              });

        Preview::Operations::CancelCommand CommandValue;
        CommandValue.Correlation = Preview::RequestId{91};
        CommandValue.Session = Preview::SessionId{44};
        const auto Result = Api.Execute(Preview::Operations::Command{CommandValue});

        EXPECT_EQ(Result.Status, Preview::Operations::CommandStatus::Completed);
        EXPECT_EQ(Result.Correlation, Preview::RequestId{91});
        EXPECT_EQ(Result.Worker, Preview::WorkerId{3});
        EXPECT_EQ(Result.Generation, Preview::GenerationId{9});
        static_assert(!std::is_pointer_v<decltype(Result) >);
    }

    TEST(Task10Operations, QueryPaginationIsSeparateFromCommands)
    {
        static_assert(!std::is_same_v<Preview::Operations::Command,
                                      Preview::Operations::Query>);

        Preview::Composition::Api::OperationsApi Api;
        Api.SetQueryHandler([](const Preview::Operations::Query &QueryValue)
                                -> Preview::Operations::QueryResult
                            {
                                const auto &QueryData =
                                    std::get<Preview::Operations::SessionQuery>(QueryValue.Value);
                                Preview::Operations::SessionSnapshot Session;
                                Session.Id = Preview::SessionId{17};
                                Session.Account = Preview::AccountId{8};
                                return Preview::Operations::QueryResult::Sessions(
                                    QueryData.Correlation,
                                    Preview::Operations::Page<Preview::Operations::SessionSnapshot>{
                                        {Session}, 17, false});
                            });

        Preview::Operations::SessionQuery QueryData;
        QueryData.Correlation = Preview::RequestId{92};
        QueryData.Page = {.Cursor = 10, .Limit = 5};
        const auto Result = Api.Query(Preview::Operations::Query{QueryData});

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
        const auto Safe = Preview::Statistics::RedactSensitiveText(
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
        Task.Worker = Worker.Id;

        EXPECT_EQ(Process.Generation, Generation.Id);
        EXPECT_EQ(Worker.Process, Process.Id);
        EXPECT_EQ(Account.Generation, Generation.Id);
        EXPECT_EQ(Stream.Session, Preview::SessionId{7});
        EXPECT_EQ(Task.Worker, Worker.Id);
    }

    TEST(Task10Operations, CompositionApiCreatesValueRouterOnTheGivenExecutor)
    {
        Net::io_context Io;
        Preview::Composition::Api::OperationsApi Api;
        Api.SetQueryHandler([](const Preview::Operations::Query &QueryValue)
                                -> Preview::Operations::QueryResult
                            {
                                const auto &QueryData =
                                    std::get<Preview::Operations::HealthQuery>(QueryValue.Value);
                                Preview::Operations::HealthSnapshot Health;
                                Health.Status = Preview::Operations::HealthStatus::Healthy;
                                Health.Ready = true;
                                return Preview::Operations::QueryResult::Health(
                                    QueryData.Correlation, std::move(Health));
                            });

        auto Router = Api.MakeRouter(Io.get_executor());
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
        Preview::Operations::Router Router(
            Io.get_executor(),
            [](const Preview::Operations::Query &QueryValue)
                -> Preview::Operations::QueryResult
            {
                const auto &QueryData =
                    std::get<Preview::Operations::SessionQuery>(QueryValue.Value);
                Preview::Operations::Page<Preview::Operations::SessionSnapshot> Page;
                for (std::uint64_t Id = 1; Id <= 3; ++Id)
                {
                    Preview::Operations::SessionSnapshot Session;
                    Session.Id = Preview::SessionId{Id};
                    Page.Items.push_back(std::move(Session));
                }
                Page.NextCursor = 3;
                Page.HasMore = false;
                return Preview::Operations::QueryResult::Sessions(QueryData.Correlation,
                                                                   std::move(Page));
            });

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
        Preview::Operations::Router Router(
            Io.get_executor(),
            [](const Preview::Operations::Query &QueryValue)
                -> Preview::Operations::QueryResult
            {
                const auto &QueryData =
                    std::get<Preview::Operations::HealthQuery>(QueryValue.Value);
                Preview::Operations::HealthSnapshot Health;
                Health.Status = Preview::Operations::HealthStatus::Healthy;
                Health.Ready = true;
                Health.CheckedAt = 1234;
                return Preview::Operations::QueryResult::Health(QueryData.Correlation,
                                                                 std::move(Health));
            });

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
        Preview::Operations::Router Router(
            Io.get_executor(),
            [](const Preview::Operations::Query &QueryValue)
                -> Preview::Operations::QueryResult
            {
                const auto &QueryData =
                    std::get<Preview::Operations::SessionQuery>(QueryValue.Value);
                Preview::Operations::SessionSnapshot Session;
                Session.Id = Preview::SessionId{7};
                Session.Target = "example.test token=secret-value";
                return Preview::Operations::QueryResult::Sessions(
                    QueryData.Correlation,
                    Preview::Operations::Page<Preview::Operations::SessionSnapshot>{{Session}, 7,
                                                                                     false});
            },
            [](const Preview::Operations::Command &CommandValue)
                -> Preview::Operations::CommandResult
            {
                auto Result = Preview::Operations::CommandResult::Completed(
                    Preview::Operations::CorrelationOf(CommandValue));
                Result.Message = "authorization=bearer token=secret-value";
                return Result;
            });

        Preview::Operations::SessionQuery QueryData;
        QueryData.Correlation = Preview::RequestId{203};
        const auto QueryResult =
            RunAwaitable(Io, Router.QueryAsync(Preview::Operations::Query{QueryData}));
        const auto *Sessions = std::get_if<Preview::Operations::Page<
            Preview::Operations::SessionSnapshot>>(&QueryResult.Value);
        ASSERT_NE(Sessions, nullptr);
        EXPECT_EQ(Sessions->Items.front().Target, "example.test token=<redacted>");

        Preview::Operations::DrainCommand Drain;
        Drain.Correlation = Preview::RequestId{204};
        const auto CommandResult =
            RunAwaitable(Io, Router.ExecuteAsync(Preview::Operations::Command{Drain}));
        EXPECT_EQ(CommandResult.Correlation, Preview::RequestId{204});
        EXPECT_EQ(CommandResult.Message, "authorization=<redacted> token=<redacted>");
    }

    TEST(Task10OperationsRouter, TracksAcceptedCommandUntilCompletionByOperationId)
    {
        Net::io_context Io;
        Preview::Operations::Router Router(
            Io.get_executor(),
            {},
            [](const Preview::Operations::Command &CommandValue)
                -> Preview::Operations::CommandResult
            {
                return Preview::Operations::CommandResult::Accepted(
                    Preview::Operations::CorrelationOf(CommandValue));
            });

        Preview::Operations::ReloadCommand Reload;
        Reload.Correlation = Preview::RequestId{205};
        const auto Accepted =
            RunAwaitable(Io, Router.ExecuteAsync(Preview::Operations::Command{Reload}));

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
        EXPECT_TRUE(
            RunAwaitable(Io, Router.CompleteAsync(Accepted.Operation, std::move(Completed))));

        const auto Finished = RunAwaitable(Io, Router.StatusAsync(Accepted.Operation));
        EXPECT_EQ(Finished.Status, Preview::Operations::CommandStatus::Completed);
        EXPECT_EQ(Finished.Correlation, Preview::RequestId{205});
        EXPECT_EQ(Finished.Operation, Accepted.Operation);
        EXPECT_EQ(Finished.Message, "password=<redacted>");
    }

    TEST(Task10OperationsRouter, RejectsBeforeCallingHandlerWhenOperationCapacityIsFull)
    {
        Net::io_context Io;
        std::size_t HandlerCalls = 0;
        Preview::Operations::RouterOptions Options;
        Options.MaxOperations = 1;
        Preview::Operations::Router Router(
            Io.get_executor(),
            {},
            [&HandlerCalls](const Preview::Operations::Command &CommandValue)
                -> Preview::Operations::CommandResult
            {
                ++HandlerCalls;
                return Preview::Operations::CommandResult::Accepted(
                    Preview::Operations::CorrelationOf(CommandValue));
            },
            Options);

        Preview::Operations::ReloadCommand First;
        First.Correlation = Preview::RequestId{212};
        const auto Accepted =
            RunAwaitable(Io, Router.ExecuteAsync(Preview::Operations::Command{First}));
        ASSERT_EQ(Accepted.Status, Preview::Operations::CommandStatus::Accepted);

        Preview::Operations::ReloadCommand Second;
        Second.Correlation = Preview::RequestId{213};
        const auto Rejected =
            RunAwaitable(Io, Router.ExecuteAsync(Preview::Operations::Command{Second}));

        EXPECT_EQ(Rejected.Status, Preview::Operations::CommandStatus::Rejected);
        EXPECT_EQ(Rejected.Message, "operation_limit");
        EXPECT_EQ(HandlerCalls, 1U);
    }

    TEST(Task10OperationsRouter, AcceptsAllTypedManagementCommands)
    {
        Net::io_context Io;
        Preview::Operations::Router Router(
            Io.get_executor(),
            {},
            [](const Preview::Operations::Command &CommandValue)
                -> Preview::Operations::CommandResult
            {
                return Preview::Operations::CommandResult::Accepted(
                    Preview::Operations::CorrelationOf(CommandValue));
            });

        Preview::Operations::ReloadCommand Reload;
        Reload.Correlation = Preview::RequestId{207};
        Preview::Operations::RevokeCommand Revoke;
        Revoke.Correlation = Preview::RequestId{208};
        Preview::Operations::CancelCommand Cancel;
        Cancel.Correlation = Preview::RequestId{209};
        Preview::Operations::DrainCommand Drain;
        Drain.Correlation = Preview::RequestId{210};

        const std::array Commands{
            Preview::Operations::Command{Reload},
            Preview::Operations::Command{Revoke},
            Preview::Operations::Command{Cancel},
            Preview::Operations::Command{Drain}};
        for (const auto &CommandValue : Commands)
        {
            const auto Result = RunAwaitable(Io, Router.ExecuteAsync(CommandValue));
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

        Preview::Operations::Router Router(
            Io.get_executor(),
            [&Ring](const Preview::Operations::Query &QueryValue)
                -> Preview::Operations::QueryResult
            {
                const auto &QueryData =
                    std::get<Preview::Operations::EventQuery>(QueryValue.Value);
                const auto Source = Ring.Page(QueryData.Page.Cursor, QueryData.Page.BoundedLimit());
                return Preview::Operations::QueryResult::Events(
                    QueryData.Correlation,
                    Preview::Operations::Page<Preview::Operations::EventSnapshot>{
                        Source.Items, Source.NextCursor, Source.HasMore});
            });

        Preview::Operations::EventQuery QueryData;
        QueryData.Correlation = Preview::RequestId{211};
        QueryData.Page = {.Cursor = 0, .Limit = 1};
        const auto Result =
            RunAwaitable(Io, Router.QueryAsync(Preview::Operations::Query{QueryData}));

        ASSERT_EQ(Result.Status, Preview::Operations::QueryStatus::Ok);
        const auto *Events = std::get_if<Preview::Operations::Page<
            Preview::Operations::EventSnapshot>>(&Result.Value);
        ASSERT_NE(Events, nullptr);
        ASSERT_EQ(Events->Items.size(), 1U);
        EXPECT_EQ(Events->Items.front().Detail, "token=<redacted>");
        EXPECT_EQ(Events->NextCursor, 1U);
        EXPECT_TRUE(Events->HasMore);
    }

} // namespace

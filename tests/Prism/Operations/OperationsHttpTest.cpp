/**
 * @file OperationsHttpTest.cpp
 * @brief Operations HTTP listener 的解析、路由、脱敏与停机契约测试。
 */

#include <gtest/gtest.h>

#include <Prism/Operations/HttpServer.hpp>
#include <Prism/Operations/Routes/RouteDispatch.hpp>
#include "OperationsHttpAuthTestSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using Prism::Operations::Command;
    using Prism::Operations::CommandResult;
    using Prism::Operations::AccountSnapshot;
    using Prism::Operations::HealthSnapshot;
    using Prism::Operations::HttpServer;
    using Prism::Operations::RequestParserDetail::ParseStatus;
    using Prism::Operations::Query;
    using Prism::Operations::QueryResult;
    using Prism::Operations::Router;
    using HttpExchange = Prism::Testing::OperationsHttp::Exchange;
    using Prism::Testing::OperationsHttp::MakeServer;
    using Prism::Testing::OperationsHttp::MakeTestBootstrap;
    using Prism::Testing::OperationsHttp::RunExchange;

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

    auto ExecuteCommand(Router &RouterValue, Command CommandValue)
        -> Net::awaitable<CommandResult>
    {
        const auto Executor = co_await Net::this_coro::executor;
        auto Delivery = Prism::Operations::ResponseDeliveryReceipt::Create(Executor);
        co_return co_await RouterValue.ExecuteAsync(std::move(CommandValue), std::move(Delivery));
    }


    [[nodiscard]] auto MakeDegradedHealth(Query QueryValue) -> Net::awaitable<QueryResult>
    {
        const auto Correlation = Prism::Operations::CorrelationOf(QueryValue);
        HealthSnapshot Health;
        Health.Status = Prism::Operations::HealthStatus::Degraded;
        Health.Ready = false;
        Health.TcpReady = true;
        Health.UdpReady = false;
        Health.QuicReady = true;
        co_return QueryResult::Health(Correlation, Health);
    }

    auto MakeStreamQuerySnapshot(Query QueryValue) -> Net::awaitable<QueryResult>
    {
        const auto QueryData = std::get<Prism::Operations::StreamQuery>(QueryValue.Value);
        Prism::Operations::StreamSnapshot Stream;
        Stream.Id = QueryData.Id;
        Stream.Task = Prism::TaskId{8};
        Stream.ParentTask = Prism::TaskId{6};
        Stream.Process = QueryData.Process;
        Stream.Session = QueryData.Session;
        Stream.Worker = QueryData.Worker;
        Stream.Generation = QueryData.Generation;
        Stream.Protocol = "Smux";
        Stream.Active = true;
        Stream.Traffic = Prism::Statistics::TrafficValue{5U, 7U, 1U, 0U};
        Prism::Operations::Page<Prism::Operations::StreamSnapshot> Page;
        Page.Items.push_back(std::move(Stream));
        co_return QueryResult::Streams(QueryData.Correlation, std::move(Page));
    }

    struct IdleSocketOutcome final
    {
        bool Closed{false};
        bool TimedOut{false};
        bool Completed{false};
        std::exception_ptr Failure;
    };

    struct IdleSocketRequest final
    {
        HttpServer &Server;
        Net::io_context &Io;
        std::shared_ptr<IdleSocketOutcome> Result;
        std::shared_ptr<Net::steady_timer> Watchdog;
    };

    auto RunIdleSocketScenario(IdleSocketRequest Request) -> Net::awaitable<void>
    {
        const auto Started = co_await Request.Server.Start();
        if (!Started)
        {
            Request.Result->Failure = std::make_exception_ptr(std::runtime_error("server_start_failed"));
            Request.Result->Completed = true;
            Request.Io.stop();
            co_return;
        }
        Tcp::socket Socket(co_await Net::this_coro::executor);
        boost::system::error_code Error;
        co_await Socket.async_connect(*Started, Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            Request.Result->Failure = std::make_exception_ptr(std::runtime_error("connect_failed"));
            Request.Result->Completed = true;
            Request.Io.stop();
            co_return;
        }
        std::array<char, 1> Buffer{};
        co_await Socket.async_read_some(
            Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Error));
        Request.Result->Closed = static_cast<bool>(Error);
        Request.Result->Completed = true;
        (void)Request.Server.CloseAdmission();
        boost::system::error_code CloseError;
        Socket.close(CloseError);
        Request.Watchdog->cancel();
        Request.Io.stop();
    }

    auto RunIdleSocketWatchdog(
        Net::io_context &Io,
        const std::shared_ptr<IdleSocketOutcome> &Result,
        const std::shared_ptr<Net::steady_timer> &Watchdog) -> Net::awaitable<void>
    {
        Watchdog->expires_after(std::chrono::milliseconds{250});
        boost::system::error_code Error;
        co_await Watchdog->async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error && !Result->Completed)
        {
            Result->TimedOut = true;
            Io.stop();
        }
    }

    struct DrainSocketOutcome final
    {
        bool Drained{false};
        bool TimedOut{false};
        std::exception_ptr Failure;
    };

    struct DrainSocketRequest final
    {
        HttpServer &Server;
        Net::io_context &Io;
        std::shared_ptr<DrainSocketOutcome> Result;
        std::shared_ptr<Net::steady_timer> Watchdog;
    };

    auto RunDrainSocketScenario(DrainSocketRequest Request) -> Net::awaitable<void>
    {
        const auto Started = co_await Request.Server.Start();
        if (!Started)
        {
            Request.Result->Failure = std::make_exception_ptr(std::runtime_error("server_start_failed"));
            Request.Io.stop();
            co_return;
        }
        Tcp::socket Socket(co_await Net::this_coro::executor);
        boost::system::error_code Error;
        co_await Socket.async_connect(*Started, Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            Request.Result->Failure = std::make_exception_ptr(std::runtime_error("connect_failed"));
            Request.Io.stop();
            co_return;
        }
        Net::steady_timer Delay(co_await Net::this_coro::executor);
        Delay.expires_after(std::chrono::milliseconds{5});
        co_await Delay.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        const auto Drained = co_await Request.Server.Drain(HttpServer::Deadline::max());
        Request.Result->Drained = Drained.Failure.Succeeded();
        Request.Result->TimedOut = Drained.Failure.Code == Prism::Fault::Code::Timeout;
        boost::system::error_code CloseError;
        Socket.close(CloseError);
        Request.Watchdog->cancel();
        Request.Io.stop();
    }

    auto RunDrainSocketWatchdog(
        Net::io_context &Io,
        const std::shared_ptr<DrainSocketOutcome> &Result,
        const std::shared_ptr<Net::steady_timer> &Watchdog) -> Net::awaitable<void>
    {
        Watchdog->expires_after(std::chrono::milliseconds{250});
        boost::system::error_code Error;
        co_await Watchdog->async_wait(Net::redirect_error(Net::use_awaitable, Error));
        if (!Error && !Result->Drained)
        {
            Result->TimedOut = true;
            Io.stop();
        }
    }

    auto RunIdempotentDrainScenario(HttpServer &Server, bool &Completed)
        -> Net::awaitable<void>
    {
        const auto Started = co_await Server.Start();
        if (!Started)
        {
            co_return;
        }
        (void)Server.CloseAdmission();
        (void)Server.CloseAdmission();
        (void)co_await Server.Drain(HttpServer::Deadline::max());
        (void)co_await Server.Drain(HttpServer::Deadline::max());
        Completed = true;
    }

} // namespace

TEST(OperationsHttpParser, AcceptsBoundedHealthRequest)
{
    Prism::Operations::HttpRequest Request;
    const auto Result = Prism::Operations::RequestParserDetail::ParseRequest(
        "GET /Operations/Health?correlation=7 HTTP/1.1\r\nHost: localhost\r\n\r\n", Request);

    EXPECT_EQ(Result, ParseStatus::Complete);
    EXPECT_EQ(Request.Method, "GET");
    EXPECT_EQ(Request.Target, "/Operations/Health?correlation=7");
    EXPECT_EQ(Request.ContentLength, 0U);
}

TEST(OperationsHttpParser, RejectsMalformedAndOversizedRequests)
{
    Prism::Operations::HttpRequest Request;
    EXPECT_EQ(Prism::Operations::RequestParserDetail::ParseRequest(
                  "GET /Operations/Health HTTP/1.0\r\nHost: localhost\r\n\r\n", Request),
              ParseStatus::Malformed);
    EXPECT_EQ(Prism::Operations::RequestParserDetail::ParseRequest(
                  "GET /Operations/Health HTTP/1.1\r\n\r\n", Request),
              ParseStatus::Malformed);

    const std::string Oversized(Prism::Operations::MaxRequestBytes + 1U, 'x');
    EXPECT_EQ(Prism::Operations::RequestParserDetail::ParseRequest(
                  Oversized, Request),
              ParseStatus::Oversized);
}

TEST(OperationsHttpRoutes, RegistersReloadAsATypedCommand)
{
    Prism::Operations::HttpRequest Request;
    Request.Method = "POST";
    Request.Target = "/Operations/Reload";
    Request.Correlation = "9";
    Request.ContentType = "application/json";
    Request.Body = R"json({"mode":"apply","base_generation":"4","configuration":{}})json";

    std::atomic<std::uint64_t> NextCorrelation{1};
    const auto Route = Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);

    ASSERT_TRUE(Route.has_value());
    const auto *CommandValue = std::get_if<Prism::Operations::Command>(&*Route);
    ASSERT_NE(CommandValue, nullptr);
    const auto *Reload = std::get_if<Prism::Operations::ReloadCommand>(&CommandValue->Value);
    ASSERT_NE(Reload, nullptr);
    EXPECT_EQ(Reload->BaseGeneration, Prism::GenerationId{4});
    EXPECT_EQ(Reload->Mode, Prism::Operations::ReloadMode::Apply);
    EXPECT_EQ(Reload->ConfigurationJson, "{}");
    EXPECT_EQ(Reload->Correlation, Prism::RequestId{9});
}

TEST(OperationsHttpRoutes, RejectsReloadQueryParameters)
{
    Prism::Operations::HttpRequest Request;
    Request.Method = "POST";
    Request.Target = "/Operations/Reload?correlation=9";
    Request.Correlation = "9";
    Request.ContentType = "application/json";
    Request.Body = R"json({"mode":"apply","base_generation":"4","configuration":{}})json";

    std::atomic<std::uint64_t> NextCorrelation{1};
    const auto Route = Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);

    ASSERT_FALSE(Route.has_value());
    EXPECT_EQ(Route.error().Status, 400);
    EXPECT_EQ(Route.error().Message, "bad_command");
}

TEST(OperationsHttpRoutes, PreservesCancelStreamAndTaskSelectors)
{
    Prism::Operations::HttpRequest Request;
    Request.Method = "POST";
    Request.Target =
        "/Operations/Processes/1/Workers/2/Sessions/44/Tasks/8/Cancel?"
        "generation=3&stream=7&parent_task=6&correlation=10";

    std::atomic<std::uint64_t> NextCorrelation{1};
    const auto Route = Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);

    ASSERT_TRUE(Route.has_value());
    const auto *CommandValue = std::get_if<Prism::Operations::Command>(&*Route);
    ASSERT_NE(CommandValue, nullptr);
    const auto *Cancel = std::get_if<Prism::Operations::CancelCommand>(&CommandValue->Value);
    ASSERT_NE(Cancel, nullptr);
    EXPECT_EQ(Cancel->Process, Prism::ProcessId{1});
    EXPECT_EQ(Cancel->Generation, Prism::GenerationId{3});
    EXPECT_EQ(Cancel->Worker, Prism::WorkerId{2});
    EXPECT_EQ(Cancel->Session, Prism::SessionId{44});
    EXPECT_EQ(Cancel->Stream, Prism::StreamId{7});
    EXPECT_EQ(Cancel->ParentTask, Prism::TaskId{6});
    EXPECT_EQ(Cancel->Task, Prism::TaskId{8});
    EXPECT_EQ(Cancel->Correlation, Prism::RequestId{10});

    Request.Target = "/Operations/Processes/1/Sessions/44/Streams/7/Reset?"
        "generation=3&worker=2&parent_task=6&task=8&correlation=11";
    const auto StreamRoute = Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);
    ASSERT_TRUE(StreamRoute.has_value());
    const auto *StreamCommand = std::get_if<Prism::Operations::Command>(&*StreamRoute);
    ASSERT_NE(StreamCommand, nullptr);
    const auto *StreamReset = std::get_if<Prism::Operations::StreamResetCommand>(
        &StreamCommand->Value);
    ASSERT_NE(StreamReset, nullptr);
    EXPECT_EQ(StreamReset->Process, Prism::ProcessId{1});
    EXPECT_EQ(StreamReset->Generation, Prism::GenerationId{3});
    EXPECT_EQ(StreamReset->Worker, Prism::WorkerId{2});
    EXPECT_EQ(StreamReset->Session, Prism::SessionId{44});
    EXPECT_EQ(StreamReset->Stream, Prism::StreamId{7});
    EXPECT_EQ(StreamReset->ParentTask, Prism::TaskId{6});
    EXPECT_EQ(StreamReset->Task, Prism::TaskId{8});
    EXPECT_EQ(StreamReset->Correlation, Prism::RequestId{11});
}

TEST(OperationsHttpRoutes, RejectsStreamResetWithoutExactParentAndTaskScope)
{
    Prism::Operations::HttpRequest Request;
    Request.Method = "POST";
    Request.Target = "/Operations/Processes/1/Sessions/44/Streams/7/Reset?correlation=11";

    std::atomic<std::uint64_t> NextCorrelation{1};
    const auto Route = Prism::Operations::RouteDispatch::BuildRoute(Request, NextCorrelation);

    EXPECT_FALSE(Route.has_value());
}

TEST(OperationsHttpServer, RoutesHealthWithCorrelationAndRedactedValues)
{
    Net::io_context Io;
    Router RouterValue(Io.get_executor(),
        Prism::Operations::RouterHandlers{[](Query QueryValue) -> Net::awaitable<QueryResult>
            {
                const auto Correlation = Prism::Operations::CorrelationOf(QueryValue);
                HealthSnapshot Health;
                Health.Status = Prism::Operations::HealthStatus::Healthy;
                Health.Ready = true;
                co_return QueryResult::Health(Correlation, Health);
            },
            {}});
    auto Server = MakeServer(std::move(RouterValue), Io);

    const auto Exchange = RunExchange(
        Io,
        Server,
        "GET /Operations/Health?correlation=7 HTTP/1.1\r\nHost: localhost\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("HTTP/1.1 200"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"correlation\":\"7\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"ready\":true"), std::string::npos);
}

TEST(OperationsHttpServer, ReturnsTypedStreamSnapshotFromQueryOwner)
{
    Net::io_context Io;
    Router RouterValue(Io.get_executor(),
        Prism::Operations::RouterHandlers{MakeStreamQuerySnapshot, {}});
    auto Server = MakeServer(std::move(RouterValue), Io);

    const auto Exchange = RunExchange(
        Io,
        Server,
        "GET /Operations/Processes/1/Sessions/2/Streams/3?generation=4&worker=5&correlation=71 "
        "HTTP/1.1\r\nHost: localhost\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("HTTP/1.1 200"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"process\":\"1\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"session\":\"2\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"task\":\"8\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"parent_task\":\"6\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"generation\":\"4\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"state\":\"active\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"up_bytes\":\"5\""), std::string::npos);
}

TEST(OperationsHttpServer, ExposesIndependentTcpUdpAndQuicReadiness)
{
    Net::io_context Io;
    Router RouterValue(Io.get_executor(),
        Prism::Operations::RouterHandlers{MakeDegradedHealth,
            {}});
    auto Server = MakeServer(std::move(RouterValue), Io);

    const auto Exchange = RunExchange(
        Io,
        Server,
        "GET /Operations/Health?correlation=70 HTTP/1.1\r\nHost: localhost\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("\"correlation\":\"70\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"status\":\"degraded\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"ready\":false"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"tcp_ready\":true"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"udp_ready\":false"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"quic_ready\":true"), std::string::npos);
}

TEST(OperationsHttpServer, FailsClosedWhenHandlerIsUnavailable)
{
    Net::io_context Io;
    auto Server = MakeServer(Router(Io.get_executor()), Io);

    const auto Exchange = RunExchange(
        Io,
        Server,
        "GET /Operations/Health HTTP/1.1\r\nHost: localhost\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("HTTP/1.1 503"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("handler_unavailable"), std::string::npos);
}

TEST(OperationsHttpServer, RedactsQueryValuesBeforeJsonSerialization)
{
    Net::io_context Io;
    Router RouterValue(Io.get_executor(),
        Prism::Operations::RouterHandlers{[](Query QueryValue) -> Net::awaitable<QueryResult>
            {
                const auto QueryData = std::get<Prism::Operations::AccountQuery>(QueryValue.Value);
                AccountSnapshot Account;
                Account.Id = Prism::AccountId{3};
                Account.Label = "token=operations-secret";
                co_return QueryResult::Accounts(QueryData.Correlation,
                    Prism::Operations::Page<AccountSnapshot>{{Account}, Account.Id.Value(), false});
            },
            {}});
    auto Server = MakeServer(std::move(RouterValue), Io);

    const auto Exchange = RunExchange(
        Io,
        Server,
        "GET /Operations/Accounts?correlation=8 HTTP/1.1\r\nHost: localhost\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("<redacted>"), std::string::npos);
    EXPECT_EQ(Exchange.Response.find("operations-secret"), std::string::npos);
}

TEST(OperationsHttpServer, RejectsMalformedRequestsAtTheWireBoundary)
{
    Net::io_context Io;
    auto Server = MakeServer(Router(Io.get_executor()), Io);

    const auto Exchange = RunExchange(
        Io,
        Server,
        "GET /Operations/Health HTTP/1.1\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("HTTP/1.1 400"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("bad_request"), std::string::npos);
}

TEST(OperationsHttpServer, RoutesAcceptedCommandsWithOperationId)
{
    Net::io_context Io;
    Router RouterValue(Io.get_executor(),
        Prism::Operations::RouterHandlers{{}, [](Command CommandValue,
            Prism::Operations::OperationCompletion) -> Net::awaitable<CommandResult>
            { co_return CommandResult::Accepted(Prism::Operations::CorrelationOf(CommandValue)); }});
    auto Server = MakeServer(std::move(RouterValue), Io);
    const std::string Body =
        R"({"mode":"apply","base_generation":"4","configuration":{}})";
    const std::string Request =
        std::string{"POST /Operations/Reload HTTP/1.1\r\nHost: localhost\r\nX-Correlation-Id: 11\r\n"} +
        "Content-Type: application/json\r\nContent-Length: " + std::to_string(Body.size()) + "\r\n\r\n" + Body;

    const auto Exchange = RunExchange(
        Io,
        Server,
        Request);

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("HTTP/1.1 202"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"correlation\":\"11\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"operation\":\"1\""), std::string::npos);
}

TEST(OperationsHttpServer, RoutesGetOperationStatus)
{
    Net::io_context Io;
    Router RouterValue(Io.get_executor(),
        Prism::Operations::RouterHandlers{{}, [](Command CommandValue,
            Prism::Operations::OperationCompletion) -> Net::awaitable<CommandResult>
            { co_return CommandResult::Accepted(Prism::Operations::CorrelationOf(CommandValue)); }});

    Prism::Operations::ReloadCommand Reload;
    Reload.Correlation = Prism::RequestId{214};
    const auto Accepted =
        RunAwaitable(Io, ExecuteCommand(RouterValue, Command{Reload}));
    ASSERT_EQ(Accepted.Status, Prism::Operations::CommandStatus::Accepted);
    ASSERT_EQ(Accepted.Operation, Prism::Operations::OperationId{1});

    auto Server = MakeServer(std::move(RouterValue), Io);
    const auto Exchange = RunExchange(
        Io,
        Server,
        "GET /Operations/Operations/1?correlation=215 HTTP/1.1\r\nHost: localhost\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("HTTP/1.1 202"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"status\":\"accepted\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"operation\":\"1\""), std::string::npos);
}

TEST(OperationsHttpServer, OmitsEventDetailsWhenIncludeDetailsIsFalse)
{
    Net::io_context Io;
    Router RouterValue(Io.get_executor(),
        Prism::Operations::RouterHandlers{[](Query QueryValue) -> Net::awaitable<QueryResult>
            {
                const auto QueryData = std::get<Prism::Operations::EventQuery>(QueryValue.Value);
                Prism::Operations::EventSnapshot Event;
                Event.Sequence = 1;
                Event.Detail = "api_key=event-secret";
                co_return QueryResult::Events(QueryData.Correlation,
                    Prism::Statistics::EventPage{{Event}, 1, false});
            },
            {}});
    auto Server = MakeServer(std::move(RouterValue), Io);

    const auto Exchange = RunExchange(
        Io,
        Server,
        "GET /Operations/Events?include_details=false&correlation=216 HTTP/1.1\r\n"
        "Host: localhost\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_EQ(Exchange.Response.find("\"detail\""), std::string::npos);
    EXPECT_EQ(Exchange.Response.find("event-secret"), std::string::npos);
}

TEST(OperationsHttpServer, RejectsNonLoopbackBindAtTheApiBoundary)
{
    Net::io_context Io;
    HttpServer Server(HttpServer::Options{
        Io.get_executor(),
        Tcp::endpoint(Tcp::v4(), 0),
        Router(Io.get_executor()),
        std::chrono::milliseconds{5000},
        std::chrono::milliseconds{5000},
        MakeTestBootstrap()});
    bool Completed = false;
    bool Rejected = false;
    std::exception_ptr Failure;

    Net::co_spawn(
        Io,
        [&]() -> Net::awaitable<void>
        {
            const auto Started = co_await Server.Start();
            Rejected = !Started;
            Completed = true;
            Io.stop();
        },
        [&](std::exception_ptr Error)
        {
            Failure = std::move(Error);
            Io.stop();
        });
    Io.run();

    EXPECT_FALSE(Failure);
    EXPECT_TRUE(Completed);
    EXPECT_TRUE(Rejected);
}

TEST(OperationsHttpServer, DrainBeforeStartIsTerminal)
{
    Net::io_context Io;
    auto Server = MakeServer(Router(Io.get_executor()), Io);
    bool Completed = false;
    bool StartedAfterDrain = true;
    std::exception_ptr Failure;

    Net::co_spawn(
        Io,
        [&]() -> Net::awaitable<void>
        {
            (void)co_await Server.Drain(HttpServer::Deadline::max());
            const auto Started = co_await Server.Start();
            StartedAfterDrain = static_cast<bool>(Started);
            Completed = true;
            Io.stop();
        },
        [&](std::exception_ptr Error)
        {
            Failure = std::move(Error);
            Io.stop();
        });
    Io.run();

    EXPECT_FALSE(Failure);
    EXPECT_TRUE(Completed);
    EXPECT_FALSE(StartedAfterDrain);
}

TEST(OperationsHttpServer, ConfiguredReadDeadlineClosesAnIdleAcceptedSocket)
{
    Net::io_context Io;
    HttpServer::Options Options{
        Io.get_executor(),
        Tcp::endpoint(Net::ip::address_v4::loopback(), 0),
        Router(Io.get_executor()),
        std::chrono::milliseconds{5000},
        std::chrono::milliseconds{5000},
        MakeTestBootstrap()};
    Options.ReadDeadline = std::chrono::milliseconds{25};
    HttpServer Server(std::move(Options));

    const auto Result = std::make_shared<IdleSocketOutcome>();
    const auto Watchdog = std::make_shared<Net::steady_timer>(Io);

    Net::co_spawn(
        Io,
        RunIdleSocketScenario(IdleSocketRequest{Server, Io, Result, Watchdog}),
        [Result](std::exception_ptr Error)
        {
            Result->Failure = std::move(Error);
            Result->Completed = true;
        });

    Net::co_spawn(
        Io,
        RunIdleSocketWatchdog(Io, Result, Watchdog),
        Net::detached);

    Io.run();

    EXPECT_FALSE(Result->Failure);
    EXPECT_TRUE(Result->Completed);
    EXPECT_TRUE(Result->Closed);
    EXPECT_FALSE(Result->TimedOut);
}

TEST(OperationsHttpServer, DrainClosesAllAcceptedSockets)
{
    Net::io_context Io;
    auto Server = MakeServer(Router(Io.get_executor()), Io);
    const auto Result = std::make_shared<DrainSocketOutcome>();
    const auto Watchdog = std::make_shared<Net::steady_timer>(Io);

    Net::co_spawn(
        Io,
        RunDrainSocketScenario(DrainSocketRequest{Server, Io, Result, Watchdog}),
        [Result](std::exception_ptr Error)
        {
            Result->Failure = std::move(Error);
        });

    Net::co_spawn(
        Io,
        RunDrainSocketWatchdog(Io, Result, Watchdog),
        Net::detached);

    Io.run();

    EXPECT_FALSE(Result->Failure);
    EXPECT_TRUE(Result->Drained);
    EXPECT_FALSE(Result->TimedOut);
}

TEST(OperationsHttpServer, StopAndDrainAreIdempotent)
{
    Net::io_context Io;
    auto Server = MakeServer(Router(Io.get_executor()), Io);
    bool Completed = false;
    std::exception_ptr Failure;

    Net::co_spawn(
        Io,
        RunIdempotentDrainScenario(Server, Completed),
        [&](std::exception_ptr Error)
        {
            Failure = std::move(Error);
            Io.stop();
        });
    Io.run();

    EXPECT_FALSE(Failure);
    EXPECT_TRUE(Completed);
}

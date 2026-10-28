/**
 * @file ConnectionEndTest.cpp
 * @brief Operations HTTP 同次字节/终态读取与半关闭回归。
 */

#include <gtest/gtest.h>

#include <Prism/Operations/Http/Detail/ReadCompletion.hpp>
#include <Prism/Operations/Http/Detail/Connection.hpp>
#include <Prism/Operations/HttpServer.hpp>
#include <Prism/Operations/Routes/RouteDispatch.hpp>
#include <Prism/Operations/Routes/RequestParser.hpp>
#include <Prism/Operations/Web/Catalog.hpp>

#include "AuthSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/errc.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace
{

    namespace Net = boost::asio;
    namespace HttpConnection = Prism::Operations::HttpConnection;
    using HttpServer = Prism::Operations::HttpServer;
    using Query = Prism::Operations::Query;
    using QueryResult = Prism::Operations::QueryResult;
    using Router = Prism::Operations::Router;
    using Tcp = Net::ip::tcp;
    using Prism::Testing::OperationsHttp::MakeTestBootstrap;
    using Prism::Testing::OperationsHttp::MakeServer;
    using Prism::Testing::OperationsHttp::PrepareRequest;

    struct WireReadResult final
    {
        std::string Bytes;
        boost::system::error_code Failure;
        bool Closed{false};
    };

    struct HttpScenarioResult final
    {
        WireReadResult Response;
        boost::system::error_code Failure;
        bool WriteHalfClosed{false};
        bool CloseAdmissionSucceeded{false};
        bool DrainSucceeded{false};
    };

    struct HttpScenarioRequest final
    {
        HttpServer &Server;
        std::string Request;
    };

    struct HttpDispatchState final
    {
        HttpDispatchState(HttpServer::Endpoint EndpointValue, Router RouterValue)
            : Bootstrap(MakeTestBootstrap()), LocalEndpoint(std::move(EndpointValue)),
              OperationsRouter(std::move(RouterValue))
        {
        }

        std::shared_ptr<const Prism::Operations::BootstrapIdentity> Bootstrap;
        HttpServer::Endpoint LocalEndpoint;
        std::shared_ptr<const Prism::Operations::Web::Catalog> WebResources;
        Router OperationsRouter;
        std::atomic<std::uint64_t> NextCorrelation{1U};
        std::atomic<bool> StateOperationFailed{false};
    };

    struct NativeTerminalOwnerResult final
    {
        WireReadResult Response;
        std::optional<Prism::Fault::Failure> DeliveryFailure;
        boost::system::error_code SetupFailure;
        boost::system::error_code Terminal;
        Prism::Operations::RequestParserDetail::ParseStatus ParseStatus{
            Prism::Operations::RequestParserDetail::ParseStatus::Incomplete};
        std::size_t HandlerCalls{0U};
        bool DeliveryCompleted{false};
        bool ResponseOutstanding{true};
        bool StateOperationFailed{false};
    };

    [[nodiscard]] auto ReadUntilClose(Tcp::socket &Socket)
        -> Net::awaitable<WireReadResult>
    {
        WireReadResult Result;
        std::array<char, 4096> Buffer{};
        while (true)
        {
            boost::system::error_code Error;
            const auto Count = co_await Socket.async_read_some(
                Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Error));
            if (Count != 0U)
            {
                Result.Bytes.append(Buffer.data(), Count);
            }
            if (Error)
            {
                if (Error == Net::error::eof)
                {
                    Result.Closed = true;
                }
                else
                {
                    Result.Failure = Error;
                }
                co_return Result;
            }
            if (Count == 0U)
            {
                Result.Failure = boost::system::errc::make_error_code(
                    boost::system::errc::io_error);
                co_return Result;
            }
        }
    }

    [[nodiscard]] auto MakeHealthRouter(
        Net::io_context &Io,
        std::atomic<std::size_t> &HandlerCalls) -> Router
    {
        return Router(Io.get_executor(),
            Prism::Operations::RouterHandlers{
                [&HandlerCalls](Query Value) -> Net::awaitable<QueryResult>
                {
                    HandlerCalls.fetch_add(1U, std::memory_order_relaxed);
                    Prism::Operations::HealthSnapshot Health;
                    Health.Status = Prism::Operations::HealthStatus::Healthy;
                    Health.Ready = true;
                    co_return QueryResult::Health(
                        Prism::Operations::CorrelationOf(Value), Health);
                },
                {}});
    }

    [[nodiscard]] auto RunHttpScenario(HttpScenarioRequest Request)
        -> Net::awaitable<HttpScenarioResult>
    {
        HttpScenarioResult Result;
        const auto Started = co_await Request.Server.Start();
        if (!Started)
        {
            Result.Failure = Started.error();
        }
        else if (!PrepareRequest(Request.Request, *Started, std::nullopt))
        {
            Result.Failure = boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
        }
        else
        {
            Tcp::socket Socket(co_await Net::this_coro::executor);
            co_await Socket.async_connect(
                *Started, Net::redirect_error(Net::use_awaitable, Result.Failure));
            if (!Result.Failure)
            {
                co_await Net::async_write(Socket, Net::buffer(Request.Request),
                    Net::redirect_error(Net::use_awaitable, Result.Failure));
            }
            if (!Result.Failure)
            {
                Socket.shutdown(Tcp::socket::shutdown_send, Result.Failure);
                Result.WriteHalfClosed = !Result.Failure;
            }
            if (!Result.Failure)
            {
                Result.Response = co_await ReadUntilClose(Socket);
                if (Result.Response.Failure)
                {
                    Result.Failure = Result.Response.Failure;
                }
            }
            boost::system::error_code CloseError;
            Socket.close(CloseError);
            if (CloseError && !Result.Failure)
            {
                Result.Failure = CloseError;
            }
        }
        Result.CloseAdmissionSucceeded = Request.Server.CloseAdmission().has_value();
        const auto Drain = co_await Request.Server.Drain(HttpServer::Deadline::max());
        Result.DrainSucceeded = Drain.Failure.Succeeded() && Drain.RemainingConnections == 0U;
        co_return Result;
    }

    template <typename Value>
    [[nodiscard]] auto RunAwaitable(Net::io_context &Io,
        Net::awaitable<Value> Operation) -> Value
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

    [[nodiscard]] auto HealthRequest() -> std::string
    {
        return "GET /Operations/Health?correlation=31 HTTP/1.1\r\n"
               "Host: localhost\r\n\r\n";
    }

    [[nodiscard]] auto RunNativeTerminalOwnerScenario(Net::io_context &Io)
        -> Net::awaitable<NativeTerminalOwnerResult>
    {
        NativeTerminalOwnerResult Result;
        const auto Executor = co_await Net::this_coro::executor;
        Tcp::acceptor Acceptor(Executor,
            Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        const auto Endpoint = Acceptor.local_endpoint();
        std::atomic<std::size_t> HandlerCalls{0U};
        auto State = std::make_shared<HttpDispatchState>(Endpoint,
            MakeHealthRouter(Io, HandlerCalls));
        auto Connection = std::make_shared<HttpConnection::ConnectionState>(Executor);
        Tcp::socket Peer(Executor);
        co_await Peer.async_connect(Endpoint, Net::use_awaitable);
        co_await Acceptor.async_accept(*Connection->Socket, Net::use_awaitable);

        auto Request = HealthRequest();
        if (!PrepareRequest(Request, Endpoint, std::nullopt))
        {
            Result.SetupFailure = boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
            co_return Result;
        }
        HttpConnection::Detail::RequestReadState ReadState;
        const auto Native = Net::error::connection_reset;
        const auto Completion = HttpConnection::Detail::ApplyReadCompletion(ReadState,
            HttpConnection::Detail::ReadCompletion{
                std::span<const char>(Request.data(), Request.size()), Native});
        Result.Terminal = Completion.Terminal;
        Result.ParseStatus = Completion.Status;
        if (Completion.Action != HttpConnection::Detail::ReadAction::Parsed)
        {
            Result.SetupFailure = boost::system::errc::make_error_code(
                boost::system::errc::invalid_argument);
            co_return Result;
        }

        auto Input = HttpConnection::MakeRequestReadResult(
            std::move(ReadState), HttpConnection::RequestByteLease{}, Completion.Terminal);
        Result.SetupFailure = Input.Ready ? boost::system::error_code{}
            : boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        if (Result.SetupFailure)
        {
            co_return Result;
        }
        Result.Terminal = Input.Terminal;
        auto Routed = co_await Net::co_spawn(Connection->Strand,
            HttpConnection::DispatchRequest(State, Connection, std::move(Input)),
            Net::use_awaitable);
        if (!Routed.Delivery)
        {
            Result.SetupFailure = boost::system::errc::make_error_code(
                boost::system::errc::permission_denied);
            co_return Result;
        }
        const auto Delivery = *Routed.Delivery;
        co_await Net::co_spawn(Connection->Strand,
            HttpConnection::FinishRoutedRequest(
                State, Connection, std::move(Routed)), Net::use_awaitable);
        Result.Response = co_await ReadUntilClose(Peer);
        const auto DeliveryOutcome = co_await Delivery.WaitAsync(HttpServer::Deadline::max());
        Result.DeliveryCompleted = true;
        if (!DeliveryOutcome)
        {
            Result.DeliveryFailure = DeliveryOutcome.error();
        }
        Result.HandlerCalls = HandlerCalls.load(std::memory_order_relaxed);
        Result.ResponseOutstanding =
            Connection->ResponseOutstanding.load(std::memory_order_acquire);
        Result.StateOperationFailed =
            State->StateOperationFailed.load(std::memory_order_acquire);
        co_return Result;
    }

} // namespace

TEST(OperationsHttpReadCompletion, ParsesBytesBeforeRetainingEof)
{
    const std::string Request = HealthRequest();
    HttpConnection::Detail::RequestReadState State;
    const auto Result = HttpConnection::Detail::ApplyReadCompletion(State,
        HttpConnection::Detail::ReadCompletion{
            std::span<const char>(Request.data(), Request.size()), Net::error::eof});

    EXPECT_EQ(Result.Action, HttpConnection::Detail::ReadAction::Parsed);
    EXPECT_EQ(Result.Status, Prism::Operations::RequestParserDetail::ParseStatus::Complete);
    EXPECT_EQ(Result.Terminal, Net::error::eof);
    EXPECT_EQ(State.Bytes, Request);
    EXPECT_EQ(State.Parsed.Method, "GET");
    EXPECT_EQ(State.Parsed.Target, "/Operations/Health?correlation=31");
}

TEST(OperationsHttpReadCompletion, ParsesBytesBeforeRetainingNativeFailure)
{
    const std::string Request = HealthRequest();
    const auto Native = Net::error::connection_reset;
    HttpConnection::Detail::RequestReadState State;
    const auto Result = HttpConnection::Detail::ApplyReadCompletion(State,
        HttpConnection::Detail::ReadCompletion{
            std::span<const char>(Request.data(), Request.size()), Native});

    EXPECT_EQ(Result.Action, HttpConnection::Detail::ReadAction::Parsed);
    EXPECT_EQ(Result.Status, Prism::Operations::RequestParserDetail::ParseStatus::Complete);
    EXPECT_EQ(Result.Terminal, Native);
    EXPECT_EQ(State.Bytes, Request);
    EXPECT_EQ(State.Parsed.Target, "/Operations/Health?correlation=31");
}

TEST(OperationsHttpReadCompletion, IncompleteBytesWithEofRemainTerminal)
{
    const std::string Request =
        "GET /Operations/Health HTTP/1.1\r\nHost: localhost\r\n";
    HttpConnection::Detail::RequestReadState State;
    const auto Result = HttpConnection::Detail::ApplyReadCompletion(State,
        HttpConnection::Detail::ReadCompletion{
            std::span<const char>(Request.data(), Request.size()), Net::error::eof});

    EXPECT_EQ(Result.Action, HttpConnection::Detail::ReadAction::Terminal);
    EXPECT_EQ(Result.Status, Prism::Operations::RequestParserDetail::ParseStatus::Incomplete);
    EXPECT_EQ(Result.Terminal, Net::error::eof);
    EXPECT_EQ(State.Bytes, Request);
}

TEST(OperationsHttpReadCompletion, PreservesPartialBytesWithNativeFailure)
{
    const std::string Request =
        "GET /Operations/Health HTTP/1.1\r\nHost: localhost\r\n";
    const auto Native = Net::error::connection_reset;
    HttpConnection::Detail::RequestReadState State;
    const auto Result = HttpConnection::Detail::ApplyReadCompletion(State,
        HttpConnection::Detail::ReadCompletion{
            std::span<const char>(Request.data(), Request.size()), Native});

    EXPECT_EQ(Result.Action, HttpConnection::Detail::ReadAction::Terminal);
    EXPECT_EQ(Result.Status, Prism::Operations::RequestParserDetail::ParseStatus::Incomplete);
    EXPECT_EQ(Result.Terminal, Native);
    EXPECT_EQ(State.Bytes, Request);
}

TEST(OperationsHttpReadDeadline, ClassifiesTimerAndSocketCancelFailures)
{
    using Source = HttpConnection::Detail::ReadDeadlineErrorSource;
    using HttpConnection::Detail::HasUnexpectedReadDeadlineError;
    Net::io_context Io;
    std::atomic<std::size_t> CancelCalls{0U};
    std::atomic<std::size_t> FailureCalls{0U};
    HttpConnection::Detail::ReadDeadlineActions Actions{
        .CancelSocket = [&CancelCalls]
        {
            CancelCalls.fetch_add(1U, std::memory_order_relaxed);
            return boost::system::error_code{};
        },
        .ReportFailure = [&FailureCalls](
            const std::shared_ptr<HttpConnection::Detail::ReadDeadlineTask> &,
            const boost::system::error_code &)
        {
            FailureCalls.fetch_add(1U, std::memory_order_relaxed);
        }};
    const auto Task = std::make_shared<HttpConnection::Detail::ReadDeadlineTask>(
        Io.get_executor(), std::chrono::seconds(1), std::move(Actions));

    EXPECT_FALSE(HasUnexpectedReadDeadlineError(Source::TimerWait, {}));
    EXPECT_FALSE(HasUnexpectedReadDeadlineError(Source::TimerWait, Net::error::operation_aborted));
    EXPECT_TRUE(HasUnexpectedReadDeadlineError(
        Source::TimerWait, boost::system::errc::make_error_code(
            boost::system::errc::io_error)));
    EXPECT_TRUE(HasUnexpectedReadDeadlineError(
        Source::TimerCancel, Net::error::operation_aborted));
    EXPECT_FALSE(HasUnexpectedReadDeadlineError(Source::SocketCancel, {}));
    EXPECT_TRUE(HasUnexpectedReadDeadlineError(
        Source::SocketCancel, Net::error::operation_aborted));
    EXPECT_TRUE(HasUnexpectedReadDeadlineError(
        Source::SocketCancel, boost::system::errc::make_error_code(
            boost::system::errc::bad_file_descriptor)));
    HttpConnection::Detail::CompleteReadDeadlineWait(Task, Net::error::operation_aborted);
    HttpConnection::Detail::CompleteReadDeadlineTask(Task, {});
    EXPECT_EQ(CancelCalls.load(std::memory_order_relaxed), 0U);
    EXPECT_EQ(FailureCalls.load(std::memory_order_relaxed), 0U);
    EXPECT_FALSE(Task->Failed);
    EXPECT_TRUE(Task->Finished);
}

TEST(OperationsHttpConnection, NativeReadTerminalRoutesThenFailsReceiptWithoutWriting)
{
    Net::io_context Io;
    const auto Result = RunAwaitable(Io, RunNativeTerminalOwnerScenario(Io));

    EXPECT_FALSE(Result.SetupFailure);
    EXPECT_EQ(Result.ParseStatus,
        Prism::Operations::RequestParserDetail::ParseStatus::Complete);
    EXPECT_EQ(Result.Terminal, Net::error::connection_reset);
    EXPECT_EQ(Result.HandlerCalls, 1U);
    EXPECT_TRUE(Result.Response.Closed);
    EXPECT_TRUE(Result.Response.Bytes.empty());
    EXPECT_FALSE(Result.Response.Failure);
    ASSERT_TRUE(Result.DeliveryCompleted);
    ASSERT_TRUE(Result.DeliveryFailure);
    const auto ExpectedNative = static_cast<std::error_code>(
        boost::system::error_code(Net::error::connection_reset));
    EXPECT_EQ(Result.DeliveryFailure->Native,
        ExpectedNative);
    EXPECT_FALSE(Result.ResponseOutstanding);
    EXPECT_FALSE(Result.StateOperationFailed);
}

TEST(OperationsHttpConnection, CloseRequestedBeforeRouteRejectsCompleteRequest)
{
    Net::io_context Io;
    std::atomic<std::size_t> HandlerCalls{0U};
    auto State = std::make_shared<HttpDispatchState>(
        Tcp::endpoint(Net::ip::address_v4::loopback(), 1),
        MakeHealthRouter(Io, HandlerCalls));
    auto Connection = std::make_shared<HttpConnection::ConnectionState>(Io.get_executor());
    Connection->CloseRequested.store(true, std::memory_order_release);

    const auto Result = RunAwaitable(Io,
        Net::co_spawn(Connection->Strand,
            HttpConnection::DispatchRequest(State, Connection,
                HttpConnection::RequestReadResult{true, HealthRequest(), {}, {}}),
            Net::use_awaitable));

    EXPECT_TRUE(Result.Closed);
    EXPECT_FALSE(Result.Delivery);
    EXPECT_EQ(HandlerCalls.load(std::memory_order_relaxed), 0U);
}

TEST(OperationsHttpConnection, WritesResponseAfterClientWriteHalfClose)
{
    Net::io_context Io;
    std::atomic<std::size_t> HandlerCalls{0U};
    HttpScenarioResult Result;
    {
        auto Server = MakeServer(MakeHealthRouter(Io, HandlerCalls), Io);
        Result = RunAwaitable(Io,
            RunHttpScenario(HttpScenarioRequest{Server, HealthRequest()}));
    }
    Io.restart();
    Io.run();

    EXPECT_FALSE(Result.Failure);
    EXPECT_TRUE(Result.WriteHalfClosed);
    EXPECT_TRUE(Result.Response.Closed);
    EXPECT_TRUE(Result.Response.Bytes.starts_with("HTTP/1.1 200"));
    EXPECT_NE(Result.Response.Bytes.find("\"ready\":true"), std::string::npos);
    EXPECT_EQ(HandlerCalls.load(std::memory_order_relaxed), 1U);
    EXPECT_TRUE(Result.CloseAdmissionSucceeded);
    EXPECT_TRUE(Result.DrainSucceeded);
}

TEST(OperationsHttpConnection, DoesNotDispatchIncompleteHalfClosedRequest)
{
    Net::io_context Io;
    std::atomic<std::size_t> HandlerCalls{0U};
    const std::string PartialRequest =
        "GET /Operations/Health HTTP/1.1\r\nHost: localhost\r\n";
    HttpScenarioResult Result;
    {
        auto Server = MakeServer(MakeHealthRouter(Io, HandlerCalls), Io);
        Result = RunAwaitable(Io,
            RunHttpScenario(HttpScenarioRequest{Server, PartialRequest}));
    }
    Io.restart();
    Io.run();

    EXPECT_FALSE(Result.Failure);
    EXPECT_TRUE(Result.WriteHalfClosed);
    EXPECT_TRUE(Result.Response.Closed);
    EXPECT_TRUE(Result.Response.Bytes.empty());
    EXPECT_EQ(HandlerCalls.load(std::memory_order_relaxed), 0U);
    EXPECT_TRUE(Result.CloseAdmissionSucceeded);
    EXPECT_TRUE(Result.DrainSucceeded);
}

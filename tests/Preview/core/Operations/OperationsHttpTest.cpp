/**
 * @file OperationsHttpTest.cpp
 * @brief Operations HTTP listener 的解析、路由、脱敏与停机契约测试。
 */

#include <gtest/gtest.h>

#include <Preview/Operations/HttpServer.hpp>

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
    using Preview::Operations::Command;
    using Preview::Operations::CommandResult;
    using Preview::Operations::AccountSnapshot;
    using Preview::Operations::HealthSnapshot;
    using Preview::Operations::HttpServer;
    using Preview::Operations::ParseStatus;
    using Preview::Operations::Query;
    using Preview::Operations::QueryResult;
    using Preview::Operations::Router;

    struct HttpExchange final
    {
        std::string Response;
        boost::system::error_code Error;
    };

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

    [[nodiscard]] auto ReadResponse(Tcp::socket &Socket) -> Net::awaitable<std::string>
    {
        std::array<char, 4096> Chunk{};
        std::string Response;
        while (Response.find("\r\n\r\n") == std::string::npos)
        {
            boost::system::error_code Error;
            const auto Count = co_await Socket.async_read_some(
                Net::buffer(Chunk), Net::redirect_error(Net::use_awaitable, Error));
            if (Error || Count == 0U)
            {
                co_return Response;
            }
            Response.append(Chunk.data(), Count);
            if (Response.size() > 65536U)
            {
                co_return Response;
            }
        }

        const auto HeadersEnd = Response.find("\r\n\r\n");
        const auto LengthStart = Response.find("Content-Length:");
        if (LengthStart == std::string::npos)
        {
            co_return Response;
        }
        const auto ValueStart = Response.find_first_not_of(" \t", LengthStart + 15U);
        const auto ValueEnd = Response.find("\r\n", ValueStart);
        const auto Length = static_cast<std::size_t>(
            std::stoull(Response.substr(ValueStart, ValueEnd - ValueStart)));
        const auto BodyStart = HeadersEnd + 4U;
        while (Response.size() < BodyStart + Length)
        {
            boost::system::error_code Error;
            const auto Count = co_await Socket.async_read_some(
                Net::buffer(Chunk), Net::redirect_error(Net::use_awaitable, Error));
            if (Error || Count == 0U)
            {
                break;
            }
            Response.append(Chunk.data(), Count);
        }
        co_return Response;
    }

    [[nodiscard]] auto RunExchange(Net::io_context &Io,
                                   HttpServer &Server,
                                   std::string Request)
        -> HttpExchange
    {
        HttpExchange Result;
        Io.restart();
        Net::co_spawn(
            Io,
            [&Server, &Result, Request = std::move(Request)]() mutable -> Net::awaitable<void>
            {
                const auto Started = co_await Server.Start();
                if (!Started)
                {
                    Result.Error = Started.error();
                    co_return;
                }
                Tcp::socket Socket(co_await Net::this_coro::executor);
                co_await Socket.async_connect(
                    *Started, Net::redirect_error(Net::use_awaitable, Result.Error));
                if (Result.Error)
                {
                    co_return;
                }
                co_await Net::async_write(
                    Socket, Net::buffer(Request),
                    Net::redirect_error(Net::use_awaitable, Result.Error));
                if (!Result.Error)
                {
                    Result.Response = co_await ReadResponse(Socket);
                }
                boost::system::error_code CloseError;
                Socket.close(CloseError);
                Server.Stop();
                co_await Server.Drain();
            },
            [&](std::exception_ptr Failure)
            {
                if (Failure)
                {
                    Result.Error = make_error_code(boost::system::errc::operation_canceled);
                }
                Io.stop();
            });
        Io.run();
        return Result;
    }

    [[nodiscard]] auto MakeServer(Router RouterValue, Net::io_context &Io) -> HttpServer
    {
        return HttpServer(HttpServer::Options{
            Io.get_executor(),
            Tcp::endpoint(Net::ip::address_v4::loopback(), 0),
            std::move(RouterValue)});
    }

} // namespace

TEST(OperationsHttpParser, AcceptsBoundedHealthRequest)
{
    Preview::Operations::HttpRequest Request;
    const auto Result = Preview::Operations::ParseRequest(
        "GET /Operations/Health?correlation=7 HTTP/1.1\r\nHost: localhost\r\n\r\n", Request);

    EXPECT_EQ(Result, ParseStatus::Complete);
    EXPECT_EQ(Request.Method, "GET");
    EXPECT_EQ(Request.Target, "/Operations/Health?correlation=7");
    EXPECT_EQ(Request.ContentLength, 0U);
}

TEST(OperationsHttpParser, RejectsMalformedAndOversizedRequests)
{
    Preview::Operations::HttpRequest Request;
    EXPECT_EQ(Preview::Operations::ParseRequest(
                  "GET /Operations/Health HTTP/1.0\r\nHost: localhost\r\n\r\n", Request),
              ParseStatus::Malformed);
    EXPECT_EQ(Preview::Operations::ParseRequest(
                  "GET /Operations/Health HTTP/1.1\r\n\r\n", Request),
              ParseStatus::Malformed);

    const std::string Oversized(Preview::Operations::MaxRequestBytes + 1U, 'x');
    EXPECT_EQ(Preview::Operations::ParseRequest(Oversized, Request), ParseStatus::Oversized);
}

TEST(OperationsHttpServer, RoutesHealthWithCorrelationAndRedactedValues)
{
    Net::io_context Io;
    Router RouterValue(
        Io.get_executor(),
        [](const Query &QueryValue) -> QueryResult
        {
            const auto Correlation = Preview::Operations::CorrelationOf(QueryValue);
            HealthSnapshot Health;
            Health.Status = Preview::Operations::HealthStatus::Healthy;
            Health.Ready = true;
            return QueryResult::Health(Correlation, Health);
        });
    auto Server = MakeServer(std::move(RouterValue), Io);

    const auto Exchange = RunExchange(
        Io,
        Server,
        "GET /Operations/Health?correlation=7 HTTP/1.1\r\nHost: localhost\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("HTTP/1.1 200"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"correlation\":7"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"ready\":true"), std::string::npos);
}

TEST(OperationsHttpServer, ExposesIndependentTcpUdpAndQuicReadiness)
{
    Net::io_context Io;
    Router RouterValue(
        Io.get_executor(),
        [](const Query &QueryValue) -> QueryResult
        {
            const auto Correlation = Preview::Operations::CorrelationOf(QueryValue);
            HealthSnapshot Health;
            Health.Status = Preview::Operations::HealthStatus::Degraded;
            Health.Ready = false;
            Health.TcpReady = true;
            Health.UdpReady = false;
            Health.QuicReady = true;
            return QueryResult::Health(Correlation, Health);
        });
    auto Server = MakeServer(std::move(RouterValue), Io);

    const auto Exchange = RunExchange(
        Io,
        Server,
        "GET /Operations/Health?correlation=70 HTTP/1.1\r\nHost: localhost\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("\"correlation\":70"), std::string::npos);
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
    Router RouterValue(
        Io.get_executor(),
        [](const Query &QueryValue) -> QueryResult
        {
            const auto QueryData = std::get<Preview::Operations::AccountQuery>(QueryValue.Value);
            AccountSnapshot Account;
            Account.Id = Preview::AccountId{3};
            Account.Label = "token=operations-secret";
            return QueryResult::Accounts(
                QueryData.Correlation,
                Preview::Operations::Page<AccountSnapshot>{{Account}, Account.Id.Value(), false});
        });
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
    Router RouterValue(
        Io.get_executor(),
        {},
        [](const Command &CommandValue) -> CommandResult
        {
            return CommandResult::Accepted(Preview::Operations::CorrelationOf(CommandValue));
        });
    auto Server = MakeServer(std::move(RouterValue), Io);

    const auto Exchange = RunExchange(
        Io,
        Server,
        "POST /Operations/Reload?correlation=11 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("HTTP/1.1 202"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"correlation\":11"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"operation\":1"), std::string::npos);
}

TEST(OperationsHttpServer, RoutesGetOperationStatus)
{
    Net::io_context Io;
    Router RouterValue(
        Io.get_executor(),
        {},
        [](const Command &CommandValue) -> CommandResult
        {
            return CommandResult::Accepted(Preview::Operations::CorrelationOf(CommandValue));
        });

    Preview::Operations::ReloadCommand Reload;
    Reload.Correlation = Preview::RequestId{214};
    const auto Accepted =
        RunAwaitable(Io, RouterValue.ExecuteAsync(Command{Reload}));
    ASSERT_EQ(Accepted.Status, Preview::Operations::CommandStatus::Accepted);
    ASSERT_EQ(Accepted.Operation, Preview::Operations::OperationId{1});

    auto Server = MakeServer(std::move(RouterValue), Io);
    const auto Exchange = RunExchange(
        Io,
        Server,
        "GET /Operations/Status/1?correlation=215 HTTP/1.1\r\nHost: localhost\r\n\r\n");

    EXPECT_FALSE(Exchange.Error);
    EXPECT_NE(Exchange.Response.find("HTTP/1.1 202"), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"status\":\"accepted\""), std::string::npos);
    EXPECT_NE(Exchange.Response.find("\"operation\":1"), std::string::npos);
}

TEST(OperationsHttpServer, OmitsEventDetailsWhenIncludeDetailsIsFalse)
{
    Net::io_context Io;
    Router RouterValue(
        Io.get_executor(),
        [](const Query &QueryValue) -> QueryResult
        {
            const auto QueryData = std::get<Preview::Operations::EventQuery>(QueryValue.Value);
            Preview::Operations::EventSnapshot Event;
            Event.Sequence = 1;
            Event.Detail = "api_key=event-secret";
            return QueryResult::Events(
                QueryData.Correlation,
                Preview::Operations::Page<Preview::Operations::EventSnapshot>{{Event}, 1, false});
        });
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
        Router(Io.get_executor())});
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
            co_await Server.Drain();
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
        Router(Io.get_executor())};
    Options.ReadDeadline = std::chrono::milliseconds{25};
    HttpServer Server(std::move(Options));

    struct Outcome final
    {
        bool Closed{false};
        bool TimedOut{false};
        bool Completed{false};
        std::exception_ptr Failure;
    };
    const auto Result = std::make_shared<Outcome>();
    const auto Watchdog = std::make_shared<Net::steady_timer>(Io);

    Net::co_spawn(
        Io,
        [&Server, &Io, Result, Watchdog]() -> Net::awaitable<void>
        {
            const auto Started = co_await Server.Start();
            if (!Started)
            {
                Result->Failure = std::make_exception_ptr(std::runtime_error("server_start_failed"));
                Result->Completed = true;
                Io.stop();
                co_return;
            }
            Tcp::socket Socket(co_await Net::this_coro::executor);
            boost::system::error_code Error;
            co_await Socket.async_connect(*Started, Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                Result->Failure = std::make_exception_ptr(std::runtime_error("connect_failed"));
                Result->Completed = true;
                Io.stop();
                co_return;
            }
            std::array<char, 1> Buffer{};
            co_await Socket.async_read_some(
                Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Error));
            Result->Closed = static_cast<bool>(Error);
            Result->Completed = true;
            Server.Stop();
            boost::system::error_code CloseError;
            Socket.close(CloseError);
            Watchdog->cancel();
            Io.stop();
        },
        [Result](std::exception_ptr Error)
        {
            Result->Failure = std::move(Error);
            Result->Completed = true;
        });

    Net::co_spawn(
        Io,
        [&Io, Result, Watchdog]() -> Net::awaitable<void>
        {
            Watchdog->expires_after(std::chrono::milliseconds{250});
            boost::system::error_code Error;
            co_await Watchdog->async_wait(Net::redirect_error(Net::use_awaitable, Error));
            if (!Error && !Result->Completed)
            {
                Result->TimedOut = true;
                Io.stop();
            }
        },
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
    struct Outcome final
    {
        bool Drained{false};
        bool TimedOut{false};
        std::exception_ptr Failure;
    };
    const auto Result = std::make_shared<Outcome>();
    const auto Watchdog = std::make_shared<Net::steady_timer>(Io);

    Net::co_spawn(
        Io,
        [&Server, &Io, Result, Watchdog]() -> Net::awaitable<void>
        {
            const auto Started = co_await Server.Start();
            if (!Started)
            {
                Result->Failure = std::make_exception_ptr(std::runtime_error("server_start_failed"));
                Io.stop();
                co_return;
            }
            Tcp::socket Socket(co_await Net::this_coro::executor);
            boost::system::error_code Error;
            co_await Socket.async_connect(*Started, Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                Result->Failure = std::make_exception_ptr(std::runtime_error("connect_failed"));
                Io.stop();
                co_return;
            }
            Net::steady_timer Delay(co_await Net::this_coro::executor);
            Delay.expires_after(std::chrono::milliseconds{5});
            co_await Delay.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            Server.Stop();
            co_await Server.Drain();
            Result->Drained = true;
            boost::system::error_code CloseError;
            Socket.close(CloseError);
            Watchdog->cancel();
            Io.stop();
        },
        [Result](std::exception_ptr Error)
        {
            Result->Failure = std::move(Error);
        });

    Net::co_spawn(
        Io,
        [&Io, Result, Watchdog]() -> Net::awaitable<void>
        {
            Watchdog->expires_after(std::chrono::milliseconds{250});
            boost::system::error_code Error;
            co_await Watchdog->async_wait(Net::redirect_error(Net::use_awaitable, Error));
            if (!Error && !Result->Drained)
            {
                Result->TimedOut = true;
                Io.stop();
            }
        },
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
        [&]() -> Net::awaitable<void>
        {
            const auto Started = co_await Server.Start();
            if (!Started)
            {
                co_return;
            }
            Server.Stop();
            Server.Stop();
            co_await Server.Drain();
            co_await Server.Drain();
            Completed = true;
        },
        [&](std::exception_ptr Error)
        {
            Failure = std::move(Error);
            Io.stop();
        });
    Io.run();

    EXPECT_FALSE(Failure);
    EXPECT_TRUE(Completed);
}

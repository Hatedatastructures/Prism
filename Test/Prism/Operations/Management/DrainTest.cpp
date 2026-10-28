/**
 * @file DrainTest.cpp
 * @brief Operations HTTP listener 的 typed Drain 合同测试。
 * @details 测试受控挂起的 Router handler、deadline 超时、延迟 socket 关闭和重复 Drain。
 *          handler 由 gate 控制释放，watchdog 负责在测试异常时回收它和 socket。
 */

#include <gtest/gtest.h>

#include <Prism/Operations/HttpServer.hpp>
#include <Prism/Operations/HttpServerStartResult.hpp>
#include "../Http/AuthSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <string>
#include <thread>
#include <utility>

namespace
{

    namespace Net = boost::asio;
    using Tcp = Net::ip::tcp;
    using Command = Prism::Operations::Command;
    using CommandResult = Prism::Operations::CommandResult;
    using HttpServer = Prism::Operations::HttpServer;
    using Router = Prism::Operations::Router;
    using DrainResult = HttpServer::DrainResult;
    using Prism::Testing::OperationsHttp::MakeTestBootstrap;
    using Prism::Testing::OperationsHttp::ReadBootstrapToken;

    constexpr auto ReadDeadline = std::chrono::milliseconds{15};
    constexpr auto ShortDrainTimeout = std::chrono::milliseconds{35};
    constexpr auto WatchdogDeadline = std::chrono::milliseconds{500};

    class HandlerGate final
    {
    public:
        auto Wait() -> void
        {
            std::unique_lock Lock(Mutex_);
            Entered_ = true;
            Condition_.notify_all();
            Condition_.wait(Lock, [this] { return Released_; });
            Exited_ = true;
            Condition_.notify_all();
        }

        auto Release() noexcept -> void
        {
            {
                std::lock_guard Lock(Mutex_);
                Released_ = true;
            }
            Condition_.notify_all();
        }

        [[nodiscard]] auto IsEntered() const -> bool
        {
            std::lock_guard Lock(Mutex_);
            return Entered_;
        }

        [[nodiscard]] auto IsExited() const -> bool
        {
            std::lock_guard Lock(Mutex_);
            return Exited_;
        }

    private:
        mutable std::mutex Mutex_;
        std::condition_variable Condition_;
        bool Entered_{false};
        bool Released_{false};
        bool Exited_{false};
    };

    struct DrainObservation final
    {
        std::atomic<bool> Started{false};
        std::atomic<bool> Completed{false};
        std::atomic<bool> ConcurrentCompleted{false};
        std::atomic<bool> ConcurrentFailed{false};
        std::atomic<bool> WatchdogFired{false};
        std::atomic<bool> SocketReadCompleted{false};
        std::atomic<bool> SocketClosedBeforeRelease{false};
        std::atomic<bool> SocketClosed{false};
        std::exception_ptr Failure;
        std::optional<DrainResult> First;
        std::optional<DrainResult> Second;
        std::optional<DrainResult> Third;
    };

    struct TestClientState final
    {
        explicit TestClientState(Net::any_io_executor Executor)
            : Strand(Net::make_strand(std::move(Executor))),
              Socket(std::make_shared<Tcp::socket>(Strand))
        {
        }

        Net::strand<Net::any_io_executor> Strand;
        std::shared_ptr<Tcp::socket> Socket;
    };

    auto CloseTestClient(const std::shared_ptr<TestClientState> &Client) noexcept -> void
    {
        try
        {
            Net::post(
                Client->Strand,
                [Client]
                {
                    boost::system::error_code Error;
                    Client->Socket->close(Error);
                });
        }
        catch (...)
        {
        }
    }

    [[nodiscard]] auto WaitForGate(const std::shared_ptr<HandlerGate> &Gate,
                                   const bool WaitForExit) -> Net::awaitable<bool>
    {
        Net::steady_timer Timer(co_await Net::this_coro::executor);
        for (std::size_t Attempt = 0; Attempt < 200U; ++Attempt)
        {
            bool Ready = false;
            if (WaitForExit)
            {
                Ready = Gate->IsExited();
            }
            else
            {
                Ready = Gate->IsEntered();
            }
            if (Ready)
            {
                co_return true;
            }
            Timer.expires_after(std::chrono::milliseconds{1});
            boost::system::error_code Error;
            co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return false;
            }
        }
        if (WaitForExit)
        {
            co_return Gate->IsExited();
        }
        co_return Gate->IsEntered();
    }

    [[nodiscard]] auto AwaitDrained(HttpServer &Server) -> Net::awaitable<DrainResult>
    {
        Net::steady_timer RetryTimer(co_await Net::this_coro::executor);
        DrainResult Last{Prism::Fault::Failure{Prism::Fault::Code::Blocked}, 0U};
        for (std::size_t Attempt = 0; Attempt < 200U; ++Attempt)
        {
            Last = co_await Server.Drain(HttpServer::Deadline::max());
            if (Last.Failure.Succeeded() && Last.RemainingConnections == 0U)
            {
                co_return Last;
            }
            RetryTimer.expires_after(std::chrono::milliseconds{1});
            boost::system::error_code Error;
            co_await RetryTimer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return Last;
            }
        }
        co_return Last;
    }

    [[nodiscard]] auto WaitForSocketRead(const std::shared_ptr<DrainObservation> &Observation)
        -> Net::awaitable<bool>
    {
        Net::steady_timer Timer(co_await Net::this_coro::executor);
        for (std::size_t Attempt = 0; Attempt < 200U; ++Attempt)
        {
            if (Observation->SocketReadCompleted.load(std::memory_order_acquire))
            {
                co_return true;
            }
            Timer.expires_after(std::chrono::milliseconds{1});
            boost::system::error_code Error;
            co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return false;
            }
        }
        co_return Observation->SocketReadCompleted.load(std::memory_order_acquire);
    }

    struct EmptyDrainRequest final
    {
        HttpServer &Server;
        Net::io_context &Io;
        std::shared_ptr<DrainObservation> Observation;
        std::shared_ptr<Net::steady_timer> Watchdog;
    };

    auto RunEmptyDrainOperation(EmptyDrainRequest Request) -> Net::awaitable<void>
    {
        const auto Started = co_await Request.Server.Start();
        if (!Started)
        {
            throw std::runtime_error("operations server failed to start");
        }
        Request.Observation->Started.store(true, std::memory_order_release);
        Request.Observation->First = co_await Request.Server.Drain(HttpServer::Deadline::max());
        Request.Observation->Second = co_await Request.Server.Drain(HttpServer::Deadline::max());
        Request.Observation->Completed.store(true, std::memory_order_release);
        Request.Watchdog->cancel();
        Request.Io.stop();
    }

    auto RunEmptyDrainWatchdog(EmptyDrainRequest Request) -> Net::awaitable<void>
    {
        Request.Watchdog->expires_after(WatchdogDeadline);
        boost::system::error_code Error;
        co_await Request.Watchdog->async_wait(
            Net::redirect_error(Net::use_awaitable, Error));
        if (!Error && !Request.Observation->Completed.load(std::memory_order_acquire))
        {
            Request.Observation->WatchdogFired.store(true, std::memory_order_release);
            (void)Request.Server.CloseAdmission();
            Request.Io.stop();
        }
    }

    struct StalledDrainRequest final
    {
        HttpServer &Server;
        Net::io_context &Io;
        std::shared_ptr<DrainObservation> Observation;
        std::shared_ptr<Net::steady_timer> Watchdog;
        std::shared_ptr<HandlerGate> Gate;
        std::shared_ptr<TestClientState> Client;
    };

    auto ConnectStalledDrainClient(
        const std::shared_ptr<TestClientState> &Client,
        const HttpServer::Endpoint Endpoint,
        const std::string &Token) -> Net::awaitable<bool>
    {
        boost::system::error_code Error;
        co_await Client->Socket->async_connect(
            Endpoint, Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            co_return false;
        }
        const auto Request = "POST /Operations/Reload HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(Endpoint.port()) +
            "\r\nX-Correlation-Id: 701"
            "\r\nAuthorization: Bearer " + Token +
            "\r\nContent-Type: application/json\r\nContent-Length: 57\r\n\r\n"
            "{\"mode\":\"apply\",\"base_generation\":\"1\",\"configuration\":{}}";
        co_await Net::async_write(
            *Client->Socket, Net::buffer(Request),
            Net::redirect_error(Net::use_awaitable, Error));
        co_return !Error;
    }

    auto MonitorStalledDrainSocket(
        const std::shared_ptr<DrainObservation> &Observation,
        const std::shared_ptr<TestClientState> &Client) -> Net::awaitable<void>
    {
        std::array<char, 4096> Buffer{};
        boost::system::error_code ReadError;
        while (!ReadError)
        {
            (void)co_await Client->Socket->async_read_some(
                Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, ReadError));
        }
        Observation->SocketClosed.store(true, std::memory_order_release);
        Observation->SocketReadCompleted.store(true, std::memory_order_release);
    }

    auto RunConcurrentStalledDrain(
        HttpServer &Server,
        const std::shared_ptr<DrainObservation> &Observation) -> Net::awaitable<void>
    {
        try
        {
            Observation->Second = co_await Server.Drain(HttpServer::Deadline::max());
        }
        catch (...)
        {
            Observation->ConcurrentFailed.store(true, std::memory_order_release);
        }
        Observation->ConcurrentCompleted.store(true, std::memory_order_release);
    }

    auto StopStalledDrain(HttpServer &Server) -> Net::awaitable<void>
    {
        (void)Server.CloseAdmission();
        co_return;
    }

    auto RunStalledDrainOperation(StalledDrainRequest Request) -> Net::awaitable<void>
    {
        const auto Started = co_await Request.Server.Start();
        if (!Started)
        {
            throw std::runtime_error("operations server failed to start");
        }
        Request.Observation->Started.store(true, std::memory_order_release);
        const auto Token = co_await ReadBootstrapToken(*Started);
        if (!Token)
        {
            throw std::runtime_error("operations bootstrap token was unavailable");
        }
        const auto Connected = co_await Net::co_spawn(
            Request.Client->Strand,
            ConnectStalledDrainClient(Request.Client, *Started, *Token),
            Net::use_awaitable);
        if (!Connected)
        {
            throw std::runtime_error("operations client failed to connect");
        }
        if (!(co_await WaitForGate(Request.Gate, false)))
        {
            throw std::runtime_error("operations handler did not become active");
        }

        Net::co_spawn(
            Request.Client->Strand,
            MonitorStalledDrainSocket(Request.Observation, Request.Client),
            Net::detached);
        Net::co_spawn(
            Request.Io,
            RunConcurrentStalledDrain(Request.Server, Request.Observation),
            Net::detached);
        Net::co_spawn(Request.Io, StopStalledDrain(Request.Server), Net::detached);
        Request.Observation->First = co_await Request.Server.Drain(HttpServer::Deadline::max());

        Net::steady_timer ConcurrentWait(co_await Net::this_coro::executor);
        boost::system::error_code ConcurrentError;
        for (std::size_t Attempt = 0; Attempt < 200U; ++Attempt)
        {
            if (Request.Observation->ConcurrentCompleted.load(std::memory_order_acquire))
            {
                break;
            }
            ConcurrentWait.expires_after(std::chrono::milliseconds{1});
            co_await ConcurrentWait.async_wait(
                Net::redirect_error(Net::use_awaitable, ConcurrentError));
        }
        if (!Request.Observation->ConcurrentCompleted.load(std::memory_order_acquire) ||
            Request.Observation->ConcurrentFailed.load(std::memory_order_acquire))
        {
            throw std::runtime_error("concurrent drain did not complete");
        }
        if (!Request.Observation->First.has_value() ||
            !Request.Observation->Second.has_value() ||
            Request.Observation->First->Failure.Code != Prism::Fault::Code::Timeout ||
            Request.Observation->First->RemainingConnections != 1U ||
            Request.Observation->Second->Failure.Code != Prism::Fault::Code::Timeout ||
            Request.Observation->Second->RemainingConnections != 1U)
        {
            throw std::runtime_error("drain did not time out while handler was blocked");
        }
        const auto ClosedBeforeRelease =
            Request.Observation->SocketReadCompleted.load(std::memory_order_acquire);
        Request.Observation->SocketClosedBeforeRelease.store(
            ClosedBeforeRelease, std::memory_order_release);
        if (ClosedBeforeRelease)
        {
            throw std::runtime_error("socket closed before handler release");
        }
        Request.Gate->Release();
        if (!(co_await WaitForGate(Request.Gate, true)))
        {
            throw std::runtime_error("operations handler did not release");
        }
        if (!(co_await WaitForSocketRead(Request.Observation)) ||
            !Request.Observation->SocketClosed.load(std::memory_order_acquire))
        {
            throw std::runtime_error("operations socket did not close after release");
        }
        Request.Observation->Third = co_await AwaitDrained(Request.Server);
        CloseTestClient(Request.Client);
        Request.Observation->Completed.store(true, std::memory_order_release);
        Request.Watchdog->cancel();
        Request.Io.stop();
    }

    auto RunStalledDrainWatchdog(StalledDrainRequest Request) -> Net::awaitable<void>
    {
        Request.Watchdog->expires_after(WatchdogDeadline);
        boost::system::error_code Error;
        co_await Request.Watchdog->async_wait(
            Net::redirect_error(Net::use_awaitable, Error));
        if (!Error && !Request.Observation->Completed.load(std::memory_order_acquire))
        {
            Request.Observation->WatchdogFired.store(true, std::memory_order_release);
            Request.Gate->Release();
            (void)Request.Server.CloseAdmission();
            CloseTestClient(Request.Client);
            Request.Io.stop();
        }
    }

    struct StartAttemptRequest final
    {
        HttpServer &Server;
        std::optional<Prism::Operations::HttpServerStartResult> &Result;
        std::exception_ptr &Failure;
        Net::io_context &Io;
    };

    auto RunStartAttempt(StartAttemptRequest Request) -> Net::awaitable<void>
    {
        try
        {
            Request.Result = co_await Request.Server.Start();
        }
        catch (...)
        {
            Request.Failure = std::current_exception();
        }
        Request.Io.stop();
    }

    [[nodiscard]] auto RunEmptyDrain(HttpServer &Server, Net::io_context &Io)
        -> std::shared_ptr<DrainObservation>
    {
        const auto Observation = std::make_shared<DrainObservation>();
        const auto Watchdog = std::make_shared<Net::steady_timer>(Io);
        const auto Request = EmptyDrainRequest{Server, Io, Observation, Watchdog};
        Io.restart();
        Net::co_spawn(
            Io,
            RunEmptyDrainOperation(Request),
            [Observation, &Io, Watchdog](std::exception_ptr Failure)
            {
                Observation->Failure = std::move(Failure);
                Observation->Completed.store(true, std::memory_order_release);
                Watchdog->cancel();
                Io.stop();
            });

        Net::co_spawn(
            Io,
            RunEmptyDrainWatchdog(Request),
            Net::detached);

        Io.run();
        (void)Server.CloseAdmission();
        Io.restart();
        Io.run();
        return Observation;
    }

    [[nodiscard]] auto RunStalledDrain(HttpServer &Server,
                                       const std::shared_ptr<HandlerGate> &Gate,
                                       Net::io_context &Io) -> std::shared_ptr<DrainObservation>
    {
        const auto Observation = std::make_shared<DrainObservation>();
        const auto Watchdog = std::make_shared<Net::steady_timer>(Io);
        const auto Client = std::make_shared<TestClientState>(Io.get_executor());
        const auto Request = StalledDrainRequest{Server, Io, Observation, Watchdog, Gate, Client};
        Io.restart();
        Net::co_spawn(
            Io,
            RunStalledDrainOperation(Request),
            [Observation, &Io, Watchdog, Gate, Client](std::exception_ptr Failure)
            {
                Observation->Failure = std::move(Failure);
                Gate->Release();
                CloseTestClient(Client);
                Observation->Completed.store(true, std::memory_order_release);
                Watchdog->cancel();
                Io.stop();
            });

        Net::co_spawn(
            Io,
            RunStalledDrainWatchdog(Request),
            Net::detached);

        std::thread FirstRunner([&Io] { Io.run(); });
        std::thread SecondRunner([&Io] { Io.run(); });
        FirstRunner.join();
        SecondRunner.join();
        Gate->Release();
        CloseTestClient(Client);
        (void)Server.CloseAdmission();
        Io.restart();
        Io.run();
        return Observation;
    }

} // namespace

TEST(OperationsDrainContract, StopBeforeStartIsLinearizedOnStateStrand)
{
    Net::io_context Io;
    HttpServer::Options Options{
        Io.get_executor(),
        Tcp::endpoint(Net::ip::address_v4::loopback(), 0),
        Router(Io.get_executor()),
        ReadDeadline,
        ShortDrainTimeout,
        MakeTestBootstrap()};
    HttpServer Server(Options);
    (void)Server.CloseAdmission();

    std::optional<Prism::Operations::HttpServerStartResult> Result;
    std::exception_ptr Failure;
    Net::co_spawn(
        Io,
        RunStartAttempt(StartAttemptRequest{Server, Result, Failure, Io}),
        Net::detached);

    std::thread FirstRunner([&Io] { Io.run(); });
    std::thread SecondRunner([&Io] { Io.run(); });
    FirstRunner.join();
    SecondRunner.join();

    ASSERT_FALSE(Failure);
    ASSERT_TRUE(Result.has_value());
    EXPECT_FALSE(Result->has_value());
    EXPECT_FALSE(Server.IsRunning());
    (void)Server.CloseAdmission();
    Io.restart();
    Io.run();
}

TEST(OperationsDrainContract, StartFailureRollsBackRunningState)
{
    Net::io_context Io;
    HttpServer::Options Options{
        Io.get_executor(),
        Tcp::endpoint(Net::ip::address_v4::any(), 0),
        Router(Io.get_executor()),
        ReadDeadline,
        ShortDrainTimeout,
        MakeTestBootstrap()};
    HttpServer Server(Options);

    std::optional<Prism::Operations::HttpServerStartResult> Result;
    std::exception_ptr Failure;
    Net::co_spawn(
        Io,
        RunStartAttempt(StartAttemptRequest{Server, Result, Failure, Io}),
        Net::detached);
    Io.run();

    ASSERT_FALSE(Failure);
    ASSERT_TRUE(Result.has_value());
    EXPECT_FALSE(Result->has_value());
    EXPECT_FALSE(Server.IsRunning());
    (void)Server.CloseAdmission();
    Io.restart();
    Io.run();
}

TEST(OperationsDrainContract, ReportsDrainedForAnIdleServerAndIsIdempotent)
{
    Net::io_context Io;
    HttpServer::Options Options{
        Io.get_executor(),
        Tcp::endpoint(Net::ip::address_v4::loopback(), 0),
        Router(Io.get_executor()),
        ReadDeadline,
        ShortDrainTimeout,
        MakeTestBootstrap()};
    HttpServer Server(Options);

    const auto Observation = RunEmptyDrain(Server, Io);

    ASSERT_TRUE(Observation->Started.load(std::memory_order_acquire));
    ASSERT_TRUE(Observation->Completed.load(std::memory_order_acquire));
    EXPECT_FALSE(Observation->WatchdogFired.load(std::memory_order_acquire));
    EXPECT_FALSE(Observation->Failure);
    ASSERT_TRUE(Observation->First.has_value());
    ASSERT_TRUE(Observation->Second.has_value());
    EXPECT_TRUE(Observation->First->Failure.Succeeded());
    EXPECT_EQ(Observation->First->RemainingConnections, 0U);
    EXPECT_TRUE(Observation->Second->Failure.Succeeded());
    EXPECT_EQ(Observation->Second->RemainingConnections, 0U);
}

TEST(OperationsDrainContract, ReportsTimeoutForAStalledHandlerAndClosesItsSocketAfterRelease)
{
    Net::io_context Io;
    const auto Gate = std::make_shared<HandlerGate>();
    Router RouterValue(Io.get_executor(),
        Prism::Operations::RouterHandlers{{}, [Gate](Command CommandValue,
            Prism::Operations::OperationCompletion) -> Net::awaitable<CommandResult>
            {
                // 故意模拟不合作的同步 handler；watchdog 和测试流程会释放 gate。
                Gate->Wait();
                co_return CommandResult::Accepted(Prism::Operations::CorrelationOf(CommandValue));
            }});
    HttpServer::Options Options{
        Io.get_executor(),
        Tcp::endpoint(Net::ip::address_v4::loopback(), 0),
        std::move(RouterValue),
        ReadDeadline,
        ShortDrainTimeout,
        MakeTestBootstrap()};
    HttpServer Server(Options);

    const auto Observation = RunStalledDrain(Server, Gate, Io);

    ASSERT_TRUE(Observation->Started.load(std::memory_order_acquire));
    ASSERT_TRUE(Observation->Completed.load(std::memory_order_acquire));
    EXPECT_FALSE(Observation->WatchdogFired.load(std::memory_order_acquire));
    EXPECT_FALSE(Observation->Failure);
    EXPECT_TRUE(Gate->IsEntered());
    EXPECT_TRUE(Gate->IsExited());
    EXPECT_FALSE(Observation->SocketClosedBeforeRelease.load(std::memory_order_acquire));
    EXPECT_TRUE(Observation->SocketReadCompleted.load(std::memory_order_acquire));
    EXPECT_TRUE(Observation->SocketClosed.load(std::memory_order_acquire));
    ASSERT_TRUE(Observation->First.has_value());
    ASSERT_TRUE(Observation->Second.has_value());
    ASSERT_TRUE(Observation->Third.has_value());
    EXPECT_EQ(Observation->First->Failure.Code, Prism::Fault::Code::Timeout);
    EXPECT_EQ(Observation->First->Failure.Native, std::make_error_code(std::errc::timed_out));
    EXPECT_EQ(Observation->First->RemainingConnections, 1U);
    EXPECT_EQ(Observation->Second->Failure.Code, Prism::Fault::Code::Timeout);
    EXPECT_EQ(Observation->Second->RemainingConnections, 1U);
    EXPECT_TRUE(Observation->Third->Failure.Succeeded());
    EXPECT_EQ(Observation->Third->RemainingConnections, 0U);
}

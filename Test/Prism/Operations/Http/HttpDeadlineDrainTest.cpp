/**
 * @file HttpDeadlineDrainTest.cpp
 * @brief Operations HTTP deadline failure 与真实 Drain 的并发 owner 回归。
 */

#include <gtest/gtest.h>

#include <Prism/Operations/Http/ReadDeadline.hpp>
#include <Prism/Operations/HttpConnection.hpp>
#include <Prism/Operations/HttpServer.hpp>

#include "OperationsAuthSupport.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/errc.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace Prism::Operations
{
    struct HttpServerTestAccess final
    {
        [[nodiscard]] static auto StateExecutor(HttpServer &Server)
            -> boost::asio::any_io_executor
        {
            return Server.State_->StateStrand;
        }

        static auto RegisterActiveConnection(
            HttpServer &Server,
            const std::shared_ptr<HttpConnection::ConnectionState> &Connection) -> void
        {
            Server.State_->ActiveConnections.push_back(Connection);
            Server.State_->ActiveConnectionCount.fetch_add(1U, std::memory_order_acq_rel);
        }

        [[nodiscard]] static auto DrainTimerArmed(HttpServer &Server) -> bool
        {
            return Server.State_->DrainTimerArmed;
        }

        [[nodiscard]] static auto OwnerFailed(HttpServer &Server) -> bool
        {
            return Server.State_->StateOperationFailed.load(std::memory_order_acquire);
        }

        [[nodiscard]] static auto AdmissionClosed(HttpServer &Server) -> bool
        {
            return Server.State_->StopRequested.load(std::memory_order_acquire) &&
                   !Server.State_->Running.load(std::memory_order_acquire);
        }

        static auto WakeDrainForTestCleanup(HttpServer &Server)
            -> boost::asio::awaitable<void>
        {
            co_await boost::asio::post(Server.State_->StateStrand, boost::asio::use_awaitable);
            (void)Server.State_->DrainTimer.cancel();
        }

        static auto ReportDeadlineFailure(
            HttpServer &Server,
            const std::shared_ptr<HttpConnection::Detail::ReadDeadlineTask> &Task,
            const boost::system::error_code &Failure) -> void
        {
            HttpConnection::NotifyReadDeadlineFailure(Server.State_, Task, Failure);
        }

        [[nodiscard]] static auto CancelReadDeadline(
            HttpServer &Server,
            const std::shared_ptr<HttpConnection::ConnectionState> &Connection,
            const std::shared_ptr<HttpConnection::Detail::ReadDeadlineTask> &Task)
            -> boost::asio::awaitable<bool>
        {
            return HttpConnection::CancelReadDeadline(Server.State_, Connection, Task);
        }

        static auto PublishDeadlineFailureForTestCleanup(
            HttpServer &Server,
            const std::shared_ptr<HttpConnection::Detail::ReadDeadlineTask> &Task)
            -> boost::asio::awaitable<void>
        {
            co_await boost::asio::post(Server.State_->StateStrand, boost::asio::use_awaitable);
            if (Task->Failure && !Task->FailureOwnerPublished.load(std::memory_order_acquire))
            {
                HttpConnection::FailReadDeadlineOnStateStrand(
                    Server.State_, Task, *Task->Failure);
            }
        }
    };
}

namespace
{
    namespace Net = boost::asio;
    namespace HttpConnection = Prism::Operations::HttpConnection;
    using HttpServer = Prism::Operations::HttpServer;
    using Query = Prism::Operations::Query;
    using QueryResult = Prism::Operations::QueryResult;
    using Router = Prism::Operations::Router;
    using Tcp = Net::ip::tcp;
    using Prism::Testing::OperationsHttp::MakeServer;

    enum class Injection
    {
        TimerWaitFailure,
        SocketCancelFailure,
    };

    struct PendingReadProbe final
    {
        explicit PendingReadProbe(Net::any_io_executor Executor)
            : Completion(std::move(Executor), 1)
        {
        }

        Net::experimental::channel<void(boost::system::error_code)> Completion;
        boost::system::error_code Failure;
        std::exception_ptr Exception;
        bool Started{false};
        bool Completed{false};
        bool ReceiptObserved{false};
        bool ReceiptFailed{false};
    };

    struct DrainProbe final
    {
        explicit DrainProbe(Net::any_io_executor Executor)
            : Completion(std::move(Executor), 1)
        {
        }

        Net::experimental::channel<void(boost::system::error_code)> Completion;
        std::optional<HttpServer::DrainResult> Result;
        std::exception_ptr Exception;
        bool ReceiptFailed{false};
    };

    struct ScenarioResult final
    {
        boost::system::error_code SetupFailure;
        boost::system::error_code ReadFailure;
        std::error_code DeadlineFailure;
        HttpServer::DrainResult Drain;
        bool ReadCompleted{false};
        bool PeerClosed{false};
        bool PeerResponseEmpty{false};
        bool DeadlineReceiptCompleted{false};
        bool OwnerWaitCleanupCompleted{false};
        bool FailureOwnerPublished{false};
        bool DrainWaitReached{false};
        bool DrainStarted{false};
        bool DrainCompleted{false};
        bool DrainCompletionFailed{false};
        bool ReadCleanupCompleted{false};
        bool OwnerFailed{false};
        bool AdmissionClosed{false};
        bool DeadlineRetired{true};
        std::size_t CancelCalls{0U};
    };

    struct ScenarioRequest final
    {
        HttpServer &Server;
        std::shared_ptr<HttpConnection::ConnectionState> Connection;
        std::shared_ptr<Tcp::socket> Peer;
        Injection Failure;
        std::shared_ptr<PendingReadProbe> Read;
    };

    struct DeadlineInjectionResult final
    {
        boost::system::error_code Failure;
        std::size_t CancelCalls{0U};
        bool Retired{true};
        bool OwnerWaitCompleted{false};
        bool OwnerWaitTimedOut{false};
        bool OwnerWaitCleanupCompleted{false};
        bool TaskReceiptCompleted{false};
        bool OwnerPublished{false};
    };

    struct DeadlineCancelWaitResult final
    {
        bool Completed{false};
        bool Retired{true};
        bool CleanupCompleted{false};
    };

    struct DeadlineCancelProbe final
    {
        explicit DeadlineCancelProbe(Net::any_io_executor Executor)
            : Completion(std::move(Executor), 1)
        {
        }

        Net::experimental::channel<void(boost::system::error_code)> Completion;
        std::exception_ptr Exception;
        bool Retired{false};
        bool Completed{false};
        bool ReceiptFailed{false};
    };

    struct DeadlineOwnerWaitRequest final
    {
        HttpServer &Server;
        std::shared_ptr<HttpConnection::ConnectionState> Connection;
        std::shared_ptr<HttpConnection::Detail::ReadDeadlineTask> Task;
        std::chrono::milliseconds Limit;
    };

    struct ReceiptWaitResult final
    {
        boost::system::error_code Failure;
        bool Completed{false};
    };

    struct PeerReadResult final
    {
        boost::system::error_code Failure;
        std::size_t Bytes{0U};
        bool Completed{false};
    };

    [[nodiscard]] auto WaitForReceipt(
        Net::experimental::channel<void(boost::system::error_code)> &Channel,
        const std::chrono::milliseconds Limit) -> Net::awaitable<ReceiptWaitResult>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Timer(Executor);
        Timer.expires_after(Limit);
        ReceiptWaitResult Result;
        auto Receive = [&Channel, &Result]() -> Net::awaitable<void>
        {
            co_await Channel.async_receive(
                Net::redirect_error(Net::use_awaitable, Result.Failure));
            Result.Completed = true;
        };
        auto Timeout = [&Timer]() -> Net::awaitable<void>
        {
            boost::system::error_code Error;
            co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        };
        using Net::experimental::awaitable_operators::operator||;
        const auto Race = co_await (Receive() || Timeout());
        if (Race.index() == 1U)
        {
            Result.Failure = boost::system::errc::make_error_code(
                boost::system::errc::timed_out);
            co_return Result;
        }
        co_return Result;
    }

    [[nodiscard]] auto ReadPeerWithTimeout(
        Tcp::socket &Peer,
        const std::chrono::milliseconds Limit) -> Net::awaitable<PeerReadResult>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Timer(Executor);
        Timer.expires_after(Limit);
        std::array<char, 1> Buffer{};
        PeerReadResult Result;
        auto Read = [&Peer, &Buffer, &Result]() -> Net::awaitable<std::size_t>
        {
            co_return co_await Peer.async_read_some(Net::buffer(Buffer),
                Net::redirect_error(Net::use_awaitable, Result.Failure));
        };
        auto Timeout = [&Timer]() -> Net::awaitable<void>
        {
            boost::system::error_code Error;
            co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
        };
        using Net::experimental::awaitable_operators::operator||;
        const auto Race = co_await (Read() || Timeout());
        if (Race.index() == 1U)
        {
            Result.Failure = boost::system::errc::make_error_code(
                boost::system::errc::timed_out);
            co_return Result;
        }
        Result.Completed = true;
        Result.Bytes = std::get<0>(Race);
        co_return Result;
    }

    [[nodiscard]] auto CloseConnectionReadForTestCleanup(
        const std::shared_ptr<HttpConnection::ConnectionState> &Connection,
        const std::shared_ptr<PendingReadProbe> &Probe) -> Net::awaitable<bool>
    {
        boost::system::error_code Error;
        Connection->Socket->cancel(Error);
        Connection->Socket->shutdown(Tcp::socket::shutdown_both, Error);
        Connection->Socket->close(Error);
        if (Probe->ReceiptObserved || Probe->Completed || Probe->Exception)
        {
            co_return true;
        }
        const auto Receipt = co_await WaitForReceipt(
            Probe->Completion, std::chrono::seconds(1));
        Probe->ReceiptObserved = Receipt.Completed;
        co_return Probe->ReceiptObserved;
    }

    [[nodiscard]] auto ClosePeerForTestCleanup(Tcp::socket &Peer) -> Net::awaitable<void>
    {
        co_await Net::post(Peer.get_executor(), Net::use_awaitable);
        boost::system::error_code Error;
        Peer.cancel(Error);
        Peer.close(Error);
    }

    [[nodiscard]] auto CloseReadAndPeerForTestCleanup(
        const std::shared_ptr<HttpConnection::ConnectionState> &Connection,
        const std::shared_ptr<PendingReadProbe> &Probe,
        const std::shared_ptr<Tcp::socket> &Peer) -> Net::awaitable<bool>
    {
        const auto ReadCleanup = co_await CloseConnectionReadForTestCleanup(Connection, Probe);
        co_await ClosePeerForTestCleanup(*Peer);
        co_return ReadCleanup;
    }

    [[nodiscard]] auto WaitForDeadlineOwner(DeadlineOwnerWaitRequest Request)
        -> Net::awaitable<DeadlineCancelWaitResult>
    {
        const auto Executor = co_await Net::this_coro::executor;
        const auto Probe = std::make_shared<DeadlineCancelProbe>(Executor);
        Net::co_spawn(Executor,
            Prism::Operations::HttpServerTestAccess::CancelReadDeadline(
                Request.Server, Request.Connection, Request.Task),
            [Probe](std::exception_ptr Exception, const bool Retired)
            {
                Probe->Exception = Exception;
                Probe->Retired = Retired;
                Probe->Completed = true;
                Probe->ReceiptFailed = !Probe->Completion.try_send(
                    boost::system::error_code{});
            });
        auto Receipt = co_await WaitForReceipt(Probe->Completion, Request.Limit);
        if (Receipt.Completed && !Receipt.Failure && Probe->Completed &&
            !Probe->Exception && !Probe->ReceiptFailed)
        {
            co_return DeadlineCancelWaitResult{true, Probe->Retired, true};
        }
        co_await Prism::Operations::HttpServerTestAccess::PublishDeadlineFailureForTestCleanup(
            Request.Server, Request.Task);
        Receipt = co_await WaitForReceipt(Probe->Completion, std::chrono::seconds(1));
        const auto CleanupCompleted = Receipt.Completed && !Receipt.Failure &&
            Probe->Completed && !Probe->Exception && !Probe->ReceiptFailed;
        co_return DeadlineCancelWaitResult{false, false, CleanupCompleted};
    }

    [[nodiscard]] auto MakeRouter(
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

    [[nodiscard]] auto ReadPendingSocket(
        const std::shared_ptr<HttpConnection::ConnectionState> &Connection,
        const std::shared_ptr<PendingReadProbe> &Probe) -> Net::awaitable<void>
    {
        std::array<char, 1> Buffer{};
        Probe->Started = true;
        co_await Connection->Socket->async_read_some(
            Net::buffer(Buffer), Net::redirect_error(Net::use_awaitable, Probe->Failure));
        Probe->Completed = true;
        if (!Probe->Completion.try_send(boost::system::error_code{}))
        {
            Probe->ReceiptFailed = true;
        }
    }

    [[nodiscard]] auto WaitForDrainTimerArmed(HttpServer &Server)
        -> Net::awaitable<bool>
    {
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Retry(Executor);
        const auto StateExecutor = Prism::Operations::HttpServerTestAccess::StateExecutor(Server);
        for (std::size_t Attempt = 0U; Attempt < 100U; ++Attempt)
        {
            co_await Net::post(StateExecutor, Net::use_awaitable);
            if (Prism::Operations::HttpServerTestAccess::DrainTimerArmed(Server))
            {
                co_return true;
            }
            Retry.expires_after(std::chrono::milliseconds(1));
            boost::system::error_code Error;
            co_await Retry.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return false;
            }
        }
        co_return false;
    }

    [[nodiscard]] auto InjectDeadlineFailure(ScenarioRequest Request)
        -> Net::awaitable<DeadlineInjectionResult>
    {
        DeadlineInjectionResult Result;
        const auto CancelCalls = std::make_shared<std::atomic<std::size_t>>(0U);
        const auto CancelFailure = Request.Failure == Injection::SocketCancelFailure
            ? boost::system::errc::make_error_code(boost::system::errc::io_error)
            : boost::system::error_code{};
        HttpConnection::Detail::ReadDeadlineActions Actions{
            .CancelSocket = [CancelCalls, CancelFailure]
            {
                CancelCalls->fetch_add(1U, std::memory_order_relaxed);
                return CancelFailure;
            },
            .ReportFailure = [&Server = Request.Server](
                const std::shared_ptr<HttpConnection::Detail::ReadDeadlineTask> &Task,
                const boost::system::error_code &Failure)
            {
                Prism::Operations::HttpServerTestAccess::ReportDeadlineFailure(
                    Server, Task, Failure);
            }};
        const auto Task = std::make_shared<HttpConnection::Detail::ReadDeadlineTask>(
            Request.Connection->Strand, std::chrono::seconds(1), std::move(Actions));
        const auto TimerFailure = Request.Failure == Injection::TimerWaitFailure
            ? Net::error::connection_reset
            : boost::system::error_code{};
        HttpConnection::Detail::CompleteReadDeadlineWait(Task, TimerFailure);
        HttpConnection::Detail::CompleteReadDeadlineTask(Task, {});
        const auto OwnerWait = co_await WaitForDeadlineOwner(
            DeadlineOwnerWaitRequest{
                Request.Server, Request.Connection, Task, std::chrono::seconds(1)});
        Result.Retired = OwnerWait.Retired;
        Result.OwnerWaitCompleted = OwnerWait.Completed;
        Result.OwnerWaitTimedOut = !OwnerWait.Completed;
        Result.OwnerWaitCleanupCompleted = OwnerWait.CleanupCompleted;
        Result.Failure = Task->Failure.value_or(boost::system::error_code{});
        Result.OwnerPublished = Task->FailureOwnerPublished.load(std::memory_order_acquire);
        const auto Receipt = co_await WaitForReceipt(
            Task->Completion, std::chrono::seconds(1));
        Result.TaskReceiptCompleted = Receipt.Completed && !Receipt.Failure;
        Result.CancelCalls = CancelCalls->load(std::memory_order_relaxed);
        co_return Result;
    }

    [[nodiscard]] auto RunReadDeadlineFailureScenario(ScenarioRequest Request)
        -> Net::awaitable<ScenarioResult>
    {
        ScenarioResult Result;
        const auto Injected = co_await InjectDeadlineFailure(Request);
        Result.DeadlineRetired = Injected.Retired;
        Result.DeadlineReceiptCompleted = Injected.TaskReceiptCompleted;
        Result.OwnerWaitCleanupCompleted = Injected.OwnerWaitCleanupCompleted;
        Result.FailureOwnerPublished = Injected.OwnerPublished;
        Result.DeadlineFailure = static_cast<std::error_code>(Injected.Failure);
        Result.CancelCalls = Injected.CancelCalls;
        if (!Injected.OwnerWaitCompleted)
        {
            Result.SetupFailure = boost::system::errc::make_error_code(
                boost::system::errc::timed_out);
        }
        if (!Injected.OwnerWaitCleanupCompleted && !Result.SetupFailure)
        {
            Result.SetupFailure = boost::system::errc::make_error_code(
                boost::system::errc::timed_out);
        }
        const auto ReadReceipt = co_await WaitForReceipt(
            Request.Read->Completion, std::chrono::seconds(1));
        Request.Read->ReceiptObserved = ReadReceipt.Completed;
        Result.ReadFailure = Request.Read->Failure;
        Result.ReadCompleted = Request.Read->Completed && !Request.Read->Exception &&
                               !Request.Read->ReceiptFailed && ReadReceipt.Completed &&
                               !ReadReceipt.Failure;
        const auto Peer = co_await ReadPeerWithTimeout(
            *Request.Peer, std::chrono::seconds(2));
        Result.PeerClosed = Peer.Completed && static_cast<bool>(Peer.Failure) &&
                            Peer.Failure != boost::system::errc::make_error_code(
                                boost::system::errc::timed_out);
        Result.PeerResponseEmpty = Peer.Bytes == 0U;
        if (!Result.PeerClosed)
        {
            Result.SetupFailure = Peer.Failure
                ? Peer.Failure
                : boost::system::errc::make_error_code(boost::system::errc::io_error);
        }
        Result.OwnerFailed = Prism::Operations::HttpServerTestAccess::OwnerFailed(Request.Server);
        Result.AdmissionClosed =
            Prism::Operations::HttpServerTestAccess::AdmissionClosed(Request.Server);
        co_return Result;
    }

    [[nodiscard]] auto RunInjectedDeadlineDrainScenario(
        Net::io_context &Io,
        const Injection Failure) -> Net::awaitable<ScenarioResult>
    {
        ScenarioResult Result;
        std::atomic<std::size_t> HandlerCalls{0U};
        auto Server = MakeServer(MakeRouter(Io, HandlerCalls), Io);
        Tcp::acceptor PairAcceptor(Io,
            Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        auto Connection = std::make_shared<HttpConnection::ConnectionState>(
            Prism::Operations::HttpServerTestAccess::StateExecutor(Server));
        auto Peer = std::make_shared<Tcp::socket>(Io);
        co_await Peer->async_connect(PairAcceptor.local_endpoint(), Net::use_awaitable);
        co_await PairAcceptor.async_accept(*Connection->Socket, Net::use_awaitable);
        co_await Net::post(
            Prism::Operations::HttpServerTestAccess::StateExecutor(Server), Net::use_awaitable);
        Prism::Operations::HttpServerTestAccess::RegisterActiveConnection(Server, Connection);
        const auto Read = std::make_shared<PendingReadProbe>(Connection->Strand);
        Net::co_spawn(Connection->Strand, ReadPendingSocket(Connection, Read),
            [Read](std::exception_ptr Exception)
            {
                if (Exception)
                {
                    Read->Exception = Exception;
                    Read->ReceiptFailed = !Read->Completion.try_send(
                        boost::system::error_code{});
                }
            });
        co_await Net::post(Connection->Strand, Net::use_awaitable);
        if (!Read->Started)
        {
            ScenarioResult Result;
            Result.SetupFailure = boost::system::errc::make_error_code(
                boost::system::errc::io_error);
            Result.ReadCleanupCompleted = co_await Net::co_spawn(Connection->Strand,
                CloseReadAndPeerForTestCleanup(Connection, Read, Peer), Net::use_awaitable);
            Result.OwnerWaitCleanupCompleted = true;
            co_return Result;
        }

        const auto Drain = std::make_shared<DrainProbe>(Io.get_executor());
        Net::co_spawn(Io, Server.Drain(std::chrono::steady_clock::now() +
            std::chrono::seconds(2)),
            [Drain](std::exception_ptr Exception, HttpServer::DrainResult Result)
            {
                Drain->Exception = Exception;
                if (!Exception)
                {
                    Drain->Result = std::move(Result);
                }
                Drain->ReceiptFailed = !Drain->Completion.try_send(
                    boost::system::error_code{});
            });
        const auto DrainWaitReached = co_await WaitForDrainTimerArmed(Server);
        const auto Owner = co_await Net::co_spawn(Connection->Strand,
            RunReadDeadlineFailureScenario(
                ScenarioRequest{Server, Connection, Peer, Failure, Read}),
            Net::use_awaitable);
        const auto ReadCleanup = co_await Net::co_spawn(Connection->Strand,
            CloseReadAndPeerForTestCleanup(Connection, Read, Peer), Net::use_awaitable);
        const auto DrainReceipt = co_await WaitForReceipt(
            Drain->Completion, std::chrono::seconds(3));
        auto DrainReceiptCompleted = DrainReceipt.Completed && !DrainReceipt.Failure;
        if (!DrainReceiptCompleted)
        {
            co_await Prism::Operations::HttpServerTestAccess::WakeDrainForTestCleanup(Server);
            const auto CleanupReceipt = co_await WaitForReceipt(
                Drain->Completion, std::chrono::seconds(1));
            DrainReceiptCompleted = CleanupReceipt.Completed && !CleanupReceipt.Failure;
        }
        Result = Owner;
        Result.DrainStarted = true;
        Result.DrainWaitReached = DrainWaitReached;
        Result.ReadCleanupCompleted = ReadCleanup;
        Result.DrainCompletionFailed = static_cast<bool>(Drain->Exception) ||
            Drain->ReceiptFailed || !DrainReceipt.Completed || DrainReceipt.Failure ||
            !Drain->Result;
        Result.DrainCompleted = DrainReceiptCompleted && !Drain->Exception &&
                                Drain->Result.has_value();
        if (Drain->Result)
        {
            Result.Drain = *Drain->Result;
        }
        if (Result.CancelCalls != static_cast<std::size_t>(
            Failure == Injection::SocketCancelFailure))
        {
            Result.SetupFailure = boost::system::errc::make_error_code(
                boost::system::errc::state_not_recoverable);
        }
        if (!ReadCleanup && !Result.SetupFailure)
        {
            Result.SetupFailure = boost::system::errc::make_error_code(
                boost::system::errc::timed_out);
        }
        co_return Result;
    }

    [[nodiscard]] auto RunDeadlineOwnerCloseScenario(
        Net::io_context &Io,
        const Injection Failure) -> Net::awaitable<ScenarioResult>
    {
        std::atomic<std::size_t> HandlerCalls{0U};
        auto Server = MakeServer(MakeRouter(Io, HandlerCalls), Io);
        Tcp::acceptor PairAcceptor(Io,
            Tcp::endpoint(Net::ip::address_v4::loopback(), 0));
        auto Connection = std::make_shared<HttpConnection::ConnectionState>(
            Prism::Operations::HttpServerTestAccess::StateExecutor(Server));
        auto Peer = std::make_shared<Tcp::socket>(Io);
        co_await Peer->async_connect(PairAcceptor.local_endpoint(), Net::use_awaitable);
        co_await PairAcceptor.async_accept(*Connection->Socket, Net::use_awaitable);
        co_await Net::post(
            Prism::Operations::HttpServerTestAccess::StateExecutor(Server), Net::use_awaitable);
        Prism::Operations::HttpServerTestAccess::RegisterActiveConnection(Server, Connection);
        const auto Read = std::make_shared<PendingReadProbe>(Connection->Strand);
        Net::co_spawn(Connection->Strand, ReadPendingSocket(Connection, Read),
            [Read](std::exception_ptr Exception)
            {
                if (Exception)
                {
                    Read->Exception = Exception;
                    Read->ReceiptFailed = !Read->Completion.try_send(
                        boost::system::error_code{});
                }
            });
        co_await Net::post(Connection->Strand, Net::use_awaitable);
        if (!Read->Started)
        {
            ScenarioResult Result;
            Result.SetupFailure = boost::system::errc::make_error_code(
                boost::system::errc::io_error);
            Result.ReadCleanupCompleted = co_await Net::co_spawn(Connection->Strand,
                CloseReadAndPeerForTestCleanup(Connection, Read, Peer), Net::use_awaitable);
            Result.OwnerWaitCleanupCompleted = true;
            co_return Result;
        }
        auto Result = co_await Net::co_spawn(Connection->Strand,
            RunReadDeadlineFailureScenario(
                ScenarioRequest{Server, Connection, Peer, Failure, Read}),
            Net::use_awaitable);
        Result.ReadCleanupCompleted = co_await Net::co_spawn(Connection->Strand,
            CloseReadAndPeerForTestCleanup(Connection, Read, Peer), Net::use_awaitable);
        if (!Result.ReadCleanupCompleted && !Result.SetupFailure)
        {
            Result.SetupFailure = boost::system::errc::make_error_code(
                boost::system::errc::timed_out);
        }
        co_return Result;
    }

    template <typename Value>
    [[nodiscard]] auto RunAwaitable(Net::io_context &Io, Net::awaitable<Value> Awaitable)
        -> Value
    {
        std::optional<Value> Result;
        std::exception_ptr Exception;
        Net::co_spawn(Io, std::move(Awaitable),
            [&Io, &Result, &Exception](std::exception_ptr Failure, Value ValueResult)
            {
                Exception = Failure;
                if (!Failure)
                {
                    Result = std::move(ValueResult);
                }
                Io.stop();
            });
        Io.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
        if (!Result)
        {
            throw std::runtime_error("deadline drain scenario did not complete");
        }
        return std::move(*Result);
    }
}

TEST(OperationsHttpReadDeadline, TimerWaitFailureClosesReadAndFailsDrain)
{
    Net::io_context Io;
    const auto Result = RunAwaitable(Io,
        RunInjectedDeadlineDrainScenario(Io, Injection::TimerWaitFailure));
    if (Result.ReadCleanupCompleted && (!Result.DrainStarted || Result.DrainCompleted) &&
        Result.OwnerWaitCleanupCompleted)
    {
        Io.restart();
        Io.run();
    }

    ASSERT_FALSE(Result.SetupFailure);
    EXPECT_TRUE(Result.DrainWaitReached);
    EXPECT_TRUE(Result.ReadCleanupCompleted);
    EXPECT_TRUE(Result.ReadCompleted);
    EXPECT_TRUE(Result.ReadFailure);
    EXPECT_TRUE(Result.PeerClosed);
    EXPECT_TRUE(Result.PeerResponseEmpty);
    EXPECT_TRUE(Result.DeadlineReceiptCompleted);
    EXPECT_TRUE(Result.OwnerWaitCleanupCompleted);
    EXPECT_TRUE(Result.FailureOwnerPublished);
    EXPECT_FALSE(Result.DeadlineRetired);
    EXPECT_TRUE(Result.OwnerFailed);
    EXPECT_TRUE(Result.AdmissionClosed);
    ASSERT_TRUE(Result.DrainCompleted);
    EXPECT_FALSE(Result.DrainCompletionFailed);
    EXPECT_EQ(Result.Drain.Failure.Code, Prism::Fault::Code::ConnectionReset);
    const auto ExpectedNative = static_cast<std::error_code>(
        boost::system::error_code(Net::error::connection_reset));
    EXPECT_EQ(Result.DeadlineFailure, ExpectedNative);
    EXPECT_EQ(Result.Drain.Failure.Native, ExpectedNative);
    EXPECT_EQ(Result.Drain.RemainingConnections, 1U);
}

TEST(OperationsHttpReadDeadline, SocketCancelFailureUsesCloseFallbackAndFailsDrain)
{
    Net::io_context Io;
    const auto Result = RunAwaitable(Io,
        RunInjectedDeadlineDrainScenario(Io, Injection::SocketCancelFailure));
    if (Result.ReadCleanupCompleted && (!Result.DrainStarted || Result.DrainCompleted) &&
        Result.OwnerWaitCleanupCompleted)
    {
        Io.restart();
        Io.run();
    }

    ASSERT_FALSE(Result.SetupFailure);
    EXPECT_TRUE(Result.DrainWaitReached);
    EXPECT_TRUE(Result.ReadCleanupCompleted);
    EXPECT_TRUE(Result.ReadCompleted);
    EXPECT_TRUE(Result.ReadFailure);
    EXPECT_TRUE(Result.PeerClosed);
    EXPECT_TRUE(Result.PeerResponseEmpty);
    EXPECT_TRUE(Result.DeadlineReceiptCompleted);
    EXPECT_TRUE(Result.OwnerWaitCleanupCompleted);
    EXPECT_TRUE(Result.FailureOwnerPublished);
    EXPECT_FALSE(Result.DeadlineRetired);
    EXPECT_TRUE(Result.OwnerFailed);
    EXPECT_TRUE(Result.AdmissionClosed);
    ASSERT_TRUE(Result.DrainCompleted);
    EXPECT_FALSE(Result.DrainCompletionFailed);
    EXPECT_EQ(Result.Drain.Failure.Code, Prism::Fault::Code::IoError);
    EXPECT_EQ(Result.DeadlineFailure,
        static_cast<std::error_code>(boost::system::errc::make_error_code(
            boost::system::errc::io_error)));
    EXPECT_EQ(Result.Drain.Failure.Native,
        static_cast<std::error_code>(boost::system::errc::make_error_code(
            boost::system::errc::io_error)));
    EXPECT_EQ(Result.Drain.RemainingConnections, 1U);
}

TEST(OperationsHttpReadDeadline, SocketCancelFailureClosesPendingReadThroughConnectionOwner)
{
    Net::io_context Io;
    const auto Result = RunAwaitable(Io,
        RunDeadlineOwnerCloseScenario(Io, Injection::SocketCancelFailure));
    if (Result.ReadCleanupCompleted && Result.OwnerWaitCleanupCompleted)
    {
        Io.restart();
        Io.run();
    }

    ASSERT_FALSE(Result.SetupFailure);
    EXPECT_TRUE(Result.ReadCleanupCompleted);
    EXPECT_TRUE(Result.ReadCompleted);
    EXPECT_TRUE(Result.ReadFailure);
    EXPECT_TRUE(Result.PeerClosed);
    EXPECT_TRUE(Result.PeerResponseEmpty);
    EXPECT_TRUE(Result.DeadlineReceiptCompleted);
    EXPECT_TRUE(Result.OwnerWaitCleanupCompleted);
    EXPECT_TRUE(Result.FailureOwnerPublished);
    EXPECT_FALSE(Result.DeadlineRetired);
    EXPECT_TRUE(Result.OwnerFailed);
    EXPECT_TRUE(Result.AdmissionClosed);
    EXPECT_EQ(Result.DeadlineFailure,
        static_cast<std::error_code>(boost::system::errc::make_error_code(
            boost::system::errc::io_error)));
    EXPECT_EQ(Result.CancelCalls, 1U);
}

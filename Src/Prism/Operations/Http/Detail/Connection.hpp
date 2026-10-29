/**
 * @file Connection.hpp
 * @brief Operations HTTP accepted connection 与 accept loop owner。
 * @details 所有函数按 state duck type 工作；State 的最终生命周期仍由 HttpServer 拥有。
 */

#pragma once

#include <Prism/Operations/HttpServer.hpp>
#include <Prism/Operations/Http/Detail/Lifecycle.hpp>
#include <Prism/Operations/Detail/HttpRequestLifecycle.hpp>
#include <Prism/Operations/HttpRequestBudget.hpp>
#include <Prism/Operations/HttpServerStartResult.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Operations
{

    using Tcp = Net::ip::tcp;

    struct HttpServer::State final
    {
        explicit State(Options OptionsValue)
            : Executor(std::move(OptionsValue.Executor)),
              StateStrand(Net::make_strand(Executor)),
              BindEndpoint(OptionsValue.BindEndpoint),
              OperationsRouter(std::move(OptionsValue.OperationsRouter)),
              ReadDeadline(OptionsValue.ReadDeadline),
              DrainTimeout(OptionsValue.DrainTimeout),
              Bootstrap(std::move(OptionsValue.Bootstrap)),
              WebResources(std::move(OptionsValue.WebResources)),
              Acceptor(StateStrand),
              DrainTimer(StateStrand)
        {
        }

        Net::any_io_executor Executor;
        Net::strand<Net::any_io_executor> StateStrand;
        Endpoint BindEndpoint;
        Endpoint LocalEndpoint{};
        Router OperationsRouter;
        std::chrono::milliseconds ReadDeadline;
        std::chrono::milliseconds DrainTimeout;
        std::shared_ptr<const BootstrapIdentity> Bootstrap;
        std::shared_ptr<const Web::Catalog> WebResources;
        std::shared_ptr<HttpConnection::RequestByteBudget> RequestBudget{
            std::make_shared<HttpConnection::RequestByteBudget>()};
        std::vector<std::shared_ptr<HttpConnection::ConnectionState>> ActiveConnections;
        Tcp::acceptor Acceptor;
        Net::steady_timer DrainTimer;
        std::optional<std::chrono::steady_clock::time_point> DrainDeadline;
        std::optional<Prism::Fault::Failure> DrainFailure;
        bool DrainTimerArmed{false};
        bool DrainTimerExpired{false};
        bool AcceptLoopCompleted{true};
        std::atomic<std::size_t> ActiveConnectionCount{0};
        std::atomic<std::uint64_t> NextCorrelation{1};
        std::atomic<bool> Started{false};
        std::atomic<bool> Running{false};
        std::atomic<bool> StopRequested{false};
        std::atomic<bool> Draining{false};
        std::atomic<bool> Drained{false};
        std::atomic<bool> StateOperationFailed{false};
    };

} // namespace Prism::Operations

namespace Prism::Operations::HttpConnection
{

    template <typename StateValue>
    inline auto RegisterConnectionOnStateStrand(
        const std::shared_ptr<StateValue> &State,
        const std::shared_ptr<ConnectionState> &Connection) -> void
    {
        if (State->StopRequested.load(std::memory_order_acquire))
        {
            RequestConnectionCloseOnStateStrand(State, Connection);
            return;
        }
        bool Registered = false;
        try
        {
            State->ActiveConnections.push_back(Connection);
            Registered = true;
            State->ActiveConnectionCount.fetch_add(1U, std::memory_order_acq_rel);
            Net::co_spawn(
                Connection->Strand,
                Serve(State, Connection),
                [State](std::exception_ptr Failure) noexcept
                {
                    if (Failure)
                    {
                        State->StateOperationFailed.store(true, std::memory_order_release);
                    }
                });
        }
        catch (...)
        {
            if (Registered)
            {
                const auto It = std::find(
                    State->ActiveConnections.begin(), State->ActiveConnections.end(), Connection);
                if (It != State->ActiveConnections.end())
                {
                    State->ActiveConnections.erase(It);
                }
                (void)State->ActiveConnectionCount.fetch_sub(1U, std::memory_order_acq_rel);
            }
            State->StateOperationFailed.store(true, std::memory_order_release);
            RequestConnectionCloseOnStateStrand(State, Connection);
        }
    }

    template <typename StateValue>
    [[nodiscard]] inline auto AcceptLoop(std::shared_ptr<StateValue> State) -> Net::awaitable<void>
    {
        try
        {
            while (!State->StopRequested.load(std::memory_order_acquire))
            {
                const auto Connection = std::make_shared<ConnectionState>(State->Executor);
                boost::system::error_code Error;
                co_await State->Acceptor.async_accept(
                    *Connection->Socket, Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    if (!State->StopRequested.load(std::memory_order_acquire))
                    {
                        State->StateOperationFailed.store(true, std::memory_order_release);
                        State->Running.store(false, std::memory_order_release);
                        CloseOnStateStrand(State);
                    }
                    break;
                }
                if (State->StopRequested.load(std::memory_order_acquire))
                {
                    RequestConnectionCloseOnStateStrand(State, Connection);
                    break;
                }
                RegisterConnectionOnStateStrand(State, Connection);
                if (State->StateOperationFailed.load(std::memory_order_acquire))
                {
                    CloseOnStateStrand(State);
                    break;
                }
            }
        }
        catch (...)
        {
            if (!State->DrainFailure)
            {
                State->DrainFailure = StateFailureFromException(std::current_exception());
            }
            State->StateOperationFailed.store(true, std::memory_order_release);
            State->Started.store(false, std::memory_order_release);
            State->Running.store(false, std::memory_order_release);
            CloseOnStateStrand(State);
        }
    }

    template <typename StateValue>
    inline auto CompleteAcceptLoop(
        const std::shared_ptr<StateValue> &State,
        const std::exception_ptr Failure) noexcept -> void
    {
        if (Failure)
        {
            State->StateOperationFailed.store(true, std::memory_order_release);
            if (!State->DrainFailure)
            {
                State->DrainFailure = StateFailureFromException(Failure);
            }
        }
        State->AcceptLoopCompleted = true;
        boost::system::error_code Error;
        try
        {
            static_cast<void>(State->DrainTimer.cancel());
        }
        catch (const boost::system::system_error &FailureValue)
        {
            Error = FailureValue.code();
        }
        catch (...)
        {
            Error = boost::system::errc::make_error_code(boost::system::errc::io_error);
        }
        if (Error)
        {
            State->StateOperationFailed.store(true, std::memory_order_release);
            if (!State->DrainFailure)
            {
                State->DrainFailure = Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error));
            }
        }
    }

    template <typename StateValue>
    [[nodiscard]] inline auto StartOnStateStrand(const std::shared_ptr<StateValue> &State)
        -> HttpServerStartResult
    {
        if (State->Started.load(std::memory_order_acquire) ||
            State->StopRequested.load(std::memory_order_acquire) ||
            State->Draining.load(std::memory_order_acquire) ||
            State->Drained.load(std::memory_order_acquire) ||
            State->StateOperationFailed.load(std::memory_order_acquire))
        {
            return std::unexpected(make_error_code(boost::system::errc::operation_canceled));
        }
        if (!State->BindEndpoint.address().is_loopback())
        {
            return std::unexpected(make_error_code(boost::system::errc::permission_denied));
        }
        boost::system::error_code Error;
        State->Acceptor.open(State->BindEndpoint.protocol(), Error);
        if (!Error)
        {
            State->Acceptor.set_option(Tcp::acceptor::reuse_address(true), Error);
        }
        if (!Error)
        {
            State->Acceptor.bind(State->BindEndpoint, Error);
        }
        if (!Error)
        {
            State->Acceptor.listen(Net::socket_base::max_listen_connections, Error);
        }
        if (Error)
        {
            boost::system::error_code CloseError;
            State->Acceptor.close(CloseError);
            return std::unexpected(Error);
        }
        State->LocalEndpoint = State->Acceptor.local_endpoint(Error);
        if (Error)
        {
            boost::system::error_code CloseError;
            State->Acceptor.close(CloseError);
            return std::unexpected(Error);
        }
        State->Started.store(true, std::memory_order_release);
        State->Running.store(true, std::memory_order_release);
        State->AcceptLoopCompleted = false;
        try
        {
            Net::co_spawn(State->StateStrand, AcceptLoop(State),
                [State](std::exception_ptr Failure)
                {
                    CompleteAcceptLoop(State, Failure);
                });
        }
        catch (...)
        {
            State->StateOperationFailed.store(true, std::memory_order_release);
            State->Started.store(false, std::memory_order_release);
            State->Running.store(false, std::memory_order_release);
            State->AcceptLoopCompleted = true;
            /** @brief 保留 co_spawn 失败主因，计时器清理异常不得阻断 acceptor 关闭。 */
            try
            {
                static_cast<void>(State->DrainTimer.cancel());
            }
            catch (...)
            {
            }
            boost::system::error_code CloseError;
            State->Acceptor.cancel(CloseError);
            State->Acceptor.close(CloseError);
            return std::unexpected(make_error_code(boost::system::errc::operation_canceled));
        }
        return State->LocalEndpoint;
    }

} // namespace Prism::Operations::HttpConnection

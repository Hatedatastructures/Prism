/**
 * @file HttpConnection.hpp
 * @brief Operations HTTP accepted connection、read deadline 和 accept loop owner。
 * @details 所有函数按 state duck type 工作；State 的最终生命周期仍由 HttpServer 拥有。
 */

#pragma once

#include <Prism/Operations/Http/Limits.hpp>
#include <Prism/Operations/HttpConnectionLifecycle.hpp>
#include <Prism/Operations/HttpRequestBudget.hpp>
#include <Prism/Operations/Routes/RouteDispatch.hpp>
#include <Prism/Operations/HttpConnectionLifecycle.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/errc.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace Prism::Operations::HttpConnection
{

    [[nodiscard]] inline auto StartReadDeadline(
        const std::shared_ptr<Tcp::socket> &Socket,
        const std::chrono::milliseconds Deadline) -> std::shared_ptr<Net::steady_timer>
    {
        const auto Timer = std::make_shared<Net::steady_timer>(Socket->get_executor());
        Timer->expires_after(Deadline);
        Net::co_spawn(
            Socket->get_executor(),
            [Socket, Timer]() -> Net::awaitable<void>
            {
                boost::system::error_code Error;
                co_await Timer->async_wait(Net::redirect_error(Net::use_awaitable, Error));
                if (!Error)
                {
                    Socket->cancel(Error);
                }
            },
            Net::detached);
        return Timer;
    }

    inline auto CancelReadDeadline(const std::shared_ptr<Net::steady_timer> &Timer) noexcept -> void
    {
        if (Timer)
        {
            try
            {
                (void)Timer->cancel();
            }
            catch (...)
            {
            }
        }
    }

    /** @brief 保存请求头原文；借用视图仅在拥有该字符串的协程帧内生成。 */
    struct RequestReadResult final
    {
        bool Ready{false};
        std::string Bytes;
        RequestByteLease Budget;
    };

    /** @brief 读取并解析一个完整 HTTP 请求；I/O 失败由连接 owner 关闭 socket。 */
    template <typename StateValue>
    [[nodiscard]] inline auto ReadRequest(
        const std::shared_ptr<StateValue> &State,
        const std::shared_ptr<ConnectionState> &Connection) -> Net::awaitable<RequestReadResult>
    {
        const auto Socket = Connection->Socket;
        if (Connection->CloseRequested.load(std::memory_order_acquire))
        {
            CloseSocketOnConnectionStrand(Connection);
            co_return RequestReadResult{};
        }
        const auto Budget = State->RequestBudget;
        if (!Budget || !Budget->TryReserve(MaxRequestBytes))
        {
            boost::system::error_code Error;
            const auto Response = HttpDetail::MakeErrorResponse(503, "request_budget_exhausted");
            co_await Net::async_write(*Socket, Net::buffer(Response),
                Net::redirect_error(Net::use_awaitable, Error));
            CloseSocketOnConnectionStrand(Connection);
            co_return RequestReadResult{};
        }
        RequestByteLease Lease{Budget, MaxRequestBytes};
        std::shared_ptr<Net::steady_timer> ReadDeadline;
        try
        {
            ReadDeadline = StartReadDeadline(Socket, State->ReadDeadline);
        }
        catch (...)
        {
            State->StateOperationFailed.store(true, std::memory_order_release);
            CloseSocketOnConnectionStrand(Connection);
            co_return RequestReadResult{};
        }
        std::array<char, 4096> Chunk{};
        std::string RequestBytes;
        RequestBytes.reserve(MaxRequestBytes);
        HttpRequest Request;
        RequestParserDetail::ParseStatus Status =
            RequestParserDetail::ParseStatus::Incomplete;
        while (Status == RequestParserDetail::ParseStatus::Incomplete)
        {
            boost::system::error_code Error;
            const auto Count = co_await Socket->async_read_some(
                Net::buffer(Chunk), Net::redirect_error(Net::use_awaitable, Error));
            if (Error || Count == 0U)
            {
                CancelReadDeadline(ReadDeadline);
                CloseSocketOnConnectionStrand(Connection);
                co_return RequestReadResult{};
            }
            if (Count > MaxRequestBytes - std::min(RequestBytes.size(), MaxRequestBytes))
            {
                const auto Response = HttpDetail::MakeErrorResponse(413, "request_too_large");
                CancelReadDeadline(ReadDeadline);
                co_await Net::async_write(*Socket, Net::buffer(Response),
                    Net::redirect_error(Net::use_awaitable, Error));
                CloseSocketOnConnectionStrand(Connection);
                co_return RequestReadResult{};
            }
            RequestBytes.append(Chunk.data(), Count);
            Status = RequestParserDetail::ParseRequest(RequestBytes, Request);
        }
        CancelReadDeadline(ReadDeadline);
        co_return RequestReadResult{true, std::move(RequestBytes), std::move(Lease)};
    }

    struct RequestResponse final
    {
        std::string Body;
        std::optional<ResponseDeliveryReceipt> Delivery;
        bool Closed{false};
    };

    /** @brief 在自有字节上重建借用视图，再分派并保留响应回执。 */
    template <typename StateValue>
    [[nodiscard]] inline auto DispatchRequest(
        const std::shared_ptr<StateValue> &State,
        const std::shared_ptr<ConnectionState> &Connection,
        RequestReadResult Input) -> Net::awaitable<RequestResponse>
    {
        RequestResponse Result;
        HttpRequest Request;
        const auto Status = RequestParserDetail::ParseRequest(Input.Bytes, Request);
        if (Status == RequestParserDetail::ParseStatus::Oversized)
        {
            Result.Body = HttpDetail::MakeErrorResponse(413, "request_too_large");
            co_return Result;
        }
        if (Status != RequestParserDetail::ParseStatus::Complete)
        {
            Result.Body = HttpDetail::MakeErrorResponse(400, "bad_request");
            co_return Result;
        }
        Result.Delivery.emplace(ResponseDeliveryReceipt::Create(Connection->Strand));
        Connection->ResponseOutstanding.store(true, std::memory_order_release);
        Connection->HandlerActive.store(true, std::memory_order_release);
        try
        {
            Result.Body = co_await RouteDispatch::Dispatch(
                State, Request, *Result.Delivery);
        }
        catch (...)
        {
            Result.Body = HttpDetail::MakeErrorResponse(500, "handler_failed");
        }
        Connection->HandlerActive.store(false, std::memory_order_release);
        if (Connection->CloseRequested.load(std::memory_order_acquire))
        {
            const auto Acknowledged = co_await Result.Delivery->CompleteAsync(
                std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked}));
            if (!Acknowledged || !*Acknowledged)
            {
                State->StateOperationFailed.store(true, std::memory_order_release);
            }
            Connection->ResponseOutstanding.store(false, std::memory_order_release);
            CloseSocketOnConnectionStrand(Connection);
            Result.Closed = true;
        }
        co_return Result;
    }

    template <typename StateValue>
    [[nodiscard]] inline auto ServeRequest(std::shared_ptr<StateValue> State,
                                           std::shared_ptr<ConnectionState> Connection)
        -> Net::awaitable<void>
    {
        auto Input = co_await ReadRequest(State, Connection);
        if (!Input.Ready) co_return;
        auto Routed = co_await DispatchRequest(State, Connection, std::move(Input));
        if (Routed.Closed) co_return;
        boost::system::error_code Error;
        auto Response = std::move(Routed.Body);
        auto Delivery = std::move(Routed.Delivery);
        std::size_t Written{};
        std::exception_ptr WriteException;
        std::optional<Prism::Fault::Failure> WriteFailure;
        try
        {
            Written = co_await Net::async_write(
                *Connection->Socket, Net::buffer(Response), Net::redirect_error(Net::use_awaitable, Error));
        }
        catch (const std::system_error &Failure)
        {
            WriteFailure = Prism::Fault::FromNative(Failure.code());
            WriteException = std::current_exception();
        }
        catch (...)
        {
            WriteFailure = Prism::Fault::Failure{Prism::Fault::Code::IoError};
            WriteException = std::current_exception();
        }
        if (Delivery)
        {
            auto Outcome = std::expected<void, Prism::Fault::Failure>{};
            if (Error)
            {
                Outcome = std::unexpected(
                    Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
            }
            else if (WriteFailure)
            {
                Outcome = std::unexpected(*WriteFailure);
            }
            else if (Written != Response.size())
            {
                Outcome = std::unexpected(Prism::Fault::FromNative(
                    std::make_error_code(std::errc::io_error)));
            }
            const auto Acknowledged = co_await Delivery->CompleteAsync(std::move(Outcome));
            if (!Acknowledged || !*Acknowledged)
            {
                State->StateOperationFailed.store(true, std::memory_order_release);
            }
        }
        if (Delivery)
        {
            Connection->ResponseOutstanding.store(false, std::memory_order_release);
        }
        if (WriteException)
        {
            std::rethrow_exception(WriteException);
        }
        CloseSocketOnConnectionStrand(Connection);
    }

    template <typename StateValue>
    [[nodiscard]] inline auto Serve(std::shared_ptr<StateValue> State,
                                    std::shared_ptr<ConnectionState> Connection)
        -> Net::awaitable<void>
    {
        ConnectionGuard Guard(State, Connection);
        try
        {
            co_await ServeRequest(State, Connection);
        }
        catch (...)
        {
            State->StateOperationFailed.store(true, std::memory_order_release);
            Connection->HandlerActive.store(false, std::memory_order_release);
            Connection->ResponseOutstanding.store(false, std::memory_order_release);
            CloseSocketOnConnectionStrand(Connection);
        }
    }

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
                    co_return;
                }
                if (State->StopRequested.load(std::memory_order_acquire))
                {
                    RequestConnectionCloseOnStateStrand(State, Connection);
                    co_return;
                }
                RegisterConnectionOnStateStrand(State, Connection);
                if (State->StateOperationFailed.load(std::memory_order_acquire))
                {
                    CloseOnStateStrand(State);
                    co_return;
                }
            }
        }
        catch (...)
        {
            State->StateOperationFailed.store(true, std::memory_order_release);
            State->Started.store(false, std::memory_order_release);
            State->Running.store(false, std::memory_order_release);
            CloseOnStateStrand(State);
        }
    }

    template <typename StateValue>
    [[nodiscard]] inline auto StartOnStateStrand(const std::shared_ptr<StateValue> &State)
        -> HttpServer::StartResult
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
        try
        {
            Net::co_spawn(State->StateStrand, AcceptLoop(State), Net::detached);
        }
        catch (...)
        {
            State->StateOperationFailed.store(true, std::memory_order_release);
            State->Started.store(false, std::memory_order_release);
            State->Running.store(false, std::memory_order_release);
            boost::system::error_code CloseError;
            State->Acceptor.cancel(CloseError);
            State->Acceptor.close(CloseError);
            return std::unexpected(make_error_code(boost::system::errc::operation_canceled));
        }
        return State->LocalEndpoint;
    }

} // namespace Prism::Operations::HttpConnection

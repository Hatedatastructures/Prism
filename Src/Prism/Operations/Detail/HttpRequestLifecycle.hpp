/**
 * @file HttpRequestLifecycle.hpp
 * @brief Operations HTTP 请求读取、分派与响应生命周期实现。
 * @details 保留每连接请求处理模板及测试使用的状态替身边界。
 */

#pragma once

#include <Prism/Operations/Http/Detail/Lifecycle.hpp>
#include <Prism/Operations/Detail/RouteHttpDispatch.hpp>
#include <Prism/Operations/Http/Limits.hpp>
#include <Prism/Operations/Http/Detail/ReadCompletion.hpp>
#include <Prism/Operations/Http/Detail/ReadDeadline.hpp>
#include <Prism/Operations/Http/Detail/ReadDeadlineOwner.hpp>
#include <Prism/Operations/Http/Detail/ReadRequestResult.hpp>
#include <Prism/Operations/HttpRequest.hpp>
#include <Prism/Operations/HttpRequestBudget.hpp>
#include <Prism/Operations/ResponseDeliveryReceipt.hpp>
#include <Prism/Operations/Routes/RequestParser.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>

namespace Prism::Operations::HttpConnection
{

    template <typename StateValue>
    [[nodiscard]] inline auto CancelReadDeadline(
        const std::shared_ptr<StateValue> &State,
        const std::shared_ptr<ConnectionState> &Connection,
        const std::shared_ptr<Detail::ReadDeadlineTask> &Task) -> Net::awaitable<bool>
    {
        const auto Retired = co_await Detail::CancelReadDeadline(Task);
        if (!Retired && Task && Task->Failure &&
            !Task->FailureOwnerPublished.load(std::memory_order_acquire))
        {
            co_await Net::post(State->StateStrand, Net::use_awaitable);
            FailReadDeadlineOnStateStrand(State, Task, *Task->Failure);
            co_await Net::post(Connection->Strand, Net::use_awaitable);
        }
        co_return Retired;
    }

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
        std::array<char, 4096> Chunk{};
        Detail::RequestReadState ReadState;
        try
        {
            ReadState.Bytes.reserve(MaxRequestBytes);
        }
        catch (...)
        {
            State->StateOperationFailed.store(true, std::memory_order_release);
            CloseSocketOnConnectionStrand(Connection);
            co_return RequestReadResult{};
        }
        std::shared_ptr<Detail::ReadDeadlineTask> ReadDeadline;
        try
        {
            Detail::ReadDeadlineActions Actions{
                .CancelSocket = [Socket]
                {
                    boost::system::error_code Error;
                    Socket->cancel(Error);
                    return Error;
                },
                .ReportFailure = [State](
                    const std::shared_ptr<Detail::ReadDeadlineTask> &Task,
                    const boost::system::error_code &Failure)
                {
                    NotifyReadDeadlineFailure(State, Task, Failure);
                }};
            ReadDeadline = Detail::StartReadDeadline(
                Socket, State->ReadDeadline, std::move(Actions));
        }
        catch (...)
        {
            State->StateOperationFailed.store(true, std::memory_order_release);
            CloseSocketOnConnectionStrand(Connection);
            co_return RequestReadResult{};
        }
        boost::system::error_code CompletionTerminal;
        RequestReadResult Result;
        std::exception_ptr ReadFailure;
        try
        {
            while (ReadState.Status == RequestParserDetail::ParseStatus::Incomplete)
            {
                boost::system::error_code Error;
                const auto Count = co_await Socket->async_read_some(
                    Net::buffer(Chunk), Net::redirect_error(Net::use_awaitable, Error));
                const auto Completion = Detail::ApplyReadCompletion(ReadState,
                    Detail::ReadCompletion{std::span<const char>(Chunk.data(), Count), Error});
                CompletionTerminal = Completion.Terminal;
                if (Connection->CloseRequested.load(std::memory_order_acquire) ||
                    Completion.Terminal == Net::error::operation_aborted)
                {
                    (void)co_await CancelReadDeadline(State, Connection, ReadDeadline);
                    CloseSocketOnConnectionStrand(Connection);
                    co_return RequestReadResult{};
                }
                if (Completion.Action == Detail::ReadAction::Oversized)
                {
                    const auto Response = HttpDetail::MakeErrorResponse(413, "request_too_large");
                    const auto DeadlineRetired =
                        co_await CancelReadDeadline(State, Connection, ReadDeadline);
                    if (!DeadlineRetired)
                    {
                        CloseSocketOnConnectionStrand(Connection);
                        co_return RequestReadResult{};
                    }
                    (void)co_await Net::async_write(*Socket, Net::buffer(Response),
                        Net::redirect_error(Net::use_awaitable, Error));
                    CloseSocketOnConnectionStrand(Connection);
                    co_return RequestReadResult{};
                }
                if (Completion.Action == Detail::ReadAction::Terminal ||
                    Completion.Action == Detail::ReadAction::NoProgress)
                {
                    (void)co_await CancelReadDeadline(State, Connection, ReadDeadline);
                    CloseSocketOnConnectionStrand(Connection);
                    co_return RequestReadResult{};
                }
            }
            const auto DeadlineRetired =
                co_await CancelReadDeadline(State, Connection, ReadDeadline);
            if (!DeadlineRetired ||
                Connection->CloseRequested.load(std::memory_order_acquire))
            {
                CloseSocketOnConnectionStrand(Connection);
                co_return RequestReadResult{};
            }
            Result = MakeRequestReadResult(std::move(ReadState), std::move(Lease), CompletionTerminal);
        }
        catch (...)
        {
            ReadFailure = std::current_exception();
        }
        if (ReadFailure)
        {
            (void)co_await CancelReadDeadline(State, Connection, ReadDeadline);
            CloseSocketOnConnectionStrand(Connection);
            std::rethrow_exception(ReadFailure);
        }
        co_return Result;
    }

    struct RequestResponse final
    {
        std::string Body;
        std::optional<ResponseDeliveryReceipt> Delivery;
        boost::system::error_code Terminal;
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
        Result.Terminal = Input.Terminal;
        if (Connection->CloseRequested.load(std::memory_order_acquire))
        {
            CloseSocketOnConnectionStrand(Connection);
            Result.Closed = true;
            co_return Result;
        }
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
        /**
         * @brief 原始请求字节已解析为拥有型 HttpRequest，立即归还输入额度。
         * @details 额度只约束尚未解析的 wire 字节；若持有到路由和响应写完，
         *          连续管理请求会按 MaxInFlightRequestBytes 累积并提前收到 503。
         */
        Input.Budget = RequestByteLease{};
        Result.Delivery.emplace(ResponseDeliveryReceipt::Create(Connection->Strand));
        Connection->ResponseOutstanding.store(true, std::memory_order_release);
        Connection->HandlerActive.store(true, std::memory_order_release);
        try
        {
            Result.Body = co_await Prism::Operations::Detail::RouteHttpDispatch::Dispatch(
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
    [[nodiscard]] inline auto FinishRoutedRequest(
        std::shared_ptr<StateValue> State,
        std::shared_ptr<ConnectionState> Connection,
        RequestResponse Routed)
        -> Net::awaitable<void>
    {
        if (Routed.Closed) co_return;
        if (Routed.Terminal && Routed.Terminal != Net::error::eof)
        {
            if (Routed.Delivery)
            {
                const auto Failure = Prism::Fault::FromNative(
                    static_cast<std::error_code>(Routed.Terminal));
                const auto Acknowledged = co_await Routed.Delivery->CompleteAsync(
                    std::unexpected(Failure));
                if (!Acknowledged || !*Acknowledged)
                {
                    State->StateOperationFailed.store(true, std::memory_order_release);
                }
                Connection->ResponseOutstanding.store(false, std::memory_order_release);
            }
            CloseSocketOnConnectionStrand(Connection);
            co_return;
        }
        boost::system::error_code Error;
        /** @brief 写完响应后先关闭 socket，再发布回执；避免观察者推进 Drain 时连接仍为 OPEN。 */
        auto Response = std::move(Routed.Body);
        auto Delivery = std::move(Routed.Delivery);
        std::size_t Written{};
        std::exception_ptr WriteException;
        std::optional<Prism::Fault::Failure> WriteFailure;
        auto Outcome = std::expected<void, Prism::Fault::Failure>{};
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
        }
        if (Error || WriteFailure || Written != Response.size())
        {
            CloseSocketOnConnectionStrand(Connection);
        }
        else
        {
            CloseCompletedResponseOnConnectionStrand(Connection);
        }
        if (Delivery)
        {
            const auto Acknowledged = co_await Delivery->CompleteAsync(std::move(Outcome));
            if (!Acknowledged || !*Acknowledged)
            {
                State->StateOperationFailed.store(true, std::memory_order_release);
            }
        }
        Connection->ResponseOutstanding.store(false, std::memory_order_release);
        if (WriteException)
        {
            std::rethrow_exception(WriteException);
        }
    }

    template <typename StateValue>
    [[nodiscard]] inline auto ServeRequest(std::shared_ptr<StateValue> State,
                                           std::shared_ptr<ConnectionState> Connection)
        -> Net::awaitable<void>
    {
        auto Input = co_await ReadRequest(State, Connection);
        if (!Input.Ready) co_return;
        auto Routed = co_await DispatchRequest(State, Connection, std::move(Input));
        co_await FinishRoutedRequest(
            std::move(State), std::move(Connection), std::move(Routed));
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

} // namespace Prism::Operations::HttpConnection

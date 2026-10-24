/** @file Reliable.cpp @brief TCP socket ownership、deadline I/O 与 half-close 实现。 */
#include <Prism/Transport/Reliable.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>

#include <boost/asio/async_result.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_composed.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/experimental/parallel_group.hpp>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <chrono>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <tuple>
#include <utility>

namespace Prism::Transport
{
    struct Reliable::ConnectOptions final
    {
        Net::ip::tcp::endpoint Endpoint;
        std::chrono::milliseconds Timeout;
    };

    struct Reliable::ConnectInput final
    {
        std::shared_ptr<Reliable> Owner;
        ConnectOptions Options;
    };

    struct Reliable::ConnectOperation final
    {
        template<class State>
        auto operator()(State Operation, ConnectInput Input) const -> void
        {
            Prism::Transmission::ConfigureIo(Operation);
            if (!Input.Owner->Socket_) co_return std::tuple{IoResult{0, {Fault::Code::InvalidArgument}}};
            Net::steady_timer Timer(Input.Owner->Executor());
            if (Input.Options.Timeout.count() <= 0) Timer.expires_at((Net::steady_timer::time_point::max)());
            else Timer.expires_after(Input.Options.Timeout);
            auto [Order, Error, TimerError] = co_await Net::experimental::make_parallel_group(
                Input.Owner->Socket_->async_connect(Input.Options.Endpoint, Net::deferred), Timer.async_wait(Net::deferred))
                .async_wait(Net::experimental::wait_for_one(), Net::deferred);
            auto Failure = Fault::FromNative(static_cast<std::error_code>(Error));
            if (Order[0] == 1 && !TimerError) Failure.Code = Fault::Code::Timeout;
            if (Failure.Failed()) { boost::system::error_code CloseError; Input.Owner->Socket_->close(CloseError); }
            co_return std::tuple{IoResult{0, Failure}};
        }
    };

    struct Reliable::ConnectWork final
    {
        ConnectInput Input;
        auto operator()(Completion Handler) -> void
        {
            const auto Executor = Input.Owner->Executor();
            Completion Routed(Detail::OriginalCompletion(Executor, std::move(Handler)));
            Net::async_initiate<Completion, void(IoResult)>(Net::co_composed<void(IoResult)>(ConnectOperation{}, Executor),
                Routed, std::move(Input));
        }
    };

    struct Reliable::ConnectInitiation final
    {
        std::shared_ptr<Reliable> Owner;
        ConnectOptions Options;
        ExecutorType Executor;
        template<class Handler>
        auto operator()(Handler&& Callback) -> void
        {
            const auto Domain = Net::get_associated_executor(Callback, Executor);
            Completion Bound(Net::bind_executor(Domain, std::forward<Handler>(Callback)));
            if (!Owner) { Prism::Transmission::PostResult(Executor, std::move(Bound), {0, {Fault::Code::InvalidArgument}}); return; }
            Owner->StartOwned(ConnectWork{{Owner, Options}}, std::move(Bound));
        }
    };

    auto Reliable::AwaitConnect(ConnectInitiation Initiation) -> Net::awaitable<ControlResult>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        const auto Cancellation = co_await Net::this_coro::cancellation_state;
        if (!!Cancellation.cancelled()) co_return std::unexpected(Fault::Failure{Fault::Code::Canceled});
        auto Token = Net::use_awaitable;
        const auto Result = co_await Net::async_initiate<decltype(Token), void(IoResult)>(std::move(Initiation), Token);
        if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
        co_return ControlResult{};
    }

    class Reliable::TimedRead final : public Detail::AssociatedCompletion<Completion>
    {
    public:
        TimedRead(std::shared_ptr<Net::steady_timer> Timer, Completion Handler)
            : AssociatedCompletion(std::move(Handler)), Timer_(std::move(Timer)) {}
        auto operator()(std::tuple<std::array<std::size_t, 2>, boost::system::error_code,
            std::size_t, boost::system::error_code> Result) -> void
        {
            auto [Order, Error, Bytes, TimerError] = Result;
            auto Failure = Fault::FromNative(static_cast<std::error_code>(Error));
            if (Order[0] == 1 && !TimerError) Failure.Code = Fault::Code::Timeout;
            std::move(Handler_)(IoResult{Bytes, Failure});
        }
    private:
        std::shared_ptr<Net::steady_timer> Timer_;
    };

    Reliable::Reliable(Net::any_io_executor Executor)
        : Transmission(Executor), Socket_(Executor)
    {
    }

    Reliable::Reliable(SocketType Socket)
        : Transmission(Socket.get_executor()), Socket_(std::move(Socket))
    {
    }

    auto Reliable::Connect(const Net::ip::tcp::endpoint& Endpoint, std::chrono::milliseconds Timeout)
        -> Net::awaitable<ControlResult>
    {
        return AwaitConnect(ConnectInitiation{
            std::static_pointer_cast<Reliable>(weak_from_this().lock()), {Endpoint, Timeout}, Executor()});
    }

    auto Reliable::ReleaseSocket() noexcept -> std::optional<SocketType>
    {
        auto Result = std::move(Socket_);
        Socket_.reset();
        return Result;
    }

    auto Reliable::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        if (!Socket_) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
        if (Timeout_.count() <= 0)
        {
            Socket_->async_read_some(Net::buffer(Buffer.data(), Buffer.size()), Detail::NativeCompletion(std::move(Handler)));
            return;
        }
        auto Timer = std::make_shared<Net::steady_timer>(Executor());
        Timer->expires_after(Timeout_);
        Net::experimental::make_parallel_group(
            Socket_->async_read_some(Net::buffer(Buffer.data(), Buffer.size()), Net::deferred),
            Timer->async_wait(Net::deferred))
            .async_wait(Net::experimental::wait_for_one(), Net::as_tuple(TimedRead(std::move(Timer), std::move(Handler))));
    }

    auto Reliable::StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        if (!Socket_) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
        Socket_->async_write_some(Net::buffer(Buffer.data(), Buffer.size()), Detail::NativeCompletion(std::move(Handler)));
    }

    auto Reliable::StartWriteShutdown(Completion Handler) -> void
    {
        boost::system::error_code Error;
        if (!Socket_) { Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, {Fault::Code::InvalidArgument}}); return; }
        Socket_->shutdown(SocketType::shutdown_send, Error);
        Prism::Transmission::PostResult(Executor(), std::move(Handler), {0, Fault::FromNative(static_cast<std::error_code>(Error))});
    }

    auto Reliable::OnClose() -> ControlResult
    {
        boost::system::error_code Error;
        if (Socket_) Socket_->close(Error);
        if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
        return {};
    }

    auto Reliable::OnCancel() -> ControlResult
    {
        boost::system::error_code Error;
        if (Socket_ && Socket_->is_open()) Socket_->cancel(Error);
        if (Error) return std::unexpected(Fault::FromNative(static_cast<std::error_code>(Error)));
        return {};
    }

    auto MakeReliable(const Net::any_io_executor& Executor) -> SharedTransmission
    {
        return std::make_shared<Reliable>(Executor);
    }

    auto MakeReliable(Net::ip::tcp::socket Socket) -> SharedTransmission
    {
        return std::make_shared<Reliable>(std::move(Socket));
    }
}

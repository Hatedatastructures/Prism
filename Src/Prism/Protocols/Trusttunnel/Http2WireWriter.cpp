/**
 * @file Http2WireWriter.cpp
 * @brief TrustTunnel HTTP/2 wire 写入队列实现
 */

#include <Prism/Protocols/Trusttunnel/Detail/Http2WireWriter.hpp>

namespace Prism::Trusttunnel::Detail
{
    auto Http2WireWriter::LoopCompletion::operator()(std::exception_ptr Exception) const -> void
    {
        Owner->CompleteLoop(Exception);
    }

    auto Http2WireWriter::Write(std::span<const std::byte> Data) -> Net::awaitable<Http2WireResult>
    {
        if (Data.empty())
        {
            co_return Http2WireResult{};
        }
        if (Closed_ || !Sink_)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                std::make_error_code(std::errc::not_connected)));
        }
        auto Request = std::make_shared<WriteRequest>(Executor_, Data);
        Queue_.push_back(Request);
        Drained_.store(false, std::memory_order_release);
        Start();
        boost::system::error_code WaitError;
        auto Receive = Request->Done.async_receive(
            Net::redirect_error(Net::use_awaitable, WaitError));
        auto Result = co_await std::move(Receive);
        if (WaitError)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(WaitError)));
        }
        co_return Result;
    }

    auto Http2WireWriter::Close() -> void
    {
        Closed_ = true;
        CloseSubmitted_.store(true, std::memory_order_release);
        RejectQueued(Prism::Fault::FromNative(
            std::make_error_code(std::errc::not_connected)));
        RefreshDrained();
    }

    auto Http2WireWriter::Drain()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::throw_if_cancelled(false);
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        while (Running_ || !Queue_.empty() || Active_)
        {
            if (!Running_ && !Queue_.empty() && !Closed_) Start();
            Idle_->reset();
            if (!Running_ && Queue_.empty() && !Active_) break;
            boost::system::error_code Error;
            co_await Idle_->async_receive(Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                RecordFailure(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
                break;
            }
        }
        const auto Failure = FirstFailure_.Load();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto Http2WireWriter::Start() -> void
    {
        if (Running_ || Closed_ || Queue_.empty())
        {
            return;
        }
        Running_ = true;
        Drained_.store(false, std::memory_order_release);
        auto Self = shared_from_this();
        const auto CompletionOwner = Self;
        try
        {
            Net::co_spawn(Executor_, [Self]() -> Net::awaitable<void>
            { co_await Self->Loop(); }, LoopCompletion{CompletionOwner});
        }
        catch (...)
        {
            CompleteLoop(std::current_exception());
        }
    }

    auto Http2WireWriter::Loop() -> Net::awaitable<void>
    {
        while (!Queue_.empty())
        {
            auto Request = std::move(Queue_.front());
            Queue_.pop_front();
            Active_ = Request;
            Http2WireResult Result;
            if (Closed_ || !Sink_)
            {
                Result = std::unexpected(Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected)));
            }
            else
            {
                Result = co_await Sink_(Request->Data);
            }
            const bool Failed = !Result;
            if (Failed) RecordFailure(Result.error());
            (void)Request->Done.try_send(boost::system::error_code{}, std::move(Result));
            Active_.reset();
            if (Failed)
            {
                Closed_ = true;
                RejectQueued(FirstFailure_.Load());
                break;
            }
        }
        co_return;
    }

    auto Http2WireWriter::CompleteLoop(std::exception_ptr Exception) -> void
    {
        if (Exception)
        {
            RecordFailure(FailureFromException(Exception));
            Closed_ = true;
        }
        if (Active_)
        {
            const auto Failure = FirstFailure_.Load();
            (void)Active_->Done.try_send(
                boost::system::error_code{}, std::unexpected(Failure));
            Active_.reset();
        }
        Running_ = false;
        if (Closed_)
        {
            RejectQueued(FirstFailure_.Load());
        }
        else if (!Queue_.empty())
        {
            Start();
            return;
        }
        RefreshDrained();
        (void)Idle_->try_send(boost::system::error_code{});
    }

    auto Http2WireWriter::RejectQueued(const Prism::Fault::Failure Failure) -> void
    {
        while (!Queue_.empty())
        {
            auto Request = std::move(Queue_.front());
            Queue_.pop_front();
            (void)Request->Done.try_send(boost::system::error_code{}, std::unexpected(Failure));
        }
    }

    auto Http2WireWriter::RefreshDrained() noexcept -> void
    {
        Drained_.store(!Running_ && Queue_.empty() && !Active_, std::memory_order_release);
    }

    auto Http2WireWriter::RecordFailure(const Prism::Fault::Failure Failure) noexcept -> void
    {
        if (Failure.Failed())
        {
            // TrySet 输掉竞态只表示已有首因已发布；物理排空仍由 IsRetired 回报。
            (void)FirstFailure_.TrySet(Failure);
        }
    }

    auto Http2WireWriter::FailureFromException(const std::exception_ptr Exception) noexcept
        -> Prism::Fault::Failure
    {
        if (!Exception) return {Prism::Fault::Code::IoError};
        try
        {
            std::rethrow_exception(Exception);
        }
        catch (const boost::system::system_error &Value)
        {
            return Prism::Fault::FromNative(static_cast<std::error_code>(Value.code()));
        }
        catch (const std::system_error &Value)
        {
            return Prism::Fault::FromNative(Value.code());
        }
        catch (const std::bad_alloc &)
        {
            return {Prism::Fault::Code::ResourceUnavailable,
                    std::make_error_code(std::errc::not_enough_memory)};
        }
        catch (...)
        {
            return {Prism::Fault::Code::IoError};
        }
    }

    auto WriteHttp2Wire(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted,
        const std::span<const std::byte> Data) -> Net::awaitable<Http2WireResult>
    {
        const auto Result = co_await Encrypted->WriteExact(Data);
        if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
        if (Result.Bytes != Data.size())
            co_return std::unexpected(Prism::Fault::FromNative(
                std::make_error_code(std::errc::io_error)));
        co_return Http2WireResult{};
    }

    auto MakeHttp2Wire(
        const std::shared_ptr<Prism::Transport::Encrypted> &Encrypted)
        -> std::shared_ptr<Http2WireWriter>
    {
        return std::make_shared<Http2WireWriter>(
            Encrypted->Executor(),
            [Encrypted](std::span<const std::byte> Data) -> Net::awaitable<Http2WireResult>
            { return WriteHttp2Wire(Encrypted, Data); });
    }

    auto FlushHttp2Frames(
        const std::shared_ptr<H2::Session> &Session,
        const std::shared_ptr<Http2WireWriter> &Wire) -> Net::awaitable<Http2WireResult>
    {
        std::vector<std::byte> Output;
        if (Session->Collect(Output) && !Output.empty())
        {
            co_return co_await Wire->Write(Output);
        }
        co_return Http2WireResult{};
    }
} // namespace Prism::Trusttunnel::Detail

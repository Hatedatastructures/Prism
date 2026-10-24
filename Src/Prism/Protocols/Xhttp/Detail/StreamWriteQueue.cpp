/**
 * @file StreamWriteQueue.cpp
 * @brief XHTTP Stream-one 写队列实现。
 */
#include <Prism/Protocols/Xhttp/Detail/StreamWriteQueue.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <exception>
#include <memory>
#include <new>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail::Detail
{
    StreamWriteQueue::StreamWriteQueue(
        Net::any_io_executor Executor,
        WriteCallback Write,
        FinishCallback Finish)
        : Ex_(std::move(Executor)), Write_(std::move(Write)),
          Finish_(std::move(Finish)), Idle_(std::make_shared<IdleChannel>(Ex_, 1))
    {
    }

    [[nodiscard]] auto StreamWriteQueue::Write(std::span<const std::byte> Data)
            -> Net::awaitable<std::expected<std::size_t, Prism::Fault::Failure>>
    {
        if (Data.empty())
            co_return std::size_t{0};
        if (Closed_ || Finished_ || !Write_)
            co_return std::unexpected(NotConnected());
        if (StreamId_ < 0)
        {
            try
            {
                Pending_.insert(Pending_.end(), Data.begin(), Data.end());
            }
            catch (const std::bad_alloc &)
            {
                co_return std::unexpected(ExceptionFailure());
            }
            co_return Data.size();
        }
        auto Result = co_await Enqueue(
            WriteCommand{StreamId_, Data, false, true});
        if (!Result) co_return std::unexpected(Result.error());
        co_return *Result;

    }

    [[nodiscard]] auto StreamWriteQueue::Finish()
            -> Net::awaitable<WriteResult>
    {
        if (Closed_ || Finished_ || StreamId_ < 0 || !Finish_)
            co_return std::unexpected(NotConnected());
        Finished_ = true;
        const auto Result = co_await Enqueue(
            WriteCommand{StreamId_, {}, true, true});
        if (!Result) co_return std::unexpected(Result.error());
        co_return WriteResult{};

    }

    void StreamWriteQueue::BindStream(std::int32_t StreamId, FailureCallback Failure)
    {
        if (Closed_ || StreamId_ >= 0)
            return;
        StreamId_ = StreamId;
        Failure_ = std::move(Failure);
        if (Pending_.empty())
            return;
        auto Pending = std::move(Pending_);
        QueueWrite(QueuedWrite{StreamId_, std::move(Pending), false, {}});

    }

    void StreamWriteQueue::Close()
    {
        if (!Closed_)
        {
            Closed_ = true;
            Pending_.clear();
            FailQueued(NotConnected());
        }
        RefreshRetired();
        NotifyIdle();

    }

    [[nodiscard]] auto StreamWriteQueue::Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        Close();
        while (!IsRetired())
        {
            Idle_->reset();
            if (IsRetired()) break;
            boost::system::error_code Error;
            co_await Idle_->async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
                co_return std::unexpected(Prism::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
        }
        const auto Failure = FirstFailure_.Load();
        if (Failure.Failed()) co_return std::unexpected(Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};

    }

    [[nodiscard]] auto StreamWriteQueue::IsRetired() const noexcept -> bool
    {
        return Retired_.load(std::memory_order_acquire);

    }

    StreamWriteQueue::WriteRequest::WriteRequest(
                Net::any_io_executor Executor,
                WriteCommand Command)
                : StreamId(Command.StreamId), Data(Command.Data.begin(), Command.Data.end()),
                  EndStream(Command.EndStream)
    {
            if (Command.AwaitCompletion)
                Done = std::make_shared<CompletionChannel>(std::move(Executor), 1);

    }

    [[nodiscard]] auto StreamWriteQueue::NotConnected() noexcept -> Prism::Fault::Failure
    {
        return Prism::Fault::FromNative(
            std::make_error_code(std::errc::not_connected));

    }

    [[nodiscard]] auto StreamWriteQueue::ExceptionFailure() noexcept -> Prism::Fault::Failure
    {
        return Prism::Contract::InboundAdmission::ExceptionFailure(
            std::current_exception());

    }

    [[nodiscard]] auto StreamWriteQueue::Enqueue(
            WriteCommand Command)
            -> Net::awaitable<std::expected<std::size_t, Prism::Fault::Failure>>
    {
        std::shared_ptr<WriteRequest> Request;
        try
        {
            Request = std::make_shared<WriteRequest>(Ex_, Command);
            WriteQueue_.push_back(Request);
            StartWriter();
        }
        catch (const std::bad_alloc &)
        {
            const auto Failure = ExceptionFailure();
            if (Request && Request->Done)
                (void)Request->Done->try_send(
                    boost::system::error_code{}, 0, Failure);
            FailQueued(Failure);
            Closed_ = true;
            NotifyFailure(Failure);
            RefreshRetired();
            NotifyIdle();
            co_return std::unexpected(Failure);
        }
        if (!Request->Done)
            co_return Command.Data.size();
        boost::system::error_code WaitError;
        const auto [Written, Failure] = co_await Request->Done->async_receive(
            Net::redirect_error(Net::use_awaitable, WaitError));
        if (WaitError)
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(WaitError)));
        if (Failure.Failed()) co_return std::unexpected(Failure);
        co_return Written;

    }

    void StreamWriteQueue::QueueWrite(QueuedWrite Value)
    {
        try
        {
            auto Request = std::make_shared<WriteRequest>(
                Ex_, WriteCommand{Value.StreamId, Value.Data, Value.EndStream, false});
            Request->Done = std::move(Value.Completion);
            WriteQueue_.push_back(std::move(Request));
            StartWriter();
        }
        catch (const std::bad_alloc &)
        {
            const auto Failure = ExceptionFailure();
            FailQueued(Failure);
            Closed_ = true;
            NotifyFailure(Failure);
            RefreshRetired();
            NotifyIdle();
        }

    }

    void StreamWriteQueue::StartWriter()
    {
        if (WriterRunning_ || Closed_ || WriteQueue_.empty())
            return;
        WriterRunning_ = true;
        auto Self = shared_from_this();
        try
        {
            Net::co_spawn(
                Ex_, [Self]() -> Net::awaitable<void> { co_await Self->WriteLoop(); },
                [Self](std::exception_ptr Exception)
                { Self->CompleteWriteLoop(std::move(Exception)); });
        }
        catch (const std::bad_alloc &)
        {
            WriterRunning_ = false;
            throw;
        }

    }

    void StreamWriteQueue::FailQueued(Prism::Fault::Failure Failure)
    {
        while (!WriteQueue_.empty())
        {
            auto Request = std::move(WriteQueue_.front());
            WriteQueue_.pop_front();
            if (Request->Done)
                (void)Request->Done->try_send(
                    boost::system::error_code{}, 0, Failure);
        }

    }

    void StreamWriteQueue::NotifyFailure(Prism::Fault::Failure Failure) noexcept
    {
        if (!Failure.Failed()) return;
        (void)FirstFailure_.TrySet(Failure);
        if (!Failure_) return;
        auto Callback = std::move(Failure_);
        try
        {
            Callback(Failure);
        }
        catch (...)
        {
            (void)FirstFailure_.TrySet(
                Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
        }

    }

    auto StreamWriteQueue::WriteLoop() -> Net::awaitable<void>
    {
        while (!WriteQueue_.empty())
        {
            auto Request = std::move(WriteQueue_.front());
            WriteQueue_.pop_front();
            ActiveRequest_ = Request;
            Prism::Fault::Failure Failure;
            std::size_t Written = 0;
            if (!Closed_ && Request->EndStream)
            {
                if (Finish_)
                {
                    const auto Result = co_await Finish_(Request->StreamId);
                    if (!Result) Failure = Result.error();
                }
                else
                {
                    Failure = NotConnected();
                }
            }
            else if (!Closed_ && Write_ && !Request->EndStream)
            {
                const auto Result = co_await Write_(
                    Request->StreamId, std::span<const std::byte>(Request->Data));
                if (!Result) Failure = Result.error();
                if (!Failure.Failed()) Written = Request->Data.size();
            }
            else
            {
                Failure = NotConnected();
            }
            if (Request->Done)
                (void)Request->Done->try_send(
                    boost::system::error_code{}, Written, Failure);
            ActiveRequest_.reset();
            if (!Failure.Failed())
                continue;
            Closed_ = true;
            FailQueued(Failure);
            NotifyFailure(Failure);
            break;
        }
        co_return;

    }

    auto StreamWriteQueue::CompleteWriteLoop(std::exception_ptr Exception) noexcept -> void
    {
        if (Exception)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::move(Exception));
            if (ActiveRequest_ && ActiveRequest_->Done)
                (void)ActiveRequest_->Done->try_send(
                    boost::system::error_code{}, 0, Failure);
            ActiveRequest_.reset();
            Closed_ = true;
            FailQueued(Failure);
            NotifyFailure(Failure);
        }
        WriterRunning_ = false;
        RefreshRetired();
        NotifyIdle();

    }

    auto StreamWriteQueue::RefreshRetired() noexcept -> void
    {
        Retired_.store(
            Closed_ && Pending_.empty() && !WriterRunning_ && WriteQueue_.empty() && !ActiveRequest_,
            std::memory_order_release);

    }

    auto StreamWriteQueue::NotifyIdle() noexcept -> void
    {
        (void)Idle_->try_send(boost::system::error_code{});

    }
} // namespace Prism::Xhttp::Detail::Detail

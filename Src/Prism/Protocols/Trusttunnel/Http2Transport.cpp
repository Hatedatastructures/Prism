/**
 * @file Http2Transport.cpp
 * @brief TrustTunnel HTTP/2 CONNECT 流传输实现
 */

#include <Prism/Protocols/Trusttunnel/Detail/Http2Transport.hpp>

namespace Prism::Trusttunnel::Detail
{
    auto Http2Transport::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        Initiate<ReadWork>(ReadInput{Owner(), Buffer}, std::move(Handler));
    }

    auto Http2Transport::StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        Initiate<WriteWork>(WriteInput{Owner(), Buffer}, std::move(Handler));
    }

    auto Http2Transport::StartWriteShutdown(Completion Handler) -> void
    {
        Initiate<ShutdownWork>(ShutdownInput{Owner()}, std::move(Handler));
    }

    auto Http2Transport::OnClose() -> ControlResult
    {
        if (Closed_)
        {
            if (CloseFailure_.Failed())
            {
                return std::unexpected(CloseFailure_);
            }
            return {};
        }
        CloseLocal();
        CloseCarrier();
        if (CloseFailure_.Failed())
        {
            return std::unexpected(CloseFailure_);
        }
        return {};
    }

    auto Http2Transport::OnCancel() -> ControlResult
    {
        return OnClose();
    }

    auto Http2Transport::Finish() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (Closed_ || Finished_ || StreamId_ < 0 || !FinishFunction_)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                std::make_error_code(std::errc::not_connected)));
        }
        Finished_ = true;
        auto Request = std::make_shared<WriteRequest>(WriteRequestOptions{
            Executor_, StreamId_, std::span<const std::byte>{}, true});
        WriteQueue_.push_back(Request);
        StartWriter();
        boost::system::error_code WaitError;
        auto Receive = Request->Done->async_receive(
            Net::redirect_error(Net::use_awaitable, WaitError));
        auto Result = co_await std::move(Receive);
        if (WaitError)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                static_cast<std::error_code>(WaitError)));
        }
        if (Result.Failure.Failed()) co_return std::unexpected(Result.Failure);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    void Http2Transport::Push(std::span<const std::byte> Data)
    {
        if (Closed_ || DrainTerminal_ || TerminalError_ || Data.empty())
        {
            return;
        }
        std::vector<std::byte> Copy(Data.begin(), Data.end());
        if (!Notify_.try_send(boost::system::error_code{}, std::move(Copy)))
        {
            CloseLocal();
        }
    }

    void Http2Transport::NotifyEof()
    {
        if (!Closed_ && !TerminalError_ && !DrainTerminal_ && !Eof_)
        {
            if (!Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{}))
            {
                EofPending_ = true;
            }
        }
    }

    auto Http2Transport::NotifyError(Prism::Fault::Failure Failure) -> void
    {
        if (TerminalError_ || DrainTerminal_ || Closed_)
        {
            return;
        }
        TerminalError_ = Prism::Fault::ToNative(Failure);
        DrainTerminal_ = false;
        (void)Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{});
    }

    auto Http2Transport::NotifyReadTerminal(Prism::Fault::Failure Failure) -> void
    {
        if (TerminalError_ || DrainTerminal_ || Closed_)
        {
            return;
        }
        if (Failure.Succeeded()) Failure = {Prism::Fault::Code::WouldBlock};
        ReadTerminalFailure_ = Failure;
        TerminalError_ = Prism::Fault::ToNative(Failure);
        DrainTerminal_ = true;
        Eof_ = false;
        EofPending_ = false;
        (void)Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{});
    }

    auto Http2Transport::CloseCarrierForReadTerminal() -> Prism::Fault::Failure
    {
        if (DrainTerminal_ && !ReadHalfClosed())
        {
            CloseCarrier();
        }
        return CloseFailure_;
    }

    auto Http2Transport::CloseCarrier() -> void
    {
        if (CloseCarrierInvoked_)
        {
            return;
        }
        CloseCarrierInvoked_ = true;
        if (CloseFunction_)
        {
            const auto Closed = CloseFunction_();
            if (!Closed && CloseFailure_.Succeeded()) CloseFailure_ = Closed.error();
        }
    }

    void Http2Transport::BindStream(std::int32_t StreamId)
    {
        if (Closed_ || StreamId_ >= 0)
        {
            return;
        }
        StreamId_ = StreamId;
        if (!PendingWrite_.empty())
        {
            QueuePendingWrite(std::move(PendingWrite_));
        }
    }

    auto Http2Transport::SetAuthority(std::string Authority) -> void
    {
        Authority_ = std::move(Authority);
    }

    auto Http2Transport::CloseLocal() -> void
    {
        if (Closed_) return;
        Closed_ = true;
        if (!DrainTerminal_)
        {
            Notify_.cancel();
        }
        while (!WriteQueue_.empty())
        {
            auto Request = std::move(WriteQueue_.front());
            WriteQueue_.pop_front();
            if (Request->Done)
            {
                (void)Request->Done->try_send(
                    boost::system::error_code{},
                    WriteResult{0, Prism::Fault::FromNative(
                                      std::make_error_code(std::errc::not_connected))});
            }
        }
        PendingWrite_.clear();
        WriterRunning_ = false;
    }

    auto Http2Transport::ReadPartial(std::span<std::byte> Buffer, std::error_code &Error)
        -> Net::awaitable<std::size_t>
    {
        Error.clear();
        while (ReadOffset_ >= ReadCurrent_.size())
        {
            if (TerminalError_ && (!DrainTerminal_ || !Notify_.ready()))
            {
                Error = TerminalError_;
                co_return 0;
            }
            if (Closed_ && !DrainTerminal_)
            {
                Error = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (Eof_)
            {
                co_return 0;
            }
            if (EofPending_ && !Notify_.ready())
            {
                EofPending_ = false;
                Eof_ = true;
                co_return 0;
            }
            boost::system::error_code ChannelError;
            auto Receive = Notify_.async_receive(
                Net::redirect_error(Net::use_awaitable, ChannelError));
            auto Block = co_await std::move(Receive);
            if (ChannelError)
            {
                if (Closed_) co_return 0;
                if (TerminalError_)
                {
                    Error = TerminalError_;
                    co_return 0;
                }
                Error = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (Block.empty())
            {
                if (TerminalError_)
                {
                    Error = TerminalError_;
                    co_return 0;
                }
                Eof_ = true;
                co_return 0;
            }
            ReadCurrent_ = std::move(Block);
            ReadOffset_ = 0;
        }
        const auto Count = (std::min)(Buffer.size(), ReadCurrent_.size() - ReadOffset_);
        std::memcpy(Buffer.data(), ReadCurrent_.data() + ReadOffset_, Count);
        ReadOffset_ += Count;
        Error.clear();
        co_return Count;
    }

    auto Http2Transport::WritePartial(std::span<const std::byte> Buffer)
        -> Net::awaitable<WriteResult>
    {
        if (Buffer.empty())
        {
            co_return WriteResult{};
        }
        if (Closed_ || Finished_ || !WriteFunction_)
        {
            co_return WriteResult{0, Prism::Fault::FromNative(
                std::make_error_code(std::errc::not_connected))};
        }
        if (StreamId_ < 0)
        {
            PendingWrite_.insert(PendingWrite_.end(), Buffer.begin(), Buffer.end());
            co_return WriteResult{Buffer.size(), {}};
        }
        auto Request = std::make_shared<WriteRequest>(WriteRequestOptions{
            Executor_, StreamId_, Buffer});
        WriteQueue_.push_back(Request);
        StartWriter();
        boost::system::error_code WaitError;
        auto Receive = Request->Done->async_receive(
            Net::redirect_error(Net::use_awaitable, WaitError));
        auto Result = co_await std::move(Receive);
        if (WaitError)
        {
            co_return WriteResult{Result.Bytes,
                Prism::Fault::FromNative(static_cast<std::error_code>(WaitError))};
        }
        co_return Result;
    }

    auto Http2Transport::ShutdownPartial()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (Closed_ || Finished_ || StreamId_ < 0 || !FinishFunction_)
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        }
        auto Result = co_await Finish();
        if (!Result)
        {
            CloseLocal();
            co_return std::unexpected(Result.error());
        }
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    void Http2Transport::QueuePendingWrite(std::vector<std::byte> Data)
    {
        if (Data.empty() || Closed_ || !WriteFunction_)
        {
            return;
        }
        auto Request = std::make_shared<WriteRequest>(WriteRequestOptions{
            Executor_, StreamId_, Data});
        Request->Done.reset();
        WriteQueue_.push_back(std::move(Request));
        StartWriter();
    }

    void Http2Transport::StartWriter()
    {
        if (WriterRunning_ || Closed_ || WriteQueue_.empty())
        {
            return;
        }
        WriterRunning_ = true;
        auto Self = std::static_pointer_cast<Http2Transport>(Transmission::shared_from_this());
        Net::co_spawn(
            Executor_,
            [Self]() -> Net::awaitable<void> { co_await Self->WriteLoop(); },
            Net::detached);
    }

    auto Http2Transport::WriteLoop() -> Net::awaitable<void>
    {
        while (!WriteQueue_.empty())
        {
            auto Request = std::move(WriteQueue_.front());
            WriteQueue_.pop_front();
            boost::system::error_code Error;
            WriteResult Result;
            bool MissingFunction = false;
            if (Request->EndStream)
            {
                MissingFunction = !FinishFunction_;
            }
            else
            {
                MissingFunction = !WriteFunction_;
            }
            if (Closed_ || MissingFunction)
                Result.Failure = Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected));
            else if (Request->EndStream)
            {
                const auto Finished = co_await FinishFunction_(Request->StreamId);
                if (!Finished) Result.Failure = Finished.error();
            }
            else
            {
                const auto Written = co_await WriteFunction_(Request->StreamId, Request->Data);
                if (!Written) Result.Failure = Written.error();
                else Result.Bytes = Request->Data.size();
            }
            const auto Failed = Result.Failure.Failed();
            if (Request->Done)
            {
                (void)Request->Done->try_send(boost::system::error_code{}, Result);
            }
            if (Failed)
            {
                Closed_ = true;
                break;
            }
        }
        WriterRunning_ = false;
        co_return;
    }
} // namespace Prism::Trusttunnel::Detail

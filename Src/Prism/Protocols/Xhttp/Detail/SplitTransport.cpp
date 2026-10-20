/**
 * @file SplitTransport.cpp
 * @brief XHTTP Split 传输状态实现。
 */
#include <Prism/Protocols/Xhttp/Detail/SplitTransport.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstring>
#include <exception>
#include <memory>
#include <new>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail
{
    SplitTransport::SplitTransport(
        Net::any_io_executor Executor,
        WriteCb WriteFunction,
        CloseCb CloseFunction)
        : Transmission(Executor),
          Ex_(std::move(Executor)),
          WriteFn_(std::move(WriteFunction)),
          CloseFn_(std::move(CloseFunction)),
          Notify_(Ex_, 64)
    {
    }

    [[nodiscard]] auto SplitTransport::Executor() const -> ExecutorType
    {
        return Ex_;

    }

    [[nodiscard]] auto SplitTransport::CloseFailure() const noexcept -> Prism::Fault::Failure
    {
        return CloseFailure_;

    }

    auto SplitTransport::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        Initiate<ReadWork>(ReadInput{Owner(), Buffer}, std::move(Handler));

    }

    auto SplitTransport::StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        Initiate<WriteWork>(WriteInput{Owner(), Buffer}, std::move(Handler));

    }

    auto SplitTransport::StartWriteShutdown(Completion Handler) -> void
    {
        Prism::Transmission::PostResult(Executor(), std::move(Handler), Prism::IoResult{0, {}});

    }

    [[nodiscard]] auto SplitTransport::OnClose() -> ControlResult
    {
        return CloseLocal();

    }

    [[nodiscard]] auto SplitTransport::OnCancel() -> ControlResult
    {
        return OnClose();

    }

    void SplitTransport::Push(std::span<const std::byte> Data)
    {
        if (Closed_ || DrainTerminal_ || TerminalError_ || Data.empty())
        {
            return;
        }
        std::vector<std::byte> Copy(Data.begin(), Data.end());
        if (!Notify_.try_send(boost::system::error_code{}, std::move(Copy)))
        {
            const auto Closed = Close();
            if (!Closed)
            {
                const auto Failure = Closed.error();
                if (CloseFailure_.Succeeded()) CloseFailure_ = Failure;
                NotifyError(Prism::Fault::ToNative(Failure));
            }
        }

    }

    void SplitTransport::NotifyEof()
    {
        if (!Closed_ && !DrainTerminal_ && !TerminalError_ && !Eof_ && !EofPending_)
        {
            if (!Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{}))
            {
                EofPending_ = true;
            }
        }

    }

    void SplitTransport::NotifyError(std::error_code ErrorCode)
    {
        if (TerminalError_ || DrainTerminal_)
        {
            return;
        }
        TerminalError_ = ErrorCode;
        if (!TerminalError_)
            TerminalError_ = std::make_error_code(std::errc::protocol_error);
        Eof_ = false;
        EofPending_ = false;
        (void)Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{});
        FailQueued(Prism::Fault::FromNative(TerminalError_));

    }

    void SplitTransport::NotifyReadTerminal(Prism::Fault::Failure Failure)
    {
        if (TerminalError_ || DrainTerminal_ || Closed_)
        {
            return;
        }
        if (Failure.Succeeded()) Failure = {Prism::Fault::Code::WouldBlock};
        TerminalError_ = Prism::Fault::ToNative(Failure);
        DrainTerminal_ = true;
        Eof_ = false;
        EofPending_ = false;
        (void)Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{});
        FailQueued(Prism::Fault::FromNative(TerminalError_));

    }

    [[nodiscard]] auto SplitTransport::DrainTerminalPending() const noexcept -> bool
    {
        return DrainTerminal_;

    }

    [[nodiscard]] auto SplitTransport::Owner() -> std::shared_ptr<SplitTransport>
    {
        return std::static_pointer_cast<SplitTransport>(Transmission::shared_from_this());

    }

    auto SplitTransport::CloseLocal() -> ControlResult
    {
        if (Closed_)
        {
            if (CloseFailure_.Failed())
            {
                return std::unexpected(CloseFailure_);
            }
            return {};
        }
        Closed_ = true;
        Notify_.cancel();
        FailQueued(Prism::Fault::FromNative(
            std::make_error_code(std::errc::not_connected)));
        const auto Failure = NotifyClose();
        if (Failure.Failed())
        {
            return std::unexpected(Failure);
        }
        return {};

    }

    [[nodiscard]] auto SplitTransport::ReadPartial(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>
    {
        if (Buffer.empty())
        {
            ErrorCode.clear();
            co_return 0;
        }
        // RST/终止协议错误立即使排队载荷失效；错误可见后不再交付旧字节。
        if (TerminalError_ && !DrainTerminal_)
        {
            ErrorCode = TerminalError_;
            co_return 0;
        }
        while (RxOffset_ >= RxCurrent_.size())
        {
            if (TerminalError_ && (!DrainTerminal_ || !Notify_.ready()))
            {
                ErrorCode = TerminalError_;
                co_return 0;
            }
            if (Closed_ && !DrainTerminal_)
            {
                ErrorCode = std::make_error_code(std::errc::not_connected);
                co_return 0;
            }
            if (Eof_)
            {
                ErrorCode.clear();
                co_return 0;
            }
            if (EofPending_ && !Notify_.ready())
            {
                EofPending_ = false;
                Eof_ = true;
                ErrorCode.clear();
                co_return 0;
            }
            boost::system::error_code ChannelError;
            auto Block = co_await Notify_.async_receive(
                Net::redirect_error(Net::use_awaitable, ChannelError));
            if (ChannelError)
            {
                if (TerminalError_)
                {
                    ErrorCode = TerminalError_;
                }
                else
                {
                    ErrorCode = std::make_error_code(std::errc::not_connected);
                }
                co_return 0;
            }
            if (TerminalError_ && !DrainTerminal_)
            {
                ErrorCode = TerminalError_;
                co_return 0;
            }
            if (Block.empty())
            {
                if (TerminalError_)
                {
                    ErrorCode = TerminalError_;
                    co_return 0;
                }
                Eof_ = true;
                ErrorCode.clear();
                co_return 0;
            }
            RxCurrent_ = std::move(Block);
            RxOffset_ = 0;
        }
        const auto Count = (std::min)(Buffer.size(), RxCurrent_.size() - RxOffset_);
        std::memcpy(Buffer.data(), RxCurrent_.data() + RxOffset_, Count);
        RxOffset_ += Count;
        ErrorCode.clear();
        co_return Count;

    }

    [[nodiscard]] auto SplitTransport::WritePartial(
            std::span<const std::byte> Buffer,
            Prism::Fault::Failure &Failure)
            -> Net::awaitable<std::size_t>
    {
        if (Buffer.empty())
        {
            Failure = {};
            co_return 0;
        }
        if (TerminalError_ || DrainTerminal_)
        {
            Failure = Prism::Fault::FromNative(TerminalError_);
            co_return 0;
        }
        if (Closed_ || !WriteFn_)
        {
            Failure = Prism::Fault::FromNative(
                std::make_error_code(std::errc::not_connected));
            co_return 0;
        }
        std::shared_ptr<WriteRequest> Request;
        try
        {
            Request = std::make_shared<WriteRequest>(Ex_, Buffer);
            WriteQueue_.push_back(Request);
            StartWriter();
        }
        catch (const std::bad_alloc &)
        {
            Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
            FailQueued(Failure);
            co_return 0;
        }

        boost::system::error_code WaitError;
        const auto [Written, WriteFailure] = co_await Request->Done->async_receive(
            Net::redirect_error(Net::use_awaitable, WaitError));
        if (WaitError)
        {
            Failure = Prism::Fault::FromNative(
                static_cast<std::error_code>(WaitError));
            co_return 0;
        }
        Failure = WriteFailure;
        if (Failure.Failed()) co_return 0;
        co_return Written;

    }

    SplitTransport::WriteRequest::WriteRequest(Net::any_io_executor Executor, std::span<const std::byte> Bytes)
                : Data(Bytes.begin(), Bytes.end()), Done(std::make_shared<CompletionChannel>(Executor, 1))
    {

    }

    void SplitTransport::StartWriter()
    {
        if (WriterRunning_ || Closed_ || WriteQueue_.empty())
        {
            return;
        }
        WriterRunning_ = true;
        auto Self = std::static_pointer_cast<SplitTransport>(Transmission::shared_from_this());
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

    void SplitTransport::FailQueued(Prism::Fault::Failure Failure)
    {
        while (!WriteQueue_.empty())
        {
            auto Request = std::move(WriteQueue_.front());
            WriteQueue_.pop_front();
            (void)Request->Done->try_send(
                boost::system::error_code{}, 0, Failure);
        }

    }

    auto SplitTransport::NotifyClose() -> Prism::Fault::Failure
    {
        if (CloseNotified_)
        {
            return CloseFailure_;
        }
        CloseNotified_ = true;
        if (CloseFn_)
        {
            try
            {
                const auto Failure = CloseFn_();
                if (CloseFailure_.Succeeded() && Failure.Failed())
                    CloseFailure_ = Failure;
            }
            catch (...)
            {
                CloseFailure_ = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
            }
        }
        if (CloseFailure_.Failed()) NotifyError(Prism::Fault::ToNative(CloseFailure_));
        return CloseFailure_;

    }

    auto SplitTransport::WriteLoop() -> Net::awaitable<void>
    {
        while (!WriteQueue_.empty())
        {
            auto Request = std::move(WriteQueue_.front());
            WriteQueue_.pop_front();
            ActiveWriteRequest_ = Request;
            Prism::Fault::Failure Failure;
            std::size_t Written = 0;
            if (Closed_ || !WriteFn_)
            {
                Failure = Prism::Fault::FromNative(
                    std::make_error_code(std::errc::not_connected));
            }
            else
            {
                const auto Result = co_await WriteFn_(Request->Data);
                if (!Result) Failure = Result.error();
                if (!Failure.Failed()) Written = Request->Data.size();
            }
            (void)Request->Done->try_send(
                boost::system::error_code{}, Written, Failure);
            ActiveWriteRequest_.reset();
            if (Failure.Failed())
            {
                NotifyError(Prism::Fault::ToNative(Failure));
                Closed_ = true;
                FailQueued(Failure);
                (void)NotifyClose();
                break;
            }
        }
        co_return;

    }

    auto SplitTransport::CompleteWriteLoop(std::exception_ptr Exception) noexcept -> void
    {
        if (Exception)
        {
            const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::move(Exception));
            if (ActiveWriteRequest_)
            {
                (void)ActiveWriteRequest_->Done->try_send(
                    boost::system::error_code{}, 0, Failure);
                ActiveWriteRequest_.reset();
            }
            NotifyError(Prism::Fault::ToNative(Failure));
            Closed_ = true;
            FailQueued(Failure);
            NotifyClose();
        }
        WriterRunning_ = false;

    }
} // namespace Prism::Xhttp::Detail

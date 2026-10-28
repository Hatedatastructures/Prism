/**
 * @file Transport.cpp
 * @brief XHTTP Stream-one 传输状态实现。
 */
#include <Prism/Protocols/Xhttp/Detail/Stream/Transport.hpp>

#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Error.hpp>

#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstring>
#include <expected>
#include <exception>
#include <memory>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace Prism::Xhttp::Detail
{
    XhttpTransport::XhttpTransport(Options Value)
        : Transmission(Value.Executor),
          Ex_(std::move(Value.Executor)),
          Writer_(std::make_shared<Detail::StreamWriteQueue>(
              Ex_, std::move(Value.Write), std::move(Value.Finish))),
          CloseOwner_(std::move(Value.CloseOwner)),
          Notify_(Ex_, 64)
    {
    }

    [[nodiscard]] auto XhttpTransport::Executor() const -> ExecutorType
    {
        return Ex_;

    }

    [[nodiscard]] auto XhttpTransport::CloseFailure() const noexcept -> Prism::Fault::Failure
    {
        return CloseFailure_;

    }

    auto XhttpTransport::RecordCloseFailure(const Prism::Fault::Failure Failure) noexcept -> void
    {
        if (CloseFailure_.Succeeded() && Failure.Failed()) CloseFailure_ = Failure;

    }

    auto XhttpTransport::StartRead(std::span<std::byte> Buffer, Completion Handler) -> void
    {
        Initiate<ReadWork>(ReadInput{Owner(), Buffer}, std::move(Handler));

    }

    auto XhttpTransport::StartWrite(std::span<const std::byte> Buffer, Completion Handler) -> void
    {
        Initiate<WriteWork>(WriteInput{Owner(), Buffer}, std::move(Handler));

    }

    auto XhttpTransport::StartWriteShutdown(Completion Handler) -> void
    {
        Initiate<ShutdownWork>(ShutdownInput{Owner()}, std::move(Handler));

    }

    [[nodiscard]] auto XhttpTransport::OnClose() -> ControlResult
    {
        return CloseLocal();

    }

    [[nodiscard]] auto XhttpTransport::OnCancel() -> ControlResult
    {
        return OnClose();

    }

    [[nodiscard]] auto XhttpTransport::Finish() -> Net::awaitable<WriteResult>
    {
        return Writer_->Finish();

    }

    [[nodiscard]] auto XhttpTransport::DrainWriter()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        return Writer_->Drain();

    }

    [[nodiscard]] auto XhttpTransport::WriterIsRetired() const noexcept -> bool
    {
        return Writer_->IsRetired();

    }

    [[nodiscard]] auto XhttpTransport::NextLayer() noexcept -> Transmission *
    {
        return nullptr;

    }

    [[nodiscard]] auto XhttpTransport::NextLayer() const noexcept -> const Transmission *
    {
        return nullptr;

    }

    void XhttpTransport::Push(std::span<const std::byte> Data)
    {
        if (Closed_ || DrainTerminal_ || TerminalError_ || Data.empty())
        {
            return;
        }
        std::vector<std::byte> Copy(Data.begin(), Data.end());
        if (!Notify_.try_send(boost::system::error_code{}, std::move(Copy)))
        {
            (void)Diagnose::Error("XhttpReceiveChannelFull Action=CloseStream");
            const auto Closed = Close();
            if (!Closed)
            {
                RecordCloseFailure(Closed.error());
                Writer_->Close();
                NotifyError(Prism::Fault::ToNative(Closed.error()));
            }
        }

    }

    void XhttpTransport::NotifyEof()
    {
        if (!Closed_ && !DrainTerminal_ && !TerminalError_ && !Eof_ && !EofPending_)
        {
            if (!Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{}))
            {
                EofPending_ = true;
            }
        }

    }

    void XhttpTransport::NotifyError(std::error_code ErrorCode)
    {
        if (TerminalError_ || DrainTerminal_)
        {
            PreserveAcceptedDataForOutputFailure_ = false;
            return;
        }
        PreserveAcceptedDataForOutputFailure_ = false;
        TerminalError_ = ErrorCode;
        if (!TerminalError_)
            TerminalError_ = std::make_error_code(std::errc::protocol_error);
        (void)Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{});

    }

    void XhttpTransport::PreserveAcceptedDataForOutputFailure()
    {
        if (!Closed_ && !TerminalError_ && !DrainTerminal_)
        {
            PreserveAcceptedDataForOutputFailure_ = true;
        }

    }

    void XhttpTransport::NotifyOutputFailure(Prism::Fault::Failure Failure)
    {
        if (PreserveAcceptedDataForOutputFailure_)
        {
            PreserveAcceptedDataForOutputFailure_ = false;
            NotifyReadTerminal(Failure);
            return;
        }
        NotifyError(Prism::Fault::ToNative(Failure));

    }

    void XhttpTransport::NotifyReadTerminal(Prism::Fault::Failure Failure)
    {
        if (TerminalError_ || DrainTerminal_ || Closed_)
        {
            return;
        }
        PreserveAcceptedDataForOutputFailure_ = false;
        if (Failure.Succeeded()) Failure = {Prism::Fault::Code::WouldBlock};
        TerminalError_ = Prism::Fault::ToNative(Failure);
        DrainTerminal_ = true;
        Eof_ = false;
        EofPending_ = false;
        (void)Notify_.try_send(boost::system::error_code{}, std::vector<std::byte>{});
        Writer_->Close();

    }

    [[nodiscard]] auto XhttpTransport::DrainTerminalPending() const noexcept -> bool
    {
        return DrainTerminal_;

    }

    void XhttpTransport::BindStream(std::int32_t StreamId)
    {
        if (Closed_ || TerminalError_ || StreamId_ >= 0)
        {
            return;
        }
        StreamId_ = StreamId;
        const auto Weak = std::weak_ptr<XhttpTransport>(Owner());
        Writer_->BindStream(StreamId, [Weak](Prism::Fault::Failure Failure)
        {
            if (const auto State = Weak.lock())
            {
                State->NotifyError(Prism::Fault::ToNative(Failure));
                (void)State->CloseLocal();
            }
        });

    }

    [[nodiscard]] auto XhttpTransport::Owner() -> std::shared_ptr<XhttpTransport>
    {
        return std::static_pointer_cast<XhttpTransport>(Transmission::shared_from_this());

    }

    auto XhttpTransport::CloseLocal() -> ControlResult
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
        PreserveAcceptedDataForOutputFailure_ = false;
        Notify_.cancel();
        Writer_->Close();
        const auto Failure = NotifyOwnerClose();
        if (Failure.Failed())
        {
            return std::unexpected(Failure);
        }
        return {};

    }

    [[nodiscard]] auto XhttpTransport::ReadPartial(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t>
    {
        if (Buffer.empty())
        {
            ErrorCode.clear();
            co_return 0;
        }
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
                ErrorCode = make_error_code(Error::UnexpectedEof);
                co_return 0;
            }
            if (EofPending_ && !Notify_.ready())
            {
                EofPending_ = false;
                Eof_ = true;
                ErrorCode.clear();
                co_return 0;
            }
            boost::system::error_code ChEc;
            auto Block = co_await Notify_.async_receive(
                Net::redirect_error(Net::use_awaitable, ChEc));
            if (ChEc)
            {
                if (TerminalError_)
                {
                    ErrorCode = TerminalError_;
                    co_return 0;
                }
                ErrorCode = std::make_error_code(std::errc::not_connected);
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
        const auto N = std::min(Buffer.size(), RxCurrent_.size() - RxOffset_);
        std::memcpy(Buffer.data(), RxCurrent_.data() + RxOffset_, N);
        RxOffset_ += N;
        ErrorCode.clear();
        co_return N;

    }

    [[nodiscard]] auto XhttpTransport::WritePartial(
            std::span<const std::byte> Buffer,
            Prism::Fault::Failure &Failure)
            -> Net::awaitable<std::size_t>
    {
        if (Buffer.empty())
        {
            Failure = {};
            co_return 0;
        }
        if (Closed_ || DrainTerminal_ || TerminalError_)
        {
            Failure = Prism::Fault::FromNative(
                std::make_error_code(std::errc::not_connected));
            co_return 0;
        }
        const auto Written = co_await Writer_->Write(Buffer);
        if (!Written)
        {
            Failure = Written.error();
            co_return 0;
        }
        Failure = {};
        co_return *Written;

    }

    [[nodiscard]] auto XhttpTransport::ShutdownPartial() -> Net::awaitable<Prism::Fault::Failure>
    {
        if (Closed_ || StreamId_ < 0)
        {
            co_return Prism::Fault::FromNative(
                std::make_error_code(std::errc::not_connected));
        }
        const auto Result = co_await Finish();
        if (!Result) co_return Result.error();
        co_return Prism::Fault::Failure{};

    }

    auto XhttpTransport::NotifyOwnerClose() noexcept -> Prism::Fault::Failure
    {
        if (!CloseOwner_)
        {
            return {};
        }
        auto Callback = std::move(CloseOwner_);
        try
        {
            const auto Failure = Callback();
            RecordCloseFailure(Failure);
            if (Failure.Failed()) NotifyError(Prism::Fault::ToNative(Failure));
            return Failure;
        }
        catch (...)
        {
            const auto Typed = Prism::Contract::InboundAdmission::ExceptionFailure(
                std::current_exception());
            RecordCloseFailure(Typed);
            NotifyError(Prism::Fault::ToNative(Typed));
            return Typed;
        }

    }
} // namespace Prism::Xhttp::Detail

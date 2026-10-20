/** @file H2MuxStream.cpp @brief H2Mux 子流状态与 I/O 实现。 */
#include <Prism/Protocols/Mux/H2Mux/Http2Stream.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/system/error_code.hpp>

#include <algorithm>
#include <cstddef>
#include <system_error>
#include <utility>

namespace Prism::Mux::H2Mux
{

    [[nodiscard]] auto Http2Stream::CanAttemptRetirement() const noexcept -> bool
    {
        return LocalTerminal_ && RemoteClosed_ && !LocalEndPending_ && !ResetPending_ &&
            !IncomingPending_ && Rx_.empty() &&
            (!StreamTerminalPending_ || TerminalCloseFinalized_);
    }

    Http2Stream::Http2Stream(
        std::shared_ptr<Http2State> StateValue,
        const std::int32_t StreamIdValue)
        : Prism::Transmission(StateValue ? StateValue->Strand : Net::any_io_executor{}),
          Executor_(StateValue ? StateValue->Strand : Net::any_io_executor{}),
          State_(std::move(StateValue)), StreamId_(StreamIdValue), Notify_(State_->Strand),
          Terminations_(std::make_shared<Prism::Lifecycle::DrainBarrier>(State_->Tasks->Reclaimer()))
    {
    }

    auto Http2Stream::OnClose() -> Prism::Transmission::ControlResult
    {
        CloseReceiptAvailable_ = true;
        if (!State_) return {};
        if (ConnectionClosed_ || StreamTerminalPending_)
        {
            FinalizeTerminalClose();
            return {};
        }
        if (Closed_) return {};
        if (State_->CloseRequested.load(std::memory_order_acquire))
        {
            SetConnectionClosed(State_->ConnectionCloseFailure());
            FinalizeTerminalClose();
            return {};
        }
        Closed_ = true;
        Rx_.clear();
        Activity()->Seal();
        Notify_.try_send(boost::system::error_code{});
        if (!FinSent_)
        {
            FinSent_ = true;
            LocalEndPending_ = true;
            auto Request = MakeControlRequest(ControlKind::Fin, Prism::Http2::ErrorNoError);
            return SubmitControl(std::move(Request));
        }
        TryQueueRetirement();
        return {};
    }

    auto Http2Stream::StartWriteShutdown(Prism::Transmission::Completion Handler) -> void
    {
        if (LocalEndFlushed_)
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), Prism::IoResult{});
            return;
        }
        if (LocalEndFailure_)
        {
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {0, *LocalEndFailure_});
            return;
        }
        if (!State_ || State_->Closed ||
            State_->CloseRequested.load(std::memory_order_acquire))
        {
            auto Failure = State_ ? State_->ConnectionTerminal.Load() :
                Prism::Fault::Failure{Prism::Fault::Code::Canceled};
            if (!Failure.Failed()) Failure = {Prism::Fault::Code::Canceled};
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {0, Failure});
            return;
        }
        if (FinSent_ && LocalEndPending_)
        {
            PendingWriteShutdowns_.push_back(std::move(Handler));
            return;
        }
        if (Closed_ || FinSent_)
        {
            const auto Failure = ResetByPeer_
                ? PeerResetFailure()
                : Prism::Fault::Failure{Prism::Fault::Code::Canceled};
            Prism::Transmission::PostResult(
                Executor(), std::move(Handler), {0, Failure});
            return;
        }
        FinSent_ = true;
        LocalEndPending_ = true;
        PendingWriteShutdowns_.push_back(std::move(Handler));
        auto Request = MakeControlRequest(ControlKind::Fin, Prism::Http2::ErrorNoError);
        const auto Scheduled = SubmitControl(std::move(Request));
        if (!Scheduled)
        {
            LocalEndPending_ = false;
            if (!LocalEndFailure_) LocalEndFailure_ = Scheduled.error();
            CompletePendingWriteShutdowns(*LocalEndFailure_);
        }
    }

    auto Http2Stream::StartReset(const std::uint32_t ErrorCode)
        -> Prism::Transmission::ControlResult
    {
        if (!State_) return {};
        if (State_->CloseRequested.load(std::memory_order_acquire))
        {
            SetConnectionClosed(State_->ConnectionCloseFailure());
            FinalizeTerminalClose();
            return {};
        }
        if (State_->Closed) return {};
        if (LocalTerminal_ && RemoteClosed_)
        {
            const auto BaseClosed = CloseBase();
            if (BaseClosed) TryQueueRetirement();
            return BaseClosed;
        }
        if (ResetByPeer_)
        {
            Closed_ = true;
            LocalTerminal_ = true;
            const auto BaseClosed = CloseBase();
            if (BaseClosed) TryQueueRetirement();
            return BaseClosed;
        }
        if (ResetPending_) return {};
        Closed_ = true;
        Rx_.clear();
        const auto BaseClosed = CloseBase();
        Notify_.try_send(boost::system::error_code{});
        if (!BaseClosed) return BaseClosed;
        ResetPending_ = true;
        LocalEndPending_ = true;
        return SubmitControl(MakeControlRequest(ControlKind::Reset, ErrorCode));
    }

    auto Http2Stream::Push(const std::span<const std::byte> Data) -> void
    {
        if (Closed_ || RemoteClosed_ || Data.empty()) return;
        Rx_.emplace_back(Data.begin(), Data.end());
        Notify_.try_send(boost::system::error_code{});
    }

    auto Http2Stream::MarkIncomingPending(const bool Pending) -> void
    {
        IncomingPending_ = Pending;
        if (!Pending) TryQueueRetirement();
    }

    auto Http2Stream::SetRemoteClosed() -> void
    {
        RemoteClosed_ = true;
        Notify_.try_send(boost::system::error_code{});
        TryQueueRetirement();
    }

    auto Http2Stream::SetRemoteReset(const std::uint32_t ErrorCode) -> void
    {
        const auto Unaccepted = IncomingPending_;
        RemoteResetCode_ = ErrorCode;
        RemoteClosed_ = true;
        ResetByPeer_ = true;
        LocalTerminal_ = true;
        Closed_ = true;
        Rx_.clear();
        LocalEndPending_ = ResetPending_ = false;
        StreamTerminalPending_ = true;
        IncomingPending_ = false;
        Notify_.try_send(boost::system::error_code{});
        if (Unaccepted || CloseReceiptAvailable_) FinalizeTerminalClose();
        else
        {
            TryQueueRetirement();
            if (State_) State_->NotifyStreamDrain();
        }
    }

    auto Http2Stream::SetConnectionClosed(const Prism::Fault::Failure Terminal) -> void
    {
        if (ConnectionClosed_) return;
        ConnectionClosed_ = true;
        Closed_ = true;
        if (!RemoteClosed_)
        {
            RemoteClosed_ = true;
            ConnectionTerminal_ = Terminal.Failed()
                ? Terminal : Prism::Fault::Failure{Prism::Fault::Code::Eof};
        }
        LocalEndPending_ = ResetPending_ = false;
        FinSent_ = true;
        StreamTerminalPending_ = true;
        Notify_.try_send(boost::system::error_code{});
        if (IncomingPending_ || CloseReceiptAvailable_) FinalizeTerminalClose();
        else
        {
            TryQueueRetirement();
            if (State_) State_->NotifyStreamDrain();
        }
    }

    auto Http2Stream::FinalizeTerminalClose() -> void
    {
        if (TerminalCloseFinalized_) return;
        TerminalCloseFinalized_ = true;
        Closed_ = true;
        RemoteClosed_ = LocalTerminal_ = FinSent_ = true;
        LocalEndPending_ = ResetPending_ = false;
        Rx_.clear();
        IncomingPending_ = false;
        Notify_.try_send(boost::system::error_code{});
        if (!CloseReceiptAvailable_)
        {
            const auto CloseResult = CloseBase();
            if (!CloseResult && State_) State_->RecordFailure(CloseResult.error());
        }
        Activity()->Seal();
        TryQueueRetirement();
        if (State_) State_->NotifyStreamDrain();
    }

    auto Http2Stream::CloseBase() -> Prism::Transmission::ControlResult
    {
        const auto Result = Prism::Transmission::Close();
        if (!Result) { Activity()->Seal(); MarkRetirementFailed(Result.error()); }
        return Result;
    }

    auto Http2Stream::MarkRetirementFailed(const Prism::Fault::Failure Failure) -> void
    {
        RetirementFailed_ = true;
        RetirementQueued_ = false;
        if (State_) State_->RecordFailure(Failure);
    }

    auto Http2Stream::MarkRetired() noexcept -> void
    {
        Retired_ = true;
        Closed_ = true;
        RemoteClosed_ = true;
        LocalTerminal_ = true;
        Rx_.clear();
        Activity()->Seal();
        State_.reset();
        Terminations_.reset();
    }

    auto Http2Stream::DrainTerminations()
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        if (!Terminations_) co_return std::expected<void, Prism::Fault::Failure>{};
        Terminations_->Seal();
        co_return co_await Terminations_->Drain();
    }

    auto Http2Stream::ReadPartial(
        const std::span<std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (Buffer.empty())
        {
            ErrorCode.clear();
            co_return 0;
        }
        while (true)
        {
            if (!Rx_.empty())
            {
                auto &Front = Rx_.front();
                const auto Count = (std::min)(Buffer.size(), Front.size());
                std::copy_n(Front.begin(), Count, Buffer.begin());
                if (Count == Front.size()) Rx_.pop_front();
                else Front.erase(Front.begin(), Front.begin() + static_cast<std::ptrdiff_t>(Count));
                ErrorCode.clear();
                if (Rx_.empty()) TryQueueRetirement();
                co_return Count;
            }
            if (ConnectionTerminal_)
            {
                ErrorCode = Prism::Fault::ToNative(*ConnectionTerminal_);
                co_return 0;
            }
            if (ResetByPeer_)
            {
                ErrorCode = Prism::Fault::ToNative(PeerResetFailure());
                TryQueueRetirement();
                co_return 0;
            }
            if (RemoteClosed_)
            {
                ErrorCode = Prism::Fault::Code::Eof;
                TryQueueRetirement();
                co_return 0;
            }
            if (!State_ || State_->Closed || Closed_)
            {
                ErrorCode = Prism::Fault::Code::Eof;
                co_return 0;
            }
            Notify_.reset();
            boost::system::error_code Notified;
            co_await Notify_.async_receive(Net::redirect_error(Net::use_awaitable, Notified));
            if (Notified)
            {
                ErrorCode = Prism::Fault::Code::Eof;
                co_return 0;
            }
            co_await Net::dispatch(Executor_, Net::use_awaitable);
        }
    }

    auto Http2Stream::WritePartial(
        const std::span<const std::byte> Buffer,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        co_await Net::dispatch(Executor_, Net::use_awaitable);
        if (Closed_ || FinSent_ || !State_ || State_->Closed || !State_->Session)
        {
            ErrorCode = std::make_error_code(std::errc::broken_pipe);
            co_return 0;
        }
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            const auto Count = (std::min)(std::size_t{16U * 1024U}, Buffer.size() - Offset);
            const auto Chunk = Buffer.subspan(Offset, Count);
            auto Submitted = State_->Session->SubmitData(StreamId_, Chunk, false);
            while (Submitted == Prism::Http2::SubmitDataStatus::Blocked)
            {
                const auto PendingFrames = co_await State_->Flush();
                if (!PendingFrames)
                {
                    ErrorCode = Prism::Fault::ToNative(PendingFrames.Error);
                    if (PendingFrames.CloseCanceled)
                        State_->RecordCloseCancellation(PendingFrames.Error);
                    else
                        State_->RecordFailure(PendingFrames.Error);
                    co_return Offset;
                }
                const auto Writable = co_await State_->Session->AwaitWritable(StreamId_, Count);
                if (!Writable)
                {
                    ErrorCode = Prism::Fault::ToNative(Writable.error());
                    co_return Offset;
                }
                Submitted = State_->Session->SubmitData(StreamId_, Chunk, false);
            }
            if (Submitted != Prism::Http2::SubmitDataStatus::Accepted)
            {
                Prism::Fault::Failure Failure{Prism::Fault::Code::InvalidArgument};
                if (Submitted == Prism::Http2::SubmitDataStatus::Closed)
                {
                    Failure = {Prism::Fault::Code::ConnectionAborted};
                }
                ErrorCode = Prism::Fault::ToNative(Failure);
                co_return Offset;
            }
            const auto Flushed = co_await State_->Flush();
            if (!Flushed)
            {
                ErrorCode = Prism::Fault::ToNative(Flushed.Error);
                if (Flushed.CloseCanceled)
                    State_->RecordCloseCancellation(Flushed.Error);
                else
                    State_->RecordFailure(Flushed.Error);
                co_return Offset;
            }
            Offset += Count;
        }
        ErrorCode.clear();
        co_return Offset;
    }

} // namespace Prism::Mux::H2Mux

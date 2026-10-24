/**
 * @file NativeConnectionShutdown.cpp
 * @brief 原生 QUIC 流 FIN、typed 关闭结果和首个发送错误 owner。
 */
#include <Prism/Protocols/Quic/Detail/NativeConnectionProviders.hpp>
#include "Detail/NativeConnectionStreamAdmission.hpp"
#include <ngtcp2/ngtcp2.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <memory>
#include <new>
#include <system_error>
#include <utility>

namespace Prism::Quic::Detail
{
    namespace
    {
        [[nodiscard]] auto FailedShutdown(Prism::Fault::Failure Failure)
            -> Net::awaitable<StreamProvider::ShutdownResult>
        {
            co_return std::unexpected(std::move(Failure));
        }
    }

    [[nodiscard]] inline auto PeerStreamFailure(const StreamState &State)
        -> Prism::Fault::Failure
    {
        return Prism::Fault::FromNative(
            State.PeerWriteFailure ? State.PeerWriteFailure
                              : std::make_error_code(std::errc::connection_reset));
    }

    auto NativeConnection::ShutdownStreamWrite(std::shared_ptr<StreamState> State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Self = shared_from_this();
        (void)Self;
        using ShutdownResult = std::expected<void, Prism::Fault::Failure>;
        if (!State)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (State->FinSenderDrained)
        {
            co_return ShutdownResult{};
        }
        if (State->PeerStopSending)
        {
            co_return std::unexpected(PeerStreamFailure(*State));
        }
        if (Closed_ || !Conn_ || State->Closed)
        {
            if (State->LocalWriteFailure.Failed())
            {
                co_return std::unexpected(State->LocalWriteFailure);
            }
            if (SendFailure_.Failed())
            {
                co_return std::unexpected(SendFailure_);
            }
            co_return std::unexpected(
                Prism::Fault::FromNative(ToStdError(Prism::Error::BrokenPipe)));
        }

        boost::system::error_code PermitError;
        co_await WritePermit_.async_receive(
            Net::redirect_error(Net::use_awaitable, PermitError));
        if (PermitError)
        {
            if (SendFailure_.Failed())
            {
                co_return std::unexpected(SendFailure_);
            }
            co_return std::unexpected(
                Prism::Fault::FromNative(static_cast<std::error_code>(PermitError)));
        }
        WritePermitRelease Permit(WritePermit_);
        if (Closed_ || !Conn_ || State->Closed)
        {
            if (State->LocalWriteFailure.Failed())
            {
                co_return std::unexpected(State->LocalWriteFailure);
            }
            if (SendFailure_.Failed())
            {
                co_return std::unexpected(SendFailure_);
            }
            co_return std::unexpected(
                Prism::Fault::FromNative(ToStdError(Prism::Error::BrokenPipe)));
        }
        if (State->PeerStopSending)
        {
            co_return std::unexpected(PeerStreamFailure(*State));
        }
        if (State->FinSenderDrained)
        {
            co_return ShutdownResult{};
        }
        if (SendFailure_.Failed())
        {
            State->LocalWriteClosed = true;
            State->LocalWriteFailure = SendFailure_;
            co_return std::unexpected(SendFailure_);
        }

        State->LocalWriteClosed = true;
        State->LocalWriteFailure = {};
        try
        {
            co_return co_await QueueStreamFin(State);
        }
        catch (const std::system_error &Error)
        {
            State->LocalWriteFailure = SendFailure_.Failed()
                ? SendFailure_
                : Prism::Fault::FromNative(Error.code());
        }
        catch (const std::bad_alloc &)
        {
            State->LocalWriteFailure = SendFailure_.Failed()
                ? SendFailure_
                : Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable};
        }
        catch (...)
        {
            State->LocalWriteFailure = SendFailure_.Failed()
                ? SendFailure_
                : Prism::Fault::Failure{Prism::Fault::Code::IoError};
        }
        co_return std::unexpected(State->LocalWriteFailure);
    }

    auto NativeConnection::QueueStreamFin(std::shared_ptr<StreamState> State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        using ShutdownResult = std::expected<void, Prism::Fault::Failure>;
        const auto StoreFailure = [&State](Prism::Fault::Failure Failure) -> ShutdownResult
        {
            State->LocalWriteFailure = Failure;
            return std::unexpected(Failure);
        };
        try
        {
            if (State->FinSubmitted)
            {
                if (!State->FinOffsetKnown)
                {
                    co_return StoreFailure(
                        Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
                }
                if (!co_await WaitForSendDrain())
                {
                    const auto Failure = SendFailure_.Failed()
                        ? SendFailure_
                        : Prism::Fault::FromNative(ToStdError(Prism::Error::BrokenPipe));
                    co_return StoreFailure(Failure);
                }
                if (State->PeerStopSending || State->Closed)
                {
                    const auto Failure = State->PeerStopSending
                        ? PeerStreamFailure(*State)
                        : Prism::Fault::FromNative(ToStdError(Prism::Error::BrokenPipe));
                    co_return StoreFailure(Failure);
                }
                State->FinSenderDrained = true;
                State->LocalWriteFailure = {};
                co_return ShutdownResult{};
            }

            const auto Fin = co_await QueueFinUntilAccepted(State);
            if (!Fin)
            {
                co_return StoreFailure(Fin.error());
            }
            if (!co_await WaitForSendDrain())
            {
                const auto Failure = SendFailure_.Failed()
                    ? SendFailure_
                    : Prism::Fault::FromNative(ToStdError(Prism::Error::BrokenPipe));
                co_return StoreFailure(Failure);
            }
            if (State->PeerStopSending || State->Closed)
            {
                const auto Failure = State->PeerStopSending
                    ? PeerStreamFailure(*State)
                    : Prism::Fault::FromNative(ToStdError(Prism::Error::BrokenPipe));
                co_return StoreFailure(Failure);
            }
            State->FinSenderDrained = true;
            State->LocalWriteFailure = {};
            co_return ShutdownResult{};
        }
        catch (const std::system_error &Error)
        {
            co_return StoreFailure(Prism::Fault::FromNative(Error.code()));
        }
        catch (const std::bad_alloc &)
        {
            co_return StoreFailure(
                Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable});
        }
        catch (...)
        {
            co_return StoreFailure(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
    }

    auto NativeConnection::TryQueueFinPacket(
        const std::shared_ptr<StreamState> &State)
        -> std::expected<FinPacketAttempt, Prism::Fault::Failure>
    {
        std::array<std::byte, 65536> Packet{};
        ngtcp2_path_storage PathStorage{};
        auto Local = Socket_->local_endpoint();
        auto *Path = MakePath(PathStorage, Local, Peer_);
        ngtcp2_pkt_info PacketInfo{};
        ngtcp2_ssize Accepted = -1;
        const auto PacketLength = ngtcp2_conn_writev_stream(
            Conn_, Path, &PacketInfo,
            reinterpret_cast<std::uint8_t *>(Packet.data()), Packet.size(), &Accepted,
            NGTCP2_WRITE_STREAM_FLAG_FIN, State->Id, nullptr, 0, Now());
        if (RandomFailed_)
        {
            CloseOnExecutor();
            return std::unexpected(Prism::Fault::FromNative(
                ToStdError(Prism::Error::IoError)));
        }
        if (PacketLength == NGTCP2_ERR_STREAM_DATA_BLOCKED)
        {
            return FinPacketAttempt::FlowBlocked;
        }
        if (PacketLength < 0)
        {
            return std::unexpected(NgTcp2IoFailure(static_cast<int>(PacketLength)));
        }
        if (Accepted > 0)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
        if (PacketLength > 0)
        {
            QueuePacket(Packet.data(), static_cast<std::size_t>(PacketLength), Peer_);
            ngtcp2_conn_update_pkt_tx_time(Conn_, Now());
            if (Accepted == 0)
            {
                State->FinOffset = State->SentOffset;
                State->FinOffsetKnown = true;
                State->FinSubmitted = true;
                return FinPacketAttempt::Submitted;
            }
        }
        else
        {
            ngtcp2_conn_update_pkt_tx_time(Conn_, Now());
        }
        return FinPacketAttempt::Retry;
    }

    auto NativeConnection::QueueFinUntilAccepted(std::shared_ptr<StreamState> State)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        using ShutdownResult = std::expected<void, Prism::Fault::Failure>;
        if (Closed_ || !Conn_ || State->Closed || State->PeerStopSending)
        {
            if (State->PeerStopSending)
            {
                co_return std::unexpected(PeerStreamFailure(*State));
            }
            const auto Failure = SendFailure_.Failed()
                ? SendFailure_
                : Prism::Fault::FromNative(ToStdError(Prism::Error::BrokenPipe));
            co_return std::unexpected(Failure);
        }

        Net::steady_timer RetryTimer(Executor_);
        std::size_t RetryCount = 0;
        bool FinQueued = false;
        while (RetryCount < 1000 && !Closed_ && Conn_)
        {
            const auto Attempt = TryQueueFinPacket(State);
            if (!Attempt)
            {
                co_return std::unexpected(Attempt.error());
            }
            if (*Attempt == FinPacketAttempt::Submitted)
            {
                FinQueued = true;
                break;
            }
            if (*Attempt == FinPacketAttempt::FlowBlocked)
            {
                boost::system::error_code FlowError;
                co_await FlowNotify_.async_receive(
                    Net::redirect_error(Net::use_awaitable, FlowError));
                if (FlowError || Closed_ || !Conn_ || State->Closed ||
                    State->PeerStopSending)
                {
                    if (State->PeerStopSending)
                    {
                        co_return std::unexpected(PeerStreamFailure(*State));
                    }
                    const auto Failure = SendFailure_.Failed()
                        ? SendFailure_
                        : Prism::Fault::FromNative(
                              ToStdError(Prism::Error::BrokenPipe));
                    co_return std::unexpected(Failure);
                }
                continue;
            }

            RetryTimer.expires_after(std::chrono::milliseconds(1));
            boost::system::error_code TimerError;
            co_await RetryTimer.async_wait(
                Net::redirect_error(Net::use_awaitable, TimerError));
            if (TimerError || Closed_ || !Conn_ || State->Closed ||
                State->PeerStopSending)
            {
                if (State->PeerStopSending)
                {
                    co_return std::unexpected(PeerStreamFailure(*State));
                }
                if (State->Closed)
                {
                    co_return std::unexpected(Prism::Fault::FromNative(
                        ToStdError(Prism::Error::BrokenPipe)));
                }
                if (TimerError)
                {
                    const auto Failure = SendFailure_.Failed()
                        ? SendFailure_
                        : Prism::Fault::FromNative(
                              static_cast<std::error_code>(TimerError));
                    co_return std::unexpected(Failure);
                }
                break;
            }
            ++RetryCount;
        }

        if (Conn_)
        {
            ngtcp2_conn_update_pkt_tx_time(Conn_, Now());
        }
        if (!FinQueued)
        {
            const auto Failure = SendFailure_.Failed()
                ? SendFailure_
                : Prism::Fault::FromNative(ToStdError(
                      Closed_ || !Conn_ ? Prism::Error::BrokenPipe
                                        : Prism::Error::IoError));
            co_return std::unexpected(Failure);
        }
        co_return ShutdownResult{};
    }

    auto NativeConnection::CloseStream(const std::shared_ptr<StreamState> &State) -> void
    {
        if (!State || Closed_)
        {
            return;
        }
        State->Closed = true;
        State->LocalWriteClosed = true;
        (void)State->Notify.try_send(boost::system::error_code{});
        (void)State->FinAcknowledgedNotify.try_send(boost::system::error_code{});
        (void)FlowNotify_.try_send(boost::system::error_code{});
        if (State->FinSenderDrained && State->PeerFin)
        {
            State->StreamCloseFailure = {};
            return;
        }
        if (Conn_)
        {
            const auto Result = ngtcp2_conn_shutdown_stream(Conn_, 0, State->Id, 0);
            if (Result < 0)
            {
                if (!State->StreamCloseFailure.Failed())
                {
                    State->StreamCloseFailure = NgTcp2IoFailure(Result);
                }
                return;
            }
            State->StreamCloseFailure = {};
            QueueFlush();
        }
    }

    auto NativeConnection::OnStreamDataAcknowledged(
        const std::int64_t StreamId,
        const std::uint64_t Offset,
        const std::uint64_t DataLength) -> void
    {
        const auto It = Streams_.find(StreamId);
        if (It == Streams_.end() || !It->second)
        {
            return;
        }
        const auto State = It->second;
        if (DataLength != 0)
        {
            if (DataLength > (std::numeric_limits<std::uint64_t>::max)() - Offset)
            {
                return;
            }
            const auto AcknowledgedEnd = Offset + DataLength;
            for (const auto &Sent : State->SentBuffers)
            {
                const auto RangeBegin = (std::max)(Offset, Sent->BeginOffset);
                const auto RangeEnd = (std::min)(AcknowledgedEnd, Sent->EndOffset);
                if (RangeEnd > RangeBegin)
                {
                    Sent->AcknowledgedBytes += RangeEnd - RangeBegin;
                }
            }
            std::erase_if(State->SentBuffers, [](const auto &Sent)
            {
                const auto SentLength = Sent->EndOffset - Sent->BeginOffset;
                return Sent->SubmissionComplete && Sent->AcknowledgedBytes >= SentLength;
            });
            return;
        }
        if (!State->FinSubmitted || !State->FinOffsetKnown || State->FinOffset != Offset)
        {
            return;
        }
        State->FinAcknowledged = true;
        (void)State->FinAcknowledgedNotify.try_send(boost::system::error_code{});
    }

    auto NativeConnection::OnStreamReset(
        const std::int64_t StreamId,
        const std::uint64_t FinalSize,
        const std::uint64_t ApplicationErrorCode) -> void
    {
        const auto It = Streams_.find(StreamId);
        if (It == Streams_.end() || !It->second || It->second->Closed)
        {
            return;
        }
        auto &State = *It->second;
        State.PeerReset = true;
        State.PeerFinalSize = FinalSize;
        State.PeerApplicationErrorCode = ApplicationErrorCode;
        State.PeerReadFailure = std::make_error_code(std::errc::connection_reset);
        (void)State.Notify.try_send(boost::system::error_code{});
    }

    auto NativeConnection::OnPeerStopSending(
        const std::int64_t StreamId, const std::uint64_t ApplicationErrorCode) -> void
    {
        const auto It = Streams_.find(StreamId);
        if (It == Streams_.end() || !It->second || It->second->Closed)
        {
            return;
        }
        auto &State = *It->second;
        State.PeerStopSending = true;
        State.PeerApplicationErrorCode = ApplicationErrorCode;
        State.PeerWriteFailure = std::make_error_code(std::errc::broken_pipe);
        State.LocalWriteClosed = true;
        State.LocalWriteFailure = Prism::Fault::FromNative(State.PeerWriteFailure);
        (void)State.Notify.try_send(boost::system::error_code{});
        (void)State.FinAcknowledgedNotify.try_send(boost::system::error_code{});
        (void)FlowNotify_.try_send(boost::system::error_code{});
        if (!Conn_)
        {
            return;
        }
        const auto Result = ngtcp2_conn_shutdown_stream_write(
            Conn_, 0, StreamId, ApplicationErrorCode);
        if (Result < 0)
        {
            if (!SendFailure_.Failed()) SendFailure_ = NgTcp2IoFailure(Result);
            State.LocalWriteFailure = SendFailure_;
            BoundedFailureAtomic_.store(true, std::memory_order_release);
            return;
        }
        QueueFlush();
    }

    auto NativeStream::WaitForWriteAcknowledgement()
        -> Net::awaitable<ShutdownResult>
    {
        const auto Provider = weak_from_this().lock();
        if (!Provider || !Activity_)
        {
            return FailedShutdown(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        auto Reservation = Activity_->BeginOperation(Provider);
        if (!Reservation)
        {
            return FailedShutdown(Reservation.error());
        }
        return AcknowledgementOwned(Provider, std::move(*Reservation));
    }

    auto NativeStream::AcknowledgementOwned(
        std::shared_ptr<NativeStream> Owner,
        NativeStreamActivity::Operation ProviderReservation) -> Net::awaitable<ShutdownResult>
    {
        (void)ProviderReservation;
        if (!Owner || !Owner->State_)
        {
            co_return std::unexpected(Prism::Fault::FromNative(
                ToStdError(Prism::Error::BrokenPipe)));
        }
        const auto State = Owner->State_;
        try
        {
            co_await Net::dispatch(State->Executor, Net::use_awaitable);
            const auto Connection = Owner->Owner_.lock();
            if (!Connection)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    ToStdError(Prism::Error::BrokenPipe)));
            }
            NativeConnection::OperationReservation NativeReservation{Connection};
            if (!NativeReservation && !State->FinAcknowledged)
            {
                co_return std::unexpected(Prism::Fault::FromNative(
                    ToStdError(Prism::Error::BrokenPipe)));
            }
            if (!State->FinSenderDrained)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            while (!State->FinAcknowledged)
            {
                if (State->PeerStopSending)
                    co_return std::unexpected(PeerStreamFailure(*State));
                if (State->LocalWriteFailure.Failed())
                    co_return std::unexpected(State->LocalWriteFailure);
                if (State->Closed || Connection->Health().Closed)
                {
                    co_return std::unexpected(Prism::Fault::FromNative(
                        ToStdError(Prism::Error::BrokenPipe)));
                }
                boost::system::error_code NotifyError;
                co_await State->FinAcknowledgedNotify.async_receive(
                    Net::redirect_error(Net::use_awaitable, NotifyError));
                if (NotifyError && !State->FinAcknowledged)
                {
                    co_return std::unexpected(Prism::Fault::FromNative(
                        static_cast<std::error_code>(NotifyError)));
                }
            }
            co_return ShutdownResult{};
        }
        catch (const std::system_error &Error)
        {
            co_return std::unexpected(Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::IoError});
        }
    }
} // namespace Prism::Quic::Detail

/**
 * @file NativeConnectionStreams.hpp
 * @brief 原生 QUIC stream session owner。
 * @details 负责打开/接收 stream、流量窗口回收、半关闭和入站 stream
 *          callback；QUIC socket pump 由 transport owner 管理。
 */

#pragma once


#include <Prism/Protocols/Quic/Detail/NativeConnection.hpp>

namespace Prism::Quic::Detail
{
    /** @brief 写预约退栈时保留未确认字节，仅在 ACK 或真实流关闭后释放。 */
    class StreamDataSubmission final
    {
    public:
        StreamDataSubmission(
            std::shared_ptr<StreamState> StateValue,
            std::shared_ptr<SentStreamData> DataValue)
            : State_(std::move(StateValue)), Data_(std::move(DataValue))
        {
        }

        StreamDataSubmission(const StreamDataSubmission &) = delete;
        auto operator=(const StreamDataSubmission &) -> StreamDataSubmission & = delete;

        ~StreamDataSubmission() noexcept
        {
            Data_->SubmissionComplete = true;
            if (Data_->AcknowledgedBytes >= Data_->EndOffset - Data_->BeginOffset)
            {
                std::erase(State_->SentBuffers, Data_);
            }
        }

    private:
        std::shared_ptr<StreamState> State_;
        std::shared_ptr<SentStreamData> Data_;
    };

    inline auto NativeConnection::WriteStream(
        const std::int64_t StreamId,
        std::vector<std::byte> Data,
        std::error_code &ErrorCode) -> Net::awaitable<std::size_t>
    {
        const auto Self = shared_from_this();
        (void)Self;
        ErrorCode.clear();
        const auto StreamIterator = Streams_.find(StreamId);
        if (StreamIterator == Streams_.end() || !StreamIterator->second)
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }
        const auto State = StreamIterator->second;
        if (State->PeerStopSending)
        {
            ErrorCode = State->PeerWriteFailure;
            co_return 0;
        }
        if (Closed_ || !Conn_ || Data.empty())
        {
            if (Data.empty() && !Closed_ && Conn_)
            {
                co_return 0;
            }
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            co_return 0;
        }

        boost::system::error_code PermitError;
        co_await WritePermit_.async_receive(Net::redirect_error(Net::use_awaitable, PermitError));
        if (PermitError)
        {
            ErrorCode = ToStdError(PermitError);
            co_return 0;
        }
        WritePermitRelease Permit{WritePermit_};
        if (Closed_ || !Conn_ || State->Closed || State->PeerStopSending || State->LocalWriteClosed)
        {
            if (State->PeerWriteFailure)
            {
                ErrorCode = State->PeerWriteFailure;
            }
            else
            {
                ErrorCode = ToStdError(Prism::Error::BrokenPipe);
            }
            co_return 0;
        }

        const auto Result = co_await WriteStreamPackets(State, std::move(Data));
        ErrorCode = Result.Error;
        co_return Result.Bytes;
    }

    inline auto NativeConnection::WriteStreamPackets(
        std::shared_ptr<StreamState> State,
        std::vector<std::byte> Data) -> Net::awaitable<StreamWriteResult>
    {
        auto RetainedData = std::make_shared<SentStreamData>();
        RetainedData->Bytes = std::move(Data);
        RetainedData->BeginOffset = State->SentOffset;
        RetainedData->EndOffset = State->SentOffset;
        State->SentBuffers.push_back(RetainedData);
        StreamDataSubmission Submission{State, RetainedData};

        std::size_t Offset = 0;
        std::size_t RetryCount = 0;
        Net::steady_timer RetryTimer(Executor_);
        std::error_code ErrorCode;
        while (Offset < RetainedData->Bytes.size() && !Closed_ && Conn_ && !State->Closed &&
               !State->PeerStopSending)
        {
            std::array<std::byte, 65536> Packet{};
            ngtcp2_path_storage PathStorage{};
            auto Local = Socket_->local_endpoint();
            auto *Path = MakePath(PathStorage, Local, Peer_);
            ngtcp2_pkt_info PacketInfo{};
            ngtcp2_ssize Accepted = -1;
            ngtcp2_vec Vector{
                reinterpret_cast<std::uint8_t *>(RetainedData->Bytes.data() + Offset),
                RetainedData->Bytes.size() - Offset};
            const auto PacketLength = ngtcp2_conn_writev_stream(
                Conn_, Path, &PacketInfo, reinterpret_cast<std::uint8_t *>(Packet.data()), Packet.size(),
                &Accepted, NGTCP2_STREAM_DATA_FLAG_NONE, State->Id, &Vector, 1, Now());
            if (RandomFailed_)
            {
                ErrorCode = ToStdError(Prism::Error::IoError);
                break;
            }
            if (PacketLength == NGTCP2_ERR_WRITE_MORE)
            {
                if (Accepted <= 0 ||
                    static_cast<std::size_t>(Accepted) > RetainedData->Bytes.size() - Offset)
                {
                    ErrorCode = ToStdError(Prism::Error::IoError);
                    break;
                }
                Offset += static_cast<std::size_t>(Accepted);
                State->SentOffset += static_cast<std::uint64_t>(Accepted);
                RetainedData->EndOffset = State->SentOffset;
                continue;
            }
            if (PacketLength == NGTCP2_ERR_STREAM_DATA_BLOCKED)
            {
                boost::system::error_code FlowError;
                co_await FlowNotify_.async_receive(Net::redirect_error(Net::use_awaitable, FlowError));
                if (FlowError || Closed_ || !Conn_ || State->Closed ||
                    State->PeerStopSending)
                {
                    if (State->PeerWriteFailure)
                    {
                        ErrorCode = State->PeerWriteFailure;
                    }
                    else
                    {
                        ErrorCode = ToStdError(Prism::Error::BrokenPipe);
                    }
                    break;
                }
                continue;
            }
            if (PacketLength < 0)
            {
                ErrorCode = ToStdError(Prism::Error::IoError);
                break;
            }
            if (Accepted > 0)
            {
                if (static_cast<std::size_t>(Accepted) > RetainedData->Bytes.size() - Offset)
                {
                    ErrorCode = ToStdError(Prism::Error::IoError);
                    break;
                }
                Offset += static_cast<std::size_t>(Accepted);
                State->SentOffset += static_cast<std::uint64_t>(Accepted);
                RetainedData->EndOffset = State->SentOffset;
            }
            if (PacketLength > 0)
            {
                RetryCount = 0;
                QueuePacket(Packet.data(), static_cast<std::size_t>(PacketLength), Peer_);
            }
            if (PacketLength == 0 || Accepted == 0)
            {
                if (++RetryCount > 1000)
                {
                    ErrorCode = ToStdError(Prism::Error::IoError);
                    break;
                }
                RetryTimer.expires_after(std::chrono::milliseconds(1));
                boost::system::error_code TimerError;
                co_await RetryTimer.async_wait(Net::redirect_error(Net::use_awaitable, TimerError));
                if (TimerError || Closed_ || !Conn_ || State->Closed ||
                    State->PeerStopSending)
                {
                    if (State->PeerWriteFailure)
                    {
                        ErrorCode = State->PeerWriteFailure;
                    }
                    else
                    {
                        ErrorCode = ToStdError(Prism::Error::BrokenPipe);
                    }
                    break;
                }
            }
        }
        if (Conn_)
        {
            ngtcp2_conn_update_pkt_tx_time(Conn_, Now());
        }
        if (!ErrorCode && !co_await WaitForSendDrain())
        {
            ErrorCode = ToStdError(Prism::Error::BrokenPipe);
        }
        co_return StreamWriteResult{Offset, ErrorCode};
    }


    inline auto NativeConnection::OnStreamReadConsumed(
        const std::int64_t StreamId,
        const std::size_t Bytes) -> void
    {
        if (Closed_ || !Conn_ || Bytes == 0)
        {
            return;
        }
        const auto Stream = Streams_.find(StreamId);
        if (Stream != Streams_.end() && Stream->second && !Stream->second->Closed &&
            ngtcp2_conn_extend_max_stream_offset(Conn_, StreamId, Bytes) != 0)
        {
            CloseOnExecutor();
            return;
        }
        ngtcp2_conn_extend_max_offset(Conn_, Bytes);
        QueueFlush();
    }

    inline auto NativeConnection::OnTerminalStreamReadConsumed(
        const std::size_t Bytes) -> void
    {
        if (Closed_ || !Conn_ || Bytes == 0)
        {
            return;
        }
        ngtcp2_conn_extend_max_offset(Conn_, Bytes);
        QueueFlush();
    }




    inline auto NativeConnection::MakeStream(const std::int64_t StreamId, const bool Incoming,
                                      const bool Unidirectional)
        -> std::expected<SharedStreamProvider, Prism::Fault::Failure>
    {
        auto State = std::make_shared<StreamState>(Executor_, StreamId);
        State->PeerInitiated = Incoming;
        State->Unidirectional = Unidirectional;
        State->Owner = weak_from_this();
        std::shared_ptr<NativeStream> Provider;
        auto ShouldCreateProvider = !Incoming;
        if (!ShouldCreateProvider)
        {
            if (Unidirectional)
            {
                ShouldCreateProvider = static_cast<bool>(OnUnidirectional_);
            }
            else
            {
                ShouldCreateProvider = static_cast<bool>(OnStream_);
            }
        }
        if (ShouldCreateProvider)
        {
            Provider = std::make_shared<NativeStream>(weak_from_this(), State);
        }
        Streams_[StreamId] = State;
        if (Incoming && Unidirectional)
        {
            if (OnUnidirectional_)
            {
                const auto Accepted = OnUnidirectional_(Provider);
                if (!Accepted) return std::unexpected(Accepted.error());
            }
            else
            {
                IncomingUnidirectionalStreams_.push_back(State);
                (void)IncomingUnidirectionalNotify_.try_send(boost::system::error_code{});
            }
        }
        else if (Incoming)
        {
            if (OnStream_)
            {
                const auto Accepted = OnStream_(Provider);
                if (!Accepted) return std::unexpected(Accepted.error());
            }
            else
            {
                IncomingStreams_.push_back(State);
                (void)IncomingNotify_.try_send(boost::system::error_code{});
            }
        }
        return Provider;
    }

    inline auto NativeConnection::OnStreamOpen(const std::int64_t StreamId) -> int
    {
        if (Streams_.contains(StreamId))
        {
            return 0;
        }
        const bool Unidirectional = (StreamId & 2) != 0;
        bool PeerInitiated = false;
        if (Role_ == Role::Server)
        {
            PeerInitiated = (StreamId & 1) == 0;
        }
        else
        {
            PeerInitiated = (StreamId & 1) == 1;
        }
        try
        {
            const auto Made = MakeStream(StreamId, PeerInitiated, Unidirectional);
            if (!Made)
            {
                BoundedFailureAtomic_.store(true, std::memory_order_release);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }
        catch (...)
        {
            Fatal_->Publish(std::current_exception());
            BoundedFailureAtomic_.store(true, std::memory_order_release);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    inline auto NativeConnection::OnStreamData(
        const std::int64_t StreamId,
        const std::uint32_t Flags,
        const std::span<const std::byte> Data) -> int
    {
        try
        {
        if (!Streams_.contains(StreamId))
        {
            const auto Opened = OnStreamOpen(StreamId);
            if (Opened != 0) return Opened;
        }
        const auto StreamIterator = Streams_.find(StreamId);
        if (StreamIterator == Streams_.end() || !StreamIterator->second)
        {
            return 0;
        }
        auto &State = StreamIterator->second;
        if (State->PeerReset)
        {
            return 0;
        }
        if (!Data.empty())
        {
            State->Received.emplace_back(Data.begin(), Data.end());
        }
        if ((Flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0)
        {
            State->PeerFin = true;
        }
        (void)State->Notify.try_send(boost::system::error_code{});
        return 0;
        }
        catch (...)
        {
            Fatal_->Publish(std::current_exception());
            BoundedFailureAtomic_.store(true, std::memory_order_release);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    inline auto NativeConnection::OnStreamClose(
        const std::int64_t StreamId,
        const std::uint32_t Flags,
        const std::uint64_t ApplicationErrorCode) -> void
    {
        const auto StreamIterator = Streams_.find(StreamId);
        if (StreamIterator == Streams_.end() || !StreamIterator->second)
        {
            return;
        }
        const auto State = StreamIterator->second;
        State->SentBuffers.clear();
        if (!State->Closed && !State->PeerStopSending &&
            (Flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) != 0U)
        {
            State->PeerReset = true;
            State->PeerApplicationErrorCode = ApplicationErrorCode;
            State->PeerReadFailure = std::make_error_code(std::errc::connection_reset);
        }
        else if (!State->Closed && !State->PeerReset && !State->PeerStopSending)
        {
            State->PeerFin = true;
        }
        State->Closed = true;
        if (State->PeerInitiated && !State->StreamCreditReturned && Conn_)
        {
            if (State->Unidirectional)
            {
                ngtcp2_conn_extend_max_streams_uni(Conn_, 1);
            }
            else
            {
                ngtcp2_conn_extend_max_streams_bidi(Conn_, 1);
            }
            State->StreamCreditReturned = true;
            QueueFlush();
        }
        (void)State->Notify.try_send(boost::system::error_code{});
        (void)State->FinAcknowledgedNotify.try_send(boost::system::error_code{});
        (void)FlowNotify_.try_send(boost::system::error_code{});
        Streams_.erase(StreamIterator);
        State->NativeTerminal.store(true, std::memory_order_release);
        if (const auto Activity = State->Activity.lock())
        {
            Activity->MarkNativeTerminal(State->StreamCloseFailure);
        }
    }


} // namespace Prism::Quic::Detail

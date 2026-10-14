/**
 * @file StreamController.hpp
 * @brief HTTP/2 流状态、流控和输出操作 owner。
 */

#pragma once

#include <algorithm>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <span>
#include <system_error>
#include <vector>
#include <Preview/Foundation/Fault/Failure.hpp>

#include <Preview/Protocols/Http2/Detail/CodecState.hpp>
#include <Preview/Protocols/Http2/Detail/ConnectionState.hpp>
#include <Preview/Protocols/Http2/Types.hpp>

namespace Preview::Http2::Detail
{

    /**
     * @class StreamController
     * @brief 管理流 ID、半关闭状态、窗口和所有出站帧。
     * @details 输入帧的类型分发仍由 FrameProcessor 完成；本 owner 只提供流
     *          状态变更和对应的出站操作。
     */
    class StreamController final
    {
    public:
        struct StreamState
        {
            bool LocalClosed{false};
            bool RemoteClosed{false};
            std::int64_t SendWindow{DefaultInitialWindow};
            std::uint32_t ReceiveWindow{DefaultInitialWindow};
            std::vector<std::byte> RxPending;
            std::vector<std::weak_ptr<Net::steady_timer>> WritableWaiters;
        };

        StreamController(ConnectionState &Connection, CodecState &Codec, H2Session &Events)
            : Connection_(Connection), Codec_(Codec), Events_(Events)
        {
        }

        [[nodiscard]] auto OpenStream(const HeaderList &Headers, bool EndStream)
            -> std::expected<std::int32_t, Preview::Fault::Failure>
        {
            if (Connection_.IsServer())
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::NotSupported});
            }
            const auto StreamId = NextClientStreamId();
            if (!StreamId)
            {
                return std::unexpected(StreamId.error());
            }
            const auto HeaderResult = SubmitHeadersFrame(*StreamId, Headers, EndStream);
            if (!HeaderResult)
            {
                Streams_.erase(*StreamId);
                return std::unexpected(HeaderResult.error());
            }
            return *StreamId;
        }

        [[nodiscard]] auto SubmitHeaders(
            const std::int32_t StreamId,
            const HeaderList &Headers,
            const bool EndStream) -> std::expected<void, Preview::Fault::Failure>
        {
            return SubmitHeadersFrame(StreamId, Headers, EndStream);
        }

        [[nodiscard]] auto SubmitData(
            const std::int32_t StreamId,
            std::span<const std::byte> Data,
            const bool EndStream) -> SubmitDataStatus
        {
            if (StreamId <= 0 || Data.size() > 0x7FFFFFFFU)
            {
                return SubmitDataStatus::Invalid;
            }
            const auto StreamIterator = Streams_.find(StreamId);
            if (StreamIterator == Streams_.end())
            {
                return IsClosedStream(StreamId) ? SubmitDataStatus::Closed : SubmitDataStatus::Invalid;
            }
            if (StreamIterator->second.LocalClosed)
            {
                return SubmitDataStatus::Closed;
            }
            const auto RequiredBytes = static_cast<std::uint64_t>(Data.size());
            if (RequiredBytes != 0 &&
                (Connection_.ConnectionSendWindow() < 0 || StreamIterator->second.SendWindow < 0 ||
                 RequiredBytes > static_cast<std::uint64_t>(Connection_.ConnectionSendWindow()) ||
                 RequiredBytes > static_cast<std::uint64_t>(StreamIterator->second.SendWindow)))
            {
                return SubmitDataStatus::Blocked;
            }
            auto Offset = std::size_t{0};
            if (Data.empty())
            {
                const auto Flags = EndStream ? FlagEndStream : FlagNone;
                Connection_.QueueFrame(
                    {FrameType::Data, Flags, static_cast<std::uint32_t>(StreamId), {}});
            }
            while (Offset < Data.size())
            {
                const auto Remaining = Data.size() - Offset;
                const auto Count = (std::min)(Remaining, static_cast<std::size_t>(PeerMaxFrameSize_));
                const auto Last = Offset + Count == Data.size();
                const std::vector<std::byte> Payload(
                    Data.begin() + static_cast<std::ptrdiff_t>(Offset),
                    Data.begin() + static_cast<std::ptrdiff_t>(Offset + Count));
                const auto Flags = Last && EndStream ? FlagEndStream : FlagNone;
                Connection_.QueueFrame(
                    {FrameType::Data, Flags, static_cast<std::uint32_t>(StreamId), Payload});
                Connection_.ConnectionSendWindow() -= static_cast<std::uint32_t>(Count);
                StreamIterator->second.SendWindow -= static_cast<std::uint32_t>(Count);
                Offset += Count;
            }
            if (EndStream)
            {
                StreamIterator->second.LocalClosed = true;
                WakeWaiters(StreamIterator->second.WritableWaiters);
                if (StreamIterator->second.RemoteClosed)
                {
                    ClosedStreams_.insert(static_cast<std::uint32_t>(StreamId));
                    Streams_.erase(StreamIterator);
                }
            }
            return SubmitDataStatus::Accepted;
        }

        [[nodiscard]] auto AwaitWritable(
            const std::int32_t StreamId,
            const std::size_t RequiredBytes)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            if (StreamId <= 0 || RequiredBytes == 0 || RequiredBytes > 0x7FFFFFFFU)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            const auto Cancellation = co_await Net::this_coro::cancellation_state;
            while (true)
            {
                co_await Net::dispatch(Connection_.Executor(), Net::use_awaitable);
                if (Cancellation.cancelled() != Net::cancellation_type::none)
                {
                    co_return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Canceled});
                }
                const auto StreamIterator = Streams_.find(StreamId);
                if (StreamIterator == Streams_.end())
                {
                    const auto Code = IsClosedStream(StreamId)
                        ? Preview::Fault::Code::ConnectionAborted
                        : Preview::Fault::Code::InvalidArgument;
                    co_return std::unexpected(Preview::Fault::Failure{Code});
                }
                if (StreamIterator->second.LocalClosed)
                {
                    co_return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::ConnectionAborted});
                }
                if (HasSendWindow(StreamIterator->second, RequiredBytes))
                {
                    co_return std::expected<void, Preview::Fault::Failure>{};
                }
                const auto Waiter = std::make_shared<Net::steady_timer>(Connection_.Executor());
                Waiter->expires_at((Net::steady_timer::time_point::max)());
                PruneWaiters(ConnectionWaiters_);
                PruneWaiters(StreamIterator->second.WritableWaiters);
                ConnectionWaiters_.emplace_back(Waiter);
                StreamIterator->second.WritableWaiters.emplace_back(Waiter);
                boost::system::error_code WaitError;
                co_await Waiter->async_wait(Net::redirect_error(Net::use_awaitable, WaitError));
                if (Cancellation.cancelled() != Net::cancellation_type::none)
                {
                    co_return std::unexpected(
                        Preview::Fault::Failure{Preview::Fault::Code::Canceled});
                }
                if (WaitError && WaitError != Net::error::operation_aborted)
                {
                    co_return std::unexpected(Preview::Fault::FromNative(
                        static_cast<std::error_code>(WaitError)));
                }
            }
        }

        auto ConsumeData(const std::int32_t StreamId, const std::size_t Bytes) -> void
        {
            if (StreamId <= 0 || Bytes == 0)
            {
                return;
            }
            const auto StreamIterator = Streams_.find(StreamId);
            if (StreamIterator == Streams_.end())
            {
                return;
            }
            RestoreReceiveWindow(ConnectionStreamId, Bytes, Connection_.ConnectionReceiveWindow());
            RestoreReceiveWindow(
                static_cast<std::uint32_t>(StreamId), Bytes, StreamIterator->second.ReceiveWindow);
        }

        /** @brief 丢弃已关闭流的迟到 DATA，只恢复连接级窗口，不再引用已退休流窗口。 */
        auto ConsumeClosedStreamData(const std::size_t Bytes) -> void
        {
            if (Bytes == 0) return;
            RestoreReceiveWindow(ConnectionStreamId, Bytes, Connection_.ConnectionReceiveWindow());
        }

        [[nodiscard]] auto ResetStream(
            const std::int32_t StreamId,
            const std::uint32_t ErrorCode) -> std::expected<void, Preview::Fault::Failure>
        {
            if (StreamId <= 0)
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            const auto StreamIterator = Streams_.find(StreamId);
            if (StreamIterator == Streams_.end())
            {
                return std::unexpected(Preview::Fault::Failure{MissingStreamCode(StreamId)});
            }
            const auto Payload = EncodeRstStream(ErrorCode);
            Connection_.QueueFrame(
                {FrameType::RstStream, FlagNone, static_cast<std::uint32_t>(StreamId), Payload});
            ClosedStreams_.insert(static_cast<std::uint32_t>(StreamId));
            WakeWaiters(StreamIterator->second.WritableWaiters);
            Streams_.erase(StreamIterator);
            return {};
        }

        auto SendSettings(std::span<const SettingsEntry> Entries) -> void
        {
            const auto Payload = EncodeSettings(Entries);
            Connection_.QueueFrame({FrameType::Settings, FlagNone, ConnectionStreamId, Payload});
        }

        auto SendPing(std::span<const std::byte, 8> Opaque) -> void
        {
            const std::vector<std::byte> Payload(Opaque.begin(), Opaque.end());
            Connection_.QueueFrame({FrameType::Ping, FlagNone, ConnectionStreamId, Payload});
        }

        auto SendGoaway(const std::uint32_t LastStreamId, const std::uint32_t ErrorCode) -> void
        {
            GoawayParams Params;
            Params.LastStreamId = LastStreamId;
            Params.ErrorCode = ErrorCode;
            const auto Payload = EncodeGoaway(Params);
            Connection_.QueueFrame({FrameType::Goaway, FlagNone, ConnectionStreamId, Payload});
        }

        [[nodiscard]] auto Find(const std::int32_t StreamId) noexcept -> StreamState *
        {
            const auto Iterator = Streams_.find(StreamId);
            return Iterator == Streams_.end() ? nullptr : &Iterator->second;
        }

        [[nodiscard]] auto Find(const std::int32_t StreamId) const noexcept
            -> const StreamState *
        {
            const auto Iterator = Streams_.find(StreamId);
            return Iterator == Streams_.end() ? nullptr : &Iterator->second;
        }

        /** @brief 查询已完成或已重置的流；压缩与连接流控仍须继续处理迟到帧。 */
        [[nodiscard]] auto IsClosedStream(const std::int32_t StreamId) const noexcept -> bool
        {
            return StreamId > 0 && ClosedStreams_.contains(static_cast<std::uint32_t>(StreamId));
        }

        [[nodiscard]] auto ValidateIncomingStream(
            const std::uint32_t StreamId,
            std::error_code &ErrorCode) const -> bool
        {
            if (StreamId == ConnectionStreamId)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            if (const auto *State = Find(static_cast<std::int32_t>(StreamId)))
            {
                if (State->RemoteClosed)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                return true;
            }
            const auto InvalidParity = Connection_.IsServer() ? StreamId % 2U == 0 : StreamId % 2U != 0;
            if (InvalidParity)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            if (IsClosedStream(static_cast<std::int32_t>(StreamId))) return true;
            if (StreamId <= LastRxStream_)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            return true;
        }

        auto RegisterIncomingStream(const std::uint32_t StreamId) -> void
        {
            if (!Find(static_cast<std::int32_t>(StreamId)))
            {
                Streams_.emplace(static_cast<std::int32_t>(StreamId), StreamState{});
                LastRxStream_ = (std::max)(LastRxStream_, StreamId);
            }
        }

        [[nodiscard]] auto ApplyPeerSettings(
            const std::vector<SettingsEntry> &Entries,
            std::error_code &ErrorCode) -> bool
        {
            for (const auto &Entry : Entries)
            {
                if (Entry.Id == SettingsInitialWindowSize && Entry.Value > 0x7FFFFFFFU)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                if (Entry.Id == SettingsMaxFrameSize &&
                    (Entry.Value < DefaultFramePayload || Entry.Value > 0xFFFFFFU))
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
            }
            for (const auto &Entry : Entries)
            {
                if (Entry.Id == SettingsInitialWindowSize)
                {
                    const auto Delta = static_cast<std::int64_t>(Entry.Value) -
                                       static_cast<std::int64_t>(PeerInitialWindow_);
                    for (auto &[StreamId, State] : Streams_)
                    {
                        (void)StreamId;
                        State.SendWindow += Delta;
                        WakeWaiters(State.WritableWaiters);
                    }
                    PeerInitialWindow_ = Entry.Value;
                }
                else if (Entry.Id == SettingsMaxFrameSize)
                {
                    PeerMaxFrameSize_ = Entry.Value;
                }
            }
            return true;
        }

        [[nodiscard]] auto ApplyStreamWindowUpdate(
            const std::int32_t StreamId,
            const std::uint32_t Increment,
            std::error_code &ErrorCode) -> bool
        {
            const auto *State = Find(StreamId);
            if (!State)
            {
                if (IsClosedStream(StreamId)) return true;
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            if (State->SendWindow > 0x7FFFFFFFU - Increment)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            auto *MutableState = Find(StreamId);
            MutableState->SendWindow += Increment;
            WakeWaiters(MutableState->WritableWaiters);
            return true;
        }

        auto OnStreamCloseIf(const std::int32_t StreamId, const std::uint32_t ErrorCode) -> void
        {
            if (const auto Iterator = Streams_.find(StreamId); Iterator != Streams_.end())
            {
                WakeWaiters(Iterator->second.WritableWaiters);
            }
            if (StreamId > 0) ClosedStreams_.insert(static_cast<std::uint32_t>(StreamId));
            Streams_.erase(StreamId);
            if (Events_.OnStreamClose)
            {
                Events_.OnStreamClose(
                    {StreamId, StreamReceiveClosureKind::Reset, ErrorCode});
            }
        }

        auto OnRemoteEnd(const std::int32_t StreamId, const std::uint32_t ErrorCode) -> void
        {
            auto *State = Find(StreamId);
            if (!State)
            {
                return;
            }
            State->RemoteClosed = true;
            if (Events_.OnStreamClose)
            {
                Events_.OnStreamClose(
                    {StreamId, StreamReceiveClosureKind::EndStream, ErrorCode});
            }
            if (const auto *Current = Find(StreamId); Current && Current->LocalClosed)
            {
                ClosedStreams_.insert(static_cast<std::uint32_t>(StreamId));
                Streams_.erase(StreamId);
            }
        }

        [[nodiscard]] auto PeerMaxFrameSize() const noexcept -> std::uint32_t
        {
            return PeerMaxFrameSize_;
        }

    public:
        /** @brief connection WINDOW_UPDATE 后重查所有待写 stream。 */
        auto WakeConnectionWaiters() -> void
        {
            WakeWaiters(ConnectionWaiters_);
        }

    private:
        [[nodiscard]] auto HasSendWindow(
            const StreamState &State,
            const std::size_t RequiredBytes) const noexcept -> bool
        {
            if (Connection_.ConnectionSendWindow() < 0 || State.SendWindow < 0)
            {
                return false;
            }
            return RequiredBytes <= static_cast<std::uint64_t>(Connection_.ConnectionSendWindow()) &&
                   RequiredBytes <= static_cast<std::uint64_t>(State.SendWindow);
        }

        static auto PruneWaiters(
            std::vector<std::weak_ptr<Net::steady_timer>> &Waiters) -> void
        {
            Waiters.erase(
                std::remove_if(Waiters.begin(), Waiters.end(),
                    [](const auto &Waiter) { return Waiter.expired(); }),
                Waiters.end());
        }

        static auto WakeWaiters(
            std::vector<std::weak_ptr<Net::steady_timer>> &Waiters) -> void
        {
            for (const auto &WeakWaiter : Waiters)
            {
                if (const auto Waiter = WeakWaiter.lock())
                {
                    (void)Waiter->cancel();
                }
            }
            Waiters.clear();
        }

        auto RestoreReceiveWindow(
            const std::uint32_t StreamId,
            const std::size_t Bytes,
            std::uint32_t &Window) -> void
        {
            constexpr std::uint64_t MaxWindowIncrement = 0x7FFFFFFFU;
            constexpr std::uint32_t MaxWindow = 0x7FFFFFFFU;
            std::uint64_t Remaining = Bytes;
            while (Remaining != 0 && Window < MaxWindow)
            {
                const auto Capacity = static_cast<std::uint64_t>(MaxWindow - Window);
                const auto Increment = (std::min)({Remaining, Capacity, MaxWindowIncrement});
                if (Increment == 0)
                {
                    return;
                }
                Window += static_cast<std::uint32_t>(Increment);
                const auto Payload = EncodeWindowUpdate(static_cast<std::uint32_t>(Increment));
                Connection_.QueueFrame({FrameType::WindowUpdate, FlagNone, StreamId, Payload});
                Remaining -= Increment;
            }
        }

        [[nodiscard]] auto SubmitHeadersFrame(
            const std::int32_t StreamId,
            const HeaderList &Headers,
            const bool EndStream) -> std::expected<void, Preview::Fault::Failure>
        {
            if (StreamId <= 0)
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            const auto StreamIterator = Streams_.find(StreamId);
            if (StreamIterator == Streams_.end())
            {
                return std::unexpected(Preview::Fault::Failure{MissingStreamCode(StreamId)});
            }
            if (StreamIterator->second.LocalClosed)
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::ConnectionAborted});
            }
            const auto Block = Codec_.EncodeHeaders(Headers);
            if (Block.size() <= PeerMaxFrameSize_)
            {
                auto Flags = static_cast<std::uint8_t>(FlagEndHeaders);
                if (EndStream)
                {
                    Flags |= FlagEndStream;
                }
                Connection_.QueueFrame(
                    {FrameType::Headers, Flags, static_cast<std::uint32_t>(StreamId), Block});
            }
            else
            {
                auto Offset = std::size_t{0};
                while (Offset < Block.size())
                {
                    const auto Count = (std::min)(static_cast<std::size_t>(PeerMaxFrameSize_),
                                                   Block.size() - Offset);
                    const std::vector<std::byte> Fragment(
                        Block.begin() + static_cast<std::ptrdiff_t>(Offset),
                        Block.begin() + static_cast<std::ptrdiff_t>(Offset + Count));
                    const auto First = Offset == 0;
                    const auto Last = Offset + Count == Block.size();
                    if (First)
                    {
                        const auto Flags = EndStream ? FlagEndStream : FlagNone;
                        Connection_.QueueFrame(
                            {FrameType::Headers, Flags, static_cast<std::uint32_t>(StreamId), Fragment});
                    }
                    else
                    {
                        const auto Flags = Last ? FlagEndHeaders : FlagNone;
                        Connection_.QueueFrame(
                            {FrameType::Continuation, Flags, static_cast<std::uint32_t>(StreamId), Fragment});
                    }
                    Offset += Count;
                }
            }
            if (EndStream)
            {
                StreamIterator->second.LocalClosed = true;
                WakeWaiters(StreamIterator->second.WritableWaiters);
                if (StreamIterator->second.RemoteClosed)
                {
                    ClosedStreams_.insert(static_cast<std::uint32_t>(StreamId));
                    Streams_.erase(StreamIterator);
                }
            }
            return {};
        }

        [[nodiscard]] auto NextClientStreamId()
            -> std::expected<std::int32_t, Preview::Fault::Failure>
        {
            if (NextClientId_ > 0x7FFFFFFF - 2)
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable});
            }
            const auto StreamId = NextClientId_;
            NextClientId_ += 2;
            Streams_[StreamId] = {};
            return StreamId;
        }

        [[nodiscard]] auto MissingStreamCode(const std::int32_t StreamId) const noexcept
            -> Preview::Fault::Code
        {
            if (IsClosedStream(StreamId)) return Preview::Fault::Code::ConnectionAborted;
            return Preview::Fault::Code::InvalidArgument;
        }

        ConnectionState &Connection_;
        CodecState &Codec_;
        H2Session &Events_;
        std::map<std::int32_t, StreamState> Streams_;
        std::set<std::uint32_t> ClosedStreams_;
        std::vector<std::weak_ptr<Net::steady_timer>> ConnectionWaiters_;
        std::int32_t NextClientId_{1};
        std::uint32_t LastRxStream_{0};
        std::uint32_t PeerInitialWindow_{DefaultInitialWindow};
        std::uint32_t PeerMaxFrameSize_{DefaultFramePayload};
    };

} // namespace Preview::Http2::Detail

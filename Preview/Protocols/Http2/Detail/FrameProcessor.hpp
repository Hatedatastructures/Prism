/**
 * @file FrameProcessor.hpp
 * @brief HTTP/2 输入帧分发和协议校验 owner。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Protocols/Http2/Detail/CodecState.hpp>
#include <Preview/Protocols/Http2/Detail/ConnectionState.hpp>
#include <Preview/Protocols/Http2/Detail/StreamController.hpp>

namespace Preview::Http2::Detail
{

    /** @brief 会话级 SETTINGS/GOAWAY 事件，协议内部 SETTINGS/GOAWAY 事件。 */
    struct ControlCallbacks
    {
        std::function<void(const std::vector<SettingsEntry> &)> OnSettings;
        std::function<void(const GoawayParams &)> OnGoaway;
    };

    struct ProcessorState final
    {
        ConnectionState &Connection;
        CodecState &Codec;
        StreamController &Streams;
        H2Session &Events;
        ControlCallbacks &Controls;
    };

    struct HeaderEvent final
    {
        std::uint32_t StreamId{0};
        bool EndStream{false};
        std::span<const std::byte> Block;
    };

    /** @class FrameProcessor
     *  @brief 把完整帧转换为流事件、控制事件和状态变化。
     */
    class FrameProcessor final
    {
    public:
        explicit FrameProcessor(ProcessorState State)
            : Connection_(State.Connection), Codec_(State.Codec), Streams_(State.Streams),
              Events_(State.Events), Controls_(State.Controls)
        {
        }

        [[nodiscard]] auto Dispatch(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool
        {
            if (PendingHeaders_ && Header.Type != FrameType::Continuation)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            switch (Header.Type)
            {
            case FrameType::Data:
                return OnDataFrame(Header, Payload, ErrorCode);
            case FrameType::Headers:
                return OnHeadersFrame(Header, Payload, ErrorCode);
            case FrameType::Settings:
                return OnSettingsFrame(Header, Payload, ErrorCode);
            case FrameType::Ping:
                return OnPingFrame(Header, Payload, ErrorCode);
            case FrameType::Goaway:
                if (Payload.size() < 8)
                {
                    ErrorCode = make_error_code(Error::BadLength);
                    return false;
                }
                if (Controls_.OnGoaway)
                {
                    GoawayParams Params;
                    Params.LastStreamId = DecodeU31(Payload.first<4>());
                    Params.ErrorCode = DecodeU31(Payload.last<4>());
                    Controls_.OnGoaway(Params);
                }
                return true;
            case FrameType::WindowUpdate:
                if (Payload.size() != 4 || DecodeU31(Payload) == 0)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                return OnWindowUpdate(Header, Payload, ErrorCode);
            case FrameType::RstStream:
            {
                if (Header.StreamId == ConnectionStreamId || Payload.size() != 4)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                const auto StreamId = static_cast<std::int32_t>(Header.StreamId);
                if (!Streams_.Find(StreamId))
                {
                    if (Streams_.IsClosedStream(StreamId)) return true;
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                Streams_.OnStreamCloseIf(
                    static_cast<std::int32_t>(Header.StreamId), DecodeU32(Payload));
                return true;
            }
            case FrameType::Priority:
                if (Header.StreamId == ConnectionStreamId || Payload.size() != 5)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                return true;
            case FrameType::Continuation:
                return OnContinuationFrame(Header, Payload, ErrorCode);
            case FrameType::PushPromise:
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            default:
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
        }

    private:
        struct HeaderContinuation
        {
            std::uint32_t StreamId{0};
            bool EndStream{false};
            std::vector<std::byte> Block;
        };

        [[nodiscard]] auto OnDataFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool
        {
            if (Header.StreamId == ConnectionStreamId)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            std::span<const std::byte> Data = Payload;
            if ((Header.Flags & FlagPadded) != 0)
            {
                if (Payload.empty())
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                const auto Padding = std::to_integer<std::uint8_t>(Payload[0]);
                if (Padding + 1 > Payload.size())
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                Data = Payload.subspan(1, Payload.size() - 1 - Padding);
            }
            auto *State = Streams_.Find(static_cast<std::int32_t>(Header.StreamId));
            if (!State)
            {
                if (!Streams_.IsClosedStream(static_cast<std::int32_t>(Header.StreamId)))
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                if (Payload.size() > Connection_.ConnectionReceiveWindow())
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                Connection_.ConnectionReceiveWindow() -= static_cast<std::uint32_t>(Payload.size());
                Streams_.ConsumeClosedStreamData(Payload.size());
                return true;
            }
            if (State->RemoteClosed ||
                Payload.size() > Connection_.ConnectionReceiveWindow() ||
                Payload.size() > State->ReceiveWindow)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            Connection_.ConnectionReceiveWindow() -= static_cast<std::uint32_t>(Payload.size());
            State->ReceiveWindow -= static_cast<std::uint32_t>(Payload.size());
            if (Events_.OnData)
            {
                Events_.OnData(Header.StreamId, Data);
            }
            Streams_.ConsumeData(static_cast<std::int32_t>(Header.StreamId), Payload.size());
            if ((Header.Flags & FlagEndStream) != 0)
            {
                Streams_.OnRemoteEnd(static_cast<std::int32_t>(Header.StreamId), ErrorNoError);
            }
            return true;
        }

        [[nodiscard]] auto OnHeadersFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool
        {
            if (!Streams_.ValidateIncomingStream(Header.StreamId, ErrorCode))
            {
                return false;
            }
            std::size_t Offset = 0;
            std::size_t Padding = 0;
            if ((Header.Flags & FlagPadded) != 0)
            {
                if (Payload.empty())
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                Padding = std::to_integer<std::uint8_t>(Payload[0]);
                Offset = 1;
                if (Padding > Payload.size() - Offset)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
            }
            if ((Header.Flags & FlagPriority) != 0)
            {
                Offset += 5;
                if (Offset > Payload.size() - Padding)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
            }
            const auto BlockEnd = Payload.size() - Padding;
            if (Offset > BlockEnd)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            const auto Block = Payload.subspan(Offset, BlockEnd - Offset);
            if ((Header.Flags & FlagEndHeaders) == 0)
            {
                PendingHeaders_ = HeaderContinuation{
                    Header.StreamId, (Header.Flags & FlagEndStream) != 0,
                    std::vector<std::byte>(Block.begin(), Block.end())};
                return true;
            }
            return FinishHeaders(
                HeaderEvent{Header.StreamId, (Header.Flags & FlagEndStream) != 0, Block},
                ErrorCode);
        }

        [[nodiscard]] auto OnContinuationFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool
        {
            if ((Header.Flags & static_cast<std::uint8_t>(0xFFU ^ FlagEndHeaders)) != 0 ||
                !PendingHeaders_ || Header.StreamId == ConnectionStreamId ||
                Header.StreamId != PendingHeaders_->StreamId)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            PendingHeaders_->Block.insert(PendingHeaders_->Block.end(), Payload.begin(), Payload.end());
            if ((Header.Flags & FlagEndHeaders) == 0)
            {
                return true;
            }
            auto Pending = std::move(*PendingHeaders_);
            PendingHeaders_.reset();
            return FinishHeaders(
                HeaderEvent{Pending.StreamId, Pending.EndStream, Pending.Block}, ErrorCode);
        }

        [[nodiscard]] auto FinishHeaders(
            const HeaderEvent &Event,
            std::error_code &ErrorCode) -> bool
        {
            const auto Headers = Codec_.DecodeHeaders(Event.Block);
            if (!Headers)
            {
                ErrorCode = make_error_code(Error::BadMessage);
                return false;
            }
            if (Streams_.IsClosedStream(static_cast<std::int32_t>(Event.StreamId)))
            {
                return true;
            }
            if (!Streams_.ValidateIncomingStream(Event.StreamId, ErrorCode))
            {
                return false;
            }
            Streams_.RegisterIncomingStream(Event.StreamId);
            if (Events_.OnHeaders)
            {
                Events_.OnHeaders(
                    static_cast<std::int32_t>(Event.StreamId), *Headers, Event.EndStream);
            }
            if (Event.EndStream)
            {
                Streams_.OnRemoteEnd(static_cast<std::int32_t>(Event.StreamId), ErrorNoError);
            }
            return true;
        }

        [[nodiscard]] auto OnWindowUpdate(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool
        {
            const auto Increment = DecodeU31(Payload);
            if (Header.StreamId == ConnectionStreamId)
            {
                if (Connection_.ConnectionSendWindow() > 0x7FFFFFFFU - Increment)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                Connection_.ConnectionSendWindow() += Increment;
                Streams_.WakeConnectionWaiters();
                return true;
            }
            return Streams_.ApplyStreamWindowUpdate(
                static_cast<std::int32_t>(Header.StreamId), Increment, ErrorCode);
        }

        [[nodiscard]] auto OnSettingsFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool
        {
            if (Header.StreamId != ConnectionStreamId)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            if ((Header.Flags & FlagAck) != 0)
            {
                if (!Payload.empty())
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                return true;
            }
            const auto Entries = DecodeSettings(Payload);
            if (!Entries)
            {
                ErrorCode = make_error_code(Error::BadMessage);
                return false;
            }
            if (!Streams_.ApplyPeerSettings(*Entries, ErrorCode))
            {
                return false;
            }
            if (Controls_.OnSettings)
            {
                Controls_.OnSettings(*Entries);
            }
            Connection_.QueueFrame({FrameType::Settings, FlagAck, ConnectionStreamId, {}});
            return true;
        }

        [[nodiscard]] auto OnPingFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool
        {
            if (Header.StreamId != ConnectionStreamId || Payload.size() != 8)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            if ((Header.Flags & FlagAck) == 0)
            {
                const std::vector<std::byte> Ack(Payload.begin(), Payload.end());
                Connection_.QueueFrame({FrameType::Ping, FlagAck, ConnectionStreamId, Ack});
            }
            return true;
        }

        ConnectionState &Connection_;
        CodecState &Codec_;
        StreamController &Streams_;
        H2Session &Events_;
        ControlCallbacks &Controls_;
        std::optional<HeaderContinuation> PendingHeaders_;
    };

} // namespace Preview::Http2::Detail

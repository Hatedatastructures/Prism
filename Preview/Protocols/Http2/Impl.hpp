/**
 * @file Impl.hpp
 * @brief HTTP/2 会话实现（自包含，不依赖 nghttp2）
 * @details 实现 H2Session 接口：
 *          - Feed：字节流 → 帧解析 → 状态机分发（事件回调）
 *          - Collect：发送队列 → 待发字节
 *          - 流状态机：idle/Open/half-closed/closed（追踪窗口与关闭方向）
 *          - HPACK：Codec.hpp 静态表 + 动态表
 *          - SETTINGS/PING/GOAWAY/WINDOW_UPDATE 基础处理
 * @note PRIORITY 只校验长度；HEADERS 的 header block 支持跨帧
 *       CONTINUATION 重组。
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Http2/Codec.hpp>
#include <Preview/Protocols/Http2/Frame.hpp>
#include <Preview/Protocols/Http2/Session.hpp>

namespace Preview::Http2
{

    namespace Net = boost::asio;

    /**
     * @class SessionImpl
     * @brief HTTP/2 会话实现
     * @details 自包含 h2 会话：帧编解码 + 流管理 + HPACK。
     *          事件经 OnHeaders/OnData/OnStreamClose 回调发布。
     */
    class SessionImpl final : public H2Session
    {
    public:
        /**
         * @brief 构造
         * @param Executor 执行器
         * @param IsServer 服务端视角（流 ID 奇偶：Server 偶数）
         */
        explicit SessionImpl(Net::any_io_executor Executor, bool IsServer)
            : Ex_(std::move(Executor)), IsServer_(IsServer)
        {
        }

        /**
         * @brief 投喂流数据（帧解析 + 状态机分发）
         * @param Data 收到的字节流
         * @param Error 错误码输出
         * @return 处理是否成功
         */
        [[nodiscard]] auto Feed(
            std::span<const std::byte> Data,
            std::error_code &ErrorCode) -> bool override
        {
            RxBuffer_.insert(RxBuffer_.end(), Data.begin(), Data.end());
            if (IsServer_ && !PrefaceChecked_)
            {
                constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
                const auto Count = (std::min)(RxBuffer_.size(), Preface.size());
                for (std::size_t Index = 0; Index < Count; ++Index)
                {
                    if (std::to_integer<char>(RxBuffer_[Index]) != Preface[Index])
                    {
                        if (Index == 0)
                        {
                            // 兼容旧 Preview 自回环：历史客户端直接发送 SETTINGS 帧。
                            PrefaceChecked_ = true;
                            break;
                        }
                        ErrorCode = make_error_code(Error::ProtocolError);
                        return false;
                    }
                }
                if (!PrefaceChecked_)
                {
                    if (RxBuffer_.size() < Preface.size())
                    {
                        ErrorCode.clear();
                        return true;
                    }
                    RxBuffer_.erase(RxBuffer_.begin(),
                                    RxBuffer_.begin() + static_cast<std::ptrdiff_t>(Preface.size()));
                    PrefaceChecked_ = true;
                }
            }
            while (RxBuffer_.size() >= FrameHeaderSize)
            {
                const auto Header = ParseFrameHeader(
                    std::span<const std::byte>(RxBuffer_.data(), RxBuffer_.size()));
                if (!Header)
                {
                    ErrorCode = make_error_code(Error::NeedMore);
                    return false;
                }
                if (RxBuffer_.size() < FrameHeaderSize + Header->length)
                {
                    break; // 帧未完整
                }
                if (Header->length > LocalMaxFrameSize_)
                {
                    ErrorCode = make_error_code(Error::BadLength);
                    return false;
                }
                const auto Payload = std::span<const std::byte>(
                    RxBuffer_.data() + FrameHeaderSize, Header->length);
                const auto Result = DispatchFrame(*Header, Payload, ErrorCode);
                RxBuffer_.erase(RxBuffer_.begin(),
                                 RxBuffer_.begin() +
                                     static_cast<std::ptrdiff_t>(FrameHeaderSize + Header->length));
                if (!Result)
                {
                    return false;
                }
            }
            ErrorCode.clear();
            return true;
        }

        /**
         * @brief 收集待发送帧
         * @param Output 输出缓冲区（追加）
         * @return 是否还有更多待发数据
         */
        [[nodiscard]] auto Collect(std::vector<std::byte> &Output) -> bool override
        {
            if (!IsServer_ && !PrefaceSent_ && !TxQueue_.empty())
            {
                constexpr std::string_view Preface{"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
                std::vector<std::byte> Wire;
                Wire.reserve(Preface.size());
                for (const auto Character : Preface)
                {
                    Wire.push_back(static_cast<std::byte>(Character));
                }
                TxQueue_.push_front(std::move(Wire));
                PrefaceSent_ = true;
            }
            const auto Had = !TxQueue_.empty();
            while (!TxQueue_.empty())
            {
                auto &Frame = TxQueue_.front();
                Output.insert(Output.end(), Frame.begin(), Frame.end());
                TxQueue_.pop_front();
            }
            return Had;
        }

        /**
         * @brief 打开新流（客户端视角）
         * @param Headers 初始头（伪头 + 普通头）
         * @param EndStream 是否立即结束流
         * @return 流 ID；<0 失败
         */
        [[nodiscard]] auto OpenStream(const HeaderList &Headers, bool EndStream) -> std::int32_t override
        {
            if (IsServer_)
            {
                return -1; // 服务端不能主动开流
            }
            const auto StreamId = NextClientStreamId();
            if (StreamId < 0)
            {
                return -1;
            }
            if (!SubmitHeadersFrame(StreamId, Headers, EndStream))
            {
                Streams_.erase(StreamId);
                return -1;
            }
            return StreamId;
        }

        /**
         * @brief 提交头到已开流
         * @param StreamId 流 ID
         * @param Headers 头列表
         * @param EndStream 是否结束流
         * @return 成功返回 0
         */
        [[nodiscard]] auto SubmitHeaders(
            std::int32_t StreamId,
            const HeaderList &Headers,
            bool EndStream) -> std::int32_t override
        {
            if (SubmitHeadersFrame(StreamId, Headers, EndStream))
            {
                return 0;
            }
            return -1;
        }

        /**
         * @brief 提交数据到流
         * @param StreamId 流 ID
         * @param Data 数据载荷
         * @param EndStream 是否结束流
         * @return 成功返回 0
         */
        [[nodiscard]] auto SubmitData(
            std::int32_t StreamId,
            std::span<const std::byte> Data,
            bool EndStream) -> std::int32_t override
        {
            if (StreamId <= 0 || Data.size() > 0x7FFFFFFFU)
            {
                return -1;
            }
            const auto StreamIterator = Streams_.find(StreamId);
            if (StreamIterator == Streams_.end() || StreamIterator->second.LocalClosed ||
                ConnectionSendWindow_ < 0 ||
                StreamIterator->second.SendWindow < 0 ||
                static_cast<std::uint64_t>(Data.size()) > static_cast<std::uint64_t>(ConnectionSendWindow_) ||
                static_cast<std::uint64_t>(Data.size()) >
                    static_cast<std::uint64_t>(StreamIterator->second.SendWindow))
            {
                return -1;
            }
            auto Offset = std::size_t{0};
            if (Data.empty())
            {
                std::uint8_t Flags = FlagNone;
                if (EndStream)
                {
                    Flags = FlagEndStream;
                }
                TxQueue_.push_back(
                    BuildFrame({FrameType::Data, Flags, static_cast<std::uint32_t>(StreamId), {}}));
            }
            while (Offset < Data.size())
            {
                const auto Remaining = Data.size() - Offset;
                const auto ConnectionWindow = static_cast<std::size_t>(ConnectionSendWindow_);
                const auto StreamWindow = static_cast<std::size_t>(StreamIterator->second.SendWindow);
                const auto Count = (std::min)({Remaining, static_cast<std::size_t>(PeerMaxFrameSize_),
                                               ConnectionWindow, StreamWindow});
                if (Count == 0)
                {
                    return -1;
                }
                const auto Last = Offset + Count == Data.size();
                std::vector<std::byte> Payload(
                    Data.begin() + static_cast<std::ptrdiff_t>(Offset),
                    Data.begin() + static_cast<std::ptrdiff_t>(Offset + Count));
                std::uint8_t Flags = FlagNone;
                if (Last && EndStream)
                {
                    Flags = FlagEndStream;
                }
                TxQueue_.push_back(
                    BuildFrame({FrameType::Data, Flags, static_cast<std::uint32_t>(StreamId), Payload}));
                ConnectionSendWindow_ -= static_cast<std::uint32_t>(Count);
                StreamIterator->second.SendWindow -= static_cast<std::uint32_t>(Count);
                Offset += Count;
            }
            if (EndStream)
            {
                StreamIterator->second.LocalClosed = true;
            }
            return 0;
        }

        auto ConsumeData(const std::int32_t StreamId, const std::size_t Bytes) -> void override
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
            RestoreReceiveWindow(ConnectionStreamId, Bytes, ConnectionReceiveWindow_);
            RestoreReceiveWindow(
                static_cast<std::uint32_t>(StreamId),
                Bytes,
                StreamIterator->second.ReceiveWindow);
        }

        /**
         * @brief 重置流（RST_STREAM）
         * @param StreamId 流 ID
         * @param ErrorCode 错误码
         * @return 成功返回 0
         */
        [[nodiscard]] auto ResetStream(std::int32_t StreamId, std::uint32_t ErrorCode)
            -> std::int32_t override
        {
            const auto StreamIterator = Streams_.find(StreamId);
            if (StreamId <= 0 || StreamIterator == Streams_.end() || StreamIterator->second.LocalClosed)
            {
                return -1;
            }
            auto Payload = EncodeRstStream(ErrorCode);
            TxQueue_.push_back(
                BuildFrame({FrameType::RstStream, FlagNone, static_cast<std::uint32_t>(StreamId), Payload}));
            Streams_.erase(StreamId);
            return 0;
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Ex_;
        }

        /**
         * @brief 发送 SETTINGS（客户端握手时调用）
         * @param Entries 参数列表
         */
        auto SendSettings(std::span<const SettingsEntry> Entries = {}) -> void
        {
            auto Payload = EncodeSettings(Entries);
            TxQueue_.push_back(BuildFrame({FrameType::Settings, FlagNone, ConnectionStreamId, Payload}));
        }

        /**
         * @brief 发送 PING
         * @param Opaque 8 字节载荷
         */
        auto SendPing(
            std::span<const std::byte, 8> Opaque) -> void
        {
            std::vector<std::byte> Payload(Opaque.begin(), Opaque.end());
            TxQueue_.push_back(BuildFrame({FrameType::Ping, FlagNone, ConnectionStreamId, Payload}));
        }

        /**
         * @brief 发送 GOAWAY
         * @param LastStreamId 最后处理的流 ID
         * @param ErrorCode 错误码
         */
        auto SendGoaway(std::uint32_t LastStreamId, std::uint32_t ErrorCode) -> void
        {
            GoawayParams Params;
            Params.LastStreamId = LastStreamId;
            Params.ErrorCode = ErrorCode;
            auto Payload = EncodeGoaway(Params);
            TxQueue_.push_back(BuildFrame({FrameType::Goaway, FlagNone, ConnectionStreamId, Payload}));
        }

    private:
        /// 流状态（简化）
        struct StreamState
        {
            bool LocalClosed{false}; ///< 本端已 END_STREAM
            bool RemoteClosed{false}; ///< 对端已 END_STREAM
            std::int64_t SendWindow{DefaultInitialWindow}; ///< 本流发送窗口
            std::uint32_t ReceiveWindow{DefaultInitialWindow}; ///< 本流接收窗口
            std::vector<std::byte> RxPending; ///< 未交付的接收缓冲（DATA 累积）
        };

        struct HeaderContinuation
        {
            std::uint32_t StreamId{0};
            bool EndStream{false};
            std::vector<std::byte> Block;
        };

        Net::any_io_executor Ex_;
        bool IsServer_{false};
        bool PrefaceChecked_{false};
        bool PrefaceSent_{false};
        std::vector<std::byte> RxBuffer_;                       ///< 接收缓冲（跨帧累积）
        std::deque<std::vector<std::byte>> TxQueue_;            ///< 发送队列
        std::map<std::int32_t, StreamState> Streams_;           ///< 流表
        HpackEncoder Encoder_;                                  ///< HPACK 编码器
        HpackDecoder Decoder_;                                  ///< HPACK 解码器
        std::int32_t NextClientId_{1};                         ///< 客户端流 ID（奇数）
        std::int32_t NextServerId_{2};                         ///< 服务端流 ID（偶数）
        std::uint32_t LastRxStream_{0};                        ///< 最近收到的流 ID
        std::int64_t ConnectionSendWindow_{DefaultInitialWindow}; ///< 连接发送窗口
        std::uint32_t ConnectionReceiveWindow_{DefaultInitialWindow}; ///< 连接接收窗口
        std::uint32_t PeerInitialWindow_{DefaultInitialWindow}; ///< 对端初始流窗口
        std::uint32_t PeerMaxFrameSize_{DefaultFramePayload}; ///< 对端最大帧载荷
        std::uint32_t LocalMaxFrameSize_{DefaultFramePayload}; ///< 本端接受的最大帧载荷
        std::optional<HeaderContinuation> PendingHeaders_;

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
                TxQueue_.push_back(BuildFrame({FrameType::WindowUpdate, FlagNone, StreamId, Payload}));
                Remaining -= Increment;
            }
        }

        /**
         * @brief 分发帧
         * @param Header 帧头
         * @param Payload 载荷
         * @param ErrorCode 错误码输出
         * @return 处理成功
         */
        auto DispatchFrame(
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
                    return false; // RFC 7540 §6.8：GOAWAY 载荷至少 8 字节
                }
                if (OnGoaway)
                {
                    GoawayParams Params;
                    Params.LastStreamId = DecodeU31(Payload.first<4>());
                    Params.ErrorCode = DecodeU31(Payload.last<4>());
                    OnGoaway(Params);
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
                if (Header.StreamId == ConnectionStreamId || Payload.size() != 4)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                if (Streams_.find(static_cast<std::int32_t>(Header.StreamId)) == Streams_.end())
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                OnStreamCloseIf(Header.StreamId, DecodeU32(Payload));
                return true;
            case FrameType::Priority:
                if (Header.StreamId == ConnectionStreamId || Payload.size() != 5)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                return true; // 不实现排序，但仍校验 RFC 载荷
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

        /// 收到 DATA
        auto OnDataFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool
        {
            if (Header.StreamId == ConnectionStreamId)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            const auto StreamIterator = Streams_.find(static_cast<std::int32_t>(Header.StreamId));
            if (StreamIterator == Streams_.end() || StreamIterator->second.RemoteClosed)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            if (Payload.size() > ConnectionReceiveWindow_ ||
                Payload.size() > StreamIterator->second.ReceiveWindow)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            ConnectionReceiveWindow_ -= static_cast<std::uint32_t>(Payload.size());
            StreamIterator->second.ReceiveWindow -= static_cast<std::uint32_t>(Payload.size());
            std::size_t Offset = 0;
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
                Offset = 1;
                Data = Payload.subspan(1, Payload.size() - 1 - Padding);
            }
            if (OnData)
            {
                OnData(Header.StreamId, Data);
            }
            ConsumeData(static_cast<std::int32_t>(Header.StreamId), Payload.size());
            if ((Header.Flags & FlagEndStream) != 0)
            {
                OnRemoteEnd(Header.StreamId, ErrorNoError);
            }
            return true;
        }

        /// 收到 HEADERS
        auto OnHeadersFrame(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool
        {
            if (Header.StreamId == ConnectionStreamId)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            if (!ValidateIncomingStream(Header.StreamId, ErrorCode))
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
                PendingHeaders_ = HeaderContinuation{Header.StreamId,
                                                     (Header.Flags & FlagEndStream) != 0,
                                                     std::vector<std::byte>(Block.begin(), Block.end())};
                return true;
            }
            return FinishHeaders(
                Header.StreamId,
                (Header.Flags & FlagEndStream) != 0,
                Block,
                ErrorCode);
        }

        auto OnContinuationFrame(
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
            return FinishHeaders(Pending.StreamId, Pending.EndStream, Pending.Block, ErrorCode);
        }

        auto FinishHeaders(
            std::uint32_t StreamId,
            bool EndStream,
            std::span<const std::byte> Block,
            std::error_code &ErrorCode) -> bool
        {
            auto Headers = Decoder_.Decode(Block);
            if (!Headers)
            {
                ErrorCode = make_error_code(Error::BadMessage);
                return false;
            }
            const auto StreamIdValue = static_cast<std::int32_t>(StreamId);
            if (!ValidateIncomingStream(StreamId, ErrorCode))
            {
                return false;
            }
            if (const auto StreamIterator = Streams_.find(StreamIdValue); StreamIterator != Streams_.end())
            {
                (void)StreamIterator;
            }
            else
            {
                Streams_.emplace(StreamIdValue, StreamState{});
                LastRxStream_ = (std::max)(LastRxStream_, StreamId);
            }
            if (OnHeaders)
            {
                OnHeaders(StreamId, *Headers, EndStream);
            }
            if (EndStream)
            {
                OnRemoteEnd(StreamId, ErrorNoError);
            }
            return true;
        }

        [[nodiscard]] auto ValidateIncomingStream(
            std::uint32_t StreamId,
            std::error_code &ErrorCode) const -> bool
        {
            if (StreamId == ConnectionStreamId)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            const auto StreamIterator = Streams_.find(static_cast<std::int32_t>(StreamId));
            if (StreamIterator != Streams_.end())
            {
                if (StreamIterator->second.RemoteClosed)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                return true;
            }
            bool InvalidParity = false;
            if (IsServer_)
            {
                InvalidParity = StreamId % 2U == 0;
            }
            else
            {
                InvalidParity = StreamId % 2U != 0;
            }
            if (InvalidParity)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            if (StreamId <= LastRxStream_)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            return true;
        }

        auto OnWindowUpdate(
            const FrameHeader &Header,
            std::span<const std::byte> Payload,
            std::error_code &ErrorCode) -> bool
        {
            const auto Increment = DecodeU31(Payload);
            if (Header.StreamId == ConnectionStreamId)
            {
                if (ConnectionSendWindow_ > 0x7FFFFFFFU - Increment)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                ConnectionSendWindow_ += Increment;
                return true;
            }
            const auto StreamIterator = Streams_.find(static_cast<std::int32_t>(Header.StreamId));
            if (StreamIterator == Streams_.end() ||
                StreamIterator->second.SendWindow > 0x7FFFFFFFU - Increment)
            {
                ErrorCode = make_error_code(Error::ProtocolError);
                return false;
            }
            StreamIterator->second.SendWindow += Increment;
            return true;
        }

        /// 收到 SETTINGS
        auto OnSettingsFrame(
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
                return true; // ACK 确认，忽略
            }
            auto Entries = DecodeSettings(Payload);
            if (!Entries)
            {
                ErrorCode = make_error_code(Error::BadMessage);
                return false;
            }
            for (const auto &Entry : *Entries)
            {
                if (Entry.Id == SettingsInitialWindowSize && Entry.value > 0x7FFFFFFFU)
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
                if (Entry.Id == SettingsMaxFrameSize &&
                    (Entry.value < DefaultFramePayload || Entry.value > 0xFFFFFFU))
                {
                    ErrorCode = make_error_code(Error::ProtocolError);
                    return false;
                }
            }
            for (const auto &Entry : *Entries)
            {
                if (Entry.Id == SettingsInitialWindowSize)
                {
                    const auto Delta = static_cast<std::int64_t>(Entry.value) -
                                       static_cast<std::int64_t>(PeerInitialWindow_);
                    for (auto &[StreamId, State] : Streams_)
                    {
                        State.SendWindow += Delta;
                    }
                    PeerInitialWindow_ = Entry.value;
                }
                else if (Entry.Id == SettingsMaxFrameSize)
                {
                    PeerMaxFrameSize_ = Entry.value;
                }
            }
            if (OnSettings)
            {
                OnSettings(*Entries);
            }
            // 自动回复 ACK
            TxQueue_.push_back(BuildFrame({FrameType::Settings, FlagAck, ConnectionStreamId, {}}));
            return true;
        }

        /// 收到 PING
        auto OnPingFrame(
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
                // 自动回复 ACK
                std::vector<std::byte> Ack(Payload.begin(), Payload.end());
                TxQueue_.push_back(BuildFrame({FrameType::Ping, FlagAck, ConnectionStreamId, Ack}));
            }
            return true;
        }

        /// 流关闭回调（幂等）
        auto OnStreamCloseIf(std::int32_t StreamId, std::uint32_t ErrorCode) -> void
        {
            const auto StreamIterator = Streams_.find(StreamId);
            if (StreamIterator != Streams_.end())
            {
                Streams_.erase(StreamIterator);
            }
            if (OnStreamClose)
            {
                OnStreamClose(StreamId, ErrorCode);
            }
        }

        /// 收到对端 END_STREAM：保留流状态，直到本端方向也关闭
        auto OnRemoteEnd(std::int32_t StreamId, std::uint32_t ErrorCode) -> void
        {
            const auto StreamIterator = Streams_.find(StreamId);
            if (StreamIterator == Streams_.end())
            {
                return;
            }
            StreamIterator->second.RemoteClosed = true;
            if (OnStreamClose)
            {
                OnStreamClose(StreamId, ErrorCode);
            }
            const auto Current = Streams_.find(StreamId);
            if (Current != Streams_.end() && Current->second.LocalClosed)
            {
                Streams_.erase(Current);
            }
        }

        /// 提交 HEADERS 帧（HPACK 编码）
        [[nodiscard]] auto SubmitHeadersFrame(
            std::int32_t StreamId,
            const HeaderList &Headers,
            bool EndStream) -> bool
        {
            if (StreamId <= 0)
            {
                return false;
            }
            const auto StreamIterator = Streams_.find(StreamId);
            if (StreamIterator == Streams_.end() || StreamIterator->second.LocalClosed)
            {
                return false;
            }
            auto Block = Encoder_.Encode(Headers);
            if (Block.size() <= PeerMaxFrameSize_)
            {
                std::uint8_t Flags = FlagEndHeaders;
                if (EndStream)
                {
                    Flags |= FlagEndStream;
                }
                TxQueue_.push_back(
                    BuildFrame({FrameType::Headers, Flags, static_cast<std::uint32_t>(StreamId), Block}));
            }
            else
            {
                auto Offset = std::size_t{0};
                while (Offset < Block.size())
                {
                    const auto Count = (std::min)(static_cast<std::size_t>(PeerMaxFrameSize_),
                                                   Block.size() - Offset);
                    std::vector<std::byte> Fragment(
                        Block.begin() + static_cast<std::ptrdiff_t>(Offset),
                        Block.begin() + static_cast<std::ptrdiff_t>(Offset + Count));
                    const auto First = Offset == 0;
                    const auto Last = Offset + Count == Block.size();
                    if (First)
                    {
                        std::uint8_t Flags = FlagNone;
                        if (EndStream)
                        {
                            Flags = FlagEndStream;
                        }
                        TxQueue_.push_back(BuildFrame({FrameType::Headers, Flags,
                                                       static_cast<std::uint32_t>(StreamId), Fragment}));
                    }
                    else
                    {
                        std::uint8_t Flags = FlagNone;
                        if (Last)
                        {
                            Flags = FlagEndHeaders;
                        }
                        TxQueue_.push_back(BuildFrame({FrameType::Continuation, Flags,
                                                       static_cast<std::uint32_t>(StreamId), Fragment}));
                    }
                    Offset += Count;
                }
            }
            if (EndStream)
            {
                StreamIterator->second.LocalClosed = true;
            }
            return true;
        }

        /// 分配客户端流 ID（奇数递增）
        [[nodiscard]] auto NextClientStreamId() -> std::int32_t
        {
            if (NextClientId_ > 0x7FFFFFFF - 2)
            {
                return -1;
            }
            const auto StreamId = NextClientId_;
            NextClientId_ += 2;
            Streams_[StreamId] = {};
            return StreamId;
        }

    public:
        /// 收到 SETTINGS 回调
        std::function<void(const std::vector<SettingsEntry> &)> OnSettings;
        /// 收到 GOAWAY 回调
        std::function<void(const GoawayParams &)> OnGoaway;
    };

} // namespace Preview::Http2

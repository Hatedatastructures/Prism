/**
 * @file Impl.hpp
 * @brief HTTP/2 会话实现（自包含，不依赖 nghttp2）
 * @details 实现 H2Session 接口：
 *          - Feed：字节流 → 帧解析 → 状态机分发（事件回调）
 *          - Collect：发送队列 → 待发字节
 *          - 流状态机：idle/Open/half-closed/closed（简化：追踪本地关闭）
 *          - HPACK：Codec.hpp 静态表 + 动态表
 *          - SETTINGS/PING/GOAWAY/WINDOW_UPDATE 基础处理
 * @note 简化：不实现流控窗口（连接/流级窗口恒 65535）、不实现
 *       PRIORITY/CONTINUATION 重组（HEADERS 单帧）。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Protocols/Http2/Codec.hpp>
#include <common/Protocols/Http2/Frame.hpp>
#include <common/Protocols/Http2/Session.hpp>

namespace Preview::Http2
{

    namespace net = boost::asio;

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
         * @param ex 执行器
         * @param IsServer 服务端视角（流 ID 奇偶：Server 偶数）
         */
        explicit SessionImpl(net::any_io_executor ex, bool IsServer)
            : Ex_(std::move(ex)), IsServer_(IsServer)
        {
        }

        /**
         * @brief 投喂流数据（帧解析 + 状态机分发）
         * @param Data 收到的字节流
         * @param ec 错误码输出
         * @return 处理是否成功
         */
        [[nodiscard]] auto Feed(std::span<const std::byte> Data, std::error_code &ec) -> bool override
        {
            RxBuffer_.insert(RxBuffer_.end(), Data.begin(), Data.end());
            while (RxBuffer_.size() >= FrameHeaderSize)
            {
                const auto H = ParseFrameHeader(std::span<const std::byte>(RxBuffer_.data(), RxBuffer_.size()));
                if (!H)
                {
                    ec = make_error_code(Error::NeedMore);
                    return false;
                }
                if (RxBuffer_.size() < FrameHeaderSize + H->length)
                {
                    break; // 帧未完整
                }
                const auto Payload = std::span<const std::byte>(
                    RxBuffer_.data() + FrameHeaderSize, H->length);
                const auto R = DispatchFrame(*H, Payload, ec);
                RxBuffer_.erase(RxBuffer_.begin(),
                                 RxBuffer_.begin() + static_cast<std::ptrdiff_t>(FrameHeaderSize + H->length));
                if (!R)
                {
                    return false;
                }
            }
            ec.clear();
            return true;
        }

        /**
         * @brief 收集待发送帧
         * @param out 输出缓冲区（追加）
         * @return 是否还有更多待发数据
         */
        [[nodiscard]] auto Collect(std::vector<std::byte> &out) -> bool override
        {
            const auto Had = !TxQueue_.empty();
            while (!TxQueue_.empty())
            {
                auto &f = TxQueue_.front();
                out.insert(out.end(), f.begin(), f.end());
                TxQueue_.pop_front();
            }
            return Had;
        }

        /**
         * @brief 打开新流（客户端视角）
         * @param headers 初始头（伪头 + 普通头）
         * @param EndStream 是否立即结束流
         * @return 流 ID；<0 失败
         */
        [[nodiscard]] auto OpenStream(const HeaderList &Headers, bool EndStream) -> std::int32_t override
        {
            if (IsServer_)
            {
                return -1; // 服务端不能主动开流
            }
            const auto Id = NextClientStreamId();
            if (Id < 0)
            {
                return -1;
            }
            SubmitHeadersFrame(Id, Headers, EndStream);
            return Id;
        }

        /**
         * @brief 提交头到已开流
         * @param StreamId 流 ID
         * @param headers 头列表
         * @param EndStream 是否结束流
         * @return 成功返回 0
         */
        [[nodiscard]] auto SubmitHeaders(std::int32_t StreamId, const HeaderList &Headers,
                                          bool EndStream) -> std::int32_t override
        {
            SubmitHeadersFrame(StreamId, Headers, EndStream);
            return 0;
        }

        /**
         * @brief 提交数据到流
         * @param StreamId 流 ID
         * @param Data 数据载荷
         * @param EndStream 是否结束流
         * @return 成功返回 0
         */
        [[nodiscard]] auto SubmitData(std::int32_t StreamId, std::span<const std::byte> Data,
                                       bool EndStream) -> std::int32_t override
        {
            std::vector<std::byte> Payload(Data.begin(), Data.end());
            std::uint8_t Flags = 0;
            if (EndStream)
            {
                Flags |= FlagEndStream;
            }
            TxQueue_.push_back(BuildFrame(FrameType::Data, Flags, StreamId, Payload));
            return 0;
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
            auto Payload = EncodeRstStream(ErrorCode);
            TxQueue_.push_back(BuildFrame(FrameType::RstStream, FlagNone, StreamId, Payload));
            Streams_.erase(StreamId);
            return 0;
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return Ex_;
        }

        /**
         * @brief 发送 SETTINGS（客户端握手时调用）
         * @param entries 参数列表
         */
        void SendSettings(std::span<const SettingsEntry> Entries = {})
        {
            auto Payload = EncodeSettings(Entries);
            TxQueue_.push_back(BuildFrame(FrameType::Settings, FlagNone, ConnectionStreamId, Payload));
        }

        /**
         * @brief 发送 PING
         * @param opaque 8 字节载荷
         */
        void SendPing(std::span<const std::byte, 8> opaque)
        {
            std::vector<std::byte> Payload(opaque.begin(), opaque.end());
            TxQueue_.push_back(BuildFrame(FrameType::Ping, FlagNone, ConnectionStreamId, Payload));
        }

        /**
         * @brief 发送 GOAWAY
         * @param LastStreamId 最后处理的流 ID
         * @param ErrorCode 错误码
         */
        void SendGoaway(std::uint32_t LastStreamId, std::uint32_t ErrorCode)
        {
            GoawayParams params;
            params.LastStreamId = LastStreamId;
            params.ErrorCode = ErrorCode;
            auto Payload = EncodeGoaway(params);
            TxQueue_.push_back(BuildFrame(FrameType::Goaway, FlagNone, ConnectionStreamId, Payload));
        }

    private:
        /// 流状态（简化）
        struct StreamState
        {
            bool LocalClosed{false}; ///< 本端已 END_STREAM
            bool RemoteClosed{false}; ///< 对端已 END_STREAM
            std::vector<std::byte> RxPending; ///< 未交付的接收缓冲（DATA 累积）
        };

        net::any_io_executor Ex_;
        bool IsServer_{false};
        std::vector<std::byte> RxBuffer_;                       ///< 接收缓冲（跨帧累积）
        std::deque<std::vector<std::byte>> TxQueue_;            ///< 发送队列
        std::map<std::int32_t, StreamState> Streams_;           ///< 流表
        HpackEncoder Encoder_;                                  ///< HPACK 编码器
        HpackDecoder Decoder_;                                  ///< HPACK 解码器
        std::int32_t NextClientId_{1};                         ///< 客户端流 ID（奇数）
        std::int32_t NextServerId_{2};                         ///< 服务端流 ID（偶数）
        std::uint32_t LastRxStream_{0};                        ///< 最近收到的流 ID

        /**
         * @brief 分发帧
         * @param h 帧头
         * @param payload 载荷
         * @param ec 错误码输出
         * @return 处理成功
         */
        auto DispatchFrame(const FrameHeader &H, std::span<const std::byte> Payload, std::error_code &ec)
            -> bool
        {
            switch (H.Type)
            {
            case FrameType::Data:
                return OnDataFrame(H, Payload, ec);
            case FrameType::Headers:
                return OnHeadersFrame(H, Payload, ec);
            case FrameType::Settings:
                return OnSettingsFrame(H, Payload, ec);
            case FrameType::Ping:
                return OnPingFrame(H, Payload, ec);
            case FrameType::Goaway:
                if (Payload.size() < 8)
                {
                    ec = make_error_code(Error::BadLength);
                    return false; // RFC 7540 §6.8：GOAWAY 载荷至少 8 字节
                }
                if (OnGoaway)
                {
                    GoawayParams params;
                    params.LastStreamId = DecodeU31(Payload.first<4>());
                    params.ErrorCode = DecodeU31(Payload.last<4>());
                    OnGoaway(params);
                }
                return true;
            case FrameType::WindowUpdate:
                return true; // 不实现流控，忽略
            case FrameType::RstStream:
                OnStreamCloseIf(H.StreamId, ErrorCancel);
                return true;
            case FrameType::Priority:
                return true; // 忽略
            case FrameType::Continuation:
                ec = make_error_code(Error::ProtocolError);
                return false; // 不支持 CONTINUATION
            case FrameType::PushPromise:
                ec = make_error_code(Error::ProtocolError);
                return false;
            default:
                ec = make_error_code(Error::ProtocolError);
                return false;
            }
        }

        /// 收到 DATA
        auto OnDataFrame(const FrameHeader &H, std::span<const std::byte> Payload, std::error_code &ec)
            -> bool
        {
            if (H.StreamId == ConnectionStreamId)
            {
                ec = make_error_code(Error::ProtocolError);
                return false;
            }
            std::size_t Offset = 0;
            std::span<const std::byte> Data = Payload;
            if ((H.Flags & FlagPadded) != 0)
            {
                if (Payload.empty())
                {
                    ec = make_error_code(Error::ProtocolError);
                    return false;
                }
                const auto Pad = std::to_integer<std::uint8_t>(Payload[0]);
                if (Pad + 1 > Payload.size())
                {
                    ec = make_error_code(Error::ProtocolError);
                    return false;
                }
                Offset = 1;
                Data = Payload.subspan(1, Payload.size() - 1 - Pad);
            }
            if (OnData)
            {
                OnData(H.StreamId, Data);
            }
            if ((H.Flags & FlagEndStream) != 0)
            {
                OnStreamCloseIf(H.StreamId, ErrorNoError);
            }
            return true;
        }

        /// 收到 HEADERS
        auto OnHeadersFrame(const FrameHeader &H, std::span<const std::byte> Payload, std::error_code &ec)
            -> bool
        {
            if (H.StreamId == ConnectionStreamId)
            {
                ec = make_error_code(Error::ProtocolError);
                return false;
            }
            std::size_t Offset = 0;
            if ((H.Flags & FlagPadded) != 0)
            {
                if (Payload.empty())
                {
                    ec = make_error_code(Error::ProtocolError);
                    return false;
                }
                Offset = 1 + std::to_integer<std::uint8_t>(Payload[0]);
                if (Offset > Payload.size())
                {
                    ec = make_error_code(Error::ProtocolError);
                    return false;
                }
            }
            if ((H.Flags & FlagPriority) != 0)
            {
                Offset += 5;
                if (Offset > Payload.size())
                {
                    ec = make_error_code(Error::ProtocolError);
                    return false;
                }
            }
            auto Headers = Decoder_.Decode(Payload.subspan(Offset));
            if (!Headers)
            {
                ec = make_error_code(Error::BadMessage);
                return false;
            }
            const auto EndStream = (H.Flags & FlagEndStream) != 0;
            if (OnHeaders)
            {
                OnHeaders(H.StreamId, *Headers, EndStream);
            }
            if (EndStream)
            {
                OnStreamCloseIf(H.StreamId, ErrorNoError);
            }
            return true;
        }

        /// 收到 SETTINGS
        auto OnSettingsFrame(const FrameHeader &H, std::span<const std::byte> Payload, std::error_code &ec)
            -> bool
        {
            if (H.StreamId != ConnectionStreamId)
            {
                ec = make_error_code(Error::ProtocolError);
                return false;
            }
            if ((H.Flags & FlagAck) != 0)
            {
                return true; // ACK 确认，忽略
            }
            auto Entries = DecodeSettings(Payload);
            if (!Entries)
            {
                ec = make_error_code(Error::BadMessage);
                return false;
            }
            if (OnSettings)
            {
                OnSettings(*Entries);
            }
            // 自动回复 ACK
            TxQueue_.push_back(BuildFrame(FrameType::Settings, FlagAck, ConnectionStreamId, {}));
            return true;
        }

        /// 收到 PING
        auto OnPingFrame(const FrameHeader &H, std::span<const std::byte> Payload, std::error_code &ec)
            -> bool
        {
            if (H.StreamId != ConnectionStreamId || Payload.size() != 8)
            {
                ec = make_error_code(Error::ProtocolError);
                return false;
            }
            if ((H.Flags & FlagAck) == 0)
            {
                // 自动回复 ACK
                std::vector<std::byte> ack(Payload.begin(), Payload.end());
                TxQueue_.push_back(BuildFrame(FrameType::Ping, FlagAck, ConnectionStreamId, ack));
            }
            return true;
        }

        /// 流关闭回调（幂等）
        void OnStreamCloseIf(std::int32_t StreamId, std::uint32_t ErrorCode)
        {
            const auto It = Streams_.find(StreamId);
            if (It != Streams_.end())
            {
                Streams_.erase(It);
            }
            if (OnStreamClose)
            {
                OnStreamClose(StreamId, ErrorCode);
            }
        }

        /// 提交 HEADERS 帧（HPACK 编码）
        void SubmitHeadersFrame(std::int32_t StreamId, const HeaderList &Headers, bool EndStream)
        {
            auto Block = Encoder_.Encode(Headers);
            std::uint8_t Flags = FlagEndHeaders;
            if (EndStream)
            {
                Flags |= FlagEndStream;
            }
            TxQueue_.push_back(BuildFrame(FrameType::Headers, Flags, StreamId, Block));
        }

        /// 分配客户端流 ID（奇数递增）
        [[nodiscard]] auto NextClientStreamId() -> std::int32_t
        {
            if (NextClientId_ > 0x7FFFFFFF - 2)
            {
                return -1;
            }
            const auto Id = NextClientId_;
            NextClientId_ += 2;
            Streams_[Id] = {};
            return Id;
        }

    public:
        /// 收到 SETTINGS 回调
        std::function<void(const std::vector<SettingsEntry> &)> OnSettings;
        /// 收到 GOAWAY 回调
        std::function<void(const GoawayParams &)> OnGoaway;
    };

} // namespace Preview::Http2

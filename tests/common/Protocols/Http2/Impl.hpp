/**
 * @file impl.hpp
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
     *          事件经 on_headers/on_data/on_stream_close 回调发布。
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
            : ex_(std::move(ex)), IsServer_(IsServer)
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
                const auto h = ParseFrameHeader(std::span<const std::byte>(RxBuffer_.data(), RxBuffer_.size()));
                if (!h)
                {
                    ec = make_error_code(Error::need_more);
                    return false;
                }
                if (RxBuffer_.size() < FrameHeaderSize + h->length)
                {
                    break; // 帧未完整
                }
                const auto payload = std::span<const std::byte>(
                    RxBuffer_.data() + FrameHeaderSize, h->length);
                const auto r = DispatchFrame(*h, payload, ec);
                RxBuffer_.erase(RxBuffer_.begin(),
                                 RxBuffer_.begin() + static_cast<std::ptrdiff_t>(FrameHeaderSize + h->length));
                if (!r)
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
            const auto had = !TxQueue_.empty();
            while (!TxQueue_.empty())
            {
                auto &f = TxQueue_.front();
                out.insert(out.end(), f.begin(), f.end());
                TxQueue_.pop_front();
            }
            return had;
        }

        /**
         * @brief 打开新流（客户端视角）
         * @param headers 初始头（伪头 + 普通头）
         * @param EndStream 是否立即结束流
         * @return 流 ID；<0 失败
         */
        [[nodiscard]] auto OpenStream(const HeaderList &headers, bool EndStream) -> std::int32_t override
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
            SubmitHeadersFrame(Id, headers, EndStream);
            return Id;
        }

        /**
         * @brief 提交头到已开流
         * @param StreamId 流 ID
         * @param headers 头列表
         * @param EndStream 是否结束流
         * @return 成功返回 0
         */
        [[nodiscard]] auto SubmitHeaders(std::int32_t StreamId, const HeaderList &headers,
                                          bool EndStream) -> std::int32_t override
        {
            SubmitHeadersFrame(StreamId, headers, EndStream);
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
            std::vector<std::byte> payload(Data.begin(), Data.end());
            std::uint8_t Flags = 0;
            if (EndStream)
            {
                Flags |= flag_end_stream;
            }
            TxQueue_.push_back(BuildFrame(FrameType::Data, Flags, StreamId, payload));
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
            auto payload = EncodeRstStream(ErrorCode);
            TxQueue_.push_back(BuildFrame(FrameType::rst_stream, flag_none, StreamId, payload));
            streams_.erase(StreamId);
            return 0;
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto Executor() const -> net::any_io_executor override
        {
            return ex_;
        }

        /**
         * @brief 发送 SETTINGS（客户端握手时调用）
         * @param entries 参数列表
         */
        void SendSettings(std::span<const SettingsEntry> entries = {})
        {
            auto payload = EncodeSettings(entries);
            TxQueue_.push_back(BuildFrame(FrameType::settings, flag_none, ConnectionStreamId, payload));
        }

        /**
         * @brief 发送 PING
         * @param opaque 8 字节载荷
         */
        void SendPing(std::span<const std::byte, 8> opaque)
        {
            std::vector<std::byte> payload(opaque.begin(), opaque.end());
            TxQueue_.push_back(BuildFrame(FrameType::ping, flag_none, ConnectionStreamId, payload));
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
            auto payload = EncodeGoaway(params);
            TxQueue_.push_back(BuildFrame(FrameType::goaway, flag_none, ConnectionStreamId, payload));
        }

    private:
        /// 流状态（简化）
        struct StreamState
        {
            bool LocalClosed{false}; ///< 本端已 END_STREAM
            bool RemoteClosed{false}; ///< 对端已 END_STREAM
            std::vector<std::byte> RxPending; ///< 未交付的接收缓冲（DATA 累积）
        };

        net::any_io_executor ex_;
        bool IsServer_{false};
        std::vector<std::byte> RxBuffer_;                       ///< 接收缓冲（跨帧累积）
        std::deque<std::vector<std::byte>> TxQueue_;            ///< 发送队列
        std::map<std::int32_t, StreamState> streams_;           ///< 流表
        HpackEncoder encoder_;                                  ///< HPACK 编码器
        HpackDecoder decoder_;                                  ///< HPACK 解码器
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
        auto DispatchFrame(const FrameHeader &h, std::span<const std::byte> payload, std::error_code &ec)
            -> bool
        {
            switch (h.Type)
            {
            case FrameType::Data:
                return OnDataFrame(h, payload, ec);
            case FrameType::headers:
                return OnHeadersFrame(h, payload, ec);
            case FrameType::settings:
                return OnSettingsFrame(h, payload, ec);
            case FrameType::ping:
                return OnPingFrame(h, payload, ec);
            case FrameType::goaway:
                if (on_goaway)
                {
                    GoawayParams params;
                    params.LastStreamId = DecodeU31(payload.first<4>());
                    params.ErrorCode = DecodeU31(payload.last<4>());
                    on_goaway(params);
                }
                return true;
            case FrameType::window_update:
                return true; // 不实现流控，忽略
            case FrameType::rst_stream:
                OnStreamCloseIf(h.StreamId, ErrorCancel);
                return true;
            case FrameType::priority:
                return true; // 忽略
            case FrameType::continuation:
                ec = make_error_code(Error::protocol_error);
                return false; // 不支持 CONTINUATION
            case FrameType::push_promise:
                ec = make_error_code(Error::protocol_error);
                return false;
            default:
                ec = make_error_code(Error::protocol_error);
                return false;
            }
        }

        /// 收到 DATA
        auto OnDataFrame(const FrameHeader &h, std::span<const std::byte> payload, std::error_code &ec)
            -> bool
        {
            if (h.StreamId == ConnectionStreamId)
            {
                ec = make_error_code(Error::protocol_error);
                return false;
            }
            std::size_t offset = 0;
            std::span<const std::byte> Data = payload;
            if ((h.Flags & flag_padded) != 0)
            {
                if (payload.empty())
                {
                    ec = make_error_code(Error::protocol_error);
                    return false;
                }
                const auto pad = std::to_integer<std::uint8_t>(payload[0]);
                if (pad + 1 > payload.size())
                {
                    ec = make_error_code(Error::protocol_error);
                    return false;
                }
                offset = 1;
                Data = payload.subspan(1, payload.size() - 1 - pad);
            }
            if (on_data)
            {
                on_data(h.StreamId, Data);
            }
            if ((h.Flags & flag_end_stream) != 0)
            {
                OnStreamCloseIf(h.StreamId, ErrorNoError);
            }
            return true;
        }

        /// 收到 HEADERS
        auto OnHeadersFrame(const FrameHeader &h, std::span<const std::byte> payload, std::error_code &ec)
            -> bool
        {
            if (h.StreamId == ConnectionStreamId)
            {
                ec = make_error_code(Error::protocol_error);
                return false;
            }
            std::size_t offset = 0;
            if ((h.Flags & flag_padded) != 0)
            {
                if (payload.empty())
                {
                    ec = make_error_code(Error::protocol_error);
                    return false;
                }
                offset = 1 + std::to_integer<std::uint8_t>(payload[0]);
                if (offset > payload.size())
                {
                    ec = make_error_code(Error::protocol_error);
                    return false;
                }
            }
            if ((h.Flags & flag_priority) != 0)
            {
                offset += 5;
                if (offset > payload.size())
                {
                    ec = make_error_code(Error::protocol_error);
                    return false;
                }
            }
            auto headers = decoder_.Decode(payload.subspan(offset));
            if (!headers)
            {
                ec = make_error_code(Error::bad_message);
                return false;
            }
            const auto EndStream = (h.Flags & flag_end_stream) != 0;
            if (on_headers)
            {
                on_headers(h.StreamId, *headers, EndStream);
            }
            if (EndStream)
            {
                OnStreamCloseIf(h.StreamId, ErrorNoError);
            }
            return true;
        }

        /// 收到 SETTINGS
        auto OnSettingsFrame(const FrameHeader &h, std::span<const std::byte> payload, std::error_code &ec)
            -> bool
        {
            if (h.StreamId != ConnectionStreamId)
            {
                ec = make_error_code(Error::protocol_error);
                return false;
            }
            if ((h.Flags & flag_ack) != 0)
            {
                return true; // ACK 确认，忽略
            }
            auto entries = DecodeSettings(payload);
            if (!entries)
            {
                ec = make_error_code(Error::bad_message);
                return false;
            }
            if (on_settings)
            {
                on_settings(*entries);
            }
            // 自动回复 ACK
            TxQueue_.push_back(BuildFrame(FrameType::settings, flag_ack, ConnectionStreamId, {}));
            return true;
        }

        /// 收到 PING
        auto OnPingFrame(const FrameHeader &h, std::span<const std::byte> payload, std::error_code &ec)
            -> bool
        {
            if (h.StreamId != ConnectionStreamId || payload.size() != 8)
            {
                ec = make_error_code(Error::protocol_error);
                return false;
            }
            if ((h.Flags & flag_ack) == 0)
            {
                // 自动回复 ACK
                std::vector<std::byte> ack(payload.begin(), payload.end());
                TxQueue_.push_back(BuildFrame(FrameType::ping, flag_ack, ConnectionStreamId, ack));
            }
            return true;
        }

        /// 流关闭回调（幂等）
        void OnStreamCloseIf(std::int32_t StreamId, std::uint32_t ErrorCode)
        {
            const auto it = streams_.find(StreamId);
            if (it != streams_.end())
            {
                streams_.erase(it);
            }
            if (on_stream_close)
            {
                on_stream_close(StreamId, ErrorCode);
            }
        }

        /// 提交 HEADERS 帧（HPACK 编码）
        void SubmitHeadersFrame(std::int32_t StreamId, const HeaderList &headers, bool EndStream)
        {
            auto block = encoder_.Encode(headers);
            std::uint8_t Flags = flag_end_headers;
            if (EndStream)
            {
                Flags |= flag_end_stream;
            }
            TxQueue_.push_back(BuildFrame(FrameType::headers, Flags, StreamId, block));
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
            streams_[Id] = {};
            return Id;
        }

    public:
        /// 收到 SETTINGS 回调
        std::function<void(const std::vector<SettingsEntry> &)> on_settings;
        /// 收到 GOAWAY 回调
        std::function<void(const GoawayParams &)> on_goaway;
    };

} // namespace Preview::Http2

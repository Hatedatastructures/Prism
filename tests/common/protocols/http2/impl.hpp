/**
 * @file impl.hpp
 * @brief HTTP/2 会话实现（自包含，不依赖 nghttp2）
 * @details 实现 h2_session 接口：
 *          - feed：字节流 → 帧解析 → 状态机分发（事件回调）
 *          - collect：发送队列 → 待发字节
 *          - 流状态机：idle/open/half-closed/closed（简化：追踪本地关闭）
 *          - HPACK：codec.hpp 静态表 + 动态表
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

#include <common/core/error.hpp>
#include <common/protocols/http2/codec.hpp>
#include <common/protocols/http2/frame.hpp>
#include <common/protocols/http2/session.hpp>

namespace preview::http2
{

    namespace net = boost::asio;

    /**
     * @class session_impl
     * @brief HTTP/2 会话实现
     * @details 自包含 h2 会话：帧编解码 + 流管理 + HPACK。
     *          事件经 on_headers/on_data/on_stream_close 回调发布。
     */
    class session_impl final : public h2_session
    {
    public:
        /**
         * @brief 构造
         * @param ex 执行器
         * @param is_server 服务端视角（流 ID 奇偶：server 偶数）
         */
        explicit session_impl(net::any_io_executor ex, bool is_server)
            : ex_(std::move(ex)), is_server_(is_server)
        {
        }

        /**
         * @brief 投喂流数据（帧解析 + 状态机分发）
         * @param data 收到的字节流
         * @param ec 错误码输出
         * @return 处理是否成功
         */
        [[nodiscard]] auto feed(std::span<const std::byte> data, std::error_code &ec) -> bool override
        {
            rx_buffer_.insert(rx_buffer_.end(), data.begin(), data.end());
            while (rx_buffer_.size() >= frame_header_size)
            {
                const auto h = parse_frame_header(std::span<const std::byte>(rx_buffer_.data(), rx_buffer_.size()));
                if (!h)
                {
                    ec = make_error_code(error::need_more);
                    return false;
                }
                if (rx_buffer_.size() < frame_header_size + h->length)
                {
                    break; // 帧未完整
                }
                const auto payload = std::span<const std::byte>(
                    rx_buffer_.data() + frame_header_size, h->length);
                const auto r = dispatch_frame(*h, payload, ec);
                rx_buffer_.erase(rx_buffer_.begin(),
                                 rx_buffer_.begin() + static_cast<std::ptrdiff_t>(frame_header_size + h->length));
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
        [[nodiscard]] auto collect(std::vector<std::byte> &out) -> bool override
        {
            const auto had = !tx_queue_.empty();
            while (!tx_queue_.empty())
            {
                auto &f = tx_queue_.front();
                out.insert(out.end(), f.begin(), f.end());
                tx_queue_.pop_front();
            }
            return had;
        }

        /**
         * @brief 打开新流（客户端视角）
         * @param headers 初始头（伪头 + 普通头）
         * @param end_stream 是否立即结束流
         * @return 流 ID；<0 失败
         */
        [[nodiscard]] auto open_stream(const header_list &headers, bool end_stream) -> std::int32_t override
        {
            if (is_server_)
            {
                return -1; // 服务端不能主动开流
            }
            const auto id = next_client_stream_id();
            if (id < 0)
            {
                return -1;
            }
            submit_headers_frame(id, headers, end_stream);
            return id;
        }

        /**
         * @brief 提交头到已开流
         * @param stream_id 流 ID
         * @param headers 头列表
         * @param end_stream 是否结束流
         * @return 成功返回 0
         */
        [[nodiscard]] auto submit_headers(std::int32_t stream_id, const header_list &headers,
                                          bool end_stream) -> std::int32_t override
        {
            submit_headers_frame(stream_id, headers, end_stream);
            return 0;
        }

        /**
         * @brief 提交数据到流
         * @param stream_id 流 ID
         * @param data 数据载荷
         * @param end_stream 是否结束流
         * @return 成功返回 0
         */
        [[nodiscard]] auto submit_data(std::int32_t stream_id, std::span<const std::byte> data,
                                       bool end_stream) -> std::int32_t override
        {
            std::vector<std::byte> payload(data.begin(), data.end());
            std::uint8_t flags = 0;
            if (end_stream)
            {
                flags |= flag_end_stream;
            }
            tx_queue_.push_back(build_frame(frame_type::data, flags, stream_id, payload));
            return 0;
        }

        /**
         * @brief 重置流（RST_STREAM）
         * @param stream_id 流 ID
         * @param error_code 错误码
         * @return 成功返回 0
         */
        [[nodiscard]] auto reset_stream(std::int32_t stream_id, std::uint32_t error_code)
            -> std::int32_t override
        {
            auto payload = encode_rst_stream(error_code);
            tx_queue_.push_back(build_frame(frame_type::rst_stream, flag_none, stream_id, payload));
            streams_.erase(stream_id);
            return 0;
        }

        /**
         * @brief 获取执行器
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return ex_;
        }

        /**
         * @brief 发送 SETTINGS（客户端握手时调用）
         * @param entries 参数列表
         */
        void send_settings(std::span<const settings_entry> entries = {})
        {
            auto payload = encode_settings(entries);
            tx_queue_.push_back(build_frame(frame_type::settings, flag_none, connection_stream_id, payload));
        }

        /**
         * @brief 发送 PING
         * @param opaque 8 字节载荷
         */
        void send_ping(std::span<const std::byte, 8> opaque)
        {
            std::vector<std::byte> payload(opaque.begin(), opaque.end());
            tx_queue_.push_back(build_frame(frame_type::ping, flag_none, connection_stream_id, payload));
        }

        /**
         * @brief 发送 GOAWAY
         * @param last_stream_id 最后处理的流 ID
         * @param error_code 错误码
         */
        void send_goaway(std::uint32_t last_stream_id, std::uint32_t error_code)
        {
            goaway_params params;
            params.last_stream_id = last_stream_id;
            params.error_code = error_code;
            auto payload = encode_goaway(params);
            tx_queue_.push_back(build_frame(frame_type::goaway, flag_none, connection_stream_id, payload));
        }

    private:
        /// 流状态（简化）
        struct stream_state
        {
            bool local_closed{false}; ///< 本端已 END_STREAM
            bool remote_closed{false}; ///< 对端已 END_STREAM
            std::vector<std::byte> rx_pending; ///< 未交付的接收缓冲（DATA 累积）
        };

        net::any_io_executor ex_;
        bool is_server_{false};
        std::vector<std::byte> rx_buffer_;                       ///< 接收缓冲（跨帧累积）
        std::deque<std::vector<std::byte>> tx_queue_;            ///< 发送队列
        std::map<std::int32_t, stream_state> streams_;           ///< 流表
        hpack_encoder encoder_;                                  ///< HPACK 编码器
        hpack_decoder decoder_;                                  ///< HPACK 解码器
        std::int32_t next_client_id_{1};                         ///< 客户端流 ID（奇数）
        std::int32_t next_server_id_{2};                         ///< 服务端流 ID（偶数）
        std::uint32_t last_rx_stream_{0};                        ///< 最近收到的流 ID

        /**
         * @brief 分发帧
         * @param h 帧头
         * @param payload 载荷
         * @param ec 错误码输出
         * @return 处理成功
         */
        auto dispatch_frame(const frame_header &h, std::span<const std::byte> payload, std::error_code &ec)
            -> bool
        {
            switch (h.type)
            {
            case frame_type::data:
                return on_data_frame(h, payload, ec);
            case frame_type::headers:
                return on_headers_frame(h, payload, ec);
            case frame_type::settings:
                return on_settings_frame(h, payload, ec);
            case frame_type::ping:
                return on_ping_frame(h, payload, ec);
            case frame_type::goaway:
                if (on_goaway)
                {
                    goaway_params params;
                    params.last_stream_id = decode_u31(payload.first<4>());
                    params.error_code = decode_u31(payload.last<4>());
                    on_goaway(params);
                }
                return true;
            case frame_type::window_update:
                return true; // 不实现流控，忽略
            case frame_type::rst_stream:
                on_stream_close_if(h.stream_id, error_cancel);
                return true;
            case frame_type::priority:
                return true; // 忽略
            case frame_type::continuation:
                ec = make_error_code(error::protocol_error);
                return false; // 不支持 CONTINUATION
            case frame_type::push_promise:
                ec = make_error_code(error::protocol_error);
                return false;
            default:
                ec = make_error_code(error::protocol_error);
                return false;
            }
        }

        /// 收到 DATA
        auto on_data_frame(const frame_header &h, std::span<const std::byte> payload, std::error_code &ec)
            -> bool
        {
            if (h.stream_id == connection_stream_id)
            {
                ec = make_error_code(error::protocol_error);
                return false;
            }
            std::size_t offset = 0;
            std::span<const std::byte> data = payload;
            if ((h.flags & flag_padded) != 0)
            {
                if (payload.empty())
                {
                    ec = make_error_code(error::protocol_error);
                    return false;
                }
                const auto pad = std::to_integer<std::uint8_t>(payload[0]);
                if (pad + 1 > payload.size())
                {
                    ec = make_error_code(error::protocol_error);
                    return false;
                }
                offset = 1;
                data = payload.subspan(1, payload.size() - 1 - pad);
            }
            if (on_data)
            {
                on_data(h.stream_id, data);
            }
            if ((h.flags & flag_end_stream) != 0)
            {
                on_stream_close_if(h.stream_id, error_no_error);
            }
            return true;
        }

        /// 收到 HEADERS
        auto on_headers_frame(const frame_header &h, std::span<const std::byte> payload, std::error_code &ec)
            -> bool
        {
            if (h.stream_id == connection_stream_id)
            {
                ec = make_error_code(error::protocol_error);
                return false;
            }
            std::size_t offset = 0;
            if ((h.flags & flag_padded) != 0)
            {
                if (payload.empty())
                {
                    ec = make_error_code(error::protocol_error);
                    return false;
                }
                offset = 1 + std::to_integer<std::uint8_t>(payload[0]);
                if (offset > payload.size())
                {
                    ec = make_error_code(error::protocol_error);
                    return false;
                }
            }
            if ((h.flags & flag_priority) != 0)
            {
                offset += 5;
                if (offset > payload.size())
                {
                    ec = make_error_code(error::protocol_error);
                    return false;
                }
            }
            auto headers = decoder_.decode(payload.subspan(offset));
            if (!headers)
            {
                ec = make_error_code(error::bad_message);
                return false;
            }
            const auto end_stream = (h.flags & flag_end_stream) != 0;
            if (on_headers)
            {
                on_headers(h.stream_id, *headers, end_stream);
            }
            if (end_stream)
            {
                on_stream_close_if(h.stream_id, error_no_error);
            }
            return true;
        }

        /// 收到 SETTINGS
        auto on_settings_frame(const frame_header &h, std::span<const std::byte> payload, std::error_code &ec)
            -> bool
        {
            if (h.stream_id != connection_stream_id)
            {
                ec = make_error_code(error::protocol_error);
                return false;
            }
            if ((h.flags & flag_ack) != 0)
            {
                return true; // ACK 确认，忽略
            }
            auto entries = decode_settings(payload);
            if (!entries)
            {
                ec = make_error_code(error::bad_message);
                return false;
            }
            if (on_settings)
            {
                on_settings(*entries);
            }
            // 自动回复 ACK
            tx_queue_.push_back(build_frame(frame_type::settings, flag_ack, connection_stream_id, {}));
            return true;
        }

        /// 收到 PING
        auto on_ping_frame(const frame_header &h, std::span<const std::byte> payload, std::error_code &ec)
            -> bool
        {
            if (h.stream_id != connection_stream_id || payload.size() != 8)
            {
                ec = make_error_code(error::protocol_error);
                return false;
            }
            if ((h.flags & flag_ack) == 0)
            {
                // 自动回复 ACK
                std::vector<std::byte> ack(payload.begin(), payload.end());
                tx_queue_.push_back(build_frame(frame_type::ping, flag_ack, connection_stream_id, ack));
            }
            return true;
        }

        /// 流关闭回调（幂等）
        void on_stream_close_if(std::int32_t stream_id, std::uint32_t error_code)
        {
            const auto it = streams_.find(stream_id);
            if (it != streams_.end())
            {
                streams_.erase(it);
            }
            if (on_stream_close)
            {
                on_stream_close(stream_id, error_code);
            }
        }

        /// 提交 HEADERS 帧（HPACK 编码）
        void submit_headers_frame(std::int32_t stream_id, const header_list &headers, bool end_stream)
        {
            auto block = encoder_.encode(headers);
            std::uint8_t flags = flag_end_headers;
            if (end_stream)
            {
                flags |= flag_end_stream;
            }
            tx_queue_.push_back(build_frame(frame_type::headers, flags, stream_id, block));
        }

        /// 分配客户端流 ID（奇数递增）
        [[nodiscard]] auto next_client_stream_id() -> std::int32_t
        {
            if (next_client_id_ > 0x7FFFFFFF - 2)
            {
                return -1;
            }
            const auto id = next_client_id_;
            next_client_id_ += 2;
            streams_[id] = {};
            return id;
        }

    public:
        /// 收到 SETTINGS 回调
        std::function<void(const std::vector<settings_entry> &)> on_settings;
        /// 收到 GOAWAY 回调
        std::function<void(const goaway_params &)> on_goaway;
    };

} // namespace preview::http2

/**
 * @file h3_server.hpp
 * @brief Hysteria2 HTTP/3 认证会话（nghttp3 服务端封装）
 * @details 基于 nghttp3（ngtcp2 官方 HTTP/3 帧层 + QPACK 完整实现）封装
 *          服务端认证状态机：
 *          1. 创建 nghttp3 服务端连接 + 服务器控制流/QPACK 流（SETTINGS）
 *          2. 流数据喂入 nghttp3_conn_read_stream2，回调收集认证头字段
 *          3. 认证判定后提交响应（:status 233 + Hysteria 头）
 *          4. writev_stream 收集待发字节由外部写回 QUIC 流
 *          与 quic-go（mihomo 客户端）完整 HTTP/3 栈字节级兼容。
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string_view>

namespace psm::protocol::hysteria2::h3
{

    /**
     * @struct out_packet
     * @brief nghttp3 输出包（目标 QUIC 流 + 待发字节）
     */
    struct out_packet
    {
        std::int64_t stream_id{0};           ///< 目标 QUIC 流
        memory::vector<std::byte> data;      ///< 待发字节
        explicit out_packet(memory::resource_pointer mr) : data(mr) {}
    };

    /**
     * @class server
     * @brief Hysteria2 HTTP/3 认证服务端会话
     * @details 单条 QUIC 连接一个实例；所有 nghttp3 调用必须在同一线程
     *          （quic_gateway 的 io_context 线程）串行执行。
     */
    class server : public std::enable_shared_from_this<server>
    {
    public:
        explicit server(memory::resource_pointer mr);
        ~server() noexcept;

        server(const server &) = delete;
        server &operator=(const server &) = delete;

        /**
         * @brief 初始化：创建 nghttp3 服务端连接 + 服务器控制流/QPACK 流
         * @param open_uni_stream QUIC 层开单向流回调（失败返回 -1）
         * @return 是否成功
         */
        [[nodiscard]] auto init(std::function<std::int64_t()> open_uni_stream) -> bool;

        /**
         * @brief 喂入流数据（QUIC 流 → nghttp3）
         * @param stream_id 流 ID
         * @param data 明文数据
         * @param fin 是否为流末尾
         * @return 协议处理是否成功（失败即连接错误，应断开）
         */
        [[nodiscard]] auto feed(std::int64_t stream_id, std::span<const std::byte> data,
                                bool fin) -> fault::code;

        /**
         * @brief 收集待发数据（nghttp3 → QUIC 流）
         * @param out 输出包集合（写回 QUIC 后调用 add_write_offset 告知消费）
         * @return 是否成功
         */
        [[nodiscard]] auto pump_output(memory::vector<out_packet> &out) -> bool;

        /**
         * @brief 告知 nghttp3 某流已写回字节数（writev_stream 输出消费确认）
         * @param stream_id 流 ID
         * @param len 已写回字节数
         */
        void add_write_offset(std::int64_t stream_id, std::size_t len);

        /// 认证请求头是否已接收完整（end_headers 已触发）
        [[nodiscard]] auto auth_headers_complete() const noexcept -> bool;

        [[nodiscard]] auto method() const noexcept -> std::string_view;
        [[nodiscard]] auto path() const noexcept -> std::string_view;
        [[nodiscard]] auto auth() const noexcept -> std::string_view;
        [[nodiscard]] auto rx() const noexcept -> std::uint64_t;

        /// 认证请求所在流 ID（首个出现 HEADERS 的 bidi 流）
        [[nodiscard]] auto auth_stream_id() const noexcept -> std::int64_t;

        /**
         * @brief 提交认证成功响应（:status 233 + Hysteria-UDP/CC-RX/Padding）
         * @return 是否成功（响应字节随下次 pump_output 输出）
         */
        [[nodiscard]] auto submit_auth_response() -> fault::code;

        /// 释放 nghttp3 连接状态
        void close();

        [[nodiscard]] auto native() const noexcept -> nghttp3_conn *
        {
            return conn_;
        }

    private:
        static auto cb_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                                     void *stream_user_data) -> int;
        static auto cb_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                                   nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                                   void *user_data, void *stream_user_data) -> int;
        static auto cb_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                                   void *user_data, void *stream_user_data) -> int;
        static auto cb_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
                                 size_t datalen, void *user_data,
                                 void *stream_user_data) -> int;
        static auto cb_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                                    uint64_t app_error_code, void *user_data,
                                    void *stream_user_data) -> int;
        static auto cb_end_stream(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                                  void *stream_user_data) -> int;
        static void cb_rand(uint8_t *dest, size_t destlen);

        /// 当前微秒时间戳（ngtcp2/nghttp3 共用）
        [[nodiscard]] static auto now_tstamp() -> std::uint64_t;

        nghttp3_conn *conn_{nullptr};        ///< nghttp3 连接状态
        memory::resource_pointer mr_{};      ///< 内存资源
        std::int64_t ctrl_stream_{-1};       ///< 服务器控制流
        std::int64_t enc_stream_{-1};        ///< 服务器 QPACK encoder 流
        std::int64_t dec_stream_{-1};        ///< 服务器 QPACK decoder 流
        std::int64_t auth_stream_{-1};       ///< 认证请求流
        bool headers_done_{false};           ///< 认证头接收完整
        memory::string method_;              ///< :method
        memory::string path_;                ///< :path
        memory::string auth_;                ///< Hysteria-Auth 头
        std::uint64_t rx_{0};                ///< Hysteria-CC-RX 头
    };

} // namespace psm::protocol::hysteria2::h3

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

#include <common/core/diagnose/log.hpp>

#include <common/core/fault/code.hpp>
#include <common/core/memory/container.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string_view>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>

namespace psm::protocol::hysteria2::h3 {

    /**
     * @struct out_packet
     * @brief nghttp3 输出包（目标 QUIC 流 + 待发字节）
     */
    struct out_packet
    {
        std::int64_t stream_id{0};      ///< 目标 QUIC 流
        memory::vector<std::byte> data; ///< 待发字节
        explicit out_packet(memory::resource_pointer mr) : data(mr)
        {
        }
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
        /**
         * @brief 构造函数
         * @param mr 内存资源
         */
        explicit server(memory::resource_pointer mr);

        /**
         * @brief 析构函数，释放 nghttp3 连接状态
         */
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
        [[nodiscard]] auto feed(std::int64_t stream_id, std::span<const std::byte> data, bool fin)
            -> fault::code;

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

        /**
         * @brief 认证请求头是否已接收完整（end_headers 已触发）
         * @return 是否已接收完整
         */
        [[nodiscard]] auto auth_headers_complete() const noexcept -> bool;

        /** @brief 获取认证请求方法（:method） */
        [[nodiscard]] auto method() const noexcept -> std::string_view;
        /** @brief 获取认证请求路径（:path） */
        [[nodiscard]] auto path() const noexcept -> std::string_view;
        /** @brief 获取认证凭据（Hysteria-Auth 头） */
        [[nodiscard]] auto auth() const noexcept -> std::string_view;
        /** @brief 获取客户端声明的接收速率（Hysteria-CC-RX 头） */
        [[nodiscard]] auto rx() const noexcept -> std::uint64_t;

        /**
         * @brief 认证请求所在流 ID（首个出现 HEADERS 的 bidi 流）
         * @return 认证请求流 ID
         */
        [[nodiscard]] auto auth_stream_id() const noexcept -> std::int64_t;

        /**
         * @brief 提交认证成功响应（:status 233 + Hysteria-UDP/CC-RX/Padding）
         * @return 是否成功（响应字节随下次 pump_output 输出）
         */
        [[nodiscard]] auto submit_auth_response() -> fault::code;

        /**
         * @brief 释放 nghttp3 连接状态
         */
        void close();

        /**
         * @brief 获取底层 nghttp3 连接指针
         * @return nghttp3_conn* 原生连接指针
         */
        [[nodiscard]] auto native() const noexcept -> nghttp3_conn *
        {
            return conn_;
        }

    private:
        /** @brief nghttp3 回调：流开始接收头字段 */
        static auto cb_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                                     void *stream_user_data) -> int;
        /** @brief nghttp3 回调：接收单个头字段 */
        static auto cb_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token, nghttp3_rcbuf *name,
                                   nghttp3_rcbuf *value, uint8_t flags, void *user_data,
                                   void *stream_user_data) -> int;
        /** @brief nghttp3 回调：头字段接收完毕（end_headers） */
        static auto cb_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin, void *user_data,
                                   void *stream_user_data) -> int;
        /** @brief nghttp3 回调：接收请求体数据 */
        static auto cb_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data, size_t datalen,
                                 void *user_data, void *stream_user_data) -> int;
        /** @brief nghttp3 回调：对端停止发送 */
        static auto cb_stop_sending(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
                                    void *user_data, void *stream_user_data) -> int;
        /** @brief nghttp3 回调：流结束（fin） */
        static auto cb_end_stream(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                                  void *stream_user_data) -> int;
        /** @brief nghttp3 随机数回调（密钥材料生成） */
        static void cb_rand(uint8_t *dest, size_t destlen);

        /**
         * 当前微秒时间戳（ngtcp2/nghttp3 共用）
         */
        [[nodiscard]] static auto now_tstamp() -> std::uint64_t;

        nghttp3_conn *conn_{nullptr};   ///< nghttp3 连接状态
        memory::resource_pointer mr_{}; ///< 内存资源
        std::int64_t ctrl_stream_{-1};  ///< 服务器控制流
        std::int64_t enc_stream_{-1};   ///< 服务器 QPACK encoder 流
        std::int64_t dec_stream_{-1};   ///< 服务器 QPACK decoder 流
        std::int64_t auth_stream_{-1};  ///< 认证请求流
        bool headers_done_{false};      ///< 认证头接收完整
        memory::string method_;         ///< :method
        memory::string path_;           ///< :path
        memory::string auth_;           ///< Hysteria-Auth 头
        std::uint64_t rx_{0};           ///< Hysteria-CC-RX 头
    };



    namespace
    {
        /**
         * @brief 从 rcbuf 取字节视图
         * @param rc nghttp3 接收缓冲区
         * @return 缓冲区字节视图
         */
        [[nodiscard]] auto rcbuf_view(nghttp3_rcbuf *rc) -> std::string_view
        {
            const auto buf = nghttp3_rcbuf_get_buf(rc);
            return std::string_view(reinterpret_cast<const char *>(buf.base), buf.len);
        }
    } // namespace

    inline server::server(const memory::resource_pointer mr) : mr_(mr), method_(mr), path_(mr), auth_(mr)
    {
    }

    inline server::~server() noexcept
    {
        close();
    }

    inline auto server::now_tstamp() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                              std::chrono::steady_clock::now().time_since_epoch())
                                              .count());
    }

    inline auto server::init(std::function<std::int64_t()> open_uni_stream) -> bool
    {
        if (conn_)
        {
            return true;
        }

        nghttp3_callbacks callbacks{};
        callbacks.begin_headers = cb_begin_headers;
        callbacks.recv_header = cb_recv_header;
        callbacks.end_headers = cb_end_headers;
        callbacks.recv_data = cb_recv_data;
        callbacks.stop_sending = cb_stop_sending;
        callbacks.end_stream = cb_end_stream;
        callbacks.rand = cb_rand;

        nghttp3_settings settings{};
        nghttp3_settings_default_versioned(NGHTTP3_SETTINGS_VERSION, &settings);

        const auto rv = nghttp3_conn_server_new_versioned(&conn_, NGHTTP3_CALLBACKS_VERSION, &callbacks,
                                                          NGHTTP3_SETTINGS_VERSION, &settings,
                                                          nghttp3_mem_default(), this);
        if (rv != 0)
        {
            conn_ = nullptr;
            diagnose::warn("hysteria2: nghttp3_conn_server_new failed: {}", nghttp3_strerror(rv));
            return false;
        }

        // 服务器控制流（SETTINGS）+ QPACK encoder/decoder 流
        ctrl_stream_ = open_uni_stream();
        enc_stream_ = open_uni_stream();
        dec_stream_ = open_uni_stream();
        if (ctrl_stream_ < 0 || enc_stream_ < 0 || dec_stream_ < 0)
        {
            close();
            diagnose::warn("hysteria2: cannot open h3 control streams");
            return false;
        }

        if (nghttp3_conn_bind_control_stream(conn_, ctrl_stream_) != 0 ||
            nghttp3_conn_bind_qpack_streams(conn_, enc_stream_, dec_stream_) != 0)
        {
            close();
            diagnose::warn("hysteria2: cannot bind h3 control streams");
            return false;
        }
        return true;
    }

    inline auto server::feed(const std::int64_t stream_id, const std::span<const std::byte> data, const bool fin)
        -> fault::code
    {
        if (!conn_)
        {
            return fault::code::protocol_error;
        }

        const auto rc =
            nghttp3_conn_read_stream2(conn_, stream_id, reinterpret_cast<const uint8_t *>(data.data()),
                                      data.size(), fin ? 1 : 0, now_tstamp());
        if (rc < 0)
        {
            diagnose::warn("hysteria2: nghttp3 read_stream failed: {}",
                           nghttp3_strerror(static_cast<int>(rc)));
            return fault::code::protocol_error;
        }
        return fault::code::success;
    }

    inline auto server::pump_output(memory::vector<out_packet> &out) -> bool
    {
        if (!conn_)
        {
            return false;
        }

        std::array<nghttp3_vec, 16> vecs{};
        std::array<std::array<std::byte, 4096>, 16> bufs{};

        for (;;)
        {
            std::int64_t stream_id = -1;
            int fin = 0;
            for (std::size_t i = 0; i < vecs.size(); ++i)
            {
                vecs[i].base = reinterpret_cast<uint8_t *>(bufs[i].data());
                vecs[i].len = bufs[i].size();
            }

            nghttp3_ssize sveccnt =
                nghttp3_conn_writev_stream(conn_, &stream_id, &fin, vecs.data(), vecs.size());
            if (sveccnt < 0)
            {
                diagnose::warn("hysteria2: nghttp3 writev_stream failed: {}",
                               nghttp3_strerror(static_cast<int>(sveccnt)));
                return false;
            }
            if (sveccnt == 0)
            {
                break;
            }

            // 输出字节复制到 out 缓冲（应用保证写回 QUIC），立即告知 nghttp3 消费，
            // 否则下次 writev_stream 返回相同数据导致死循环
            out_packet pkt(mr_);
            pkt.stream_id = stream_id;
            for (nghttp3_ssize i = 0; i < sveccnt; ++i)
            {
                pkt.data.insert(pkt.data.end(), reinterpret_cast<const std::byte *>(vecs[i].base),
                                reinterpret_cast<const std::byte *>(vecs[i].base) + vecs[i].len);
            }
            const auto nwritten = pkt.data.size();
            out.push_back(std::move(pkt));
            nghttp3_conn_add_write_offset(conn_, stream_id, nwritten);

            if (fin)
            {
                nghttp3_conn_shutdown_stream_write(conn_, stream_id);
            }
        }
        return true;
    }

    inline void server::add_write_offset(const std::int64_t stream_id, const std::size_t len)
    {
        if (conn_ && len > 0)
        {
            nghttp3_conn_add_write_offset(conn_, stream_id, len);
        }
    }

    inline auto server::auth_headers_complete() const noexcept -> bool
    {
        return headers_done_;
    }

    inline auto server::method() const noexcept -> std::string_view
    {
        return std::string_view(method_.data(), method_.size());
    }

    inline auto server::path() const noexcept -> std::string_view
    {
        return std::string_view(path_.data(), path_.size());
    }

    inline auto server::auth() const noexcept -> std::string_view
    {
        return std::string_view(auth_.data(), auth_.size());
    }

    inline auto server::rx() const noexcept -> std::uint64_t
    {
        return rx_;
    }

    inline auto server::auth_stream_id() const noexcept -> std::int64_t
    {
        return auth_stream_;
    }

    inline auto server::submit_auth_response() -> fault::code
    {
        if (!conn_ || auth_stream_ < 0)
        {
            return fault::code::protocol_error;
        }

        std::array<nghttp3_nv, 4> nva{};
        std::size_t n = 0;
        nva[n++] = nghttp3_nv{reinterpret_cast<const uint8_t *>(":status"),
                              reinterpret_cast<const uint8_t *>("233"), 7, 3, NGHTTP3_NV_FLAG_NONE};
        nva[n++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-udp"),
                              reinterpret_cast<const uint8_t *>("true"), 12, 4, NGHTTP3_NV_FLAG_NONE};
        nva[n++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-cc-rx"),
                              reinterpret_cast<const uint8_t *>("0"), 13, 1, NGHTTP3_NV_FLAG_NONE};
        nva[n++] = nghttp3_nv{reinterpret_cast<const uint8_t *>("hysteria-padding"),
                              reinterpret_cast<const uint8_t *>("0"), 15, 1, NGHTTP3_NV_FLAG_NONE};

        const auto rv = nghttp3_conn_submit_response(conn_, auth_stream_, nva.data(), n, nullptr);
        if (rv != 0)
        {
            diagnose::warn("hysteria2: nghttp3 submit_response failed: {}", nghttp3_strerror(rv));
            return fault::code::protocol_error;
        }
        return fault::code::success;
    }

    inline void server::close()
    {
        if (conn_)
        {
            nghttp3_conn_del(conn_);
            conn_ = nullptr;
        }
    }

    inline auto server::cb_begin_headers(nghttp3_conn *conn, const int64_t stream_id, void *user_data,
                                  void *stream_user_data) -> int
    {
        (void)conn;
        (void)stream_user_data;
        auto *self = static_cast<server *>(user_data);
        if (self->auth_stream_ < 0)
        {
            self->auth_stream_ = stream_id;
        }
        return 0;
    }

    inline auto server::cb_recv_header(nghttp3_conn *conn, const int64_t stream_id, const int32_t token,
                                nghttp3_rcbuf *name, nghttp3_rcbuf *value, const uint8_t flags,
                                void *user_data, void *stream_user_data) -> int
    {
        (void)conn;
        (void)flags;
        (void)stream_user_data;
        auto *self = static_cast<server *>(user_data);
        if (self->auth_stream_ < 0 || stream_id != self->auth_stream_)
        {
            return 0;
        }

        const auto v = rcbuf_view(value);
        switch (token)
        {
        case NGHTTP3_QPACK_TOKEN__METHOD: self->method_.assign(v.data(), v.size()); return 0;
        case NGHTTP3_QPACK_TOKEN__PATH: self->path_.assign(v.data(), v.size()); return 0;
        default: break;
        }

        const auto nm = rcbuf_view(name);
        if (nm == "hysteria-auth")
        {
            self->auth_.assign(v.data(), v.size());
        }
        else if (nm == "hysteria-cc-rx")
        {
            std::from_chars(v.data(), v.data() + v.size(), self->rx_);
        }
        return 0;
    }

    inline auto server::cb_end_headers(nghttp3_conn *conn, const int64_t stream_id, const int fin, void *user_data,
                                void *stream_user_data) -> int
    {
        (void)conn;
        (void)fin;
        (void)stream_user_data;
        auto *self = static_cast<server *>(user_data);
        if (stream_id == self->auth_stream_)
        {
            self->headers_done_ = true;
        }
        return 0;
    }

    inline auto server::cb_recv_data(nghttp3_conn *conn, const int64_t stream_id, const uint8_t *data,
                              const size_t datalen, void *user_data, void *stream_user_data) -> int
    {
        (void)conn;
        (void)stream_id;
        (void)data;
        (void)datalen;
        (void)user_data;
        (void)stream_user_data;
        return 0;
    }

    inline auto server::cb_stop_sending(nghttp3_conn *conn, const int64_t stream_id, const uint64_t app_error_code,
                                 void *user_data, void *stream_user_data) -> int
    {
        (void)conn;
        (void)stream_id;
        (void)app_error_code;
        (void)user_data;
        (void)stream_user_data;
        return 0;
    }

    inline auto server::cb_end_stream(nghttp3_conn *conn, const int64_t stream_id, void *user_data,
                               void *stream_user_data) -> int
    {
        (void)conn;
        (void)stream_id;
        (void)user_data;
        (void)stream_user_data;
        return 0;
    }

    inline void server::cb_rand(uint8_t *dest, const size_t destlen)
    {
        for (std::size_t i = 0; i < destlen; ++i)
        {
            dest[i] = static_cast<std::uint8_t>(std::rand());
        }
    }


} // namespace psm::protocol::hysteria2::h3

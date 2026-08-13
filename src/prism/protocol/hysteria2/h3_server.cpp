/**
 * @file h3_server.cpp
 * @brief Hysteria2 HTTP/3 认证会话（nghttp3 服务端封装）实现
 */

#include <prism/diagnose/diagnose.hpp>
#include <prism/protocol/hysteria2/h3_server.hpp>

#include <array>
#include <charconv>
#include <chrono>

#include <nghttp3/nghttp3.h>

using namespace psm::diagnose;

namespace psm::protocol::hysteria2::h3
{

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

    server::server(const memory::resource_pointer mr) : mr_(mr), method_(mr), path_(mr), auth_(mr)
    {
    }

    server::~server() noexcept
    {
        close();
    }

    auto server::now_tstamp() -> std::uint64_t
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                              std::chrono::steady_clock::now().time_since_epoch())
                                              .count());
    }

    auto server::init(std::function<std::int64_t()> open_uni_stream) -> bool
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

    auto server::feed(const std::int64_t stream_id, const std::span<const std::byte> data, const bool fin)
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

    auto server::pump_output(memory::vector<out_packet> &out) -> bool
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

    void server::add_write_offset(const std::int64_t stream_id, const std::size_t len)
    {
        if (conn_ && len > 0)
        {
            nghttp3_conn_add_write_offset(conn_, stream_id, len);
        }
    }

    auto server::auth_headers_complete() const noexcept -> bool
    {
        return headers_done_;
    }

    auto server::method() const noexcept -> std::string_view
    {
        return std::string_view(method_.data(), method_.size());
    }

    auto server::path() const noexcept -> std::string_view
    {
        return std::string_view(path_.data(), path_.size());
    }

    auto server::auth() const noexcept -> std::string_view
    {
        return std::string_view(auth_.data(), auth_.size());
    }

    auto server::rx() const noexcept -> std::uint64_t
    {
        return rx_;
    }

    auto server::auth_stream_id() const noexcept -> std::int64_t
    {
        return auth_stream_;
    }

    auto server::submit_auth_response() -> fault::code
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

    void server::close()
    {
        if (conn_)
        {
            nghttp3_conn_del(conn_);
            conn_ = nullptr;
        }
    }

    auto server::cb_begin_headers(nghttp3_conn *conn, const int64_t stream_id, void *user_data,
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

    auto server::cb_recv_header(nghttp3_conn *conn, const int64_t stream_id, const int32_t token,
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

    auto server::cb_end_headers(nghttp3_conn *conn, const int64_t stream_id, const int fin, void *user_data,
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

    auto server::cb_recv_data(nghttp3_conn *conn, const int64_t stream_id, const uint8_t *data,
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

    auto server::cb_stop_sending(nghttp3_conn *conn, const int64_t stream_id, const uint64_t app_error_code,
                                 void *user_data, void *stream_user_data) -> int
    {
        (void)conn;
        (void)stream_id;
        (void)app_error_code;
        (void)user_data;
        (void)stream_user_data;
        return 0;
    }

    auto server::cb_end_stream(nghttp3_conn *conn, const int64_t stream_id, void *user_data,
                               void *stream_user_data) -> int
    {
        (void)conn;
        (void)stream_id;
        (void)user_data;
        (void)stream_user_data;
        return 0;
    }

    void server::cb_rand(uint8_t *dest, const size_t destlen)
    {
        for (std::size_t i = 0; i < destlen; ++i)
        {
            dest[i] = static_cast<std::uint8_t>(std::rand());
        }
    }

} // namespace psm::protocol::hysteria2::h3

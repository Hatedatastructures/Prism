/**
 * @file session.cpp
 * @brief gRPC (gun) HTTP/2 会话实现
 */

#include <prism/handshake/gun/session.hpp>
#include <prism/handshake/gun/codec.hpp>
#include <prism/diagnose/diagnose.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <cstring>

using namespace psm::diagnose;

namespace psm::handshake::gun
{

    session::session(psm::transport::shared_transmission transport, const config &cfg,
                     const memory::resource_pointer mr,
                     std::shared_ptr<diagnose::context> prefix)
        : transport_(std::move(transport))
        , config_(cfg)
        , mr_(mr)
        , prefix_(std::move(prefix))
        , request_path_(mr_)
        , frame_buf_(mr_)
        , wait_timer_(transport_->executor())
    {
        // 流匹配超时 15 秒：防非匹配客户端长期占用会话（DoS）
        wait_timer_.expires_after(std::chrono::seconds(15));
    }

    session::~session() noexcept
    {
        if (session_)
        {
            nghttp2_session_del(session_);
            session_ = nullptr;
        }
    }

    void session::start()
    {
        active_.store(true, std::memory_order_release);
        auto self = shared_from_this();
        auto task = [self]() -> net::awaitable<void>
        {
            co_await self->frame_loop();
        };
        net::co_spawn(transport_->executor(), std::move(task), [self](const std::exception_ptr &ep)
        {
            if (ep)
            {
                diagnose::debug(self->prefix_, "gun session loop error");
            }
        });
    }

    void session::close()
    {
        if (!active_.exchange(false, std::memory_order_acq_rel))
            return;
        if (transport_)
            transport_->close();
        if (gun_transport_)
            gun_transport_->close();
        wait_timer_.cancel();
    }

    auto session::init_nghttp2() -> std::int32_t
    {
        nghttp2_session_callbacks *callbacks = nullptr;
        if (nghttp2_session_callbacks_new(&callbacks) != 0)
        {
            diagnose::error(prefix_, "gun: failed to create nghttp2 callbacks");
            return -1;
        }

        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, &session::on_begin_headers);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, &session::on_header);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &session::on_frame_recv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &session::on_data);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &session::on_stream_close);

        nghttp2_option *option = nullptr;
        nghttp2_option_new(&option);
        nghttp2_option_set_no_http_messaging(option, 1);

        const std::int32_t rv = nghttp2_session_server_new3(&session_, callbacks, this, option, nullptr);
        if (option)
            nghttp2_option_del(option);
        nghttp2_session_callbacks_del(callbacks);

        if (rv != 0)
        {
            diagnose::error(prefix_, "gun: failed to create nghttp2 session: {}", nghttp2_strerror(rv));
            return -1;
        }

        if (nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0) != 0)
        {
            diagnose::error(prefix_, "gun: failed to submit settings");
            return -1;
        }
        return 0;
    }

    auto session::frame_loop() -> net::awaitable<void>
    {
        if (init_nghttp2() != 0)
        {
            close();
            co_return;
        }
        diagnose::debug(prefix_, "gun: frame loop started");

        memory::vector<std::byte> recv_buf(65536, mr_);
        while (is_active())
        {
            std::error_code read_ec;
            const auto n = co_await transport_->async_read_some(
                std::span<std::byte>(recv_buf.data(), recv_buf.size()), read_ec);
            if (read_ec || n == 0)
            {
                if (read_ec && read_ec != std::errc::operation_canceled)
                {
                    diagnose::debug(prefix_, "gun: transport read closed: {}", read_ec.message());
                }
                break;
            }

            const auto recv_len = nghttp2_session_mem_recv(
                session_, reinterpret_cast<const uint8_t *>(recv_buf.data()), n);
            if (recv_len < 0)
            {
                diagnose::debug(prefix_, "gun: nghttp2 recv error: {}",
                                nghttp2_strerror(static_cast<std::int32_t>(recv_len)));
                break;
            }

            co_await send_pending();
        }

        // 通知等待者结束
        transport_ready_ = true;
        wait_timer_.cancel();
        gun_transport_ = nullptr;
        close();
        diagnose::debug(prefix_, "gun: frame loop ended");
    }

    auto session::send_pending() -> net::awaitable<void>
    {
        while (true)
        {
            const std::uint8_t *data = nullptr;
            const auto len = nghttp2_session_mem_send(session_, &data);
            if (len <= 0)
                break;

            std::error_code write_ec;
            co_await psm::transport::async_write(*transport_,
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(data), len),
                write_ec);
            if (write_ec)
            {
                diagnose::debug(prefix_, "gun: send_pending write failed: {}", write_ec.message());
                break;
            }
        }
    }

    auto session::accept_stream(const std::int32_t stream_id) -> std::int32_t
    {
        // 响应 200 + grpc 头
        const char *status_str = "200";
        const char *content_type = "application/grpc";
        const char *te = "trailers";
        nghttp2_nv hdrs[] = {
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":status")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(status_str)), 7, 3, NGHTTP2_NV_FLAG_NONE},
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("content-type")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(content_type)), 12, 17, NGHTTP2_NV_FLAG_NONE},
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("te")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(te)), 2, 8, NGHTTP2_NV_FLAG_NONE},
        };
        const auto rc = nghttp2_submit_headers(session_, NGHTTP2_FLAG_NONE,
                                               stream_id, nullptr, hdrs, 3, nullptr);
        if (rc != 0)
        {
            diagnose::warn(prefix_, "gun: submit grpc headers failed: {}", nghttp2_strerror(rc));
            return rc;
        }

        matched_stream_ = stream_id;
        stream_accepted_ = true;
        return 0;
    }

    auto session::wait_transport() -> net::awaitable<shared_transport>
    {
        // 事件驱动：transport_ready_ 时 cancel 唤醒（或帧循环结束 cancel）
        boost::system::error_code ec;
        co_await wait_timer_.async_wait(net::redirect_error(net::use_awaitable, ec));

        if (!transport_ready_ || !gun_transport_)
        {
            co_return nullptr;
        }
        co_return gun_transport_;
    }

    auto session::on_begin_headers(nghttp2_session *, const nghttp2_frame *frame, void *user_data) -> int
    {
        auto *self = static_cast<session *>(user_data);
        if (frame->hd.type != NGHTTP2_HEADERS ||
            frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        {
            return 0;
        }
        self->request_path_.clear();
        self->request_is_post_ = false;
        self->request_is_grpc_ = false;
        return 0;
    }

    auto session::on_header(nghttp2_session *, const nghttp2_frame *frame,
                            const uint8_t *name, const size_t namelen,
                            const uint8_t *value, const size_t valuelen,
                            uint8_t, void *user_data) -> int
    {
        auto *self = static_cast<session *>(user_data);
        if (frame->hd.type != NGHTTP2_HEADERS ||
            frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        {
            return 0;
        }

        const std::string_view hname(reinterpret_cast<const char *>(name), namelen);
        const std::string_view hvalue(reinterpret_cast<const char *>(value), valuelen);

        if (hname == ":method")
        {
            self->request_is_post_ = (hvalue == "POST");
        }
        else if (hname == ":path")
        {
            self->request_path_.clear();
            self->request_path_.reserve(hvalue.size());
            for (const auto c : hvalue)
                self->request_path_.push_back(static_cast<std::byte>(c));
        }
        else if (hname == "content-type")
        {
            self->request_is_grpc_ = (hvalue.rfind("application/grpc", 0) == 0);
        }
        return 0;
    }

    auto session::on_frame_recv(nghttp2_session *, const nghttp2_frame *frame, void *user_data) -> int
    {
        auto *self = static_cast<session *>(user_data);
        if (frame->hd.type != NGHTTP2_HEADERS ||
            frame->headers.cat != NGHTTP2_HCAT_REQUEST ||
            self->stream_accepted_)
        {
            return 0;
        }

        // 路径匹配（允许服务名配置）
        const std::string_view path(reinterpret_cast<const char *>(self->request_path_.data()),
                                    self->request_path_.size());
        const std::string_view expected(self->config_.path.data(), self->config_.path.size());
        const bool path_ok = path == expected
            || (!self->config_.service_name.empty() && path == "/" + self->config_.service_name + "/Tun");

        if (!self->request_is_post_ || !self->request_is_grpc_ || !path_ok)
        {
            // 不匹配：RST 该流
            nghttp2_submit_rst_stream(self->session_, NGHTTP2_FLAG_NONE,
                                      frame->hd.stream_id, NGHTTP2_REFUSED_STREAM);
            return 0;
        }

        diagnose::debug(self->prefix_, "gun: matched stream {} path={}", frame->hd.stream_id, path);

        // 建立 gun 传输
        auto self_ptr = self->shared_from_this();
        auto write_fn = [self_ptr, stream_id = frame->hd.stream_id](memory::vector<std::byte> frame)
            -> net::awaitable<void>
        {
            // 提交 DATA 帧（数据源生命周期绑定 pending_data_，防 nghttp2 延迟读取悬垂）
            co_await self_ptr->submit_data_frame(stream_id, std::move(frame));
        };

        auto gun_transport = make_transport(self->transport_->executor(), std::move(write_fn), self->mr_);
        self->gun_transport_ = gun_transport;

        // 响应 200
        if (self->accept_stream(frame->hd.stream_id) == 0)
        {
            self->transport_ready_ = true;
            self->wait_timer_.cancel();
        }
        else
        {
            // accept 失败：唤醒等待者并清理，避免 wait_transport 永久挂起
            self->gun_transport_ = nullptr;
            self->transport_ready_ = true;
            self->wait_timer_.cancel();
        }
        return 0;
    }

    auto session::on_data(nghttp2_session *, uint8_t, const int32_t stream_id,
                          const uint8_t *data, const size_t len, void *user_data) -> int
    {
        auto *self = static_cast<session *>(user_data);
        if (stream_id != self->matched_stream_ || !self->gun_transport_)
        {
            return 0;
        }

        // 累积 gun 帧并解帧
        self->frame_buf_.insert(self->frame_buf_.end(),
                                reinterpret_cast<const std::byte *>(data),
                                reinterpret_cast<const std::byte *>(data) + len);
        if (!self->process_data(self->frame_buf_))
        {
            // 非法帧或通道拥塞：RST 流并终止会话，避免静默丢数据
            nghttp2_submit_rst_stream(self->session_, NGHTTP2_FLAG_NONE,
                                      stream_id, NGHTTP2_INTERNAL_ERROR);
            self->close();
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    auto session::process_data(const std::span<const std::byte> payload) -> bool
    {
        // 以 gun 帧为单位解析，剩余字节留在缓冲
        std::size_t offset = 0;
        while (true)
        {
            if (payload.size() - offset < codec::header_fixed_len)
            {
                // 定长头未齐：等待更多数据
                break;
            }
            codec::frame_header header;
            if (!codec::parse_frame_header(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(payload.data() + offset),
                        payload.size() - offset),
                    header))
            {
                // 定长头已齐但解析失败：varint 未齐则继续等，否则判非法帧
                if (payload.size() - offset < codec::header_fixed_len + codec::max_varint_len)
                {
                    break;
                }
                diagnose::debug(prefix_, "gun: malformed frame header");
                return false;
            }
            if (payload.size() - offset < header.header_len + header.payload_len)
            {
                // 帧载荷未齐：等待更多数据
                break;
            }
            const auto data_begin = offset + header.header_len;
            if (!gun_transport_ || !gun_transport_->push(
                    std::span<const std::byte>(payload.data() + data_begin, header.payload_len)))
            {
                // 通道拥塞或已关闭：宁可断流不丢数据
                diagnose::debug(prefix_, "gun: data push failed (congested or closed)");
                return false;
            }
            offset = data_begin + header.payload_len;
        }

        // 未消费部分保留
        if (offset > 0 && offset < payload.size())
        {
            memory::vector<std::byte> rest(payload.begin() + static_cast<std::ptrdiff_t>(offset),
                                           payload.end(), mr_);
            frame_buf_ = std::move(rest);
        }
        else if (offset >= payload.size())
        {
            frame_buf_.clear();
        }
        return true;
    }

    auto session::submit_data_frame(const std::int32_t stream_id, memory::vector<std::byte> frame)
        -> net::awaitable<void>
    {
        // 数据源存会话映射：nghttp2 在后续 mem_send 中延迟读取，须防悬垂
        auto src = std::make_unique<data_source>();
        src->buf = std::make_shared<memory::vector<std::byte>>(std::move(frame));
        auto *raw = src.get();
        pending_data_[stream_id] = std::move(src);

        nghttp2_data_provider dp;
        dp.source.ptr = raw;
        dp.read_callback = &session::read_data_source;
        const auto rv = nghttp2_submit_data(session_, NGHTTP2_FLAG_NONE, stream_id, &dp);
        if (rv != 0)
        {
            pending_data_.erase(stream_id);
            diagnose::debug(prefix_, "gun: submit data failed: {}", nghttp2_strerror(rv));
            co_return;
        }
        co_await send_pending();
    }

    auto session::read_data_source(nghttp2_session *, const int32_t stream_id, uint8_t *buf,
                                   const size_t length, uint32_t *data_flags,
                                   nghttp2_data_source *source, void *user_data) -> ssize_t
    {
        auto *self = static_cast<session *>(user_data);
        auto it = self->pending_data_.find(stream_id);
        if (it == self->pending_data_.end())
        {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }

        auto *ds = it->second.get();
        const auto remaining = ds->buf->size() - ds->offset;
        if (remaining == 0)
        {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        const auto to_copy = std::min(length, remaining);
        std::memcpy(buf, ds->buf->data() + ds->offset, to_copy);
        ds->offset += to_copy;
        if (ds->offset >= ds->buf->size())
        {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return static_cast<ssize_t>(to_copy);
    }

    auto session::on_stream_close(nghttp2_session *, const int32_t stream_id,
                                  uint32_t, void *user_data) -> int
    {
        auto *self = static_cast<session *>(user_data);
        // 流关闭后数据源不再被读取，释放避免泄漏
        self->pending_data_.erase(stream_id);
        if (stream_id == self->matched_stream_ && self->gun_transport_)
        {
            self->gun_transport_->notify_eof();
        }
        return 0;
    }

} // namespace psm::handshake::gun

/**
 * @file session.cpp
 * @brief XHTTP HTTP/2 会话实现
 */

#include <prism/handshake/xhttp/session.hpp>
#include <prism/diagnose/diagnose.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>

#include <cstring>

using namespace psm::diagnose;

namespace psm::handshake::xhttp
{

    namespace
    {
        /// 匹配流的裸流传输：读经会话缓冲，写经 nghttp2 DATA 帧
        class stream_transport final : public psm::transport::transmission
        {
        public:
            using write_cb = std::function<net::awaitable<void>(memory::vector<std::byte>)>;

            stream_transport(net::any_io_executor executor, write_cb write_fn,
                             memory::resource_pointer mr)
                : executor_(std::move(executor))
                , write_fn_(std::move(write_fn))
                , mr_(mr)
                , channel_(std::make_unique<channel_type>(executor_, 512))
                , current_(mr)
            {
            }

            [[nodiscard]] auto executor() const -> executor_type override
            {
                return executor_;
            }

            [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
                -> net::awaitable<std::size_t> override
            {
                while (current_offset_ >= current_.size())
                {
                    if (closed_)
                    {
                        ec = std::make_error_code(std::errc::not_connected);
                        co_return 0;
                    }
                    boost::system::error_code ch_ec;
                    auto token = net::redirect_error(net::use_awaitable, ch_ec);
                    auto block = co_await channel_->async_receive(token);
                    if (ch_ec)
                    {
                        ec = std::make_error_code(std::errc::not_connected);
                        co_return 0;
                    }
                    if (block.empty())
                    {
                        ec = psm::fault::make_error_code(psm::fault::code::eof);
                        co_return 0;
                    }
                    current_ = std::move(block);
                    current_offset_ = 0;
                }
                const auto n = std::min(buffer.size(), current_.size() - current_offset_);
                std::memcpy(buffer.data(), current_.data() + current_offset_, n);
                current_offset_ += n;
                ec = {};
                co_return n;
            }

            [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
                -> net::awaitable<std::size_t> override
            {
                if (closed_ || !write_fn_)
                {
                    ec = std::make_error_code(std::errc::not_connected);
                    co_return 0;
                }
                memory::vector<std::byte> copy(buffer.begin(), buffer.end(), mr_);
                co_await write_fn_(std::move(copy));
                ec = {};
                co_return buffer.size();
            }

            void close() override
            {
                closed_ = true;
                channel_->cancel();
            }

            void cancel() override
            {
                closed_ = true;
                channel_->cancel();
            }

            [[nodiscard]] auto next_layer() noexcept -> psm::transport::transmission * override
            {
                return nullptr;
            }

            [[nodiscard]] auto next_layer() const noexcept -> const psm::transport::transmission * override
            {
                return nullptr;
            }

            void push(std::span<const std::byte> data)
            {
                if (closed_ || data.empty())
                    return;
                memory::vector<std::byte> copy(data.begin(), data.end(), mr_);
                channel_->try_send(boost::system::error_code{}, std::move(copy));
            }

            void notify_eof()
            {
                if (!closed_)
                    channel_->try_send(boost::system::error_code{}, memory::vector<std::byte>(mr_));
            }

        private:
            using channel_type = net::experimental::concurrent_channel<
                void(boost::system::error_code, memory::vector<std::byte>)>;

            net::any_io_executor executor_;
            write_cb write_fn_;
            memory::resource_pointer mr_;
            std::unique_ptr<channel_type> channel_;
            memory::vector<std::byte> current_;
            std::size_t current_offset_{0};
            bool closed_{false};
        };
    } // namespace

    session::session(psm::transport::shared_transmission transport, const config &cfg,
                     const memory::resource_pointer mr,
                     std::shared_ptr<diagnose::context> prefix)
        : transport_(std::move(transport))
        , config_(cfg)
        , mr_(mr)
        , prefix_(std::move(prefix))
        , request_path_(mr_)
        , read_buffer_(mr_)
        , wait_timer_(transport_->executor())
    {
        wait_timer_.expires_after(std::chrono::hours(24));
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
                diagnose::debug(self->prefix_, "xhttp session loop error");
            }
        });
    }

    void session::close()
    {
        if (!active_.exchange(false, std::memory_order_acq_rel))
            return;
        if (transport_)
            transport_->close();
        if (matched_transport_)
            matched_transport_->close();
        wait_timer_.cancel();
    }

    auto session::init_nghttp2() -> std::int32_t
    {
        nghttp2_session_callbacks *callbacks = nullptr;
        if (nghttp2_session_callbacks_new(&callbacks) != 0)
        {
            diagnose::error(prefix_, "xhttp: failed to create nghttp2 callbacks");
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
            diagnose::error(prefix_, "xhttp: failed to create nghttp2 session: {}", nghttp2_strerror(rv));
            return -1;
        }

        if (nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0) != 0)
        {
            diagnose::error(prefix_, "xhttp: failed to submit settings");
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
        diagnose::debug(prefix_, "xhttp: frame loop started");

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
                    diagnose::debug(prefix_, "xhttp: transport read closed: {}", read_ec.message());
                }
                break;
            }

            const auto recv_len = nghttp2_session_mem_recv(
                session_, reinterpret_cast<const uint8_t *>(recv_buf.data()), n);
            if (recv_len < 0)
            {
                diagnose::debug(prefix_, "xhttp: nghttp2 recv error: {}",
                                nghttp2_strerror(static_cast<std::int32_t>(recv_len)));
                break;
            }

            co_await send_pending();
        }

        transport_ready_ = true;
        wait_timer_.cancel();
        if (matched_transport_)
            matched_transport_->close();
        close();
        diagnose::debug(prefix_, "xhttp: frame loop ended");
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
                diagnose::debug(prefix_, "xhttp: send_pending write failed: {}", write_ec.message());
                break;
            }
        }
    }

    auto session::accept_stream(const std::int32_t stream_id) -> std::int32_t
    {
        // 响应 200 + SSE 伪装头（禁中间件缓冲）
        const char *status_str = "200";
        const char *content_type = "text/event-stream";
        const char *no_buffering = "no";
        const char *cache_control = "no-store";
        nghttp2_nv hdrs[] = {
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":status")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(status_str)), 7, 3, NGHTTP2_NV_FLAG_NONE},
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("content-type")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(content_type)), 12, 17, NGHTTP2_NV_FLAG_NONE},
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("x-accel-buffering")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(no_buffering)), 18, 2, NGHTTP2_NV_FLAG_NONE},
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("cache-control")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(cache_control)), 13, 8, NGHTTP2_NV_FLAG_NONE},
        };
        const auto rc = nghttp2_submit_headers(session_, NGHTTP2_FLAG_NONE,
                                               stream_id, nullptr, hdrs, 4, nullptr);
        if (rc != 0)
        {
            diagnose::warn(prefix_, "xhttp: submit headers failed: {}", nghttp2_strerror(rc));
            return rc;
        }

        matched_stream_ = stream_id;
        stream_accepted_ = true;
        return 0;
    }

    auto session::wait_transport() -> net::awaitable<psm::transport::shared_transmission>
    {
        boost::system::error_code ec;
        co_await wait_timer_.async_wait(net::redirect_error(net::use_awaitable, ec));

        if (!transport_ready_ || !matched_transport_)
        {
            co_return nullptr;
        }
        co_return matched_transport_;
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

        const std::string_view path(reinterpret_cast<const char *>(self->request_path_.data()),
                                    self->request_path_.size());
        const std::string_view expected(self->config_.path.data(), self->config_.path.size());

        // 路径前缀匹配
        const bool path_ok = expected == "/"
            ? path.rfind('/', 0) == 0
            : path.rfind(expected, 0) == 0;

        if (!self->request_is_post_ || !path_ok)
        {
            nghttp2_submit_rst_stream(self->session_, NGHTTP2_FLAG_NONE,
                                      frame->hd.stream_id, NGHTTP2_REFUSED_STREAM);
            return 0;
        }

        diagnose::debug(self->prefix_, "xhttp: matched stream {} path={}", frame->hd.stream_id, path);

        // 建立裸流传输
        auto self_ptr = self->shared_from_this();
        auto write_fn = [self_ptr, stream_id = frame->hd.stream_id](memory::vector<std::byte> frame)
            -> net::awaitable<void>
        {
            // 提交 DATA 帧（数据源生命周期绑定 pending_data_，防 nghttp2 延迟读取悬垂）
            co_await self_ptr->submit_data_frame(stream_id, std::move(frame));
        };

        auto stream_trans = std::make_shared<stream_transport>(
            self->transport_->executor(), std::move(write_fn), self->mr_);
        self->matched_transport_ = stream_trans;

        if (self->accept_stream(frame->hd.stream_id) == 0)
        {
            self->transport_ready_ = true;
            self->wait_timer_.cancel();
        }
        else
        {
            // accept 失败：唤醒等待者并清理，避免 wait_transport 永久挂起
            self->matched_transport_ = nullptr;
            self->transport_ready_ = true;
            self->wait_timer_.cancel();
        }
        return 0;
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
            diagnose::debug(prefix_, "xhttp: submit data failed: {}", nghttp2_strerror(rv));
            co_return;
        }
        co_await send_pending();
    }

    auto session::read_data_source(nghttp2_session *, const int32_t stream_id, uint8_t *buf,
                                   const size_t length, uint32_t *data_flags,
                                   nghttp2_data_source *, void *user_data) -> ssize_t
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

    void session::push_data(const std::span<const std::byte> data)
    {
        if (matched_transport_)
        {
            if (auto *st = dynamic_cast<stream_transport *>(matched_transport_.get()))
                st->push(data);
        }
    }

    auto session::on_data(nghttp2_session *, uint8_t, const int32_t stream_id,
                          const uint8_t *data, const size_t len, void *user_data) -> int
    {
        auto *self = static_cast<session *>(user_data);
        if (stream_id != self->matched_stream_ || !self->matched_transport_)
        {
            return 0;
        }
        self->push_data(std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(data), len));
        return 0;
    }

    auto session::on_stream_close(nghttp2_session *, const int32_t stream_id,
                                  uint32_t, void *user_data) -> int
    {
        auto *self = static_cast<session *>(user_data);
        // 流关闭后数据源不再被读取，释放避免泄漏
        self->pending_data_.erase(stream_id);
        if (stream_id == self->matched_stream_ && self->matched_transport_)
        {
            if (auto *st = dynamic_cast<stream_transport *>(self->matched_transport_.get()))
                st->notify_eof();
        }
        return 0;
    }

} // namespace psm::handshake::xhttp

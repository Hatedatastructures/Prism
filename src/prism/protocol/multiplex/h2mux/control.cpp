#include <prism/protocol/multiplex/h2mux/control.hpp>

#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/outbound/direct.hpp>
#include <prism/protocol/multiplex/datagram.hpp>
#include <prism/protocol/multiplex/smux/frame.hpp>
#include <prism/protocol/multiplex/stream.hpp>
#include <prism/diagnose/diagnose.hpp>

#include <boost/asio/co_spawn.hpp>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <span>

using namespace psm::diagnose;

namespace psm::multiplex::h2mux
{

    namespace
    {
        void log_spawn_error(const std::exception_ptr &ep, std::string_view label)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                diagnose::debug("{} error: {}", label, e.what());
            }
            catch (...)
            {
            }
        }
    } // namespace

    control::control(multiplexer_options opts, address_resolver resolver)
        : multiplexer(multiplexer_options{
              std::move(opts.transport), opts.outbound, opts.cfg, opts.mr,
              opts.cfg.h2mux.max_streams}),
          resolver_(std::move(resolver)),
          router_fn_(outbound_ ? outbound_->make_router() : decltype(router_fn_){}),
          h2_pending_(mr_),
          udp_bufs_(mr_),
          connect_waiter_(transport_->executor())
    {
        connect_waiter_.expires_after(std::chrono::hours(24));
    }


    control::~control() noexcept
    {
        if (session_)
        {
            nghttp2_session_del(session_);
            session_ = nullptr;
        }
    }


    auto control::run() -> net::awaitable<void>
    {
        if (init_nghttp2() != 0)
        {
            diagnose::error(prefix_, "nghttp2 init failed");
            co_return;
        }

        co_await send_pending();

        co_await frame_loop();
    }


    auto control::write_frame(outbound_frame frame)
        -> net::awaitable<void>
    {
        if (frame.kind == outbound_kind::fin)
        {
            nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE,
                                      static_cast<std::int32_t>(frame.stream_id), NGHTTP2_NO_ERROR);
            co_await send_pending();
            co_return;
        }

        if (frame.payload.empty())
        {
            co_return;
        }

        // 将载荷包装为 nghttp2 data provider，mem_send 时按需拷贝
        auto payload = std::make_shared<memory::vector<std::byte>>(std::move(frame.payload));

        struct data_source
        {
            std::shared_ptr<memory::vector<std::byte>> buf;
            std::size_t offset{0};
        };

        auto src = std::make_unique<data_source>(data_source{payload, 0});

        nghttp2_data_provider dp;
        dp.source.ptr = src.get();
        dp.read_callback = [](nghttp2_session *, int32_t, uint8_t *buf,
                              size_t length, uint32_t *data_flags,
                              nghttp2_data_source *source, void *) -> ssize_t
        {
            auto *ds = static_cast<data_source *>(source->ptr);
            auto remaining = ds->buf->size() - ds->offset;

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
        };

        const std::int32_t rv = nghttp2_submit_data(session_, NGHTTP2_FLAG_NONE,
                                                    static_cast<std::int32_t>(frame.stream_id), &dp);
        if (rv != 0)
        {
            diagnose::warn(prefix_, "nghttp2_submit_data failed: {}", nghttp2_strerror(rv));
            co_return;
        }

        co_await send_pending();
        src.reset();
    }


    auto control::init_nghttp2() -> std::int32_t
    {
        nghttp2_session_callbacks *callbacks = nullptr;
        if (nghttp2_session_callbacks_new(&callbacks) != 0)
        {
            diagnose::error(prefix_, "failed to create nghttp2 callbacks");
            return -1;
        }

        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, &control::on_begin_headers);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, &control::on_header);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &control::on_frame_recv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &control::on_data);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &control::on_stream_close);

        const std::int32_t rv = nghttp2_session_server_new2(&session_, callbacks, this, nullptr);
        nghttp2_session_callbacks_del(callbacks);

        if (rv != 0)
        {
            diagnose::error(prefix_, "failed to create nghttp2 session: {}", nghttp2_strerror(rv));
            return -1;
        }

        if (nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0) != 0)
        {
            diagnose::error(prefix_, "failed to submit settings");
            return -1;
        }

        diagnose::debug(prefix_, "nghttp2 session initialized");
        return 0;
    }


    auto control::frame_loop() -> net::awaitable<void>
    {
        diagnose::debug(prefix_, "frame loop started");

        memory::vector<std::byte> recv_buf(config_.h2mux.buffer_size, mr_);

        while (is_active())
        {
            std::error_code read_ec;
            const auto n = co_await transport_->async_read_some(
                std::span<std::byte>(recv_buf.data(), recv_buf.size()), read_ec);

            if (read_ec || n == 0)
            {
                if (read_ec && read_ec != std::errc::operation_canceled)
                {
                    diagnose::debug(prefix_, "transport read closed: {}", read_ec.message());
                }
                break;
            }

            // 安全：nghttp2 API 要求 uint8_t*，recv_buf 仅作只读输入
            const auto recv_len = nghttp2_session_mem_recv(
                session_,
                reinterpret_cast<const std::uint8_t *>(recv_buf.data()),
                n);

            if (recv_len < 0)
            {
                diagnose::error(prefix_, "nghttp2 recv error: {}",
                             nghttp2_strerror(static_cast<std::int32_t>(recv_len)));
                break;
            }

            co_await send_pending();
        }

        if (!connect_resolved_)
        {
            connect_resolved_ = true;
            connect_waiter_.cancel();
        }

        diagnose::debug(prefix_, "frame loop ended");
    }


    auto control::send_pending() -> net::awaitable<void>
    {
        while (true)
        {
            const std::uint8_t *data = nullptr;
            const auto len = nghttp2_session_mem_send(session_, &data);
            if (len <= 0)
            {
                break;
            }

            std::error_code write_ec;
            // 安全：将 nghttp2 输出数据 (uint8_t*) 转为 byte span 写入传输层
            co_await transport::async_write(*transport_,
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(data), len),
                write_ec);

            if (write_ec)
            {
                diagnose::warn(prefix_, "send_pending write failed: {}", write_ec.message());
                break;
            }
        }
    }


    void control::handle_connect(const std::int32_t stream_id)
    {
        auto it = h2_pending_.find(static_cast<std::uint32_t>(stream_id));
        if (it == h2_pending_.end())
        {
            return;
        }

        auto &entry = it->second;

        entry.info = resolver_(stream_id, entry.headers);

        if (entry.info.valid)
        {
            if (!connect_resolved_)
            {
                first_connect_ = entry.headers;
                connect_resolved_ = true;
                connect_waiter_.cancel();
                return;
            }

            entry.connecting = true;
            auto self = std::static_pointer_cast<control>(shared_from_this());
            const auto id = static_cast<std::uint32_t>(stream_id);
            auto activate_task = [self, id]() -> net::awaitable<void>
            {
                co_await self->activate_stream(id);
            };
            auto on_error = [](const std::exception_ptr &ep)
            {
                if (ep) log_spawn_error(ep, "activate_stream");
            };
            net::co_spawn(transport_->executor(), std::move(activate_task), std::move(on_error));
        }
    }


    auto control::activate_stream(const std::uint32_t stream_id) -> net::awaitable<void>
    {
        auto it = h2_pending_.find(stream_id);
        if (it == h2_pending_.end())
        {
            co_return;
        }

        auto info = std::move(it->second.info);
        h2_pending_.erase(it);

        switch (info.type)
        {
        case stream_type::check:
        {
            const auto rc = respond_connect(static_cast<std::int32_t>(stream_id), 200);
            if (rc != 0)
            {
                diagnose::warn(prefix_, "respond_connect for health check stream {} failed: nghttp2 rc={}", stream_id, rc);
            }
            co_await send_pending();
            nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE,
                                      static_cast<std::int32_t>(stream_id), NGHTTP2_NO_ERROR);
            co_await send_pending();
            diagnose::debug(prefix_, "stream {} health check completed", stream_id);
            co_return;
        }

        case stream_type::udp:
        {
            diagnose::debug(prefix_, "stream {} creating UDP datagram -> {}:{}", stream_id, info.host, info.port);

            const auto rc = respond_connect(static_cast<std::int32_t>(stream_id), 200);
            if (rc != 0)
            {
                diagnose::warn(prefix_, "respond_connect for UDP stream {} failed: nghttp2 rc={}", stream_id, rc);
            }
            co_await send_pending();

            auto [bit, inserted] = udp_bufs_.emplace(stream_id, udp_entry(mr_));
            (void)inserted;
            bit->second.dest_host.assign(info.host.data(), info.host.size());
            bit->second.dest_port = info.port;

            auto dp = make_datagram(datagram_options{
                .stream_id = stream_id,
                .idle_timeout = config_.h2mux.udp_idle,
                .max_dgram = config_.h2mux.max_dgram,
                .executor = transport_->executor(),
                .egress = shared_from_this(),
                .resolve = make_resolve(),
                .emit = make_emit(stream_id),
                .mr = mr_,
                .prefix = prefix_,
            });

            if (is_active())
            {
                datagrams_[stream_id] = dp;
                dp->start();
            }
            else
            {
                udp_bufs_.erase(stream_id);
                dp->close();
            }

            diagnose::debug(prefix_, "stream {} UDP datagram created", stream_id);
            co_return;
        }

        case stream_type::icmp:
        {
            diagnose::warn(prefix_, "stream {} ICMP not yet implemented, treating as TCP", stream_id);
            [[fallthrough]];
        }

        case stream_type::tcp:
        default:
        {
            diagnose::debug(prefix_, "stream {} connecting to {}:{}", stream_id, info.host, info.port);

            char port_buf[8];
            const auto [port_end, port_ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), info.port);
            auto port_str = std::string_view(port_buf, std::distance(port_buf, port_end));
            auto host_str = std::string_view(info.host.data(), info.host.size());

            // 通过 outbound 接口拨号（返回 shared_transmission，无需 make_reliable）
            psm::connect::target tgt;
            tgt.host = memory::string(host_str, mr_);
            tgt.port = memory::string(port_str, mr_);
            tgt.positive = true;
            auto [code, trans] = co_await outbound_->async_connect(tgt, transport_->executor());

            if (code != fault::code::success || !trans)
            {
                diagnose::warn(prefix_, "stream {} connect to {}:{} failed", stream_id, info.host, info.port);
                nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE,
                                          static_cast<std::int32_t>(stream_id), NGHTTP2_INTERNAL_ERROR);
                co_await send_pending();
                co_return;
            }

            const auto rc = respond_connect(static_cast<std::int32_t>(stream_id), 200);
            if (rc != 0)
            {
                diagnose::warn(prefix_, "respond_connect for TCP stream {} failed: nghttp2 rc={}", stream_id, rc);
            }
            co_await send_pending();

            auto sp = make_stream(stream_options{
                .stream_id = stream_id,
                .target = std::move(trans),
                .egress = shared_from_this(),
                .buffer_size = config_.h2mux.buffer_size,
                .mr = mr_,
                .prefix = prefix_,
            });
            streams_[stream_id] = sp;
            sp->start();

            diagnose::debug(prefix_, "stream {} connected to {}:{}", stream_id, info.host, info.port);
        }
        }
    }


    auto control::process_udp(const std::uint32_t stream_id, memory::vector<std::byte> payload)
        -> net::awaitable<void>
    {
        const auto bit = udp_bufs_.find(stream_id);
        if (bit == udp_bufs_.end())
        {
            co_return;
        }
        auto &entry = bit->second;

        entry.buffer.insert(entry.buffer.end(), payload.begin(), payload.end());

        // 缓冲区超过最大数据报大小时关闭管道，防止内存持续膨胀
        if (entry.buffer.size() > config_.h2mux.max_dgram)
        {
            drop(stream_id);
            co_return;
        }

        // 串行化：已有处理循环在跑则直接返回（数据已累积）
        if (entry.processing)
        {
            co_return;
        }
        entry.processing = true;

        try
        {
            bool has_progress;
            do
            {
                memory::vector<std::byte> local(mr_);
                std::swap(local, entry.buffer);

                std::size_t offset = 0;
                while (offset < local.size())
                {
                    auto dp = datagrams_.find(stream_id);
                    if (dp == datagrams_.end() || !dp->second)
                    {
                        break;
                    }

                    auto rest = std::span<const std::byte>(local.data() + offset, local.size() - offset);
                    auto dgram = smux::parse_prefixed(rest);
                    if (!dgram)
                    {
                        break;
                    }
                    co_await dp->second->send_to(entry.dest_host, entry.dest_port, dgram->payload);
                    offset += dgram->consumed;
                }

                // 未消费数据移回入口缓冲
                if (offset < local.size())
                {
                    entry.buffer.insert(entry.buffer.begin(),
                                        local.begin() + static_cast<std::ptrdiff_t>(offset),
                                        local.end());
                }

                has_progress = offset > 0;
            } while (has_progress && !entry.buffer.empty() && is_active());
        }
        catch (const std::exception &e)
        {
            diagnose::debug(prefix_, "stream {} process udp error: {}", stream_id, e.what());
        }
        catch (...)
        {
            diagnose::error(prefix_, "stream {} process udp unknown error", stream_id);
        }
        entry.processing = false;
    }


    auto control::on_begin_headers(nghttp2_session *, const nghttp2_frame *frame, void *user_data) -> int
    {
        auto *self = static_cast<control *>(user_data);

        if (frame->hd.type == NGHTTP2_HEADERS &&
            frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        {
            const auto &nv = frame->headers.nva;
            bool is_connect = false;
            for (std::size_t i = 0; i < frame->headers.nvlen; ++i)
            {
                // 安全：将 nghttp2 头部名 (uint8_t*) 转为 string_view 解析 HTTP/2 头
                const auto name = std::string_view(
                    reinterpret_cast<const char *>(nv[i].name), nv[i].namelen);
                const auto value = std::string_view(
                    reinterpret_cast<const char *>(nv[i].value), nv[i].valuelen);

                if (name == ":method" && value == "CONNECT")
                {
                    is_connect = true;
                    break;
                }
            }

            if (is_connect)
            {
                const auto stream_id = static_cast<std::uint32_t>(frame->hd.stream_id);
                h2_pending_entry entry;
                entry.headers.stream_id = frame->hd.stream_id;
                self->h2_pending_[stream_id] = std::move(entry);
                diagnose::debug(self->prefix_, "CONNECT detected on stream {}", stream_id);
            }
        }
        return 0;
    }


    auto control::on_header(nghttp2_session *, const nghttp2_frame *frame,
                            const uint8_t *name, const size_t namelen,
                            const uint8_t *value, const size_t valuelen,
                            uint8_t, void *user_data) -> int
    {
        auto *self = static_cast<control *>(user_data);

        const auto stream_id = static_cast<std::uint32_t>(frame->hd.stream_id);
        auto it = self->h2_pending_.find(stream_id);
        if (it == self->h2_pending_.end())
        {
            return 0;
        }

        // 安全：将 nghttp2 头部名/值 (uint8_t*) 转为 string_view 分发头部字段
        const auto hname = std::string_view(reinterpret_cast<const char *>(name), namelen);
        const auto hvalue = std::string_view(reinterpret_cast<const char *>(value), valuelen);

        auto &headers = it->second.headers;

        if (hname == ":authority")
        {
            headers.authority.assign(hvalue);
        }
        else if (hname == "host" || hname == "Host")
        {
            headers.host.assign(hvalue);
        }
        else if (hname == "user-agent")
        {
            headers.user_agent.assign(hvalue);
        }
        else if (hname == "proxy-authorization")
        {
            headers.proxy_auth.assign(hvalue);
        }

        return 0;
    }


    auto control::on_frame_recv(nghttp2_session *, const nghttp2_frame *frame, void *user_data) -> int
    {
        auto *self = static_cast<control *>(user_data);

        if (frame->hd.type != NGHTTP2_HEADERS ||
            frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        {
            return 0;
        }

        const auto stream_id = frame->hd.stream_id;
        auto it = self->h2_pending_.find(static_cast<std::uint32_t>(stream_id));
        if (it == self->h2_pending_.end())
        {
            return 0;
        }

        self->handle_connect(stream_id);

        return 0;
    }


    auto control::on_data(nghttp2_session *, uint8_t, const int32_t stream_id,
                          const uint8_t *data, const size_t len, void *user_data) -> int
    {
        auto *self = static_cast<control *>(user_data);
        const auto id = static_cast<std::uint32_t>(stream_id);

        if (self->h2_pending_.contains(id))
        {
            // TODO: 实现 StreamRequest 解析(#h2mux)
            return 0;
        }

        if (const auto dit = self->streams_.find(id); dit != self->streams_.end() && dit->second)
        {
            auto sp = dit->second;
            // 安全：将 nghttp2 数据帧载荷 (uint8_t*) 转为 byte vector 分发到 stream
            auto payload = memory::vector<std::byte>(
                reinterpret_cast<const std::byte *>(data),
                reinterpret_cast<const std::byte *>(data) + len, self->mr_);

            auto self_ptr = std::static_pointer_cast<control>(self->shared_from_this());
            auto dispatch_data = [sp, p = std::move(payload), self_ptr]() mutable -> net::awaitable<void>
            {
                co_await sp->on_data(std::move(p));
            };
            auto on_stream_error = [sp](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    log_spawn_error(ep, "dispatch stream data");
                    sp->close();
                }
            };
            net::co_spawn(self->executor(), std::move(dispatch_data), std::move(on_stream_error));
            return 0;
        }

        if (self->datagrams_.contains(id))
        {
            auto payload = memory::vector<std::byte>(
                reinterpret_cast<const std::byte *>(data),
                reinterpret_cast<const std::byte *>(data) + len, self->mr_);

            auto self_ptr = std::static_pointer_cast<control>(self->shared_from_this());
            auto dispatch_udp = [self_ptr, id, p = std::move(payload)]() mutable -> net::awaitable<void>
            {
                co_await self_ptr->process_udp(id, std::move(p));
            };
            auto on_udp_error = [self_ptr, id](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    log_spawn_error(ep, "dispatch datagram data");
                    self_ptr->drop(id);
                }
            };
            net::co_spawn(self->executor(), std::move(dispatch_udp), std::move(on_udp_error));
            return 0;
        }

        nghttp2_submit_rst_stream(self->session_, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_PROTOCOL_ERROR);
        return 0;
    }


    auto control::on_stream_close(nghttp2_session *, const int32_t stream_id,
                                  uint32_t, void *user_data) -> int
    {
        auto *self = static_cast<control *>(user_data);
        const auto id = static_cast<std::uint32_t>(stream_id);

        self->h2_pending_.erase(id);

        if (const auto it = self->streams_.find(id); it != self->streams_.end() && it->second)
        {
            it->second->on_fin();
        }

        self->udp_bufs_.erase(id);

        if (const auto it = self->datagrams_.find(id); it != self->datagrams_.end() && it->second)
        {
            it->second->close();
        }

        return 0;
    }


    auto control::wait_first_connect()
        -> net::awaitable<std::optional<h2_headers>>
    {
        if (connect_resolved_)
        {
            if (first_connect_.authority.empty())
            {
                co_return std::nullopt;
            }
            co_return std::move(first_connect_);
        }

        boost::system::error_code ec;
        co_await connect_waiter_.async_wait(
            net::redirect_error(net::use_awaitable, ec));

        if (first_connect_.authority.empty())
        {
            co_return std::nullopt;
        }
        co_return std::move(first_connect_);
    }


    auto control::respond_connect(const std::int32_t stream_id, const std::uint32_t status) -> std::int32_t
    {
        if (!session_)
            return NGHTTP2_ERR_INVALID_STATE;

        const char *status_str = "407";
        if (status == 200)
            status_str = "200";
        // 安全：nghttp2 要求可变 uint8_t*，字符串字面量经 const_cast 满足 API 兼容
        auto status_name = const_cast<std::uint8_t *>(reinterpret_cast<const std::uint8_t *>(":status"));
        auto status_val = const_cast<std::uint8_t *>(reinterpret_cast<const std::uint8_t *>(status_str));
        nghttp2_nv hdrs[] = {
            {status_name, status_val, 7, 3, NGHTTP2_NV_FLAG_NONE}};

        return nghttp2_submit_headers(session_, NGHTTP2_FLAG_NONE,
                                      stream_id, nullptr, hdrs, 1, nullptr);
    }


    auto control::make_resolve() const
        -> resolve_fn
    {
        return [this](std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
        {
            co_return co_await router_fn_(host, port);
        };
    }


    auto control::make_emit(const std::uint32_t stream_id)
        -> emit_fn
    {
        auto self = std::static_pointer_cast<control>(shared_from_this());
        return [self, stream_id](const std::string_view, const std::uint16_t,
                                 const std::span<const std::byte> payload)
            -> net::awaitable<void>
        {
            auto encoded = smux::build_prefixed(payload, self->mr_);
            co_await self->send(stream_id, std::move(encoded));
        };
    }

} // namespace psm::multiplex::h2mux

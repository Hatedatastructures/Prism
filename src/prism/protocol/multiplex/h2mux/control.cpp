#include <prism/protocol/multiplex/h2mux/control.hpp>
#include <prism/protocol/multiplex/h2mux/singmux.hpp>

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

    control::control(multiplexer_options opts, address_resolver resolver, const bool sing_streams)
        : multiplexer(multiplexer_options{
              std::move(opts.transport), opts.outbound, opts.cfg, opts.mr,
              opts.cfg.h2mux.max_streams}),
          resolver_(std::move(resolver)),
          sing_streams_(sing_streams),
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
        // 数据源存入会话映射：nghttp2 延迟读取时防悬垂
        auto src = std::make_unique<data_source>();
        src->buf = std::make_shared<memory::vector<std::byte>>(std::move(frame.payload));
        auto *raw = src.get();
        pending_data_[frame.stream_id] = std::move(src);

        nghttp2_data_provider dp;
        dp.source.ptr = raw;
        dp.read_callback = [](nghttp2_session *, int32_t stream_id, uint8_t *buf,
                              size_t length, uint32_t *data_flags,
                              nghttp2_data_source *, void *user_data) -> ssize_t
        {
            auto *self = static_cast<control *>(user_data);
            auto it = self->pending_data_.find(stream_id);
            if (it == self->pending_data_.end())
            {
                *data_flags |= NGHTTP2_DATA_FLAG_EOF;
                return 0;
            }
            auto *ds = it->second.get();
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
            pending_data_.erase(frame.stream_id);
            diagnose::warn(prefix_, "nghttp2_submit_data failed: {}", nghttp2_strerror(rv));
            co_return;
        }

        co_await send_pending();
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

        // 禁用 HTTP messaging 严格检查：sing-mux 的 CONNECT 请求携带
        // body（StreamRequest），默认检查会以 messaging violation 拒绝
        nghttp2_option *option = nullptr;
        nghttp2_option_new(&option);
        nghttp2_option_set_no_http_messaging(option, 1);

        const std::int32_t rv = nghttp2_session_server_new3(&session_, callbacks, this, option, nullptr);
        if (option)
            nghttp2_option_del(option);
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

            diagnose::debug(prefix_, "frame loop received {} bytes", n);

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
            diagnose::debug(prefix_, "send_pending mem_send rc={}", static_cast<int>(len));
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
            // sing-mux 模式直接激活；TrustTunnel 模式首个 CONNECT 供 auth 验证
            if (!sing_streams_ && !connect_resolved_)
            {
                first_connect_ = entry.headers;
                connect_resolved_ = true;
                connect_waiter_.cancel();
                return;
            }

            spawn_activate(static_cast<std::uint32_t>(stream_id));
        }
    }


    void control::spawn_activate(const std::uint32_t stream_id)
    {
        auto it = h2_pending_.find(stream_id);
        if (it == h2_pending_.end() || !it->second.info.valid || it->second.connecting)
        {
            return;
        }

        it->second.connecting = true;
        auto self = std::static_pointer_cast<control>(shared_from_this());
        auto activate_task = [self, id = stream_id]() -> net::awaitable<void>
        {
            co_await self->activate_stream(id);
        };
        auto on_error = [](const std::exception_ptr &ep)
        {
            if (ep) log_spawn_error(ep, "activate_stream");
        };
        net::co_spawn(transport_->executor(), std::move(activate_task), std::move(on_error));
    }


    auto control::activate_stream(const std::uint32_t stream_id) -> net::awaitable<void>
    {
        auto it = h2_pending_.find(stream_id);
        if (it == h2_pending_.end())
        {
            co_return;
        }

        auto info = std::move(it->second.info);
        auto pending_data = std::move(it->second.pending_data);
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

            // sing-mux：UDP 流首字节前置 StreamResponse 状态（0x00 成功）
            if (sing_streams_)
            {
                auto status_payload = memory::vector<std::byte>(mr_);
                status_payload.push_back(std::byte{0});
                co_await write_frame(outbound_frame{
                    stream_id,
                    std::move(status_payload),
                    outbound_kind::data});
            }
            // StreamRequest 后的剩余数据（length-prefixed UDP 包）交给重组缓冲
            if (!pending_data.empty())
            {
                auto &buffer = bit->second.buffer;
                buffer.insert(buffer.end(), pending_data.begin(), pending_data.end());
            }

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

            // StreamRequest 后已累积的 UDP 包需要立即处理（否则等待下一个 DATA 帧）
            if (!pending_data.empty() && datagrams_.contains(stream_id))
            {
                auto self = std::static_pointer_cast<control>(shared_from_this());
                auto process_task = [self, id = stream_id]() -> net::awaitable<void>
                {
                    co_await self->process_udp(id, memory::vector<std::byte>(self->mr_));
                };
                auto on_error = [](const std::exception_ptr &ep)
                {
                    if (ep)
                        log_spawn_error(ep, "process pending udp");
                };
                net::co_spawn(transport_->executor(), std::move(process_task), std::move(on_error));
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

            // sing-mux：TCP 流首字节前置 StreamResponse 状态（0x00 成功）
            if (sing_streams_)
            {
                auto status_payload = memory::vector<std::byte>(mr_);
                status_payload.push_back(std::byte{0});
                co_await write_frame(outbound_frame{
                    stream_id,
                    std::move(status_payload),
                    outbound_kind::data});
            }
            // StreamRequest 后的剩余数据转发给流
            if (!pending_data.empty())
            {
                co_await sp->on_data(std::move(pending_data));
            }

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

        // 注：begin_headers 阶段 frame->headers.nva 尚未填充（头在 on_header
        // 回调中逐个到达），此处只按帧类型预注册 pending，:method 校验在
        // on_frame_recv（HEADERS 完整到达）时执行。
        if (frame->hd.type == NGHTTP2_HEADERS &&
            frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        {
            const auto stream_id = static_cast<std::uint32_t>(frame->hd.stream_id);
            h2_pending_entry entry;
            entry.headers.stream_id = frame->hd.stream_id;
            self->h2_pending_[stream_id] = std::move(entry);
            diagnose::debug(self->prefix_, "request headers on stream {}", stream_id);
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

        if (hname == ":method")
        {
            headers.method.assign(hvalue);
        }
        else if (hname == ":authority")
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

        // 注：nghttp2 1.69 在 on_frame_recv 阶段不填充 frame->headers.nva
        //（仅 on_header_callback2 模式填充），:method 在 on_header 中收集
        if (it->second.headers.method != "CONNECT")
        {
            // 非 CONNECT 请求：不代理，丢弃 pending
            self->h2_pending_.erase(static_cast<std::uint32_t>(stream_id));
            return 0;
        }

        diagnose::debug(self->prefix_, "CONNECT detected on stream {}", stream_id);
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
            // sing-mux：首个 DATA 帧载荷为 StreamRequest，解析后激活
            auto &entry = self->h2_pending_[id];
            entry.buffer.insert(entry.buffer.end(),
                                reinterpret_cast<const std::byte *>(data),
                                reinterpret_cast<const std::byte *>(data) + len);

            if (!entry.info.valid)
            {
                auto request = parse_sing_request(entry.buffer, self->mr_);
                if (!request)
                {
                    // 数据不足：等待更多 DATA 帧（防无限累积）
                    if (entry.buffer.size() > 512)
                    {
                        nghttp2_submit_rst_stream(self->session_, NGHTTP2_FLAG_NONE,
                                                  stream_id, NGHTTP2_PROTOCOL_ERROR);
                    }
                    return 0;
                }
                if (request->consumed == 0)
                {
                    // 非法地址类型
                    nghttp2_submit_rst_stream(self->session_, NGHTTP2_FLAG_NONE,
                                              stream_id, NGHTTP2_PROTOCOL_ERROR);
                    return 0;
                }

                entry.info.host = std::move(request->host);
                entry.info.port = request->port;
                entry.info.type = request->udp ? stream_type::udp : stream_type::tcp;
                entry.info.valid = true;

                // StreamRequest 之后的剩余数据暂存，激活后转发
                if (request->consumed < entry.buffer.size())
                {
                    entry.pending_data.assign(
                        entry.buffer.begin() + static_cast<std::ptrdiff_t>(request->consumed),
                        entry.buffer.end());
                }

                self->spawn_activate(id);
                return 0;
            }

            // 目标已解析：后续 DATA 直接累积转发（激活可能尚未完成）
            entry.pending_data.insert(entry.pending_data.end(),
                                      reinterpret_cast<const std::byte *>(data),
                                      reinterpret_cast<const std::byte *>(data) + len);
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
                                  uint32_t error_code, void *user_data) -> int
    {
        auto *self = static_cast<control *>(user_data);
        const auto id = static_cast<std::uint32_t>(stream_id);

        self->h2_pending_.erase(id);
        // 流关闭后数据源不再被读取，释放避免泄漏
        self->pending_data_.erase(id);

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

#include <prism/multiplex/h2mux/craft.hpp>
#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/parcel.hpp>
#include <prism/transport/reliable.hpp>
#include <prism/transport/transmission.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/connect/dial/dial.hpp>
#include <prism/trace.hpp>

#include <algorithm>
#include <cstring>
#include <charconv>

#include <boost/asio/co_spawn.hpp>

namespace psm::multiplex::h2mux
{
    namespace
    {
        constexpr std::string_view tag = "[H2mux.Craft]";
    } // namespace

    // ═══════════════════════════════════════════════════════════
    // 构造 / 析构
    // ═══════════════════════════════════════════════════════════

    craft::craft(transport::shared_transmission transport, craft_init init,
                 const memory::resource_pointer mr)
        : core(std::move(transport), init.router, init.cfg, mr),
          resolver_(std::move(init.resolver)),
          h2_pending_(mr_),
          send_channel_(transport_->executor(), init.cfg.h2mux.max_streams),
          first_connect_waiter_(transport_->executor())
    {
        first_connect_waiter_.expires_after(std::chrono::hours(24));
    }

    craft::~craft()
    {
        if (session_)
        {
            nghttp2_session_del(session_);
            session_ = nullptr;
        }
    }

    // ═══════════════════════════════════════════════════════════
    // nghttp2 初始化
    // ═══════════════════════════════════════════════════════════

    auto craft::init_nghttp2() -> std::int32_t
    {
        nghttp2_session_callbacks *callbacks = nullptr;
        if (nghttp2_session_callbacks_new(&callbacks) != 0)
        {
            trace::error("{} failed to create nghttp2 callbacks", tag);
            return -1;
        }

        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, &craft::on_begin_headers);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, &craft::on_header);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, &craft::on_frame_recv);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, &craft::on_data);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, &craft::on_stream_close);

        const std::int32_t rv = nghttp2_session_server_new2(&session_, callbacks, this, nullptr);
        nghttp2_session_callbacks_del(callbacks);

        if (rv != 0)
        {
            trace::error("{} failed to create nghttp2 session: {}", tag, nghttp2_strerror(rv));
            return -1;
        }

        // 发送 HTTP/2 服务端 connection preface (SETTINGS)
        if (nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0) != 0)
        {
            trace::error("{} failed to submit settings", tag);
            return -1;
        }

        trace::debug("{} nghttp2 session initialized", tag);
        return 0;
    }

    // ═══════════════════════════════════════════════════════════
    // run / frame_loop
    // ═══════════════════════════════════════════════════════════

    auto craft::run() -> net::awaitable<void>
    {
        if (init_nghttp2() != 0)
        {
            trace::error("{} nghttp2 init failed", tag);
            co_return;
        }

        // 发送初始 SETTINGS
        co_await send_pending();

        const auto self = std::static_pointer_cast<craft>(shared_from_this());

        // 启动发送循环
        net::co_spawn(executor(),
            [self]() -> net::awaitable<void> { co_await self->send_loop(); },
            net::detached);

        // 进入帧循环
        co_await frame_loop();

        send_channel_.cancel();
    }

    auto craft::frame_loop() -> net::awaitable<void>
    {
        trace::debug("{} frame loop started", tag);

        memory::vector<std::byte> recv_buf(config_.h2mux.buffer_size, mr_);

        while (active_.load(std::memory_order_acquire) && !closed_)
        {
            std::error_code read_ec;
            const auto n = co_await transport_->async_read_some(
                std::span<std::byte>(recv_buf.data(), recv_buf.size()), read_ec);

            if (read_ec || n == 0)
            {
                if (read_ec && read_ec != std::errc::operation_canceled)
                {
                    trace::debug("{} transport read closed: {}", tag, read_ec.message());
                }
                break;
            }

            // safe: nghttp2 API requires uint8_t*, recv_buf data is read-only input
            const auto recv_len = nghttp2_session_mem_recv(
                session_,
                reinterpret_cast<const uint8_t *>(recv_buf.data()),
                n);

            if (recv_len < 0)
            {
                trace::error("{} nghttp2 recv error: {}",
                             tag, nghttp2_strerror(static_cast<int>(recv_len)));
                break;
            }

            co_await send_pending();
        }

        // 通知所有等待者
        if (!first_connect_resolved_)
        {
            first_connect_resolved_ = true;
            first_connect_waiter_.cancel();
        }

        trace::debug("{} frame loop ended", tag);
    }

    // ═══════════════════════════════════════════════════════════
    // send_pending
    // ═══════════════════════════════════════════════════════════

    auto craft::send_pending() -> net::awaitable<void>
    {
        while (true)
        {
            const uint8_t *data = nullptr;
            const auto len = nghttp2_session_mem_send(session_, &data);
            if (len <= 0)
            {
                break;
            }

            std::error_code write_ec;
            // safe: casting nghttp2 output data (uint8_t*) to byte span for wire transmission
            co_await transport::async_write(*transport_,
                std::span<const std::byte>(
                    reinterpret_cast<const std::byte *>(data), len),
                write_ec);

            if (write_ec)
            {
                trace::warn("{} send_pending write failed: {}", tag, write_ec.message());
                break;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // CONNECT 处理
    // ═══════════════════════════════════════════════════════════

    void craft::handle_connect(const int32_t stream_id)
    {
        auto it = h2_pending_.find(static_cast<std::uint32_t>(stream_id));
        if (it == h2_pending_.end())
        {
            return;
        }

        auto &entry = it->second;

        // 调用 address_resolver 解析地址
        entry.info = resolver_(stream_id, entry.headers);

        // TrustTunnel 模式：resolver 直接返回完整地址
        if (entry.info.valid)
        {
            // 第一个 CONNECT：通知 wait_first_connect
            if (!first_connect_resolved_)
            {
                first_connect_ = entry.headers;
                first_connect_resolved_ = true;
                first_connect_waiter_.cancel();
                return;
            }

            // 后续 CONNECT：直接 activate
            entry.connecting = true;
            auto self = std::static_pointer_cast<craft>(shared_from_this());
            const auto id = static_cast<std::uint32_t>(stream_id);
            net::co_spawn(executor(),
                [self, id]() -> net::awaitable<void> { co_await self->activate_stream(id); },
                [](const std::exception_ptr &ep)
                {
                    if (ep)
                    {
                        try
                        {
                            std::rethrow_exception(ep);
                        }
                        catch (const std::exception &e)
                        {
                            trace::debug("{} activate_stream error: {}", tag, e.what());
                        }
                        catch (...) {}
                    }
                });
        }
        // sing-mux 模式：valid=false，等待首个 DATA 帧的 StreamRequest
    }

    // ═══════════════════════════════════════════════════════════
    // activate_stream
    // ═══════════════════════════════════════════════════════════

    auto craft::activate_stream(const std::uint32_t stream_id) -> net::awaitable<void>
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
            // 健康检查：回复 200 后关闭
            respond_connect(static_cast<int32_t>(stream_id), 200);
            std::error_code ec;
            co_await send_pending();
            nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE,
                                      static_cast<int32_t>(stream_id), NGHTTP2_NO_ERROR);
            co_await send_pending();
            trace::debug("{} stream {} health check completed", tag, stream_id);
            co_return;
        }

        case stream_type::udp:
        {
            trace::debug("{} stream {} creating UDP parcel -> {}:{}", tag, stream_id, info.host, info.port);

            // 回复 200 OK
            respond_connect(static_cast<int32_t>(stream_id), 200);
            std::error_code ec;
            co_await send_pending();

            // 创建 UDP parcel
            auto dp = make_parcel(
                parcel_config{
                    .stream_id = stream_id,
                    .udp_idle_timeout = config_.h2mux.udp_idle_timeout,
                    .udp_max_dgram = config_.h2mux.udp_max_dgram,
                    .mr = mr_,
                },
                shared_from_this(), router_);
            dp->set_destination(
                std::string_view(info.host.data(), info.host.size()),
                info.port);

            if (active_.load(std::memory_order_acquire))
            {
                parcels_[stream_id] = dp;
                dp->start();
            }
            else
            {
                dp->close();
            }

            trace::debug("{} stream {} UDP parcel created", tag, stream_id);
            co_return;
        }

        case stream_type::icmp:
        {
            // ICMP：后续迭代实现，暂按 TCP 处理
            trace::warn("{} stream {} ICMP not yet implemented, treating as TCP", tag, stream_id);
            [[fallthrough]];
        }

        case stream_type::tcp:
        default:
        {
            trace::debug("{} stream {} connecting to {}:{}", tag, stream_id, info.host, info.port);

            char port_buf[8];
            const auto [port_end, port_ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), info.port);
            auto [code, conn] = co_await connect::async_forward(
                router_,
                std::string_view(info.host.data(), info.host.size()),
                std::string_view(port_buf, std::distance(port_buf, port_end)));

            if (code != fault::code::success || !conn.valid())
            {
                trace::warn("{} stream {} connect to {}:{} failed", tag, stream_id, info.host, info.port);
                nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE,
                                          static_cast<int32_t>(stream_id), NGHTTP2_INTERNAL_ERROR);
                co_await send_pending();
                co_return;
            }

            // 回复 200 OK
            respond_connect(static_cast<int32_t>(stream_id), 200);
            std::error_code send_ec;
            co_await send_pending();

            // 创建 TCP duct
            auto target = transport::make_reliable(std::move(conn));
            const auto p = make_duct(stream_id, shared_from_this(), std::move(target),
                                     {config_.h2mux.buffer_size, mr_});
            ducts_[stream_id] = p;
            p->start();

            trace::debug("{} stream {} connected to {}:{}", tag, stream_id, info.host, info.port);
        }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // nghttp2 回调
    // ═══════════════════════════════════════════════════════════

    auto craft::on_begin_headers(nghttp2_session *, const nghttp2_frame *frame, void *user_data) -> int
    {
        auto *self = static_cast<craft *>(user_data);

        if (frame->hd.type == NGHTTP2_HEADERS &&
            frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        {
            // 检查 :method 是否为 CONNECT
            const auto &nv = frame->headers.nva;
            bool is_connect = false;
            for (std::size_t i = 0; i < frame->headers.nvlen; ++i)
            {
                // safe: casting nghttp2 header name/value (uint8_t*) to string_view for HTTP/2 header parsing
                const auto name = std::string_view(
                    reinterpret_cast<const char *>(nv[i].name), nv[i].namelen);
                // safe: casting nghttp2 header value (uint8_t*) to string_view for HTTP/2 header parsing
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
                trace::debug("{} CONNECT detected on stream {}", tag, stream_id);
            }
        }
        return 0;
    }

    auto craft::on_header(nghttp2_session *, const nghttp2_frame *frame,
                          const uint8_t *name, const size_t namelen,
                          const uint8_t *value, const size_t valuelen,
                          uint8_t, void *user_data) -> int
    {
        auto *self = static_cast<craft *>(user_data);

        const auto stream_id = static_cast<std::uint32_t>(frame->hd.stream_id);
        auto it = self->h2_pending_.find(stream_id);
        if (it == self->h2_pending_.end())
        {
            return 0;
        }

        // safe: casting nghttp2 header name/value (uint8_t*) to string_view for header field dispatch
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

    auto craft::on_frame_recv(nghttp2_session *, const nghttp2_frame *frame, void *user_data) -> int
    {
        auto *self = static_cast<craft *>(user_data);

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

        // HEADERS 帧完成，调用 handle_connect
        self->handle_connect(stream_id);

        return 0;
    }

    auto craft::on_data(nghttp2_session *, uint8_t, const int32_t stream_id,
                        const uint8_t *data, const size_t len, void *user_data) -> int
    {
        auto *self = static_cast<craft *>(user_data);
        const auto id = static_cast<std::uint32_t>(stream_id);

        // 三路分发
        // 1. h2_pending_ 中存在：sing-mux 模式首帧或 TrustTunnel 首个 CONNECT 已处理
        if (const auto pit = self->h2_pending_.find(id); pit != self->h2_pending_.end())
        {
            auto &entry = pit->second;
            // sing-mux 模式：首个 DATA 帧携带 StreamRequest
            // TODO: 实现 StreamRequest 解析
            return 0;
        }

        // 2. 已连接的 TCP duct
        if (const auto dit = self->ducts_.find(id); dit != self->ducts_.end() && dit->second)
        {
            auto dp = dit->second;
            // safe: casting nghttp2 data frame payload (uint8_t*) to byte vector for duct dispatch
            auto payload = memory::vector<std::byte>(
                reinterpret_cast<const std::byte *>(data),
                reinterpret_cast<const std::byte *>(data) + len);

            net::co_spawn(self->executor(),
                [dp, p = std::move(payload)]() mutable -> net::awaitable<void>
                { co_await dp->on_mux_data(std::move(p)); },
                [dp](const std::exception_ptr &ep)
                {
                    if (ep)
                    {
                        try
                        {
                            std::rethrow_exception(ep);
                        }
                        catch (const std::exception &e)
                        {
                            trace::debug("{} dispatch duct data error: {}", tag, e.what());
                        }
                        catch (...) {}
                        dp->close();
                    }
                });
            return 0;
        }

        // 3. 活跃 UDP parcel
        if (const auto uit = self->parcels_.find(id); uit != self->parcels_.end() && uit->second)
        {
            auto dp = uit->second;
            // safe: casting nghttp2 data frame payload (uint8_t*) to byte vector for parcel dispatch
            memory::vector<std::byte> payload(
                reinterpret_cast<const std::byte *>(data),
                reinterpret_cast<const std::byte *>(data) + len);

            net::co_spawn(self->executor(),
                [dp, p = std::move(payload)]() mutable -> net::awaitable<void>
                { co_await dp->on_mux_data(std::move(p)); },
                [dp](const std::exception_ptr &ep)
                {
                    if (ep)
                    {
                        try
                        {
                            std::rethrow_exception(ep);
                        }
                        catch (const std::exception &e)
                        {
                            trace::debug("{} dispatch parcel data error: {}", tag, e.what());
                        }
                        catch (...) {}
                        dp->close();
                    }
                });
            return 0;
        }

        // 4. 不存在：RST_STREAM
        nghttp2_submit_rst_stream(self->session_, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_PROTOCOL_ERROR);
        return 0;
    }

    auto craft::on_stream_close(nghttp2_session *, const int32_t stream_id,
                                uint32_t, void *user_data) -> int
    {
        auto *self = static_cast<craft *>(user_data);
        const auto id = static_cast<std::uint32_t>(stream_id);

        // 从 h2_pending_ 移除
        self->h2_pending_.erase(id);

        // 从 ducts_ 移除并通知半关闭
        if (const auto it = self->ducts_.find(id); it != self->ducts_.end() && it->second)
        {
            it->second->on_mux_fin();
        }

        // 从 parcels_ 移除并关闭
        if (const auto it = self->parcels_.find(id); it != self->parcels_.end() && it->second)
        {
            it->second->close();
        }

        return 0;
    }

    // ═══════════════════════════════════════════════════════════
    // send_data / send_fin / send_loop
    // ═══════════════════════════════════════════════════════════

    auto craft::send_data(const std::uint32_t stream_id, memory::vector<std::byte> payload) const
        -> net::awaitable<void>
    {
        outbound_data item(mr_);
        item.stream_id = stream_id;
        item.payload = std::move(payload);
        item.is_fin = false;

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        co_await send_channel_.async_send(boost::system::error_code{}, std::move(item), token);
        if (ec)
        {
            trace::debug("{} send_data channel send failed: {}", tag, ec.message());
        }
    }

    void craft::send_fin(const std::uint32_t stream_id)
    {
        auto self = std::static_pointer_cast<craft>(shared_from_this());
        auto send_fn = [self, stream_id]() -> net::awaitable<void>
        {
            outbound_data item(self->mr_);
            item.stream_id = stream_id;
            item.is_fin = true;

            boost::system::error_code ec;
            auto token = net::redirect_error(net::use_awaitable, ec);
            co_await self->send_channel_.async_send(boost::system::error_code{}, std::move(item), token);
        };
        net::co_spawn(executor(), std::move(send_fn), net::detached);
    }

    auto craft::send_loop() -> net::awaitable<void>
    {
        trace::debug("{} send loop started", tag);

        try
        {
            while (is_active())
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                auto item = co_await send_channel_.async_receive(token);
                if (ec)
                {
                    break;
                }

                if (item.is_fin)
                {
                    // RST_STREAM
                    nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE,
                                              static_cast<int32_t>(item.stream_id), NGHTTP2_NO_ERROR);
                    std::error_code pending_ec;
                    co_await send_pending();
                    continue;
                }

                // nghttp2_submit_data + send_pending
                if (item.payload.empty())
                {
                    continue;
                }

                // 拷贝 payload 到 shared buffer，确保 read_callback 期间有效
                auto payload = std::make_shared<memory::vector<std::byte>>(std::move(item.payload));

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
                                                    static_cast<int32_t>(item.stream_id), &dp);
                if (rv != 0)
                {
                    trace::warn("{} nghttp2_submit_data failed: {}", tag, nghttp2_strerror(rv));
                    continue;
                }

                // send_pending 同步调用 read_callback，完成后 src 不再被引用
                co_await send_pending();
                src.reset();
            }
        }
        catch (const std::exception &e)
        {
            trace::debug("{} send loop error: {}", tag, e.what());
        }
        catch (...)
        {
            trace::debug("{} send loop unknown error", tag);
        }

        trace::debug("{} send loop ended", tag);
    }

    // ═══════════════════════════════════════════════════════════
    // 公共接口
    // ═══════════════════════════════════════════════════════════

    auto craft::executor() const -> net::any_io_executor
    {
        return transport_->executor();
    }

    auto craft::wait_first_connect()
        -> net::awaitable<std::optional<h2_headers>>
    {
        if (first_connect_resolved_)
        {
            if (first_connect_.authority.empty())
            {
                co_return std::nullopt;
            }
            co_return std::move(first_connect_);
        }

        boost::system::error_code ec;
        co_await first_connect_waiter_.async_wait(
            net::redirect_error(net::use_awaitable, ec));

        if (first_connect_.authority.empty())
        {
            co_return std::nullopt;
        }
        co_return std::move(first_connect_);
    }

    auto craft::respond_connect(const int32_t stream_id, const std::uint32_t status) -> std::int32_t
    {
        const auto status_str = (status == 200) ? "200" : "407";
        // safe: nghttp2 requires mutable uint8_t* for nv pairs, string literals are cast to non-const for API compat
        nghttp2_nv hdrs[] = {
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":status")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(status_str)),
             7, 3, NGHTTP2_NV_FLAG_NONE}};

        return nghttp2_submit_headers(session_, NGHTTP2_FLAG_NONE,
                                      stream_id, nullptr, hdrs, 1, nullptr);
    }

} // namespace psm::multiplex::h2mux

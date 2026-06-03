#include <prism/multiplex/h2mux/craft.hpp>
#include <prism/connect/dial/dial.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/parcel.hpp>
#include <prism/trace.hpp>
#include <prism/trace/context.hpp>
#include <prism/transport/reliable.hpp>
#include <prism/transport/transmission.hpp>

#include <boost/asio/co_spawn.hpp>

#include <algorithm>
#include <charconv>
#include <cstring>

namespace psm::multiplex::h2mux
{

    namespace
    {
        constexpr std::string_view tag = "[H2mux.Craft]";

        void log_spawn_error(const std::exception_ptr &ep, std::string_view label)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                trace::debug("{} {} error: {}", tag, label, e.what());
            }
            catch (...)
            {
            }
        }
    } // namespace


    craft::craft(core_options opts, craft_init init)
        : core(core_options{std::move(opts.transport), init.router, init.cfg, opts.mr}),
          resolver_(std::move(init.resolver)),
          h2_pending_(mr_),
          send_channel_(transport_->executor(), init.cfg.h2mux.max_streams),
          connect_waiter_(transport_->executor())
    {
        connect_waiter_.expires_after(std::chrono::hours(24));
    }

    craft::~craft() noexcept
    {
        if (session_)
        {
            nghttp2_session_del(session_);
            session_ = nullptr;
        }
    }


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

        if (nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, nullptr, 0) != 0)
        {
            trace::error("{} failed to submit settings", tag);
            return -1;
        }

        trace::debug("{} nghttp2 session initialized", tag);
        return 0;
    }


    auto craft::run() -> net::awaitable<void>
    {
        if (init_nghttp2() != 0)
        {
            trace::error("{} nghttp2 init failed", tag);
            co_return;
        }

        co_await send_pending();

        const auto self = std::static_pointer_cast<craft>(shared_from_this());

        auto send_task = [self]() -> net::awaitable<void>
        {
            trace::active_prefix = nullptr;
            trace::scope_guard guard(self->prefix_);
            co_await self->send_loop();
        };
        net::co_spawn(executor(), std::move(send_task), net::detached);

        co_await frame_loop();

        send_channel_.cancel();
    }

    auto craft::frame_loop() -> net::awaitable<void>
    {
        trace::debug("{} frame loop started", tag);

        memory::vector<std::byte> recv_buf(config_.h2mux.buffer_size, mr_);

        while (active_.load(std::memory_order_acquire))
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
                reinterpret_cast<const std::uint8_t *>(recv_buf.data()),
                n);

            if (recv_len < 0)
            {
                trace::error("{} nghttp2 recv error: {}",
                             tag, nghttp2_strerror(static_cast<std::int32_t>(recv_len)));
                break;
            }

            co_await send_pending();
        }

        if (!connect_resolved_)
        {
            connect_resolved_ = true;
            connect_waiter_.cancel();
        }

        trace::debug("{} frame loop ended", tag);
    }


    auto craft::send_pending() -> net::awaitable<void>
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


    void craft::handle_connect(const std::int32_t stream_id)
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
            auto self = std::static_pointer_cast<craft>(shared_from_this());
            const auto id = static_cast<std::uint32_t>(stream_id);
            auto activate_task = [self, id]() -> net::awaitable<void>
            {
                trace::active_prefix = nullptr;
                trace::scope_guard guard(self->prefix_);
                co_await self->activate_stream(id);
            };
            auto on_error = [](const std::exception_ptr &ep)
            {
                if (ep) log_spawn_error(ep, "activate_stream");
            };
            net::co_spawn(executor(), std::move(activate_task), std::move(on_error));
        }
    }


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
            const auto rc = respond_connect(static_cast<std::int32_t>(stream_id), 200);
            if (rc != 0)
            {
                trace::warn("{} respond_connect for health check stream {} failed: nghttp2 rc={}", tag, stream_id, rc);
            }
            std::error_code ec;
            co_await send_pending();
            nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE,
                                      static_cast<std::int32_t>(stream_id), NGHTTP2_NO_ERROR);
            co_await send_pending();
            trace::debug("{} stream {} health check completed", tag, stream_id);
            co_return;
        }

        case stream_type::udp:
        {
            trace::debug("{} stream {} creating UDP parcel -> {}:{}", tag, stream_id, info.host, info.port);

            const auto rc = respond_connect(static_cast<std::int32_t>(stream_id), 200);
            if (rc != 0)
            {
                trace::warn("{} respond_connect for UDP stream {} failed: nghttp2 rc={}", tag, stream_id, rc);
            }
            std::error_code ec;
            co_await send_pending();

            auto dp = make_parcel(
                parcel_config{
                    .stream_id = stream_id,
                    .idle_timeout = config_.h2mux.udp_idle,
                    .max_dgram = config_.h2mux.max_dgram,
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
            trace::warn("{} stream {} ICMP not yet implemented, treating as TCP", tag, stream_id);
            [[fallthrough]];
        }

        case stream_type::tcp:
        default:
        {
            trace::debug("{} stream {} connecting to {}:{}", tag, stream_id, info.host, info.port);

            char port_buf[8];
            const auto [port_end, port_ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), info.port);
            auto port_str = std::string_view(port_buf, std::distance(port_buf, port_end));
            auto host_str = std::string_view(info.host.data(), info.host.size());
            auto [code, conn] = co_await connect::async_forward(router_, host_str, port_str);

            if (code != fault::code::success || !conn.valid())
            {
                trace::warn("{} stream {} connect to {}:{} failed", tag, stream_id, info.host, info.port);
                nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE,
                                          static_cast<std::int32_t>(stream_id), NGHTTP2_INTERNAL_ERROR);
                co_await send_pending();
                co_return;
            }

            const auto rc = respond_connect(static_cast<std::int32_t>(stream_id), 200);
            if (rc != 0)
            {
                trace::warn("{} respond_connect for TCP stream {} failed: nghttp2 rc={}", tag, stream_id, rc);
            }
            std::error_code send_ec;
            co_await send_pending();

            auto target = transport::make_reliable(std::move(conn));
            const duct_options dopts{
                stream_id, shared_from_this(), std::move(target),
                {config_.h2mux.buffer_size, mr_}};
            const auto p = make_duct(dopts);
            ducts_[stream_id] = p;
            p->start();

            trace::debug("{} stream {} connected to {}:{}", tag, stream_id, info.host, info.port);
        }
        }
    }


    auto craft::on_begin_headers(nghttp2_session *, const nghttp2_frame *frame, void *user_data) -> int
    {
        auto *self = static_cast<craft *>(user_data);

        if (frame->hd.type == NGHTTP2_HEADERS &&
            frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        {
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

        self->handle_connect(stream_id);

        return 0;
    }

    auto craft::on_data(nghttp2_session *, uint8_t, const int32_t stream_id,
                        const uint8_t *data, const size_t len, void *user_data) -> int
    {
        auto *self = static_cast<craft *>(user_data);
        const auto id = static_cast<std::uint32_t>(stream_id);

        if (const auto pit = self->h2_pending_.find(id); pit != self->h2_pending_.end())
        {
            auto &entry = pit->second;
            // TODO: 实现 StreamRequest 解析(#h2mux)
            return 0;
        }

        if (const auto dit = self->ducts_.find(id); dit != self->ducts_.end() && dit->second)
        {
            auto dp = dit->second;
            // safe: casting nghttp2 data frame payload (uint8_t*) to byte vector for duct dispatch
            auto payload = memory::vector<std::byte>(
                reinterpret_cast<const std::byte *>(data),
                reinterpret_cast<const std::byte *>(data) + len, self->mr_);

            auto craft_self = std::static_pointer_cast<craft>(self->shared_from_this());
            auto dispatch_data = [dp, p = std::move(payload), craft_self]() mutable -> net::awaitable<void>
            {
                trace::active_prefix = nullptr;
                trace::scope_guard guard(craft_self->prefix_);
                co_await dp->on_data(std::move(p));
            };
            auto on_duct_error = [dp](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    log_spawn_error(ep, "dispatch duct data");
                    dp->close();
                }
            };
            net::co_spawn(self->executor(), std::move(dispatch_data), std::move(on_duct_error));
            return 0;
        }

        if (const auto uit = self->parcels_.find(id); uit != self->parcels_.end() && uit->second)
        {
            auto dp = uit->second;
            // safe: casting nghttp2 data frame payload (uint8_t*) to byte vector for parcel dispatch
            memory::vector<std::byte> payload(
                reinterpret_cast<const std::byte *>(data),
                reinterpret_cast<const std::byte *>(data) + len, self->mr_);

            auto craft_self = std::static_pointer_cast<craft>(self->shared_from_this());
            auto dispatch_parcel = [dp, p = std::move(payload), craft_self]() mutable -> net::awaitable<void>
            {
                trace::active_prefix = nullptr;
                trace::scope_guard guard(craft_self->prefix_);
                co_await dp->on_data(std::move(p));
            };
            auto on_parcel_error = [dp](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    log_spawn_error(ep, "dispatch parcel data");
                    dp->close();
                }
            };
            net::co_spawn(self->executor(), std::move(dispatch_parcel), std::move(on_parcel_error));
            return 0;
        }

        nghttp2_submit_rst_stream(self->session_, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_PROTOCOL_ERROR);
        return 0;
    }

    auto craft::on_stream_close(nghttp2_session *, const int32_t stream_id,
                                uint32_t, void *user_data) -> int
    {
        auto *self = static_cast<craft *>(user_data);
        const auto id = static_cast<std::uint32_t>(stream_id);

        self->h2_pending_.erase(id);

        if (const auto it = self->ducts_.find(id); it != self->ducts_.end() && it->second)
        {
            it->second->on_fin();
        }

        if (const auto it = self->parcels_.find(id); it != self->parcels_.end() && it->second)
        {
            it->second->close();
        }

        return 0;
    }


    auto craft::send_data(const std::uint32_t stream_id, memory::vector<std::byte> payload) const
        -> net::awaitable<void>
    {
        outbound_data item(mr_);
        item.stream_id = stream_id;
        item.payload = std::move(payload);
        item.is_fin = false;

        boost::system::error_code ec;
        auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
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
            trace::active_prefix = nullptr;
            trace::scope_guard guard(self->prefix_);
            outbound_data item(self->mr_);
            item.stream_id = stream_id;
            item.is_fin = true;

            boost::system::error_code ec;
            auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
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
                auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
                auto item = co_await send_channel_.async_receive(token);
                if (ec)
                {
                    break;
                }

                if (item.is_fin)
                {
                    nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_NONE,
                                              static_cast<std::int32_t>(item.stream_id), NGHTTP2_NO_ERROR);
                    std::error_code pending_ec;
                    co_await send_pending();
                    continue;
                }

                if (item.payload.empty())
                {
                    continue;
                }

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
                                                    static_cast<std::int32_t>(item.stream_id), &dp);
                if (rv != 0)
                {
                    trace::warn("{} nghttp2_submit_data failed: {}", tag, nghttp2_strerror(rv));
                    continue;
                }

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


    auto craft::executor() const -> net::any_io_executor
    {
        return transport_->executor();
    }

    auto craft::wait_first_connect()
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
            net::redirect_error(trace::use_prefix_awaitable, ec));

        if (first_connect_.authority.empty())
        {
            co_return std::nullopt;
        }
        co_return std::move(first_connect_);
    }

    auto craft::respond_connect(const std::int32_t stream_id, const std::uint32_t status) -> std::int32_t
    {
        if (!session_)
            return NGHTTP2_ERR_INVALID_STATE;

        const char *status_str = "407";
        if (status == 200)
            status_str = "200";
        // safe: nghttp2 requires mutable uint8_t* for nv pairs, string literals are cast to non-const for API compat
        auto status_name = const_cast<std::uint8_t *>(reinterpret_cast<const std::uint8_t *>(":status"));
        auto status_val = const_cast<std::uint8_t *>(reinterpret_cast<const std::uint8_t *>(status_str));
        nghttp2_nv hdrs[] = {
            {status_name, status_val, 7, 3, NGHTTP2_NV_FLAG_NONE}};

        return nghttp2_submit_headers(session_, NGHTTP2_FLAG_NONE,
                                      stream_id, nullptr, hdrs, 1, nullptr);
    }

} // namespace psm::multiplex::h2mux

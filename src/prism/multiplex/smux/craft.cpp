#include <prism/multiplex/smux/craft.hpp>
#include <prism/connect/dial/dial.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/parcel.hpp>
#include <prism/trace.hpp>
#include <prism/transport/reliable.hpp>
#include <prism/transport/transmission.hpp>

#include <boost/asio/co_spawn.hpp>

#include <array>
#include <charconv>
#include <span>

namespace
{
    constexpr std::string_view tag = "[Smux.Craft]";
} // namespace

namespace psm::multiplex::smux
{

    namespace
    {
        void log_spawn_error(const std::exception_ptr &ep, const std::uint32_t stream_id, std::string_view label)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                trace::debug("{} stream {} {} error: {}", tag, stream_id, label, e.what());
            }
            catch (...)
            {
                trace::error("{} stream {} {} unknown error", tag, stream_id, label);
            }
        }
    } // namespace

    namespace
    {
        [[nodiscard]] std::array<std::byte, frame_hdrsize> build_header(
            const command cmd, const std::uint32_t stream_id, const std::uint16_t length)
        {
            return {
                std::byte{protocol_version},
                static_cast<std::byte>(cmd),
                static_cast<std::byte>(length & 0xFF),
                static_cast<std::byte>(length >> 8),
                static_cast<std::byte>(stream_id & 0xFF),
                static_cast<std::byte>(stream_id >> 8),
                static_cast<std::byte>(stream_id >> 16),
                static_cast<std::byte>(stream_id >> 24),
            };
        }
    } // namespace

    auto make_data_frame(const std::uint32_t stream_id, const std::span<const std::byte> payload)
        -> memory::vector<std::byte>
    {
        memory::vector<std::byte> buf(memory::current_resource());
        const auto hdr = build_header(command::push, stream_id,
                                      static_cast<std::uint16_t>(payload.size()));
        buf.insert(buf.end(), hdr.begin(), hdr.end());
        buf.insert(buf.end(), payload.begin(), payload.end());
        return buf;
    }


    auto make_syn(const std::uint32_t stream_id)
        -> std::array<std::byte, frame_hdrsize>
    {
        return build_header(command::syn, stream_id, 0);
    }


    auto make_fin(const std::uint32_t stream_id)
        -> std::array<std::byte, frame_hdrsize>
    {
        return build_header(command::fin, stream_id, 0);
    }


    craft::craft(core_options opts)
        : core(std::move(opts)),
          channel_(transport_->executor(), config_.smux.max_streams)
    {
    }

    craft::~craft() noexcept = default;


    auto craft::run()
        -> net::awaitable<void>
    {
        const auto self = std::static_pointer_cast<craft>(shared_from_this());
        auto start_send_loop = [self]() -> net::awaitable<void>
        {
            co_await self->send_loop();
        };
        net::co_spawn(executor(), std::move(start_send_loop), net::detached);

        if (config_.smux.keepalive_interval > 0)
        {
            auto start_keepalive = [self]() -> net::awaitable<void>
            {
                co_await self->keepalive_loop();
            };
            net::co_spawn(executor(), std::move(start_keepalive), net::detached);
        }

        co_await frame_loop();

        channel_.cancel();
    }


    auto craft::frame_loop()
        -> net::awaitable<void>
    {
        trace::debug("{} frame loop started", tag);

        std::error_code ec;
        std::array<std::byte, frame_hdrsize> frame_buffer{};

        while (active_.load(std::memory_order_acquire))
        {
            const auto frame_span = std::span<std::byte>(frame_buffer);
            const auto hdr_n = co_await transport::async_read(*transport_, frame_span, ec);
            if (ec || hdr_n < frame_hdrsize)
            {
                if (ec != std::errc::operation_canceled)
                {
                    trace::debug("{} read header failed: {}", tag, ec.message());
                }
                break;
            }

            const auto hdr_opt = deserialization(frame_buffer);
            if (!hdr_opt)
            {
                trace::warn("{} invalid frame header [{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}]",
                            tag,
                            static_cast<unsigned>(frame_buffer[0]),
                            static_cast<unsigned>(frame_buffer[1]),
                            static_cast<unsigned>(frame_buffer[2]),
                            static_cast<unsigned>(frame_buffer[3]),
                            static_cast<unsigned>(frame_buffer[4]),
                            static_cast<unsigned>(frame_buffer[5]),
                            static_cast<unsigned>(frame_buffer[6]),
                            static_cast<unsigned>(frame_buffer[7]));
                break;
            }

            const auto &hdr = *hdr_opt;

            memory::vector<std::byte> payload(mr_);
            if (hdr.length > 0)
            {
                payload.resize(hdr.length);
                const auto payload_n = co_await transport::async_read(*transport_, payload, ec);
                if (ec || payload_n < hdr.length)
                {
                    trace::debug("{} read payload failed: {}", tag, ec.message());
                    break;
                }
            }

            switch (hdr.cmd)
            {
            case command::syn:
                co_await handle_syn(hdr.stream_id);
                break;

            case command::push:
                dispatch_push(hdr.stream_id, std::move(payload));
                break;

            case command::fin:
                handle_fin(hdr.stream_id);
                break;

            case command::nop:
            default:
                break;
            }
        }

        trace::debug("{} frame loop ended", tag);
    }


    auto craft::handle_syn(const std::uint32_t stream_id)
        -> net::awaitable<void>
    {
        if (pending_.size() + ducts_.size() + parcels_.size() >= config_.smux.max_streams)
        {
            trace::warn("{} max streams reached, rejecting stream {}", tag, stream_id);
            co_return;
        }

        pending_.emplace(stream_id, pending_entry(mr_));
        trace::debug("{} stream {} pending, waiting for address", tag, stream_id);
    }


    void craft::dispatch_push(const std::uint32_t stream_id, memory::vector<std::byte> payload)
    {
        if (const auto pit = pending_.find(stream_id); pit != pending_.end())
        {
            auto &entry = pit->second;
            entry.buffer.insert(entry.buffer.end(), payload.begin(), payload.end());

            if (!entry.connecting && entry.buffer.size() >= 7)
            {
                entry.connecting = true;
                auto self = std::static_pointer_cast<craft>(shared_from_this());
                auto on_error = [stream_id](const std::exception_ptr &ep)
                {
                    if (ep) log_spawn_error(ep, stream_id, "activate_stream");
                };
                net::co_spawn(transport_->executor(), self->activate_stream(stream_id), std::move(on_error));
            }
            return;
        }

        const auto sit = ducts_.find(stream_id);
        if (sit != ducts_.end() && sit->second)
        {
            auto dp = sit->second;

            auto async_push = [dp, p = std::move(payload)]() mutable -> net::awaitable<void>
            { // dp->on_data 可能涉及网络 I/O，异步调用避免阻塞帧循环
                co_await dp->on_data(std::move(p));
            };
            auto on_error = [dp](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    log_spawn_error(ep, 0, "dispatch duct data");
                    dp->close();
                }
            };
            net::co_spawn(executor(), std::move(async_push), std::move(on_error));
            return;
        }

        const auto uit = parcels_.find(stream_id);
        if (uit != parcels_.end() && uit->second)
        {
            auto dp = uit->second;
            auto async_push = [dp, p = std::move(payload)]() mutable -> net::awaitable<void>
            {
                co_await dp->on_data(std::move(p));
            };
            auto on_error = [dp](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    log_spawn_error(ep, 0, "dispatch parcel data");
                    dp->close();
                }
            };
            net::co_spawn(executor(), std::move(async_push), std::move(on_error));
        }
    }


    void craft::handle_fin(const std::uint32_t stream_id)
    {
        if (pending_.erase(stream_id))
        {
            trace::debug("{} stream {} fin while pending", tag, stream_id);
            return;
        }

        if (const auto it = ducts_.find(stream_id); it != ducts_.end() && it->second)
        {
            it->second->on_fin();
            return;
        }

        const auto uit = parcels_.find(stream_id);
        if (uit != parcels_.end() && uit->second)
        {
            uit->second->close();
        }
    }


    auto craft::send_addr_err(const std::uint32_t stream_id)
        -> net::awaitable<void>
    {
        trace::warn("{} stream {} address parse failed", tag, stream_id);
        memory::vector<std::byte> error_buf(mr_);
        error_buf.push_back(std::byte{0x01});
        co_await send_data(stream_id, std::move(error_buf));
        pending_.erase(stream_id);
        send_fin(stream_id);
    }


    auto craft::activate_udp(activate_opts opts)
        -> net::awaitable<void>
    {
        trace::debug("{} stream {} creating UDP parcel", tag, opts.stream_id);

        memory::vector<std::byte> success_buf(mr_);
        success_buf.push_back(std::byte{0x00});
        co_await send_data(opts.stream_id, std::move(success_buf));

        pending_.erase(opts.stream_id);

        addr_mode parcel_addr_mode;
        if (opts.addr == addr_mode::packet_addr)
        {
            parcel_addr_mode = addr_mode::packet_addr;
        }
        else
        {
            parcel_addr_mode = addr_mode::length_prefixed;
        }
        auto dp = make_parcel(
            parcel_config{
                .stream_id = opts.stream_id,
                .idle_timeout = config_.smux.idle_timeout,
                .max_dgram = config_.smux.max_dgram,
                .mr = mr_,
                .mode = parcel_addr_mode,
            },
            shared_from_this(), router_);
        if (opts.addr == addr_mode::length_prefixed)
        {
            dp->set_destination(opts.host, opts.port);
        }

        if (active_.load(std::memory_order_acquire))
        {
            parcels_[opts.stream_id] = dp;
            dp->start();

            if (!opts.remaining.empty())
            {
                co_await dp->on_data(std::move(opts.remaining));
            }
        }
        else
        {
            dp->close();
        }

        trace::debug("{} stream {} UDP parcel created", tag, opts.stream_id);
    }


    auto craft::activate_tcp(activate_opts opts)
        -> net::awaitable<void>
    {
        trace::debug("{} stream {} connecting to {}:{}", tag, opts.stream_id, opts.host, opts.port);

        char port_buf[8];
        const auto [port_end, port_ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), opts.port);
        auto port_str = std::string_view(port_buf, std::distance(port_buf, port_end));
        auto [code, conn] = co_await connect::async_forward(router_, opts.host, port_str);

        if (code != fault::code::success || !conn.valid())
        {
            trace::warn("{} stream {} connect to {}:{} failed", tag, opts.stream_id, opts.host, opts.port);
            memory::vector<std::byte> error_buf(mr_);
            error_buf.push_back(std::byte{0x01});
            co_await send_data(opts.stream_id, std::move(error_buf));
            pending_.erase(opts.stream_id);
            send_fin(opts.stream_id);
            co_return;
        }

        memory::vector<std::byte> success_buf(mr_);
        success_buf.push_back(std::byte{0x00});
        co_await send_data(opts.stream_id, std::move(success_buf));

        pending_.erase(opts.stream_id);

        auto target = transport::make_reliable(std::move(conn));
        const duct_options dopts{
            opts.stream_id, shared_from_this(), std::move(target),
            {config_.smux.buffer_size, mr_}};
        const auto p = make_duct(dopts);
        ducts_[opts.stream_id] = p;

        p->start();

        if (!opts.remaining.empty())
        {
            co_await p->on_data(std::move(opts.remaining));
        }

        trace::debug("{} stream {} connected to {}:{}", tag, opts.stream_id, opts.host, opts.port);
    }


    auto craft::activate_stream(const std::uint32_t stream_id)
        -> net::awaitable<void>
    {
        const auto pit = pending_.find(stream_id);
        if (pit == pending_.end())
        {
            co_return;
        }

        auto &entry = pit->second;
        auto addr = parse_address(entry.buffer, mr_);
        if (!addr)
        {
            if (entry.buffer.size() < 21)
            {
                entry.connecting = false;
                co_return;
            }
            co_await send_addr_err(stream_id);
            co_return;
        }

        auto host = std::move(addr->host);
        const auto port = addr->port;
        const auto offset = addr->offset;
        const bool is_udp = addr->is_udp;
        const auto addr_type = addr->addr;

        memory::vector<std::byte> remaining_data(mr_);
        if (offset < entry.buffer.size())
        {
            const auto remaining = std::span<const std::byte>(entry.buffer).subspan(offset);
            remaining_data.assign(remaining.begin(), remaining.end());
        }

        if (is_udp)
        {
            activate_opts udp_opts{
                .stream_id = stream_id,
                .host = std::move(host),
                .port = port,
                .addr = addr_type,
                .remaining = std::move(remaining_data)};
            co_await activate_udp(std::move(udp_opts));
        }
        else
        {
            activate_opts tcp_opts;
            tcp_opts.stream_id = stream_id;
            tcp_opts.host = std::move(host);
            tcp_opts.port = port;
            tcp_opts.remaining = std::move(remaining_data);
            co_await activate_tcp(std::move(tcp_opts));
        }
    }


    auto craft::send_data(const std::uint32_t stream_id, memory::vector<std::byte> payload) const
        -> net::awaitable<void>
    {
        co_await push_frame(command::push, stream_id, std::move(payload));
    }


    void craft::send_fin(const std::uint32_t stream_id)
    {
        auto self = std::static_pointer_cast<craft>(shared_from_this());
        auto send_fn = [self, stream_id]() -> net::awaitable<void>
        {
            memory::vector<std::byte> empty_payload(self->mr_);
            co_await self->push_frame(command::fin, stream_id, std::move(empty_payload));
        };
        auto callback = [stream_id](const std::exception_ptr &ep)
        {
            if (ep) log_spawn_error(ep, stream_id, "send_fin");
        };
        net::co_spawn(transport_->executor(), send_fn, callback);
    }


    auto craft::executor() const
        -> net::any_io_executor
    {
        return transport_->executor();
    }


    auto craft::push_frame(const command cmd, const std::uint32_t stream_id, memory::vector<std::byte> payload) const
        -> net::awaitable<void>
    {
        outbound_frame frame(mr_);
        frame.header = build_header(cmd, stream_id, static_cast<std::uint16_t>(payload.size()));
        frame.payload = std::move(payload);

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        co_await channel_.async_send(boost::system::error_code{}, std::move(frame), token);
        if (ec)
        {
            trace::debug("{} push frame to channel failed: {}", tag, ec.message());
        }
    }


    auto craft::send_loop()
        -> net::awaitable<void>
    {
        trace::debug("{} send loop started", tag);
        try
        {
            while (is_active())
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                auto frame = co_await channel_.async_receive(token);
                if (ec)
                {
                    break;
                }

                std::error_code transport_ec;
                if (!frame.payload.empty())
                {
                    const std::size_t total_size = frame.header.size() + frame.payload.size();
                    memory::vector<std::byte> combined(total_size, mr_);
                    std::memcpy(combined.data(), frame.header.data(), frame.header.size());
                    std::memcpy(combined.data() + frame.header.size(), frame.payload.data(), frame.payload.size());
                    co_await transport::async_write(*transport_, combined, transport_ec);
                }
                else
                {
                    co_await transport::async_write(*transport_,
                        std::span<const std::byte>(frame.header.data(), frame.header.size()), transport_ec);
                }

                if (transport_ec)
                {
                    trace::debug("{} send frame failed: {}", tag, transport_ec.message());
                    close();
                    break;
                }
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


    auto craft::keepalive_loop()
        -> net::awaitable<void>
    {
        trace::debug("{} keepalive loop started, interval={}ms", tag, config_.smux.keepalive_interval);
        net::steady_timer timer(executor());
        try
        {
            while (is_active())
            {
                timer.expires_after(std::chrono::milliseconds(config_.smux.keepalive_interval));
                boost::system::error_code ec;
                co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
                if (ec || !is_active())
                {
                    break;
                }
                co_await push_frame(command::nop, 0, memory::vector<std::byte>(mr_));
            }
        }
        catch (const std::exception &e)
        {
            trace::debug("{} keepalive loop error: {}", tag, e.what());
        }
        catch (...)
        {
        }
        trace::debug("{} keepalive loop ended", tag);
    }

} // namespace psm::multiplex::smux

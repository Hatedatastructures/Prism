#include <prism/proto/multiplex/yamux/craft.hpp>
#include <prism/net/connect/dial/dial.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/proto/multiplex/duct.hpp>
#include <prism/proto/multiplex/parcel.hpp>
#include <prism/proto/multiplex/smux/frame.hpp>
#include <prism/trace/trace.hpp>
#include <prism/trace/context.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio/co_spawn.hpp>

#include <array>
#include <charconv>

namespace
{

    constexpr std::size_t max_frame_payload = 65535;
} // namespace

using namespace psm::trace;

namespace psm::multiplex::yamux
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
                trace::debug<flt::conn | flt::protocol>("stream {} {} error: {}", stream_id, label, e.what());
            }
            catch (...)
            {
                trace::error<flt::conn | flt::protocol>("stream {} {} unknown error", stream_id, label);
            }
        }
    } // namespace


    craft::craft(core_options opts)
        : core(std::move(opts)),
          channel_(transport_->executor(), config_.yamux.max_streams),
          windows_(mr_)
    {
        trace::debug<flt::conn | flt::protocol>("constructed");
    }

    craft::~craft() noexcept = default;


    auto craft::run()
        -> net::awaitable<void>
    {
        const auto self = std::static_pointer_cast<craft>(shared_from_this());
        auto start_send_loop = [self]() -> net::awaitable<void>
        {
            trace::active_prefix = nullptr;
            trace::scope_guard guard(self->prefix_);
            co_await self->send_loop();
        };
        net::co_spawn(executor(), std::move(start_send_loop), net::detached);

        if (config_.yamux.enable_ping && config_.yamux.ping_interval > 0)
        {
            auto start_ping = [self]() -> net::awaitable<void>
            {
                trace::active_prefix = nullptr;
                trace::scope_guard guard(self->prefix_);
                co_await self->ping_loop();
            };
            net::co_spawn(executor(), std::move(start_ping), net::detached);
        }

        co_await frame_loop();

        channel_.cancel();
    }


    auto craft::frame_loop()
        -> net::awaitable<void>
    {
        trace::debug<flt::conn | flt::protocol>("frame loop started");

        std::error_code ec;

        while (active_.load(std::memory_order_acquire))
        {
            const auto recv_span = std::span<std::byte>(recv_buffer_);
            const auto hdr_n = co_await transport::async_read(*transport_, recv_span, ec);
            if (ec || hdr_n < frame_hdrsize)
            {
                if (ec != std::errc::operation_canceled)
                {
                    trace::debug<flt::conn | flt::protocol>("read header failed: {}", ec.message());
                }
                break;
            }

            const auto hdr_opt = parse_header(recv_buffer_);
            if (!hdr_opt)
            {
                trace::warn<flt::conn | flt::protocol>("invalid frame header");
                break;
            }

            const auto &hdr = *hdr_opt;

            memory::vector<std::byte> payload(mr_);
            if (hdr.type == message_type::data && hdr.length > 0)
            {
                if (hdr.length > max_frame_payload)
                {
                    trace::warn<flt::conn | flt::protocol>("oversized Data frame: stream={}, length={}", hdr.stream_id, hdr.length);
                    co_await push_frame({message_type::go_away, flags::none, 0,
                                        static_cast<std::uint32_t>(away_code::protocol_error), {}});
                    break;
                }
                payload.resize(hdr.length);
                const auto payload_n = co_await transport::async_read(*transport_, payload, ec);
                if (ec || payload_n < hdr.length)
                {
                    trace::debug<flt::conn | flt::protocol>("read payload failed: {}", ec.message());
                    break;
                }
            }

            switch (hdr.type)
            {
            case message_type::data:
                co_await handle_data(hdr, std::move(payload));
                break;

            case message_type::window_update:
                co_await handle_winupd(hdr);
                break;

            case message_type::ping:
                co_await handle_ping(hdr);
                break;

            case message_type::go_away:
                co_await handle_goaway(hdr);
                break;
            }
        }

        trace::debug<flt::conn | flt::protocol>("frame loop ended");
    }


    auto craft::handle_data(const frame_header &hdr, memory::vector<std::byte> payload)
        -> net::awaitable<void>
    {
        const auto stream_id = hdr.stream_id;

        if (has_flag(hdr.flag, flags::syn))
        {
            co_await handle_syn(stream_id, std::move(payload));
            co_return;
        }

        if (has_flag(hdr.flag, flags::rst))
        {
            handle_rst(stream_id);
            co_return;
        }

        if (has_flag(hdr.flag, flags::fin))
        {
            handle_fin(stream_id);
            co_return;
        }

        co_await dispatch_data(stream_id, std::move(payload));
    }


    auto craft::handle_syn(const std::uint32_t stream_id, memory::vector<std::byte> payload)
        -> net::awaitable<void>
    {
        if (pending_.size() + ducts_.size() + parcels_.size() >= config_.yamux.max_streams)
        {
            trace::warn<flt::conn | flt::protocol>("max streams reached, rejecting stream {}", stream_id);
            co_await push_frame({message_type::window_update, flags::rst, stream_id, 0, {}});
            co_return;
        }

        auto [it, inserted] = pending_.emplace(stream_id, pending_entry(mr_));
        if (!inserted)
        {
            trace::warn<flt::conn | flt::protocol>("duplicate SYN for stream {}", stream_id);
            co_return;
        }

        if (!payload.empty())
        {
            it->second.buffer.insert(it->second.buffer.end(), payload.begin(), payload.end());
        }

        auto *window = ensure_window(stream_id);
        if (!window)
        {
            trace::warn<flt::conn | flt::protocol>("ensure_window failed for stream {}", stream_id);
        }

        start_pending(stream_id);

        frame_data winupd{message_type::window_update, flags::ack, stream_id, config_.yamux.initial_window, {}};
        co_await push_frame(std::move(winupd));

        try_activate_pending(stream_id);
    }


    void craft::handle_rst(const std::uint32_t stream_id)
    {
        pending_.erase(stream_id);

        if (const auto it = ducts_.find(stream_id); it != ducts_.end() && it->second)
        {
            it->second->on_fin();
        }

        if (const auto it = parcels_.find(stream_id); it != parcels_.end() && it->second)
        {
            it->second->close();
        }

        if (const auto wit = windows_.find(stream_id); wit != windows_.end())
        {
            wit->second->window_signal->cancel();
        }
        windows_.erase(stream_id);
        trace::debug<flt::conn | flt::protocol>("stream {} reset", stream_id);
    }


    void craft::handle_fin(const std::uint32_t stream_id)
    {
        if (pending_.erase(stream_id))
        {
            trace::debug<flt::conn | flt::protocol>("stream {} fin while pending", stream_id);
            if (const auto wit = windows_.find(stream_id); wit != windows_.end())
            {
                wit->second->window_signal->cancel();
            }
            windows_.erase(stream_id);
            return;
        }

        if (const auto it = ducts_.find(stream_id); it != ducts_.end() && it->second)
        {
            it->second->on_fin();
            return;
        }

        if (const auto it = parcels_.find(stream_id); it != parcels_.end() && it->second)
        {
            it->second->close();
        }

        trace::debug<flt::conn | flt::protocol>("stream {} fin", stream_id);
    }


    auto craft::dispatch_data(const std::uint32_t stream_id, memory::vector<std::byte> payload)
        -> net::awaitable<void>
    {
        if (const auto pit = pending_.find(stream_id); pit != pending_.end())
        {
            auto &entry = pit->second;
            if (!payload.empty())
            {
                entry.buffer.insert(entry.buffer.end(), payload.begin(), payload.end());
            }

            try_activate_pending(stream_id);

            if (!payload.empty())
            {
                co_await update_recv_win(stream_id, static_cast<std::uint32_t>(payload.size()));
            }
            co_return;
        }

        if (const auto it = ducts_.find(stream_id); it != ducts_.end() && it->second)
        {
            if (!payload.empty())
            {
                co_await update_recv_win(stream_id, static_cast<std::uint32_t>(payload.size()));
            }

            auto dp = it->second;
            auto self = std::static_pointer_cast<craft>(shared_from_this());
            auto async_push = [dp, p = std::move(payload), self]() mutable -> net::awaitable<void>
            {
                trace::active_prefix = nullptr;
                trace::scope_guard guard(self->prefix_);
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
            co_return;
        }

        if (const auto it = parcels_.find(stream_id); it != parcels_.end() && it->second)
        {
            if (!payload.empty())
            {
                co_await update_recv_win(stream_id, static_cast<std::uint32_t>(payload.size()));
            }

            auto dp = it->second;
            auto self = std::static_pointer_cast<craft>(shared_from_this());
            auto async_push = [dp, p = std::move(payload), self]() mutable -> net::awaitable<void>
            {
                trace::active_prefix = nullptr;
                trace::scope_guard guard(self->prefix_);
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
            co_return;
        }

        trace::debug<flt::conn | flt::protocol>("data for unknown stream {}", stream_id);
        co_await push_frame({message_type::window_update, flags::rst, stream_id, 0, {}});
    }


    void craft::try_activate_pending(const std::uint32_t stream_id)
    {
        const auto pit = pending_.find(stream_id);
        if (pit == pending_.end())
        {
            return;
        }
        auto &entry = pit->second;

        if (entry.connecting || entry.buffer.size() < 7)
        {
            return;
        }

        entry.connecting = true;
        const auto self = std::static_pointer_cast<craft>(shared_from_this());
        auto callback = [stream_id](const std::exception_ptr &ep)
        {
            if (ep) log_spawn_error(ep, stream_id, "activate");
        };
        auto activate_fn = [self, stream_id]() -> net::awaitable<void>
        {
            trace::active_prefix = nullptr;
            trace::scope_guard guard(self->prefix_);
            co_await self->activate_stream(stream_id);
        };
        net::co_spawn(transport_->executor(), std::move(activate_fn), callback);
    }


    auto craft::handle_winupd(const frame_header &hdr)
        -> net::awaitable<void>
    {
        const auto stream_id = hdr.stream_id;
        const auto delta = hdr.length;

        if (stream_id == 0)
        {
            co_return;
        }

        if (has_flag(hdr.flag, flags::rst))
        {
            pending_.erase(stream_id);
            if (const auto dit = ducts_.find(stream_id); dit != ducts_.end() && dit->second)
            {
                dit->second->on_fin();
            }
            if (const auto pit = parcels_.find(stream_id); pit != parcels_.end() && pit->second)
            {
                pit->second->close();
            }
            if (const auto wit = windows_.find(stream_id); wit != windows_.end())
            {
                wit->second->window_signal->cancel();
            }
            windows_.erase(stream_id);
            trace::debug<flt::conn | flt::protocol>("stream {} reset via window update", stream_id);
            co_return;
        }

        if (has_flag(hdr.flag, flags::fin))
        {
            if (pending_.erase(stream_id))
            {
                windows_.erase(stream_id);
                co_return;
            }

            if (const auto dit = ducts_.find(stream_id); dit != ducts_.end() && dit->second)
            {
                dit->second->on_fin();
            }
            co_return;
        }

        if (has_flag(hdr.flag, flags::syn) && !has_flag(hdr.flag, flags::ack))
        {
            if (pending_.size() + ducts_.size() + parcels_.size() >= config_.yamux.max_streams)
            {
                trace::warn<flt::conn | flt::protocol>("max streams reached, rejecting stream {}", stream_id);
                co_await push_frame({message_type::window_update, flags::rst, stream_id, 0, {}});
                co_return;
            }

            auto [it, inserted] = pending_.emplace(stream_id, pending_entry(mr_));
            if (!inserted)
            {
                trace::warn<flt::conn | flt::protocol>("duplicate SYN for stream {}", stream_id);
                co_return;
            }

            auto *window = ensure_window(stream_id);
            std::uint32_t client_window;
            if (delta > 0)
            {
                client_window = delta;
            }
            else
            {
                client_window = config_.yamux.initial_window;
            }
            window->send_window.store(client_window, std::memory_order_release);

            frame_data winack{message_type::window_update, flags::ack, stream_id, config_.yamux.initial_window, {}};
            co_await push_frame(std::move(winack));

            start_pending(stream_id);

            trace::debug<flt::conn | flt::protocol>("stream {} opened via window update syn, client_window={}, using_window={}",
                         stream_id, delta, client_window);
            co_return;
        }

        if (has_flag(hdr.flag, flags::syn) && has_flag(hdr.flag, flags::ack))
        {
            trace::debug<flt::conn | flt::protocol>("stream {} syn+ack received", stream_id);
            co_return;
        }

        if (auto *window = get_window(stream_id); window && delta > 0)
        {
            std::uint32_t old_val = window->send_window.load(std::memory_order_acquire);
            std::uint32_t new_val;
            do
            {
                new_val = old_val + delta;
                if (new_val < old_val)
                {
                    new_val = std::numeric_limits<std::uint32_t>::max();
                }
            } while (!window->send_window.compare_exchange_weak(old_val, new_val, std::memory_order_acq_rel));
            trace::debug<flt::conn | flt::protocol>("stream {} window update received, delta={}, new_window={}", stream_id, delta, new_val);

            window->window_signal->cancel();
        }

        co_return;
    }


    auto craft::handle_ping(const frame_header &hdr) const
        -> net::awaitable<void>
    {
        if (has_flag(hdr.flag, flags::syn) && config_.yamux.enable_ping)
        {
            co_await push_frame({message_type::ping, flags::ack, 0, hdr.length, {}});
            co_return;
        }

        if (has_flag(hdr.flag, flags::ack))
        {
        }

        co_return;
    }


    auto craft::handle_goaway(const frame_header &hdr)
        -> net::awaitable<void>
    {
        const auto code = static_cast<away_code>(hdr.length);
        trace::debug<flt::conn | flt::protocol>("go away received, code={}", static_cast<std::uint32_t>(code));
        close();
        co_return;
    }


    auto craft::send_addr_err(const std::uint32_t stream_id)
        -> net::awaitable<void>
    {
        trace::warn<flt::conn | flt::protocol>("stream {} address parse failed", stream_id);
        memory::vector<std::byte> error_buf(mr_);
        error_buf.push_back(std::byte{0x01});
        co_await send_data(stream_id, std::move(error_buf));
        pending_.erase(stream_id);
        send_fin(stream_id);
    }


    auto craft::activate_udp(activate_opts opts)
        -> net::awaitable<void>
    {
        trace::debug<flt::conn | flt::protocol>("stream {} creating UDP parcel", opts.stream_id);

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
                .idle_timeout = config_.yamux.udp_idle,
                .max_dgram = config_.yamux.max_dgram,
                .mr = mr_,
                .mode = parcel_addr_mode,
            },
            shared_from_this(), router_);
        if (opts.addr == addr_mode::length_prefixed)
        {
            dp->set_destination(opts.host, opts.port);
        }

        if (!active_.load(std::memory_order_acquire))
        {
            dp->close();
            co_return;
        }

        parcels_[opts.stream_id] = dp;

        dp->start();

        if (!opts.remaining.empty())
        {
            co_await dp->on_data(std::move(opts.remaining));
        }

        trace::debug<flt::conn | flt::protocol>("stream {} UDP parcel created", opts.stream_id);
    }


    auto craft::activate_tcp(activate_opts opts)
        -> net::awaitable<void>
    {
        trace::debug<flt::conn | flt::protocol>("stream {} connecting to {}:{}", opts.stream_id, opts.host, opts.port);

        char port_buf[8];
        const auto [port_end, port_ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), opts.port);
        auto port_str = std::string_view(port_buf, std::distance(port_buf, port_end));
        auto [code, conn] = co_await connect::async_forward(router_, opts.host, port_str);

        if (code != fault::code::success || !conn.valid())
        {
            trace::warn<flt::conn | flt::protocol>("stream {} connect to {}:{} failed", opts.stream_id, opts.host, opts.port);
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
            {config_.yamux.buffer_size, mr_}};
        const auto p = make_duct(dopts);
        ducts_[opts.stream_id] = p;

        p->start();

        if (!opts.remaining.empty())
        {
            co_await p->on_data(std::move(opts.remaining));
        }

        trace::debug<flt::conn | flt::protocol>("stream {} connected to {}:{}", opts.stream_id, opts.host, opts.port);
    }


    auto craft::activate_stream(const std::uint32_t stream_id)
        -> net::awaitable<void>
    {
        const auto pit = pending_.find(stream_id);
        if (pit == pending_.end())
        {
            co_return;
        }

        if (const auto tit = pending_timers_.find(stream_id); tit != pending_timers_.end())
        {
            tit->second->cancel();
            pending_timers_.erase(tit);
        }

        auto &entry = pit->second;
        memory::vector<std::byte> local_buffer(mr_);
        local_buffer.swap(entry.buffer);

        auto addr = smux::parse_address(local_buffer, mr_);
        if (!addr)
        {
            if (local_buffer.size() < 21)
            {
                entry.buffer.swap(local_buffer);
                entry.connecting = false;
                co_return;
            }
            co_await send_addr_err(stream_id);
            co_return;
        }

        const auto host = std::move(addr->host);
        const auto port = addr->port;
        const auto offset = addr->offset;
        const bool is_udp = addr->is_udp;
        const auto addr_type = addr->addr;

        memory::vector<std::byte> remaining_data(mr_);
        if (offset < local_buffer.size())
        {
            const auto remaining = std::span<const std::byte>(local_buffer).subspan(offset);
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


    void craft::start_pending(const std::uint32_t stream_id)
    {
        if (config_.yamux.open_timeout == 0)
        {
            return;
        }

        auto timer = std::make_shared<net::steady_timer>(executor());
        timer->expires_after(std::chrono::milliseconds(config_.yamux.open_timeout));
        pending_timers_[stream_id] = timer;

        auto self = std::static_pointer_cast<craft>(shared_from_this());
        auto timeout_task = [self, stream_id, timer = std::move(timer)]() -> net::awaitable<void>
        {
            trace::active_prefix = nullptr;
            trace::scope_guard guard(self->prefix_);
            co_return co_await self->pending_timeout(stream_id, std::move(timer));
        };
        net::co_spawn(executor(), std::move(timeout_task), net::detached);
    }


    auto craft::pending_timeout(const std::uint32_t stream_id, std::shared_ptr<net::steady_timer> timer)
        -> net::awaitable<void>
    {
        boost::system::error_code ec;
        co_await timer->async_wait(net::redirect_error(trace::use_prefix_awaitable, ec));
        if (ec)
        {
            co_return;
        }
        if (pending_.count(stream_id))
        {
            trace::warn<flt::conn | flt::protocol>("stream {} open timeout, resetting", stream_id);
            pending_.erase(stream_id);
            pending_timers_.erase(stream_id);
            windows_.erase(stream_id);
            co_await push_frame({message_type::window_update, flags::rst, stream_id, 0, {}});
        }
    }


    stream_window *craft::ensure_window(const std::uint32_t stream_id)
    {
        if (const auto it = windows_.find(stream_id); it != windows_.end())
        {
            return it->second.get();
        }

        auto win = std::make_unique<stream_window>(transport_->executor());
        auto [new_it, inserted] = windows_.emplace(stream_id, std::move(win));
        return new_it->second.get();
    }


    stream_window *craft::get_window(const std::uint32_t stream_id) const
    {
        if (const auto it = windows_.find(stream_id); it != windows_.end())
        {
            return it->second.get();
        }
        return nullptr;
    }


    auto craft::update_recv_win(const std::uint32_t stream_id, const std::uint32_t consumed)
        -> net::awaitable<void>
    {
        auto *window = ensure_window(stream_id);
        if (!window)
        {
            co_return;
        }

        const std::uint32_t total_consumed = window->recv_consumed.fetch_add(consumed, std::memory_order_acq_rel) + consumed;

        if (total_consumed >= config_.yamux.initial_window / 2)
        {
            window->recv_consumed.store(0, std::memory_order_release);

            const std::uint32_t delta = total_consumed;
            co_await push_frame({message_type::window_update, flags::none, stream_id, delta, {}});

            trace::debug<flt::conn | flt::protocol>("stream {} window update sent, delta={}", stream_id, delta);
        }
    }


    auto craft::send_data(const std::uint32_t stream_id, memory::vector<std::byte> payload) const
        -> net::awaitable<void>
    {
        const auto payload_size = static_cast<std::uint32_t>(payload.size());

        if (auto *window = get_window(stream_id); window)
        {
            auto window_acquired = false;

            while (!window_acquired && is_active())
            {
                auto old_val = window->send_window.load(std::memory_order_acquire);
                while (old_val >= payload_size)
                {
                    if (window->send_window.compare_exchange_weak(old_val, old_val - payload_size, std::memory_order_acq_rel))
                    {
                        window_acquired = true;
                        break;
                    }
                }

                if (window_acquired)
                {
                    break;
                }

                auto signal = window->window_signal;
                signal->expires_at(net::steady_timer::time_point::max());
                boost::system::error_code wait_ec;
                co_await signal->async_wait(net::redirect_error(trace::use_prefix_awaitable, wait_ec));
                if (wait_ec != net::error::operation_aborted)
                {
                    if (!is_active())
                    {
                        co_return;
                    }
                    continue;
                }
                window = get_window(stream_id);
                if (!window)
                {
                    trace::debug<flt::conn | flt::protocol>("stream {} window removed while waiting", stream_id);
                    co_return;
                }
            }

            if (!window_acquired)
            {
                co_return;
            }
        }

        co_await push_frame({message_type::data, flags::none, stream_id, payload_size, std::move(payload)});
    }


    void craft::send_fin(const std::uint32_t stream_id)
    {
        auto self = std::static_pointer_cast<craft>(shared_from_this());
        auto send_fn = [self, stream_id]() -> net::awaitable<void>
        {
            trace::active_prefix = nullptr;
            trace::scope_guard guard(self->prefix_);
            co_await self->push_frame({message_type::data, flags::fin, stream_id, 0, {}});
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


    void craft::close()
    {
        for (auto &[id, timer] : pending_timers_)
        {
            timer->cancel();
        }
        pending_timers_.clear();

        core::close();

        for (auto &[id, window] : windows_)
        {
            window->window_signal->cancel();
        }
        windows_.clear();
    }


    void craft::remove_duct(const std::uint32_t stream_id)
    {
        if (const auto it = windows_.find(stream_id); it != windows_.end())
        {
            it->second->window_signal->cancel();
        }
        windows_.erase(stream_id);
        core::remove_duct(stream_id);
    }


    void craft::remove_parcel(const std::uint32_t stream_id)
    {
        if (const auto it = windows_.find(stream_id); it != windows_.end())
        {
            it->second->window_signal->cancel();
        }
        windows_.erase(stream_id);
        core::remove_parcel(stream_id);
    }


    auto craft::push_frame(frame_data data) const
        -> net::awaitable<void>
    {
        outbound_frame frame(mr_);
        frame_header hdr{};
        hdr.type = data.type;
        hdr.flag = data.f;
        hdr.stream_id = data.stream_id;
        hdr.length = data.length;
        frame.header = build_header(hdr);
        frame.payload = std::move(data.payload);

        boost::system::error_code ec;
        auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
        co_await channel_.async_send(boost::system::error_code{}, std::move(frame), token);
        if (ec)
        {
            trace::debug<flt::conn | flt::protocol>("push frame to channel failed: {}", ec.message());
        }
    }


    auto craft::send_loop()
        -> net::awaitable<void>
    {
        trace::debug<flt::conn | flt::protocol>("send loop started");
        try
        {
            while (is_active())
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(trace::use_prefix_awaitable, ec);
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
                    trace::debug<flt::conn | flt::protocol>("send frame failed: {}", transport_ec.message());
                    close();
                    break;
                }
            }
        }
        catch (const std::exception &e)
        {
            trace::debug<flt::conn | flt::protocol>("send loop error: {}", e.what());
        }
        catch (...)
        {
            trace::debug<flt::conn | flt::protocol>("send loop unknown error");
        }
        trace::debug<flt::conn | flt::protocol>("send loop ended");
    }


    auto craft::ping_loop()
        -> net::awaitable<void>
    {
        trace::debug<flt::conn | flt::protocol>("ping loop started, interval={}ms", config_.yamux.ping_interval);
        net::steady_timer timer(executor());
        try
        {
            while (is_active())
            {
                timer.expires_after(std::chrono::milliseconds(config_.yamux.ping_interval));
                boost::system::error_code ec;
                co_await timer.async_wait(net::redirect_error(trace::use_prefix_awaitable, ec));
                if (ec || !is_active())
                {
                    break;
                }
                const auto id = ping_id_.fetch_add(1, std::memory_order_relaxed) + 1;
                co_await push_frame({message_type::ping, flags::syn, 0, id, {}});
            }
        }
        catch (const std::exception &e)
        {
            trace::debug<flt::conn | flt::protocol>("ping loop error: {}", e.what());
        }
        catch (...)
        {
        }
        trace::debug<flt::conn | flt::protocol>("ping loop ended");
    }

} // namespace psm::multiplex::yamux

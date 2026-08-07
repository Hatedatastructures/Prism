#include <prism/protocol/multiplex/yamux/control.hpp>

#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/outbound/direct.hpp>
#include <prism/protocol/multiplex/datagram.hpp>
#include <prism/protocol/multiplex/smux/frame.hpp>
#include <prism/protocol/multiplex/stream.hpp>
#include <prism/diagnose/diagnose.hpp>

#include <boost/asio/co_spawn.hpp>

#include <array>
#include <charconv>
#include <limits>
#include <span>

using namespace psm::diagnose;

namespace
{

    constexpr std::size_t max_frame_payload = 65535;
} // namespace

namespace psm::multiplex::yamux
{

    namespace
    {
        void log_spawn_error(const std::exception_ptr &ep, const std::uint32_t stream_id,
                             std::string_view label, const std::shared_ptr<diagnose::context> &prefix)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                diagnose::debug(prefix, "stream {} {} error: {}", stream_id, label, e.what());
            }
            catch (...)
            {
                diagnose::error(prefix, "stream {} {} unknown error", stream_id, label);
            }
        }
    } // namespace

    control::control(multiplexer_options opts)
        : multiplexer(multiplexer_options{
              std::move(opts.transport), opts.outbound, opts.cfg, opts.mr,
              opts.cfg.yamux.max_streams}),
          router_fn_(outbound_ ? outbound_->make_router() : decltype(router_fn_){}),
          windows_(mr_),
          pending_timers_(mr_),
          udp_bufs_(mr_)
    {
        diagnose::debug(prefix_, "constructed");
    }


    control::~control() noexcept = default;


    auto control::run()
        -> net::awaitable<void>
    {
        if (config_.yamux.enable_ping && config_.yamux.ping_interval > 0)
        {
            auto self = std::static_pointer_cast<control>(shared_from_this());
            auto start_ping = [self]() -> net::awaitable<void>
            {
                co_await self->ping_loop();
            };
            net::co_spawn(transport_->executor(), std::move(start_ping), net::detached);
        }

        co_await frame_loop();
    }


    auto control::send(const std::uint32_t stream_id, memory::vector<std::byte> payload)
        -> net::awaitable<void>
    {
        if (!is_active())
        {
            co_return;
        }

        const auto payload_size = static_cast<std::uint32_t>(payload.size());

        // 发送窗口流控：扣减 send_window，不足时等待 WindowUpdate 唤醒
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
                co_await signal->async_wait(net::redirect_error(net::use_awaitable, wait_ec));
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
                    diagnose::debug(prefix_, "stream {} window removed while waiting", stream_id);
                    co_return;
                }
            }

            if (!window_acquired)
            {
                co_return;
            }
        }

        outbound_frame frame;
        frame.stream_id = stream_id;
        frame.payload = std::move(payload);
        frame.kind = outbound_kind::data;
        co_await push_frame(std::move(frame));
    }


    void control::close()
    {
        for (auto &[id, timer] : pending_timers_)
        {
            timer->cancel();
        }
        pending_timers_.clear();

        multiplexer::close();

        for (auto &[id, window] : windows_)
        {
            window->window_signal->cancel();
        }
        windows_.clear();
    }


    void control::drop(const std::uint32_t stream_id)
    {
        if (const auto it = windows_.find(stream_id); it != windows_.end())
        {
            it->second->window_signal->cancel();
        }
        windows_.erase(stream_id);
        udp_bufs_.erase(stream_id);
        multiplexer::drop(stream_id);
    }


    auto control::write_frame(outbound_frame frame)
        -> net::awaitable<void>
    {
        memory::vector<std::byte> bytes(mr_);

        switch (frame.kind)
        {
        case outbound_kind::data:
            bytes = codec_.encode_data(frame.stream_id, frame.payload);
            break;
        case outbound_kind::fin:
            bytes = codec_.encode_fin(frame.stream_id);
            break;
        case outbound_kind::control:
            // 控制帧（WindowUpdate/Ping/GoAway/RST）由调用方预编码，直接写入
            bytes = std::move(frame.payload);
            break;
        }

        std::error_code ec;
        co_await transport::async_write(*transport_, bytes, ec);
        if (ec)
        {
            diagnose::debug(prefix_, "send frame failed: {}", ec.message());
            close();
        }
    }


    auto control::frame_loop()
        -> net::awaitable<void>
    {
        diagnose::debug(prefix_, "frame loop started");

        std::error_code ec;
        std::array<std::byte, frame_hdrsize> recv_buffer{};

        while (is_active())
        {
            const auto recv_span = std::span<std::byte>(recv_buffer);
            const auto hdr_n = co_await transport::async_read(*transport_, recv_span, ec);
            if (ec || hdr_n < frame_hdrsize)
            {
                if (ec != std::errc::operation_canceled)
                {
                    diagnose::debug(prefix_, "read header failed: {}", ec.message());
                }
                break;
            }

            const auto meta = codec_.decode_header(recv_buffer);
            if (meta.raw_type == 0 && meta.stream_id == 0 && meta.length == 0 && meta.flags == 0)
            {
                diagnose::debug(prefix_, "invalid frame header, closing session");
                break;
            }

            // 仅 Data 帧的 Length 为载荷长度，控制帧为增量/ID/原因码
            memory::vector<std::byte> payload(mr_);
            if (meta.kind == frame_kind::data && meta.length > 0)
            {
                if (meta.length > max_frame_payload)
                {
                    diagnose::warn(prefix_, "oversized Data frame: stream={}, length={}",
                                meta.stream_id, meta.length);
                    co_await push_control(message_type::go_away, flags::none, 0,
                                          static_cast<std::uint32_t>(away_code::protocol_error));
                    break;
                }
                payload.resize(meta.length);
                const auto payload_n = co_await transport::async_read(*transport_, payload, ec);
                if (ec || payload_n < meta.length)
                {
                    diagnose::debug(prefix_, "read payload failed: {}", ec.message());
                    break;
                }
            }

            frame_header hdr;
            hdr.type = static_cast<message_type>(meta.raw_type);
            hdr.flag = static_cast<flags>(meta.flags);
            hdr.stream_id = meta.stream_id;
            hdr.length = meta.length;

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

        diagnose::debug(prefix_, "frame loop ended");
    }


    auto control::handle_data(const frame_header &hdr, memory::vector<std::byte> payload)
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


    auto control::handle_syn(const std::uint32_t stream_id, memory::vector<std::byte> payload)
        -> net::awaitable<void>
    {
        if (pending_.size() + streams_.size() + datagrams_.size() >= config_.yamux.max_streams)
        {
            diagnose::warn(prefix_, "max streams reached, rejecting stream {}", stream_id);
            co_await push_control(message_type::window_update, flags::rst, stream_id, 0);
            co_return;
        }

        auto [it, inserted] = pending_.emplace(stream_id, pending_entry(mr_));
        if (!inserted)
        {
            diagnose::warn(prefix_, "duplicate SYN for stream {}", stream_id);
            co_return;
        }

        if (!payload.empty())
        {
            it->second.buffer.insert(it->second.buffer.end(), payload.begin(), payload.end());
        }

        (void)ensure_window(stream_id);

        start_pending(stream_id);

        co_await push_control(message_type::window_update, flags::ack, stream_id,
                              config_.yamux.initial_window);

        try_activate_pending(stream_id);
    }


    void control::handle_rst(const std::uint32_t stream_id)
    {
        pending_.erase(stream_id);

        if (const auto it = streams_.find(stream_id); it != streams_.end() && it->second)
        {
            it->second->on_fin();
        }

        if (const auto it = datagrams_.find(stream_id); it != datagrams_.end() && it->second)
        {
            it->second->close();
        }

        if (const auto wit = windows_.find(stream_id); wit != windows_.end())
        {
            wit->second->window_signal->cancel();
        }
        windows_.erase(stream_id);
        udp_bufs_.erase(stream_id);
        diagnose::debug(prefix_, "stream {} reset", stream_id);
    }


    void control::handle_fin(const std::uint32_t stream_id)
    {
        if (pending_.erase(stream_id))
        {
            diagnose::debug(prefix_, "stream {} fin while pending", stream_id);
            if (const auto wit = windows_.find(stream_id); wit != windows_.end())
            {
                wit->second->window_signal->cancel();
            }
            windows_.erase(stream_id);
            return;
        }

        if (const auto it = streams_.find(stream_id); it != streams_.end() && it->second)
        {
            it->second->on_fin();
            return;
        }

        udp_bufs_.erase(stream_id);

        if (const auto it = datagrams_.find(stream_id); it != datagrams_.end() && it->second)
        {
            it->second->close();
        }

        diagnose::debug(prefix_, "stream {} fin", stream_id);
    }


    auto control::dispatch_data(const std::uint32_t stream_id, memory::vector<std::byte> payload)
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

        if (const auto it = streams_.find(stream_id); it != streams_.end() && it->second)
        {
            if (!payload.empty())
            {
                co_await update_recv_win(stream_id, static_cast<std::uint32_t>(payload.size()));
            }

            auto sp = it->second;
            auto self = std::static_pointer_cast<control>(shared_from_this());
            auto async_push = [sp, p = std::move(payload), self]() mutable -> net::awaitable<void>
            {
                co_await sp->on_data(std::move(p));
            };
            auto on_error = [sp, self](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    log_spawn_error(ep, 0, "dispatch stream data", self->prefix_);
                    sp->close();
                }
            };
            net::co_spawn(transport_->executor(), std::move(async_push), std::move(on_error));
            co_return;
        }

        if (datagrams_.contains(stream_id))
        {
            if (!payload.empty())
            {
                co_await update_recv_win(stream_id, static_cast<std::uint32_t>(payload.size()));
            }

            auto self = std::static_pointer_cast<control>(shared_from_this());
            auto async_push = [self, stream_id, p = std::move(payload)]() mutable -> net::awaitable<void>
            {
                co_await self->process_udp(stream_id, std::move(p));
            };
            auto on_error = [self, stream_id](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    log_spawn_error(ep, stream_id, "dispatch datagram data", self->prefix_);
                    self->drop(stream_id);
                }
            };
            net::co_spawn(transport_->executor(), std::move(async_push), std::move(on_error));
            co_return;
        }

        diagnose::debug(prefix_, "data for unknown stream {}", stream_id);
        co_await push_control(message_type::window_update, flags::rst, stream_id, 0);
    }


    void control::try_activate_pending(const std::uint32_t stream_id)
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
        const auto self = std::static_pointer_cast<control>(shared_from_this());
        auto callback = [stream_id, self](const std::exception_ptr &ep)
        {
            if (ep) log_spawn_error(ep, stream_id, "activate", self->prefix_);
        };
        auto activate_fn = [self, stream_id]() -> net::awaitable<void>
        {
            co_await self->activate_stream(stream_id);
        };
        net::co_spawn(transport_->executor(), std::move(activate_fn), callback);
    }


    auto control::handle_winupd(const frame_header &hdr)
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
            if (const auto dit = streams_.find(stream_id); dit != streams_.end() && dit->second)
            {
                dit->second->on_fin();
            }
            if (const auto pit = datagrams_.find(stream_id); pit != datagrams_.end() && pit->second)
            {
                pit->second->close();
            }
            if (const auto wit = windows_.find(stream_id); wit != windows_.end())
            {
                wit->second->window_signal->cancel();
            }
            windows_.erase(stream_id);
            udp_bufs_.erase(stream_id);
            diagnose::debug(prefix_, "stream {} reset via window update", stream_id);
            co_return;
        }

        if (has_flag(hdr.flag, flags::fin))
        {
            if (pending_.erase(stream_id))
            {
                windows_.erase(stream_id);
                co_return;
            }

            if (const auto dit = streams_.find(stream_id); dit != streams_.end() && dit->second)
            {
                dit->second->on_fin();
            }
            co_return;
        }

        if (has_flag(hdr.flag, flags::syn) && !has_flag(hdr.flag, flags::ack))
        {
            if (pending_.size() + streams_.size() + datagrams_.size() >= config_.yamux.max_streams)
            {
                diagnose::warn(prefix_, "max streams reached, rejecting stream {}", stream_id);
                co_await push_control(message_type::window_update, flags::rst, stream_id, 0);
                co_return;
            }

            auto [it, inserted] = pending_.emplace(stream_id, pending_entry(mr_));
            if (!inserted)
            {
                diagnose::warn(prefix_, "duplicate SYN for stream {}", stream_id);
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

            co_await push_control(message_type::window_update, flags::ack, stream_id,
                                  config_.yamux.initial_window);

            start_pending(stream_id);

            diagnose::debug(prefix_, "stream {} opened via window update syn, client_window={}, using_window={}",
                         stream_id, delta, client_window);
            co_return;
        }

        if (has_flag(hdr.flag, flags::syn) && has_flag(hdr.flag, flags::ack))
        {
            diagnose::debug(prefix_, "stream {} syn+ack received", stream_id);
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
            diagnose::debug(prefix_, "stream {} window update received, delta={}, new_window={}",
                         stream_id, delta, new_val);

            window->window_signal->cancel();
        }

        co_return;
    }


    auto control::handle_ping(const frame_header &hdr)
        -> net::awaitable<void>
    {
        if (has_flag(hdr.flag, flags::syn) && config_.yamux.enable_ping)
        {
            co_await push_control(message_type::ping, flags::ack, 0, hdr.length);
            co_return;
        }

        co_return;
    }


    auto control::handle_goaway(const frame_header &hdr)
        -> net::awaitable<void>
    {
        const auto code = static_cast<away_code>(hdr.length);
        diagnose::debug(prefix_, "go away received, code={}", static_cast<std::uint32_t>(code));
        close();
        co_return;
    }


    auto control::send_addr_err(const std::uint32_t stream_id)
        -> net::awaitable<void>
    {
        diagnose::warn(prefix_, "stream {} address parse failed", stream_id);
        memory::vector<std::byte> error_buf(mr_);
        error_buf.push_back(std::byte{0x01});
        co_await send(stream_id, std::move(error_buf));
        pending_.erase(stream_id);
        fin(stream_id);
    }


    auto control::activate_udp(activate_opts opts)
        -> net::awaitable<void>
    {
        diagnose::debug(prefix_, "stream {} creating UDP datagram", opts.stream_id);

        memory::vector<std::byte> success_buf(mr_);
        success_buf.push_back(std::byte{0x00});
        co_await send(opts.stream_id, std::move(success_buf));

        if (auto pit = pending_.find(opts.stream_id); pit != pending_.end())
        {
            auto &entry = pit->second;
            if (opts.addr_offset < entry.buffer.size())
            {
                auto rest = std::span<const std::byte>(entry.buffer).subspan(opts.addr_offset);
                opts.remaining.assign(rest.begin(), rest.end());
            }
            pending_.erase(pit);
        }

        auto [it, inserted] = udp_bufs_.emplace(opts.stream_id, udp_entry(mr_));
        (void)inserted;
        auto &entry = it->second;
        entry.mode = opts.addr;
        entry.dest_host = std::move(opts.host);
        entry.dest_port = opts.port;

        auto dp = make_datagram(datagram_options{
            .stream_id = opts.stream_id,
            .idle_timeout = config_.yamux.udp_idle,
            .max_dgram = config_.yamux.max_dgram,
            .executor = transport_->executor(),
            .egress = shared_from_this(),
            .resolve = make_resolve(),
            .emit = make_emit(opts.stream_id, opts.addr),
            .mr = mr_,
            .prefix = prefix_,
        });

        if (!is_active())
        {
            udp_bufs_.erase(opts.stream_id);
            dp->close();
            co_return;
        }

        datagrams_[opts.stream_id] = dp;

        dp->start();

        if (!opts.remaining.empty())
        {
            co_await process_udp(opts.stream_id, std::move(opts.remaining));
        }

        diagnose::debug(prefix_, "stream {} UDP datagram created", opts.stream_id);
    }


    auto control::activate_tcp(activate_opts opts)
        -> net::awaitable<void>
    {
        diagnose::debug(prefix_, "stream {} connecting to {}:{}", opts.stream_id, opts.host, opts.port);

        char port_buf[8];
        const auto [port_end, port_ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), opts.port);
        auto port_str = std::string_view(port_buf, std::distance(port_buf, port_end));

        // 通过 outbound 接口拨号（返回 shared_transmission，无需 make_reliable）
        psm::connect::target tgt;
        tgt.host = memory::string(opts.host, mr_);
        tgt.port = memory::string(port_str, mr_);
        tgt.positive = true;
        auto [code, trans] = co_await outbound_->async_connect(tgt, transport_->executor());

        if (code != fault::code::success || !trans)
        {
            diagnose::warn(prefix_, "stream {} connect to {}:{} failed", opts.stream_id, opts.host, opts.port);
            memory::vector<std::byte> error_buf(mr_);
            error_buf.push_back(std::byte{0x01});
            co_await send(opts.stream_id, std::move(error_buf));
            pending_.erase(opts.stream_id);
            fin(opts.stream_id);
            co_return;
        }

        memory::vector<std::byte> success_buf(mr_);
        success_buf.push_back(std::byte{0x00});
        co_await send(opts.stream_id, std::move(success_buf));

        // 取出 pending 中地址之后的所有数据：激活期间新到达的帧
        // 也会累积到 pending.buffer，不能随 erase 丢弃（否则上行数据丢失）
        if (auto pit = pending_.find(opts.stream_id); pit != pending_.end())
        {
            auto &entry = pit->second;
            if (opts.addr_offset < entry.buffer.size())
            {
                auto rest = std::span<const std::byte>(entry.buffer).subspan(opts.addr_offset);
                opts.remaining.assign(rest.begin(), rest.end());
            }
            pending_.erase(pit);
        }

        auto sp = make_stream(stream_options{
            .stream_id = opts.stream_id,
            .target = std::move(trans),
            .egress = shared_from_this(),
            .buffer_size = config_.yamux.buffer_size,
            .mr = mr_,
            .prefix = prefix_,
        });
        streams_[opts.stream_id] = sp;

        sp->start();

        if (!opts.remaining.empty())
        {
            co_await sp->on_data(std::move(opts.remaining));
        }

        diagnose::debug(prefix_, "stream {} connected to {}:{}", opts.stream_id, opts.host, opts.port);
    }


    auto control::activate_stream(const std::uint32_t stream_id)
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
                .addr_offset = 0,
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
            tcp_opts.addr_offset = 0;
            tcp_opts.remaining = std::move(remaining_data);
            co_await activate_tcp(std::move(tcp_opts));
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
        if (entry.buffer.size() > config_.yamux.max_dgram)
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

                    if (entry.mode == addr_mode::packet_addr)
                    {
                        auto dgram = smux::parse_dgram(rest, mr_);
                        if (!dgram)
                        {
                            break;
                        }
                        co_await dp->second->send_to(dgram->host, dgram->port, dgram->payload);
                        offset += dgram->consumed;
                    }
                    else
                    {
                        auto dgram = smux::parse_prefixed(rest);
                        if (!dgram)
                        {
                            break;
                        }
                        co_await dp->second->send_to(entry.dest_host, entry.dest_port, dgram->payload);
                        offset += dgram->consumed;
                    }
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


    void control::start_pending(const std::uint32_t stream_id)
    {
        if (config_.yamux.open_timeout == 0)
        {
            return;
        }

        auto timer = std::make_shared<net::steady_timer>(transport_->executor());
        timer->expires_after(std::chrono::milliseconds(config_.yamux.open_timeout));
        pending_timers_[stream_id] = timer;

        auto self = std::static_pointer_cast<control>(shared_from_this());
        auto timeout_task = [self, stream_id, timer = std::move(timer)]() -> net::awaitable<void>
        {
            co_return co_await self->pending_timeout(stream_id, std::move(timer));
        };
        net::co_spawn(transport_->executor(), std::move(timeout_task), net::detached);
    }


    auto control::pending_timeout(const std::uint32_t stream_id, std::shared_ptr<net::steady_timer> timer)
        -> net::awaitable<void>
    {
        boost::system::error_code ec;
        co_await timer->async_wait(net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            co_return;
        }
        if (pending_.count(stream_id))
        {
            diagnose::warn(prefix_, "stream {} open timeout, resetting", stream_id);
            pending_.erase(stream_id);
            pending_timers_.erase(stream_id);
            windows_.erase(stream_id);
            co_await push_control(message_type::window_update, flags::rst, stream_id, 0);
        }
    }


    stream_window *control::ensure_window(const std::uint32_t stream_id)
    {
        if (const auto it = windows_.find(stream_id); it != windows_.end())
        {
            return it->second.get();
        }

        auto win = std::make_unique<stream_window>(transport_->executor());
        auto [new_it, inserted] = windows_.emplace(stream_id, std::move(win));
        return new_it->second.get();
    }


    stream_window *control::get_window(const std::uint32_t stream_id) const
    {
        if (const auto it = windows_.find(stream_id); it != windows_.end())
        {
            return it->second.get();
        }
        return nullptr;
    }


    auto control::update_recv_win(const std::uint32_t stream_id, const std::uint32_t consumed)
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

            co_await push_control(message_type::window_update, flags::none, stream_id, total_consumed);

            diagnose::debug(prefix_, "stream {} window update sent, delta={}", stream_id, total_consumed);
        }
    }


    auto control::push_control(const message_type type, const flags f, const std::uint32_t stream_id,
                               const std::uint32_t length)
        -> net::awaitable<void>
    {
        frame_header hdr{};
        hdr.type = type;
        hdr.flag = f;
        hdr.stream_id = stream_id;
        hdr.length = length;
        const auto hdr_bytes = build_header(hdr);

        outbound_frame frame;
        frame.stream_id = stream_id;
        frame.kind = outbound_kind::control;
        frame.payload = memory::vector<std::byte>(mr_);
        frame.payload.insert(frame.payload.end(), hdr_bytes.begin(), hdr_bytes.end());

        co_await push_frame(std::move(frame));
    }


    auto control::ping_loop()
        -> net::awaitable<void>
    {
        diagnose::debug(prefix_, "ping loop started, interval={}ms", config_.yamux.ping_interval);
        net::steady_timer timer(transport_->executor());
        try
        {
            while (is_active())
            {
                timer.expires_after(std::chrono::milliseconds(config_.yamux.ping_interval));
                boost::system::error_code ec;
                co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
                if (ec || !is_active())
                {
                    break;
                }
                const auto id = ping_id_.fetch_add(1, std::memory_order_relaxed) + 1;
                co_await push_control(message_type::ping, flags::syn, 0, id);
            }
        }
        catch (const std::exception &e)
        {
            diagnose::debug(prefix_, "ping loop error: {}", e.what());
        }
        catch (...)
        {
        }
        diagnose::debug(prefix_, "ping loop ended");
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


    auto control::make_emit(const std::uint32_t stream_id, const addr_mode mode)
        -> emit_fn
    {
        auto self = std::static_pointer_cast<control>(shared_from_this());
        return [self, stream_id, mode](const std::string_view host, const std::uint16_t port,
                                       const std::span<const std::byte> payload)
            -> net::awaitable<void>
        {
            memory::vector<std::byte> encoded(self->mr_);
            if (mode == addr_mode::packet_addr)
            {
                encoded = smux::build_dgram({host, port, payload}, self->mr_);
            }
            else
            {
                encoded = smux::build_prefixed(payload, self->mr_);
            }
            co_await self->send(stream_id, std::move(encoded));
        };
    }

} // namespace psm::multiplex::yamux

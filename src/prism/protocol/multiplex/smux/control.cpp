#include <prism/protocol/multiplex/smux/control.hpp>

#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/connection/outbound/direct.hpp>
#include <prism/protocol/multiplex/datagram.hpp>
#include <prism/protocol/multiplex/stream.hpp>
#include <prism/diagnose/diagnose.hpp>

#include <boost/asio/co_spawn.hpp>

#include <array>
#include <charconv>
#include <span>

using namespace psm::diagnose;

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
                diagnose::debug("stream {} {} error: {}", stream_id, label, e.what());
            }
            catch (...)
            {
                diagnose::error("stream {} {} unknown error", stream_id, label);
            }
        }

        [[nodiscard]] auto build_header(const command cmd, const std::uint32_t stream_id,
                                        const std::uint16_t length)
            -> std::array<std::byte, frame_hdrsize>
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

        [[nodiscard]] auto make_nop_frame(memory::resource_pointer mr)
            -> memory::vector<std::byte>
        {
            const auto hdr = build_header(command::nop, 0, 0);
            memory::vector<std::byte> buf(mr);
            buf.insert(buf.end(), hdr.begin(), hdr.end());
            return buf;
        }
    } // namespace

    control::control(multiplexer_options opts)
        : multiplexer(multiplexer_options{
              std::move(opts.transport), opts.outbound, opts.cfg, opts.mr,
              opts.cfg.smux.max_streams}),
          router_fn_(outbound_ ? outbound_->make_router() : decltype(router_fn_){}),
          udp_bufs_(mr_)
    {
    }


    control::~control() noexcept = default;


    auto control::run()
        -> net::awaitable<void>
    {
        if (config_.smux.keepalive_interval > 0)
        {
            auto self = std::static_pointer_cast<control>(shared_from_this());
            auto start_keepalive = [self]() -> net::awaitable<void>
            {
                co_await self->keepalive_loop();
            };
            net::co_spawn(transport_->executor(), std::move(start_keepalive), net::detached);
        }

        co_await frame_loop();
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
            // 控制帧（心跳等）由调用方预编码为完整字节，直接写入
            bytes = std::move(frame.payload);
            if (bytes.empty())
            {
                bytes = make_nop_frame(mr_);
            }
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
        std::array<std::byte, frame_hdrsize> frame_buffer{};

        while (is_active())
        {
            const auto frame_span = std::span<std::byte>(frame_buffer);
            const auto hdr_n = co_await transport::async_read(*transport_, frame_span, ec);
            if (ec || hdr_n < frame_hdrsize)
            {
                if (ec != std::errc::operation_canceled)
                {
                    diagnose::debug(prefix_, "read header failed: {}", ec.message());
                }
                break;
            }

            const auto meta = codec_.decode_header(frame_buffer);
            if (meta.raw_type == 0 && meta.stream_id == 0 && meta.length == 0)
            {
                diagnose::debug(prefix_, "invalid frame header, closing session");
                break;
            }

            memory::vector<std::byte> payload(mr_);
            if (meta.length > 0)
            {
                payload.resize(meta.length);
                const auto payload_n = co_await transport::async_read(*transport_, payload, ec);
                if (ec || payload_n < meta.length)
                {
                    diagnose::debug(prefix_, "read payload failed: {}", ec.message());
                    break;
                }
            }

            switch (meta.kind)
            {
            case frame_kind::syn:
                co_await handle_syn(meta.stream_id);
                break;

            case frame_kind::data:
                dispatch_push(meta.stream_id, std::move(payload));
                break;

            case frame_kind::fin:
                handle_fin(meta.stream_id);
                break;

            case frame_kind::control:
            case frame_kind::rst:
            default:
                break;
            }
        }

        diagnose::debug(prefix_, "frame loop ended");
    }


    auto control::handle_syn(const std::uint32_t stream_id)
        -> net::awaitable<void>
    {
        if (pending_.size() + streams_.size() + datagrams_.size() >= config_.smux.max_streams)
        {
            diagnose::warn(prefix_, "max streams reached, rejecting stream {}", stream_id);
            fin(stream_id);
            co_return;
        }

        // 检查 stream_id 是否已存在（冲突拒绝）
        if (pending_.contains(stream_id) || streams_.contains(stream_id) || datagrams_.contains(stream_id))
        {
            diagnose::warn(prefix_, "duplicate SYN for stream {}, rejecting", stream_id);
            fin(stream_id);
            co_return;
        }

        pending_.emplace(stream_id, pending_entry(mr_));
        diagnose::debug(prefix_, "stream {} pending, waiting for address", stream_id);
    }


    void control::dispatch_push(const std::uint32_t stream_id, memory::vector<std::byte> payload)
    {
        const auto self = std::static_pointer_cast<control>(shared_from_this());

        if (const auto pit = pending_.find(stream_id); pit != pending_.end())
        {
            auto &entry = pit->second;
            diagnose::debug(prefix_, "[up] push to pending stream={} {} bytes, buffer={}", stream_id, payload.size(), entry.buffer.size() + payload.size());
            entry.buffer.insert(entry.buffer.end(), payload.begin(), payload.end());

            if (!entry.connecting && entry.buffer.size() >= 7)
            {
                entry.connecting = true;
                auto on_error = [stream_id](const std::exception_ptr &ep)
                {
                    if (ep) log_spawn_error(ep, stream_id, "activate_stream");
                };
                net::co_spawn(transport_->executor(),
                    [self, stream_id]() -> net::awaitable<void>
                    {
                        co_await self->activate_stream(stream_id);
                    },
                    std::move(on_error));
            }
            return;
        }

        const auto sit = streams_.find(stream_id);
        if (sit != streams_.end() && sit->second)
        {
            diagnose::debug(prefix_, "[up] push to stream={} {} bytes", stream_id, payload.size());
            auto sp = sit->second;

            auto async_push = [self, sp, p = std::move(payload)]() mutable -> net::awaitable<void>
            { // sp->on_data 可能涉及网络 I/O，异步调用避免阻塞帧循环
                co_await sp->on_data(std::move(p));
            };
            auto on_error = [sp](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    log_spawn_error(ep, 0, "dispatch stream data");
                    sp->close();
                }
            };
            net::co_spawn(transport_->executor(), std::move(async_push), std::move(on_error));
            return;
        }

        // datagram 流：进入重组缓冲（进程内串行处理）
        if (datagrams_.contains(stream_id))
        {
            auto async_push = [self, stream_id, p = std::move(payload)]() mutable -> net::awaitable<void>
            {
                co_await self->process_udp(stream_id, std::move(p));
            };
            auto on_error = [self, stream_id](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    log_spawn_error(ep, stream_id, "dispatch datagram data");
                    self->drop(stream_id);
                }
            };
            net::co_spawn(transport_->executor(), std::move(async_push), std::move(on_error));
            return;
        }

        // 流不存在或已关闭：帧被丢弃（记录以便诊断上传数据丢失）
        diagnose::debug(prefix_, "[up] DROP frame for closed stream={} {} bytes", stream_id, payload.size());
    }


    void control::handle_fin(const std::uint32_t stream_id)
    {
        if (pending_.erase(stream_id))
        {
            diagnose::debug(prefix_, "stream {} fin while pending", stream_id);
            return;
        }

        if (const auto it = streams_.find(stream_id); it != streams_.end() && it->second)
        {
            it->second->on_fin();
            return;
        }

        udp_bufs_.erase(stream_id);

        const auto uit = datagrams_.find(stream_id);
        if (uit != datagrams_.end() && uit->second)
        {
            uit->second->close();
        }
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

        // 取出 pending 中地址之后的所有数据（激活期间新到达的帧）
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
            .idle_timeout = config_.smux.idle_timeout,
            .max_dgram = config_.smux.max_dgram,
            .executor = transport_->executor(),
            .egress = shared_from_this(),
            .resolve = make_resolve(),
            .emit = make_emit(opts.stream_id, opts.addr),
            .mr = mr_,
            .prefix = prefix_,
        });

        if (is_active())
        {
            datagrams_[opts.stream_id] = dp;
            dp->start();

            if (!opts.remaining.empty())
            {
                co_await process_udp(opts.stream_id, std::move(opts.remaining));
            }
        }
        else
        {
            udp_bufs_.erase(opts.stream_id);
            dp->close();
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
        diagnose::debug(prefix_, "[up] activate_tcp stream={} uplink {} bytes", opts.stream_id, opts.remaining.size());

        auto sp = make_stream(stream_options{
            .stream_id = opts.stream_id,
            .target = std::move(trans),
            .egress = shared_from_this(),
            .buffer_size = config_.smux.buffer_size,
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
                .addr_offset = offset,
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
            tcp_opts.addr_offset = offset;
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
        if (entry.buffer.size() > config_.smux.max_dgram)
        {
            datagrams_.erase(stream_id);
            udp_bufs_.erase(stream_id);
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
                // 交换缓冲区：local 数据不再被并发修改，span 指针稳定
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
                        auto dgram = parse_dgram(rest, mr_);
                        if (!dgram)
                        {
                            break;
                        }
                        co_await dp->second->send_to(dgram->host, dgram->port, dgram->payload);
                        offset += dgram->consumed;
                    }
                    else
                    {
                        auto dgram = parse_prefixed(rest);
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


    auto control::keepalive_loop()
        -> net::awaitable<void>
    {
        diagnose::debug(prefix_, "keepalive loop started, interval={}ms", config_.smux.keepalive_interval);
        net::steady_timer timer(transport_->executor());
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

                outbound_frame frame;
                frame.stream_id = 0;
                frame.kind = outbound_kind::control;
                frame.payload = make_nop_frame(mr_);
                co_await push_frame(std::move(frame));
            }
        }
        catch (const std::exception &e)
        {
            diagnose::debug(prefix_, "keepalive loop error: {}", e.what());
        }
        catch (...)
        {
        }
        diagnose::debug(prefix_, "keepalive loop ended");
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
                encoded = build_dgram({host, port, payload}, self->mr_);
            }
            else
            {
                encoded = build_prefixed(payload, self->mr_);
            }
            co_await self->send(stream_id, std::move(encoded));
        };
    }

} // namespace psm::multiplex::smux

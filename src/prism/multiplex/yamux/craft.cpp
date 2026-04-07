/**
 * @file craft.cpp
 * @brief yamux 多路复用会话服务端实现
 * @details yamux::craft 实现 yamux 协议服务端逻辑，包括帧循环、窗口管理、
 * 流生命周期管理。继承 core 的通用流管理能力。
 */

#include <prism/multiplex/yamux/craft.hpp>
#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/parcel.hpp>
#include <prism/multiplex/smux/frame.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/resolve/router.hpp>
#include <prism/trace.hpp>

#include <boost/asio/co_spawn.hpp>

constexpr std::string_view tag = "[Yamux.Craft]";

namespace psm::multiplex::yamux
{
    craft::craft(channel::transport::shared_transmission transport, resolve::router &router,
                 const multiplex::config &cfg, const memory::resource_pointer mr)
        : core(std::move(transport), router, cfg, mr),
          channel_(transport_->executor(), cfg.yamux.max_streams),
          windows_(mr_), recv_buffer_(mr_)
    {
        recv_buffer_.resize(frame_header_size);
        trace::debug("{} constructed", tag);
    }

    craft::~craft() = default;

    auto craft::run() -> net::awaitable<void>
    {
        // 启动发送循环
        const auto self = std::static_pointer_cast<craft>(shared_from_this());
        net::co_spawn(executor(), self->send_loop(), net::detached);

        // 进入帧循环
        co_await frame_loop();

        channel_.cancel();
    }

    // === 帧循环 ===

    auto craft::frame_loop() -> net::awaitable<void>
    {
        trace::debug("{} frame loop started", tag);

        std::error_code ec;

        while (active_.load(std::memory_order_acquire))
        {
            // 读取 12 字节帧头
            const auto hdr_n = co_await transport_->async_read(recv_buffer_, ec);
            if (ec || hdr_n < frame_header_size)
            {
                if (ec != std::errc::operation_canceled)
                {
                    trace::debug("{} read header failed: {}", tag, ec.message());
                }
                break;
            }

            // 解析帧头
            const auto hdr_opt = parse_header(recv_buffer_);
            if (!hdr_opt)
            {
                trace::warn("{} invalid frame header", tag);
                break;
            }

            const auto &hdr = *hdr_opt;

            // Data 帧可能有载荷，其他类型帧只有 12 字节头
            memory::vector<std::byte> payload(mr_);
            if (hdr.type == message_type::data && hdr.length > 0)
            {
                payload.resize(hdr.length);
                const auto payload_n = co_await transport_->async_read(payload, ec);
                if (ec || payload_n < hdr.length)
                {
                    trace::debug("{} read payload failed: {}", tag, ec.message());
                    break;
                }
            }

            // 按消息类型分发
            switch (hdr.type)
            {
            case message_type::data:
                co_await handle_data(hdr, std::move(payload));
                break;

            case message_type::window_update:
                co_await handle_window_update(hdr);
                break;

            case message_type::ping:
                co_await handle_ping(hdr);
                break;

            case message_type::go_away:
                co_await handle_go_away(hdr);
                break;
            }
        }

        trace::debug("{} frame loop ended", tag);
    }

    // === Data 帧处理 ===

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
            trace::warn("{} max streams reached, rejecting stream {}", tag, stream_id);
            co_await push_frame(message_type::window_update, flags::rst, stream_id, 0, {});
            co_return;
        }

        auto [it, inserted] = pending_.emplace(stream_id, pending_entry(mr_));
        if (!inserted)
        {
            trace::warn("{} duplicate SYN for stream {}", tag, stream_id);
            co_return;
        }

        // 累积 Data(SYN) 携带的地址数据
        if (!payload.empty())
        {
            it->second.buffer.insert(it->second.buffer.end(), payload.begin(), payload.end());
        }

        get_or_create_window(stream_id);

        // 回复 WindowUpdate ACK，Length 携带服务端初始窗口大小
        co_await push_frame(message_type::window_update, flags::ack, stream_id, initial_stream_window, {});

        try_activate_pending(stream_id, it->second);
    }

    void craft::handle_rst(const std::uint32_t stream_id)
    {
        pending_.erase(stream_id);

        if (const auto it = ducts_.find(stream_id); it != ducts_.end() && it->second)
        {
            it->second->on_mux_fin();
        }

        if (const auto it = parcels_.find(stream_id); it != parcels_.end() && it->second)
        {
            it->second->close();
        }

        windows_.erase(stream_id);
        trace::debug("{} stream {} reset", tag, stream_id);
    }

    void craft::handle_fin(const std::uint32_t stream_id)
    {
        if (pending_.erase(stream_id))
        {
            trace::debug("{} stream {} fin while pending", tag, stream_id);
            windows_.erase(stream_id);
            return;
        }

        if (const auto it = ducts_.find(stream_id); it != ducts_.end() && it->second)
        {
            it->second->on_mux_fin();
            return;
        }

        if (const auto it = parcels_.find(stream_id); it != parcels_.end() && it->second)
        {
            it->second->close();
        }

        trace::debug("{} stream {} fin", tag, stream_id);
    }

    auto craft::dispatch_data(const std::uint32_t stream_id, memory::vector<std::byte> payload)
        -> net::awaitable<void>
    {
        // Pending 流：累积地址数据，可能触发连接
        if (const auto pit = pending_.find(stream_id); pit != pending_.end())
        {
            auto &entry = pit->second;
            if (!payload.empty())
            {
                entry.buffer.insert(entry.buffer.end(), payload.begin(), payload.end());
            }

            try_activate_pending(stream_id, entry);

            if (!payload.empty())
            {
                co_await update_recv_window(stream_id, static_cast<std::uint32_t>(payload.size()));
            }
            co_return;
        }

        // 已连接流：更新接收窗口
        if (!payload.empty())
        {
            co_await update_recv_window(stream_id, static_cast<std::uint32_t>(payload.size()));
        }

        // TCP 流：非阻塞分发到 duct
        if (const auto it = ducts_.find(stream_id); it != ducts_.end() && it->second)
        {
            auto dp = it->second;
            auto async_push = [dp, p = std::move(payload)]() mutable -> net::awaitable<void>
            {
                co_await dp->on_mux_data(std::move(p));
            };
            net::co_spawn(executor(), std::move(async_push), net::detached);
            co_return;
        }

        // UDP 流：非阻塞分发到 parcel
        if (const auto it = parcels_.find(stream_id); it != parcels_.end() && it->second)
        {
            auto dp = it->second;
            auto async_push = [dp, p = std::move(payload)]() mutable -> net::awaitable<void>
            {
                co_await dp->on_mux_data(std::move(p));
            };
            net::co_spawn(executor(), std::move(async_push), net::detached);
            co_return;
        }

        // 流不存在，回复 RST
        trace::warn("{} data for unknown stream {}", tag, stream_id);
        co_await push_frame(message_type::window_update, flags::rst, stream_id, 0, {});
    }

    void craft::try_activate_pending(const std::uint32_t stream_id, pending_entry &entry)
    {
        // 数据不足最小地址长度（7 字节）或已在连接中，继续累积
        if (entry.connecting || entry.buffer.size() < 7)
        {
            return;
        }

        entry.connecting = true;
        const auto self = std::static_pointer_cast<craft>(shared_from_this());
        auto callback = [stream_id](const std::exception_ptr &ep)
        {
            if (ep)
            {
                try
                {
                    std::rethrow_exception(ep);
                }
                catch (const std::exception &e)
                {
                    trace::debug("{} stream {} activate error: {}", tag, stream_id, e.what());
                }
                catch (...)
                {
                    trace::error("{} stream {} activate unknown error", tag, stream_id);
                }
            }
        };
        net::co_spawn(transport_->executor(), self->activate_stream(stream_id), callback);
    }

    // === WindowUpdate 帧处理 ===

    auto craft::handle_window_update(const frame_header &hdr) -> net::awaitable<void>
    {
        const auto stream_id = hdr.stream_id;
        const auto delta = hdr.length;

        // 会话级窗口更新（stream_id == 0），当前忽略
        if (stream_id == 0)
        {
            co_return;
        }

        // RST 标志：重置流
        if (has_flag(hdr.flag, flags::rst))
        {
            pending_.erase(stream_id);
            if (const auto dit = ducts_.find(stream_id); dit != ducts_.end() && dit->second)
            {
                dit->second->on_mux_fin();
            }
            if (const auto pit = parcels_.find(stream_id); pit != parcels_.end() && pit->second)
            {
                pit->second->close();
            }
            windows_.erase(stream_id);
            trace::debug("{} stream {} reset via window update", tag, stream_id);
            co_return;
        }

        // FIN 标志：半关闭
        if (has_flag(hdr.flag, flags::fin))
        {
            if (pending_.erase(stream_id))
            {
                windows_.erase(stream_id);
                co_return;
            }

            if (const auto dit = ducts_.find(stream_id); dit != ducts_.end() && dit->second)
            {
                dit->second->on_mux_fin();
            }
            co_return;
        }

        // SYN（无 ACK）：客户端打开新流
        if (has_flag(hdr.flag, flags::syn) && !has_flag(hdr.flag, flags::ack))
        {
            if (pending_.size() + ducts_.size() + parcels_.size() >= config_.yamux.max_streams)
            {
                trace::warn("{} max streams reached, rejecting stream {}", tag, stream_id);
                co_await push_frame(message_type::window_update, flags::rst, stream_id, 0, {});
                co_return;
            }

            auto [it, inserted] = pending_.emplace(stream_id, pending_entry(mr_));
            if (!inserted)
            {
                trace::warn("{} duplicate SYN for stream {}", tag, stream_id);
                co_return;
            }

            get_or_create_window(stream_id);

            // 回复 WindowUpdate ACK，确认流创建
            co_await push_frame(message_type::window_update, flags::ack, stream_id, initial_stream_window, {});

            trace::debug("{} stream {} opened via window update syn", tag, stream_id);
            co_return;
        }

        // SYN+ACK：确认流创建（服务端发起的流收到对端确认）
        if (has_flag(hdr.flag, flags::syn) && has_flag(hdr.flag, flags::ack))
        {
            trace::debug("{} stream {} syn+ack received", tag, stream_id);
            co_return;
        }

        // 普通窗口更新：原子增加发送窗口
        if (auto *window = get_or_create_window(stream_id); window && delta > 0)
        {
            std::uint32_t old_val = window->send_window.load(std::memory_order_acquire);
            std::uint32_t new_val;
            do
            {
                new_val = old_val + delta;
                // 溢出检查，钳制到 uint32_max
                if (new_val < old_val)
                {
                    new_val = std::numeric_limits<std::uint32_t>::max();
                }
            } while (!window->send_window.compare_exchange_weak(old_val, new_val, std::memory_order_acq_rel));
        }

        co_return;
    }

    // === Ping 帧处理 ===

    auto craft::handle_ping(const frame_header &hdr) const -> net::awaitable<void>
    {
        // SYN 标志：Ping 请求，回复 ACK 并携带相同 ID
        if (has_flag(hdr.flag, flags::syn))
        {
            co_await push_frame(message_type::ping, flags::ack, 0, hdr.length, {});
            trace::debug("{} ping request {} replied", tag, hdr.length);
            co_return;
        }

        // ACK 标志：Ping 响应，忽略
        if (has_flag(hdr.flag, flags::ack))
        {
            trace::debug("{} ping response {} received", tag, hdr.length);
        }

        co_return;
    }

    // === GoAway 帧处理 ===

    auto craft::handle_go_away(const frame_header &hdr) -> net::awaitable<void>
    {
        const auto code = static_cast<go_away_code>(hdr.length);
        trace::debug("{} go away received, code={}", tag, static_cast<std::uint32_t>(code));
        close();
        co_return;
    }

    // === 流激活 ===

    auto craft::activate_stream(const std::uint32_t stream_id) -> net::awaitable<void>
    {
        const auto pit = pending_.find(stream_id);
        if (pit == pending_.end())
        {
            co_return;
        }

        auto &entry = pit->second;
        // 解析 sing-mux StreamRequest 格式的目标地址（复用 smux 的地址解析）
        auto addr = smux::parse_mux_address(entry.buffer, mr_);
        if (!addr)
        {
            // 数据不足最小地址长度，继续累积
            if (entry.buffer.size() < 21)
            {
                entry.connecting = false;
                co_return;
            }
            // 地址解析失败，发送错误状态并关闭流
            trace::warn("{} stream {} address parse failed", tag, stream_id);
            memory::vector<std::byte> error_buf(mr_);
            error_buf.push_back(std::byte{0x01});
            co_await send_data(stream_id, std::move(error_buf));
            pending_.erase(stream_id);
            send_fin(stream_id);
            co_return;
        }

        const auto host = std::move(addr->host);
        const auto port = addr->port;
        const auto offset = addr->offset;
        const bool is_udp = addr->is_udp;
        const bool packet_addr = addr->packet_addr;

        // 提取地址之后的剩余数据（连接成功后需要转发）
        memory::vector<std::byte> remaining_data(mr_);
        if (offset < entry.buffer.size())
        {
            const auto remaining = std::span<const std::byte>(entry.buffer).subspan(offset);
            remaining_data.assign(remaining.begin(), remaining.end());
        }

        // UDP 流处理
        if (is_udp)
        {
            trace::debug("{} stream {} creating UDP parcel", tag, stream_id);

            // 发送成功状态
            memory::vector<std::byte> success_buf(mr_);
            success_buf.push_back(std::byte{0x00});
            co_await send_data(stream_id, std::move(success_buf));

            pending_.erase(stream_id);

            auto dp = make_parcel(stream_id, shared_from_this(), router_,
                                   config_.yamux.udp_idle_timeout_ms, config_.yamux.udp_max_datagram,
                                   mr_, packet_addr);
            if (!packet_addr)
            {
                dp->set_destination(host, port);
            }
            dp->start();

            // 转发地址之后的剩余数据
            if (!remaining_data.empty())
            {
                co_await dp->on_mux_data(remaining_data);
            }

            if (active_.load(std::memory_order_acquire))
            {
                parcels_[stream_id] = dp;
            }
            else
            {
                dp->close();
            }

            trace::debug("{} stream {} UDP parcel created", tag, stream_id);
            co_return;
        }

        // TCP 流处理：连接目标
        trace::debug("{} stream {} connecting to {}:{}", tag, stream_id, host, port);

        auto [code, conn] = co_await router_.async_forward(host, std::to_string(port));

        if (code != fault::code::success || !conn.valid())
        {
            trace::warn("{} stream {} connect to {}:{} failed", tag, stream_id, host, port);
            memory::vector<std::byte> error_buf(mr_);
            error_buf.push_back(std::byte{0x01});
            co_await send_data(stream_id, std::move(error_buf));
            pending_.erase(stream_id);
            send_fin(stream_id);
            co_return;
        }

        // 发送成功状态
        memory::vector<std::byte> success_buf(mr_);
        success_buf.push_back(std::byte{0x00});
        co_await send_data(stream_id, std::move(success_buf));

        pending_.erase(stream_id);

        // 创建 duct 并启动双向转发
        auto target = channel::transport::make_reliable(std::move(conn));
        const auto p = make_duct(stream_id, shared_from_this(), std::move(target), config_.yamux.buffer_size, mr_);
        ducts_[stream_id] = p;

        p->start();

        // 转发地址之后的剩余数据
        if (!remaining_data.empty())
        {
            co_await p->on_mux_data(std::move(remaining_data));
        }

        trace::debug("{} stream {} connected to {}:{}", tag, stream_id, host, port);
    }

    // === 窗口管理 ===

    stream_window *craft::get_or_create_window(const std::uint32_t stream_id)
    {
        if (const auto it = windows_.find(stream_id); it != windows_.end())
        {
            return it->second.get();
        }

        auto [new_it, inserted] = windows_.emplace(stream_id, std::make_unique<stream_window>());
        return new_it->second.get();
    }

    auto craft::update_recv_window(const std::uint32_t stream_id, const std::uint32_t consumed)
        -> net::awaitable<void>
    {
        auto *window = get_or_create_window(stream_id);
        if (!window)
        {
            co_return;
        }

        // 累积已消费量
        const std::uint32_t total_consumed = window->recv_consumed.fetch_add(consumed, std::memory_order_acq_rel) + consumed;

        // 达到初始窗口一半时发送 WindowUpdate，避免客户端发送窗口耗尽
        if (total_consumed >= initial_stream_window / 2)
        {
            window->recv_consumed.store(0, std::memory_order_release);

            const std::uint32_t delta = total_consumed;
            co_await push_frame(message_type::window_update, flags::none, stream_id, delta, {});

            trace::debug("{} stream {} window update sent, delta={}", tag, stream_id, delta);
        }
    }

    // === 发送接口 ===

    auto craft::send_data(const std::uint32_t stream_id, memory::vector<std::byte> payload) const
        -> net::awaitable<void>
    {
        co_await push_frame(message_type::data, flags::none, stream_id,
                            static_cast<std::uint32_t>(payload.size()), std::move(payload));
    }

    void craft::send_fin(const std::uint32_t stream_id)
    {
        // 异步发送 FIN，不阻塞调用者（duct 的 target_read_loop）
        auto self = std::static_pointer_cast<craft>(shared_from_this());
        auto send_fn = [self, stream_id]() -> net::awaitable<void>
        {
            co_await self->push_frame(message_type::data, flags::fin, stream_id, 0, {});
        };
        auto callback = [stream_id](const std::exception_ptr &ep)
        {
            if (ep)
            {
                try
                {
                    std::rethrow_exception(ep);
                }
                catch (const std::exception &e)
                {
                    trace::debug("{} stream {} send_fin error: {}", tag, stream_id, e.what());
                }
                catch (...)
                {
                    trace::error("{} stream {} send_fin unknown error", tag, stream_id);
                }
            }
        };
        net::co_spawn(transport_->executor(), send_fn, callback);
    }

    auto craft::executor() const -> net::any_io_executor
    {
        return transport_->executor();
    }

    // === 发送通道 ===

    auto craft::push_frame(const message_type type, const flags f, const std::uint32_t stream_id,
                           const std::uint32_t length, memory::vector<std::byte> payload) const
        -> net::awaitable<void>
    {
        outbound_frame frame(mr_);
        frame_header hdr{};
        hdr.type = type;
        hdr.flag = f;
        hdr.stream_id = stream_id;
        hdr.length = length;
        frame.header = build_header(hdr);
        frame.payload = std::move(payload);

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        co_await channel_.async_send(boost::system::error_code{}, std::move(frame), token);
        if (ec)
        {
            trace::debug("{} push frame to channel failed: {}", tag, ec.message());
        }
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
                auto frame = co_await channel_.async_receive(token);
                if (ec)
                {
                    break;
                }

                // Scatter-gather: 先写帧头，再写 payload
                std::error_code transport_ec;
                co_await transport_->async_write(frame.header, transport_ec);
                if (transport_ec)
                {
                    trace::debug("{} send header failed: {}", tag, transport_ec.message());
                    close();
                    break;
                }

                if (!frame.payload.empty())
                {
                    co_await transport_->async_write(frame.payload, transport_ec);
                    if (transport_ec)
                    {
                        trace::debug("{} send payload failed: {}", tag, transport_ec.message());
                        close();
                        break;
                    }
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

} // namespace psm::multiplex::yamux

/**
 * @file craft.cpp
 * @brief smux 多路复用会话服务端实现（兼容 Mihomo/xtaci/smux v1）
 * @details smux::craft 实现 smux v1 帧协议，包括帧循环、协议协商、
 * 地址解析和流连接。继承 core 的通用流管理能力。
 */

#include <prism/multiplex/smux/craft.hpp>
#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/parcel.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/resolve/router.hpp>
#include <prism/trace.hpp>

#include <boost/asio/co_spawn.hpp>

constexpr std::string_view tag = "[Smux.Craft]";

namespace psm::multiplex::smux
{
    namespace
    {
        // 构建帧头为字节数组（不包含 payload）
        [[nodiscard]] std::array<std::byte, frame_header_size> build_header(
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

    craft::craft(channel::transport::shared_transmission transport, resolve::router &router,
                 const multiplex::config &cfg, const memory::resource_pointer mr)
        : core(std::move(transport), router, cfg, mr),
          channel_(transport_->executor(), cfg.smux.max_streams)
    {
    }

    craft::~craft() = default;

    auto craft::run() -> net::awaitable<void>
    {
        // 启动发送循环（lambda 捕获 self 保持 craft 生命周期）
        const auto self = std::static_pointer_cast<craft>(shared_from_this());
         auto start_send_loop = [self]() -> net::awaitable<void>
        {
            co_await self->send_loop();
        };
        net::co_spawn(executor(), std::move(start_send_loop), net::detached);

        // 启动 NOP 心跳（有间隔时）
        if (config_.smux.keepalive_interval_ms > 0)
        {
            auto start_keepalive = [self]() -> net::awaitable<void>
            {
                co_await self->keepalive_loop();
            };
            net::co_spawn(executor(), std::move(start_keepalive), net::detached);
        }

        // 进入帧循环，处理客户端命令
        co_await frame_loop();

        channel_.cancel();
    }

    auto craft::frame_loop() -> net::awaitable<void>
    {
        trace::debug("{} frame loop started", tag);

        std::error_code ec;
        memory::vector<std::byte> frame_buffer(mr_);
        frame_buffer.resize(frame_header_size);

        // 持续读取并处理帧，直到会话关闭或发生错误
        while (active_.load(std::memory_order_acquire))
        {
            // 读取 8 字节帧头
            const auto hdr_n = co_await transport_->async_read(frame_buffer, ec);
            if (ec || hdr_n < frame_header_size)
            {
                if (ec != std::errc::operation_canceled)
                {
                    trace::debug("{} read header failed: {}", tag, ec.message());
                }
                break;
            }

            // 解析帧头，验证格式有效性
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

            // 读取帧载荷（如果有）
            memory::vector<std::byte> payload(mr_);
            if (hdr.length > 0)
            {
                payload.resize(hdr.length);
                const auto payload_n = co_await transport_->async_read(payload, ec);
                if (ec || payload_n < hdr.length)
                {
                    trace::debug("{} read payload failed: {}", tag, ec.message());
                    break;
                }
            }

            // 根据命令类型分发处理
            switch (hdr.cmd)
            {
            case command::syn:
                // SYN：创建新的流，等待后续地址数据
                co_await handle_syn(hdr.stream_id);
                break;

            case command::push:
                dispatch_push(hdr.stream_id, std::move(payload));
                break;

            case command::fin:
                // FIN：关闭指定流
                handle_fin(hdr.stream_id);
                break;

            case command::nop:
            default:
                // NOP 或未知命令：忽略
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
        // Pending 流：累积数据，可能触发连接
        if (const auto pit = pending_.find(stream_id); pit != pending_.end())
        {
            auto &entry = pit->second;
            entry.buffer.insert(entry.buffer.end(), payload.begin(), payload.end());

            if (!entry.connecting && entry.buffer.size() >= 7)
            {
                entry.connecting = true;
                auto self = std::static_pointer_cast<craft>(shared_from_this());
                auto callback = [self, stream_id](const std::exception_ptr &ep)
                {
                    if (ep)
                    {
                        try
                        {
                            std::rethrow_exception(ep);
                        }
                        catch (const std::exception &e)
                        {
                            trace::debug("{} stream {} activate_stream error: {}", tag, stream_id, e.what());
                        }
                        catch (...)
                        {
                            trace::error("{} stream {} activate_stream unknown error", tag, stream_id);
                        }
                    }
                };
                net::co_spawn(transport_->executor(), self->activate_stream(stream_id), callback);
            }
            return;
        }

        // 已连接的 TCP 流：非阻塞 dispatch，避免慢速 duct 阻塞帧循环
        const auto sit = ducts_.find(stream_id);
        if (sit != ducts_.end() && sit->second)
        {
            auto dp = sit->second;

            auto async_push = [dp, p = std::move(payload)]() mutable -> net::awaitable<void>
            { // dp->on_mux_data 可能涉及网络 I/O，异步调用避免阻塞帧循环
                co_await dp->on_mux_data(std::move(p));
            };
            net::co_spawn(executor(), std::move(async_push), net::detached);
            return;
        }

        // UDP 流：非阻塞 dispatch
        const auto uit = parcels_.find(stream_id);
        if (uit != parcels_.end() && uit->second)
        {
            auto dp = uit->second;
            auto async_push = [dp, p = std::move(payload)]() mutable -> net::awaitable<void>
            {
                co_await dp->on_mux_data(std::move(p));
            };
            net::co_spawn(executor(), std::move(async_push), net::detached);
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
            it->second->on_mux_fin();
            return;
        }

        const auto uit = parcels_.find(stream_id);
        if (uit != parcels_.end() && uit->second)
        {
            uit->second->close();
        }
    }

    auto craft::activate_stream(const std::uint32_t stream_id) -> net::awaitable<void>
    {
        // 查找 pending 条目
        const auto pit = pending_.find(stream_id);
        if (pit == pending_.end())
        {
            co_return;
        }

        auto &entry = pit->second;
        // 解析 SOCKS5 UDP relay 格式的目标地址
        auto addr = parse_mux_address(entry.buffer, mr_);
        if (!addr)
        {
            // 数据不足，等待更多数据；超过最大长度则报错
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

        // 提取地址之后的数据，连接成功后需要转发
        memory::vector<std::byte> remaining_data(mr_);
        if (offset < entry.buffer.size())
        {
            const auto remaining = std::span<const std::byte>(entry.buffer).subspan(offset);
            remaining_data.assign(remaining.begin(), remaining.end());
        }

        // UDP 流处理：创建 parcel 进行数据报中继
        if (is_udp)
        {
            trace::debug("{} stream {} creating UDP parcel", tag, stream_id);

            // 发送成功状态
            memory::vector<std::byte> success_buf(mr_);
            success_buf.push_back(std::byte{0x00});
            co_await send_data(stream_id, std::move(success_buf));

            pending_.erase(stream_id);

            // 创建 UDP parcel 并启动
            auto dp = make_parcel(stream_id, shared_from_this(), router_,
                                   config_.smux.udp_idle_timeout_ms, config_.smux.udp_max_datagram,
                                   mr_, packet_addr);
            if (!packet_addr)
            {
                dp->set_destination(host, port);
            }
            dp->start();

            // 转发剩余数据
            if (!remaining_data.empty())
            {
                co_await dp->on_mux_data(remaining_data);
            }

            // 会话仍活跃则注册到 parcels 映射
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

        // TCP 流处理：连接目标并创建 duct
        trace::debug("{} stream {} connecting to {}:{}", tag, stream_id, host, port);

        // 通过路由器连接目标
        auto [code, conn] = co_await router_.async_forward(host, std::to_string(port));

        // 连接失败处理
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

        // 创建 TCP duct 进行双向转发
        auto target = channel::transport::make_reliable(std::move(conn));
        const auto p = make_duct(stream_id, shared_from_this(), std::move(target), config_.smux.buffer_size, mr_);
        ducts_[stream_id] = p;

        // 启动上行循环
        p->start();

        // 转发剩余数据
        if (!remaining_data.empty())
        {
            co_await p->on_mux_data(std::move(remaining_data));
        }

        trace::debug("{} stream {} connected to {}:{}", tag, stream_id, host, port);
    }

    auto craft::send_data(const std::uint32_t stream_id, memory::vector<std::byte> payload) const
        -> net::awaitable<void>
    {
        co_await push_frame(command::push, stream_id, std::move(payload));
    }

    void craft::send_fin(const std::uint32_t stream_id)
    {
        // FIN 发送不阻塞调用者，异步执行
        auto self = std::static_pointer_cast<craft>(shared_from_this());
        auto send_fn = [self, stream_id]() -> net::awaitable<void>
        {
            memory::vector<std::byte> empty_payload(self->mr_);
            co_await self->push_frame(command::fin, stream_id, std::move(empty_payload));
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

    /**
     * @brief 发送循环，将多路复用帧写入底层传输
     * @details scatter-gather 写入：先写 8 字节帧头，再写 payload。
     * header 与 payload 分离传递，消除 serialize 的 payload 拷贝。
     */
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

                // Scatter-gather: 先写帧头，再写 payload（零拷贝）
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

    auto craft::keepalive_loop() -> net::awaitable<void>
    {
        trace::debug("{} keepalive loop started, interval={}ms", tag, config_.smux.keepalive_interval_ms);
        net::steady_timer timer(executor());
        try
        {
            while (is_active())
            {
                timer.expires_after(std::chrono::milliseconds(config_.smux.keepalive_interval_ms));
                boost::system::error_code ec;
                co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
                if (ec || !is_active())
                {
                    break;
                }
                co_await push_frame(command::nop, 0, memory::vector<std::byte>(mr_));
                trace::debug("{} nop heartbeat sent", tag);
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

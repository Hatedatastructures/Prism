/**
 * @file multiplexer.cpp
 * @brief smux 多路复用会话服务端实现（兼容 Mihomo/xtaci/smux v1）
 * @details multiplexer 负责 pending 阶段的地址解析和连接，pipe 是
 * 纯粹的双向管道。pending_entry 累积首个 PSH 数据，数据足够后
 * 由 multiplexer 发起异步连接，连接成功创建 pipe。
 */

#include <forward-engine/channel/smux/multiplexer.hpp>
#include <forward-engine/channel/transport/reliable.hpp>
#include <forward-engine/resolve/router.hpp>
#include <forward-engine/trace.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

constexpr std::string_view tag = "[Smux]";

namespace ngx::channel::smux
{
    multiplexer::multiplexer(transport::shared_transmission transport, resolve::router &router,                             const config &cfg, const bool sing_mux, const memory::resource_pointer mr)
        : transport_(std::move(transport)), router_(router), config_(cfg), sing_mux_(sing_mux),
          mr_(mr ? mr : memory::current_resource()),
          pending_(mr_), pipes_(mr_), recv_buffer_(mr_),
          send_strand_(net::make_strand(transport_->executor()))
    {
        recv_buffer_.resize(config_.buffer_size);
    }

    multiplexer::~multiplexer()
    {
        close();
    }

    void multiplexer::start()
    {
        active_.store(true, std::memory_order_release);

        auto exception_functor = [self = shared_from_this()](const std::exception_ptr &ep)
        {
            if (ep)
            {
                try
                {
                    std::rethrow_exception(ep);
                }
                catch (const std::exception &e)
                {
                    trace::error("{} frame loop exception: {}", tag, e.what());
                }
            }
            self->close();
        };

        net::co_spawn(transport_->executor(), run(), std::move(exception_functor));
    }

    void multiplexer::close()
    {
        if (!active_.exchange(false, std::memory_order_acq_rel))
        {
            return;
        }

        try
        {
            transport_->cancel();
        }
        catch (...)
        {
        }

        pending_.clear();

        // std::move 避免 iterator invalidation：close() 中 pipe 调用
        // remove_pipe 对空 map 操作
        for (auto pipes = std::move(pipes_); auto &p : pipes | std::views::values)
        {
            if (p)
            {
                p->close();
            }
        }

        try
        {
            transport_->close();
        }
        catch (...)
        {
        }

        trace::debug("{} session closed", tag);
    }

    void multiplexer::remove_pipe(const std::uint32_t stream_id)
    {
        pipes_.erase(stream_id);
    }

    /**
     * @details 根据模式决定是否先执行协议协商，再进入帧循环。
     */
    auto multiplexer::run() -> net::awaitable<void>
    {
        if (sing_mux_)
        {
            const auto ec = co_await negotiate_protocol();
            if (ec)
            {
                trace::warn("{} sing-mux protocol negotiate failed: {}", tag, ec.message());
                co_return;
            }
            trace::debug("{} sing-mux protocol negotiated", tag);
        }
        co_await frame_loop();
    }

    /**
     * @details 读取 sing-mux 协议头：[Version 1B][Protocol 1B]，
     * Version > 0 时额外读取 [PaddingLen 2B big-endian][Padding N bytes]。
     */
    auto multiplexer::negotiate_protocol() -> net::awaitable<std::error_code>
    {
        std::error_code ec;

        // 读取 Version + Protocol（2 字节）
        std::array<std::byte, 2> header{};
        const auto n = co_await transport_->async_read(header, ec);
        if (ec)
        {
            co_return ec;
        }
        if (n < 2)
        {
            co_return std::make_error_code(std::errc::connection_reset);
        }

        const auto version = static_cast<std::uint8_t>(header[0]);
        // const auto protocol = static_cast<std::uint8_t>(header[1]);

        // Version > 0 时读取 padding
        if (version > 0)
        {
            std::array<std::byte, 2> padding_len_buf{};
            const auto pn = co_await transport_->async_read(padding_len_buf, ec);
            if (ec)
            {
                co_return ec;
            }
            if (pn < 2)
            {
                co_return std::make_error_code(std::errc::connection_reset);
            }

            const auto padding_len = static_cast<std::uint16_t>(padding_len_buf[0]) << 8 |
                                     static_cast<std::uint16_t>(padding_len_buf[1]);
            if (padding_len > 0)
            {
                memory::vector<std::byte> padding(mr_);
                padding.resize(padding_len);
                const auto padding_n = co_await transport_->async_read(padding, ec);
                if (ec || padding_n < padding_len)
                {
                    co_return ec ? ec : std::make_error_code(std::errc::connection_reset);
                }
            }
        }

        co_return std::error_code{};
    }

    /**
     * @details 循环读取 8 字节帧头 + 变长负载，按命令类型分发。
     * PSH 帧通过 co_await handle_data 直接写入 target，天然反压。
     * transport 关闭或读取错误时退出循环。
     */
    auto multiplexer::frame_loop() -> net::awaitable<void>
    {
        trace::debug("{} frame loop started", tag);

        std::error_code ec;
        memory::vector<std::byte> frame_buffer(mr_);
        frame_buffer.resize(frame_header_size);

        while (active_.load(std::memory_order_acquire))
        {
            // 读取帧头（8 字节）
            const auto hdr_n = co_await transport_->async_read(frame_buffer, ec);
            if (ec || hdr_n < frame_header_size)
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
                // hex dump 帧头字节用于诊断
                trace::warn("{} invalid frame header: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
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

            // 读取负载
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

            switch (hdr.cmd)
            {
            case command::syn:
                co_await handle_syn(hdr.stream_id);
                break;

            case command::push:
                co_await handle_data(hdr.stream_id, payload);
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

    /**
     * @details 检查 pending + active 总数是否超过 max_streams，
     * 未超限时创建 pending_entry 等待首个 PSH 携带地址数据。
     */
    auto multiplexer::handle_syn(const std::uint32_t stream_id)
        -> net::awaitable<void>
    {
        // 检查 pending + active 总数
        if (pending_.size() + pipes_.size() >= config_.max_streams)
        {
            trace::warn("{} max streams reached, rejecting stream {}", tag, stream_id);
            co_return;
        }

        pending_.emplace(stream_id, pending_entry(mr_));
        trace::debug("{} stream {} pending, waiting for address", tag, stream_id);
    }

    /**
     * @details 三路分发：pending 中累积数据，数据足够时通过
     * co_spawn 发起 connect_pipe（低频，仅首次连接，不阻塞帧循环）；
     * active 管道直接 co_await 写 target，天然反压。
     */
    auto multiplexer::handle_data(const std::uint32_t stream_id, std::span<const std::byte> payload)
        -> net::awaitable<void>
    {
        // 1. pending 中？累积数据
        const auto pit = pending_.find(stream_id);
        if (pit != pending_.end())
        {
            auto &entry = pit->second;
            entry.buffer.insert(entry.buffer.end(), payload.begin(), payload.end());
            // 数据足够且尚未发起连接（Flags 2B 格式最小地址约 7 字节）
            if (!entry.connecting && entry.buffer.size() >= 7)
            {
                entry.connecting = true;
                // 连接操作低频（仅首次），co_spawn 不阻塞帧循环
                auto self = shared_from_this();
                net::co_spawn(transport_->executor(), self->connect_pipe(stream_id), net::detached);
            }
            co_return;
        }

        // 2. active pipe：直接 co_await 写 target
        const auto sit = pipes_.find(stream_id);
        if (sit != pipes_.end() && sit->second)
        {
            co_await sit->second->on_mux_data(payload);
        }
    }

    /**
     * @details pending 中直接移除；active 管道通知 on_mux_fin 半关闭。
     */
    void multiplexer::handle_fin(const std::uint32_t stream_id)
    {
        // pending 中直接移除
        if (pending_.erase(stream_id))
        {
            trace::debug("{} stream {} fin while pending", tag, stream_id);
            return;
        }

        // active pipe 通知 fin
        auto it = pipes_.find(stream_id);
        if (it != pipes_.end() && it->second)
        {
            it->second->on_mux_fin();
        }
    }

    /**
     * @details 从 pending_entry 中解析 SOCKS5 风格地址，
     * 通过 router 异步连接目标，成功后创建 pipe 并启动双向转发。
     * sing_mux 模式下发送 StreamResponse（1 字节 PSH）通知客户端连接结果。
     * 连接失败时发送 FIN 帧通知客户端。
     * @note 必须在任何 co_await 前从 entry 中提取所有需要的数据，
     * 因为 co_await 期间 frame_loop 可能处理 FIN 并删除 pending 条目。
     */
    auto multiplexer::connect_pipe(const std::uint32_t stream_id) -> net::awaitable<void>
    {
        const auto pit = pending_.find(stream_id);
        if (pit == pending_.end())
        {
            co_return;
        }

        auto &entry = pit->second;
        auto addr = parse_mux_address(entry.buffer, mr_);
        if (!addr)
        {
            // 解析失败可能是数据不足（如 IPv4 需 9 字节，IPv6 需 21 字节）
            // 如果 buffer 还小，重置 connecting 等待更多 PSH 数据
            if (entry.buffer.size() < 21)
            {
                entry.connecting = false;
                co_return;
            }
            // 数据已足够多但仍然解析失败，视为格式错误
            trace::warn("{} stream {} address parse failed", tag, stream_id);
            if (sing_mux_)
            {
                const std::byte error_status{0x01};
                co_await send_data(stream_id, std::span<const std::byte>(&error_status, 1));
            }
            pending_.erase(stream_id);
            send_fin(stream_id);
            co_return;
        }

        // 在任何 co_await 之前，从 entry 中提取所有后续需要的数据
        // 因为 co_await 期间 frame_loop 可能处理 FIN 并删除 pending 条目
        const auto host = std::move(addr->host);
        const auto port = addr->port;
        const auto offset = addr->offset;
        memory::vector<std::byte> remaining_data(mr_);
        if (offset < entry.buffer.size())
        {
            const auto remaining = std::span<const std::byte>(entry.buffer).subspan(offset);
            remaining_data.assign(remaining.begin(), remaining.end());
        }

        trace::debug("{} stream {} connecting to {}:{}", tag, stream_id, host, port);

        // 通过路由器连接目标
        auto [code, conn] = co_await router_.async_forward(host, std::to_string(port));

        if (code != fault::code::success || !conn.valid())
        {
            trace::warn("{} stream {} connect to {}:{} failed", tag, stream_id, host, port);
            if (sing_mux_)
            {
                const std::byte error_status{0x01};
                co_await send_data(stream_id, std::span<const std::byte>(&error_status, 1));
            }
            pending_.erase(stream_id);
            send_fin(stream_id);
            co_return;
        }

        // sing_mux 模式发送 StreamResponse（success）
        if (sing_mux_)
        {
            const std::byte success_status{0x00};
            co_await send_data(stream_id, std::span<const std::byte>(&success_status, 1));
        }

        // 创建 pipe 前 erase pending，避免 pending_ 和 pipes_ 同时持有
        pending_.erase(stream_id);

        auto target = transport::make_reliable(std::move(conn));
        const auto p = std::make_shared<pipe>(stream_id, shared_from_this(), target, mr_);
        pipes_[stream_id] = p;

        // 先 start 启动上行循环，再发送剩余数据
        p->start();

        if (!remaining_data.empty())
        {
            co_await p->on_mux_data(remaining_data);
        }

        trace::debug("{} stream {} connected to {}:{}", tag, stream_id, host, port);
    }

    auto multiplexer::send_data(const std::uint32_t stream_id, const std::span<const std::byte> payload) const
        -> net::awaitable<void>
    {
        frame_header hdr{};
        hdr.cmd = command::push;
        hdr.stream_id = stream_id;
        hdr.length = static_cast<std::uint16_t>(payload.size());

        co_await send_frame(hdr, payload);
    }

    void multiplexer::send_fin(const std::uint32_t stream_id)
    {
        frame_header hdr{};
        hdr.cmd = command::fin;
        hdr.stream_id = stream_id;

        // 捕获 shared_ptr 确保 detached 协程运行期间 mux 不被销毁
        auto self = shared_from_this();
        net::co_spawn(transport_->executor(),
                      [self, hdr]() -> net::awaitable<void> { co_await self->send_frame(hdr, {}); },
                      net::detached);
    }

    /**
     * @details 先 post 到 send_strand_ 串行化，再序列化帧并写入 transport。
     * 确保多个管道并发发送时帧不会被交错写入。
     */
    auto multiplexer::send_frame(const frame_header &hdr, const std::span<const std::byte> payload) const
        -> net::awaitable<void>
    {
        // 通过 strand 串行化发送操作
        co_await net::post(send_strand_, net::use_awaitable);

        auto frame = serialize(hdr, payload, mr_);

        std::error_code ec;
        co_await transport_->async_write(frame, ec);

        if (ec)
        {
            trace::debug("{} send frame failed: {}", tag, ec.message());
        }
    }

    pipe::pipe(const std::uint32_t stream_id, std::shared_ptr<multiplexer> mux, transport::shared_transmission target,
               const memory::resource_pointer mr)
        : stream_id_(stream_id), mux_(std::move(mux)), mr_(mr),
          target_(std::move(target)),
          recv_buffer_(mr)
    {
        recv_buffer_.resize(mux_->config_.buffer_size);
    }

    pipe::~pipe()
    {
        close();
    }

    /**
     * @details 通过 co_spawn 在 target executor 上启动上行循环，
     * 独立生命周期，异常或正常退出时自动调用 close()。
     */
    void pipe::start()
    {
        auto self = shared_from_this();
        auto on_done = [self](const std::exception_ptr &ep)
        {
            if (ep)
            {
                try
                {
                    std::rethrow_exception(ep);
                }
                catch (const std::exception &e)
                {
                    trace::debug("{} stream {} uplink error: {}", tag, self->stream_id_, e.what());
                }
            }
            self->close();
        };
        net::co_spawn(target_->executor(), uplink_loop(), std::move(on_done));
    }

    /**
     * @details 直接 co_await 写入 target，由帧循环同步等待完成，
     * 不经过额外缓冲，天然反压。写入失败时关闭管道。
     */
    auto pipe::on_mux_data(const std::span<const std::byte> data) -> net::awaitable<void>
    {
        if (closed_)
        {
            co_return;
        }

        std::error_code ec;
        co_await target_->async_write(data, ec);
        if (ec)
        {
            trace::debug("{} stream {} write to target failed: {}", tag, stream_id_, ec.message());
            close();
        }
    }

    /**
     * @details 标记 mux_closed_，关闭 target 写端通知对端不再发送数据。
     * 若 target 也已关闭则立即 close() 完成全关闭。
     */
    void pipe::on_mux_fin()
    {
        mux_closed_.store(true, std::memory_order_release);

        if (target_)
        {
            target_->shutdown_write();
            trace::debug("{} stream {} mux fin, shutdown send", tag, stream_id_);
        }

        if (target_closed_.load(std::memory_order_acquire))
        {
            close();
        }
    }

    /**
     * @details 关闭 target 传输层并从 multiplexer 移除自身。
     * 幂等操作，closed_ 标志防止重复执行。
     */
    void pipe::close()
    {
        if (closed_)
        {
            return;
        }
        closed_ = true;

        if (target_)
        {
            try
            {
                target_->close();
            }
            catch (...)
            {
            }
            target_.reset();
        }

        mux_->remove_pipe(stream_id_);

        trace::debug("{} stream {} closed", tag, stream_id_);
    }

    /**
     * @details 循环 co_await async_read_some 从 target 读取数据，
     * 通过 multiplexer::send_data 发送 PSH 帧到客户端。
     * target EOF 或读取错误时退出循环，标记 target_closed_，
     * 若 mux 端未关闭则发送 FIN 帧通知客户端。
     */
    auto pipe::uplink_loop() -> net::awaitable<void>
    {
        std::error_code ec;

        while (!closed_)
        {
            const auto n = co_await target_->async_read_some(recv_buffer_, ec);
            if (ec || n == 0)
            {
                if (ec != std::errc::operation_canceled)
                {
                    trace::debug("{} stream {} target read eof or error: {}", tag, stream_id_, ec.message());
                }
                break;
            }

            if (!mux_->is_active())
            {
                break;
            }
            co_await mux_->send_data(stream_id_, std::span(recv_buffer_.data(), n));
        }

        target_closed_.store(true, std::memory_order_release);

        if (!mux_closed_.load(std::memory_order_acquire) && mux_->is_active())
        {
            mux_->send_fin(stream_id_);
        }
    }

} // namespace ngx::channel::smux

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
    craft::craft(channel::transport::shared_transmission transport, resolve::router &router,
                 const config &cfg, const memory::resource_pointer mr)
        : core(std::move(transport), router, cfg, mr)
    {
        recv_buffer_ = memory::vector<std::byte>(mr_);
        recv_buffer_.resize(config_.buffer_size);
    }

    craft::~craft() = default;

    auto craft::run() -> net::awaitable<void>
    {
        // 执行协议协商，验证客户端兼容性
        if (const auto ec = co_await negotiate_protocol())
        {
            trace::warn("{} protocol negotiate failed: {}", tag, ec.message());
            co_return;
        }
        trace::debug("{} protocol negotiated", tag);

        // 进入帧循环，处理客户端命令
        co_await frame_loop();
    }

    auto craft::negotiate_protocol() const -> net::awaitable<std::error_code>
    {
        std::error_code ec;

        // 读取协议头：[Version 1B][Protocol 1B]
        // Version > 0 时需要额外读取 padding 数据
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

        // 处理协议版本，Version > 0 表示有 padding
        if (const auto version = static_cast<std::uint8_t>(header[0]); version > 0)
        {
            // 读取 2 字节 padding 长度（大端序）
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

            // 解析 padding 长度并读取 padding 数据
            const auto padding_len = static_cast<std::uint16_t>(padding_len_buf[0]) << 8 | static_cast<std::uint16_t>(padding_len_buf[1]);
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
                // PSH：数据帧，转发到对应的流
                co_await handle_data(hdr.stream_id, payload);
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
        if (pending_.size() + ducts_.size() + parcels_.size() >= config_.max_streams)
        {
            trace::warn("{} max streams reached, rejecting stream {}", tag, stream_id);
            co_return;
        }

        pending_.emplace(stream_id, pending_entry(mr_));
        trace::debug("{} stream {} pending, waiting for address", tag, stream_id);
    }

    auto craft::handle_data(const std::uint32_t stream_id, std::span<const std::byte> payload)
        -> net::awaitable<void>
    {
        // 检查是否为 pending 流（刚创建，等待地址数据）
        if (const auto pit = pending_.find(stream_id); pit != pending_.end())
        {
            auto &entry = pit->second;
            // 累积数据到缓冲区
            entry.buffer.insert(entry.buffer.end(), payload.begin(), payload.end());

            // 数据足够时异步发起连接（至少 7 字节：ATYP + 地址 + 端口）
            if (!entry.connecting && entry.buffer.size() >= 7)
            {
                entry.connecting = true;
                auto self = std::static_pointer_cast<craft>(shared_from_this());
                // 异常回调：记录连接激活失败
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
                            trace::debug("{} stream {} activate_stream error: {}", tag, stream_id, e.what());
                        }
                        catch (...)
                        {
                            trace::error("{} stream {} activate_stream unknown error", tag, stream_id);
                        }
                    }
                };
                // 在 transport 执行器上启动连接协程
                net::co_spawn(transport_->executor(), self->activate_stream(stream_id), callback);
            }
            co_return;
        }

        // 已连接的 TCP 流：直接转发数据到 duct
        const auto sit = ducts_.find(stream_id);
        if (sit != ducts_.end() && sit->second)
        {
            co_await sit->second->on_mux_data(payload);
            co_return;
        }

        // UDP 流：转发数据报到 parcel
        const auto uit = parcels_.find(stream_id);
        if (uit != parcels_.end() && uit->second)
        {
            co_await uit->second->on_mux_data(payload);
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
            constexpr std::byte error_status{0x01};
            co_await send_data(stream_id, std::span(&error_status, 1));
            pending_.erase(stream_id);
            send_fin(stream_id);
            co_return;
        }

        const auto host = std::move(addr->host);
        const auto port = addr->port;
        const auto offset = addr->offset;
        const bool is_udp = addr->is_udp;

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
            constexpr std::byte success_status{0x00};
            co_await send_data(stream_id, std::span(&success_status, 1));

            pending_.erase(stream_id);

            // 创建 UDP parcel 并启动
            auto dp = std::make_shared<parcel>(stream_id, shared_from_this(), config_, router_, mr_);
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
            constexpr std::byte error_status{0x01};
            co_await send_data(stream_id, std::span(&error_status, 1));
            pending_.erase(stream_id);
            send_fin(stream_id);
            co_return;
        }

        // 发送成功状态
        constexpr std::byte success_status{0x00};
        co_await send_data(stream_id, std::span(&success_status, 1));

        pending_.erase(stream_id);

        // 创建 TCP duct 进行双向转发
        auto target = channel::transport::make_reliable(std::move(conn));
        const auto p = std::make_shared<duct>(stream_id, shared_from_this(), target, mr_);
        ducts_[stream_id] = p;

        // 启动上行循环
        p->start();

        // 转发剩余数据
        if (!remaining_data.empty())
        {
            co_await p->on_mux_data(remaining_data);
        }

        trace::debug("{} stream {} connected to {}:{}", tag, stream_id, host, port);
    }

    auto craft::send_data(const std::uint32_t stream_id, const std::span<const std::byte> payload) const
        -> net::awaitable<void>
    {
        frame_header hdr{};
        hdr.cmd = command::push;
        hdr.stream_id = stream_id;
        hdr.length = static_cast<std::uint16_t>(payload.size());

        co_await send_frame(hdr, payload);
    }

    void craft::send_fin(const std::uint32_t stream_id)
    {
        // FIN 发送不阻塞调用者，异步执行
        frame_header hdr{};
        hdr.cmd = command::fin;
        hdr.stream_id = stream_id;

        auto self = std::static_pointer_cast<craft>(shared_from_this());
        auto send_frame_fn = [self, hdr]() -> net::awaitable<void>
        {
            co_await self->send_frame(hdr, {});
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
        net::co_spawn(transport_->executor(), send_frame_fn, callback);
    }

    auto craft::executor() const -> net::any_io_executor
    {
        return transport_->executor();
    }

    auto craft::send_frame(const frame_header &hdr, const std::span<const std::byte> payload) const
        -> net::awaitable<void>
    {
        // strand 串行化发送，避免帧交错
        co_await net::post(send_strand_, net::use_awaitable);

        auto frame = serialize(hdr, payload, mr_);

        std::error_code ec;
        co_await transport_->async_write(frame, ec);
        if (ec)
        {
            trace::debug("{} send frame failed: {}", tag, ec.message());
        }
    }

} // namespace psm::multiplex::smux
#include <prism/protocol/vless/relay.hpp>
#include <prism/protocol/vless/format.hpp>
#include <prism/fault/handling.hpp>
#include <prism/protocol/common/read.hpp>
#include <prism/protocol/common/udp_relay.hpp>
#include <prism/trace.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <array>
#include <string>
#include <algorithm>
#include <cstring>
#include <charconv>

namespace psm::protocol::vless
{
    // 引用共享读取工具函数
    using protocol::common::read_at_least;
    using protocol::common::read_remaining;

    /**
     * @brief 将 UUID 字节数组转换为标准字符串格式
     */
    static auto uuid_to_string(const std::array<uint8_t, 16> &uuid) -> std::string
    {
        std::array<char, 37> buf;
        static constexpr int groups[] = {4, 2, 2, 2, 6};
        int pos = 0;
        int byte_idx = 0;
        for (int g = 0; g < 5; ++g)
        {
            for (int i = 0; i < groups[g]; ++i)
            {
                const uint8_t b = uuid[byte_idx++];
                snprintf(buf.data() + pos, 3, "%02x", b);
                pos += 2;
            }
            if (g < 4)
            {
                buf[pos++] = '-';
            }
        }
        buf[36] = '\0';
        return std::string(buf.data());
    }

    relay::relay(channel::transport::shared_transmission next_layer, const config &cfg,
                 std::function<bool(std::string_view)> verifier)
        : next_layer_(std::move(next_layer)), config_(cfg), verifier_(std::move(verifier))
    {
    }

    relay::executor_type relay::executor() const
    {
        return next_layer_->executor();
    }

    auto relay::async_read_some(const std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        co_return co_await next_layer_->async_read_some(buffer, ec);
    }

    auto relay::async_write_some(const std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        co_return co_await next_layer_->async_write_some(buffer, ec);
    }

    void relay::close()
    {
        next_layer_->close();
    }

    void relay::cancel()
    {
        next_layer_->cancel();
    }

    auto relay::handshake()
        -> net::awaitable<std::pair<fault::code, request>>
    {
        // 缓冲区足够容纳最大 VLESS 请求
        // 最大: Version(1) + UUID(16) + AddnlInfoLen(1) + Cmd(1) + Port(2) + Atyp(1) + DomainLen(1) + Domain(255) = 278
        std::array<std::uint8_t, 320> buffer{};
        const auto byte_span = std::span(reinterpret_cast<std::byte *>(buffer.data()), buffer.size());
        const auto data_span = std::span<const std::uint8_t>(buffer.data(), buffer.size());

        // 最小请求长度：Version(1) + UUID(16) + AddnlInfoLen(1) + Cmd(1) + Port(2) + Atyp(1) + IPv4(4) = 26
        static constexpr std::size_t k_min_request_size = 26;

        // 第一次读取至少 26 字节
        // 使用受限 span 防止从 preview transport 过度消费：preview 可能包含 inner probe 的
        // 多余字节（如 sing-mux 握手 + smux 帧），限制读取量确保多余字节留在 preview 中，
        // 供后续 mux bootstrap 的 negotiate() 正确读取
        auto [read_ec, total] = co_await read_at_least(*next_layer_, byte_span.first(k_min_request_size), k_min_request_size);
        if (fault::failed(read_ec))
        {
            co_return std::pair{read_ec, request{}};
        }

        // 校验版本号
        if (buffer[0] != version)
        {
            co_return std::pair{fault::code::bad_message, request{}};
        }

        // 解析 UUID (offset 1-16)
        std::array<uint8_t, 16> uuid;
        std::memcpy(uuid.data(), buffer.data() + 1, 16);

        // 解析附加信息长度 (offset 17)
        const std::uint8_t addnl_len = buffer[17];
        if (addnl_len != 0)
        {
            co_return std::pair{fault::code::bad_message, request{}};
        }

        // 解析命令 (offset 18)
        const auto cmd = static_cast<command>(buffer[18]);
        switch (cmd)
        {
        case command::tcp:
        case command::mux:
            break;
        case command::udp:
            break;
        default:
            co_return std::pair{fault::code::unsupported_command, request{}};
        }

        // 解析端口 (offset 19-20)
        const uint16_t port = static_cast<uint16_t>(buffer[19]) << 8 | static_cast<uint16_t>(buffer[20]);

        // 解析地址类型 (offset 21)
        const auto atyp = static_cast<address_type>(buffer[21]);
        std::size_t offset = 22;

        // 根据地址类型计算完整请求长度
        std::size_t required_total = offset;
        switch (atyp)
        {
        case address_type::ipv4:
            required_total = offset + 4;
            break;
        case address_type::ipv6:
            required_total = offset + 16;
            break;
        case address_type::domain:
        {
            if (total <= offset)
            {
                // 需要再读一个字节来获取域名长度
                // 限制 span 到 offset+1 防止从 preview 过度消费 mux 数据
                auto [rem_ec, new_total] = co_await read_remaining(*next_layer_, byte_span.first(offset + 1), total, offset + 1);
                if (fault::failed(rem_ec))
                {
                    co_return std::pair{rem_ec, request{}};
                }
                total = new_total;
            }
            const std::uint8_t domain_len = buffer[offset];
            required_total = offset + 1 + domain_len;
            break;
        }
        default:
            co_return std::pair{fault::code::unsupported_address, request{}};
        }

        // 如果数据不足，补读剩余字节
        if (total < required_total)
        {
            // 限制 span 到 required_total 防止从 preview 过度消费 mux 数据
            auto [rem_ec, new_total] = co_await read_remaining(*next_layer_, byte_span.first(required_total), total, required_total);
            if (fault::failed(rem_ec))
            {
                co_return std::pair{rem_ec, request{}};
            }
            total = new_total;
        }

        // 解析地址
        address dest_addr;
        switch (atyp)
        {
        case address_type::ipv4:
        {
            ipv4_address addr;
            std::memcpy(addr.bytes.data(), buffer.data() + offset, 4);
            dest_addr = addr;
            break;
        }
        case address_type::ipv6:
        {
            ipv6_address addr;
            std::memcpy(addr.bytes.data(), buffer.data() + offset, 16);
            dest_addr = addr;
            break;
        }
        case address_type::domain:
        {
            const std::uint8_t domain_len = buffer[offset];
            domain_address addr;
            addr.length = domain_len;
            std::memcpy(addr.value.data(), buffer.data() + offset + 1, domain_len);
            dest_addr = addr;
            break;
        }
        default:
            co_return std::pair{fault::code::unsupported_address, request{}};
        }

        // 通过 verifier 回调验证 UUID
        if (verifier_)
        {
            const auto uuid_str = uuid_to_string(uuid);
            if (!verifier_(uuid_str))
            {
                trace::warn("[Vless] UUID verification failed");
                co_return std::pair{fault::code::auth_failed, request{}};
            }
        }

        // 发送响应 [0x00]
        const auto response = format::make_response();
        std::error_code write_ec;
        co_await next_layer_->async_write({response.data(), response.size()}, write_ec);
        if (write_ec)
        {
            co_return std::pair{fault::to_code(write_ec), request{}};
        }

        // 构建请求
        request req;
        req.uuid = uuid;
        req.cmd = cmd;
        req.port = port;
        req.destination_address = std::move(dest_addr);
        req.form = (cmd == command::udp) ? psm::protocol::form::datagram : psm::protocol::form::stream;

        co_return std::pair{fault::code::success, std::move(req)};
    }

    channel::transport::transmission &relay::next_layer() noexcept
    {
        return *next_layer_;
    }

    const channel::transport::transmission &relay::next_layer() const noexcept
    {
        return *next_layer_;
    }

    channel::transport::shared_transmission relay::release()
    {
        return std::move(next_layer_);
    }

    auto relay::async_associate(route_callback route_cb) const -> net::awaitable<fault::code>
    {
        if (!config_.enable_udp)
        {
            co_return fault::code::not_supported;
        }

        net::steady_timer idle_timer(next_layer_->executor());
        idle_timer.expires_after(std::chrono::seconds(config_.udp_idle_timeout));

        co_await udp_frame_loop(route_cb, idle_timer);
        co_return fault::code::success;
    }

    /**
     * @brief 构建并发送 VLESS UDP 响应
     * @param transport 传输层
     * @param sender_ep 发送者端点
     * @param resp_n 响应数据长度
     * @param buf 缓冲区集合
     * @return 是否成功（失败应终止循环）
     */
    inline auto send_vless_udp_response(channel::transport::transmission &transport,
                                        const net::ip::udp::endpoint &sender_ep,
                                        std::size_t resp_n,
                                        protocol::common::udp_buffers &buf)
        -> net::awaitable<bool>
    {
        buf.send.clear();
        format::udp_frame frame;
        if (sender_ep.address().is_v4())
        {
            frame.destination_address = ipv4_address{sender_ep.address().to_v4().to_bytes()};
        }
        else
        {
            frame.destination_address = ipv6_address{sender_ep.address().to_v6().to_bytes()};
        }
        frame.destination_port = sender_ep.port();
        format::build_udp_packet(frame, {buf.response.data(), resp_n}, buf.send);

        std::error_code write_ec;
        co_await transport.async_write({buf.send.data(), buf.send.size()}, write_ec);
        if (write_ec)
        {
            trace::debug("[Vless.UDP] Write response failed: {}", write_ec.message());
            co_return false;
        }
        co_return true;
    }

    auto relay::udp_frame_loop(route_callback &route_cb, net::steady_timer &idle_timer) const
        -> net::awaitable<void>
    {
        using namespace boost::asio::experimental::awaitable_operators;

        protocol::common::udp_buffers buf(config_.udp_max_datagram);

        // 复用 UDP socket 避免每包 open/close（节省 2 syscall/包）
        net::ip::udp::socket udp_socket(next_layer_->executor());

        while (true)
        {
            idle_timer.expires_after(std::chrono::seconds(config_.udp_idle_timeout));

            // 包装读取操作，使 transmission 接口适配 || 运算符
            auto do_read = [&]() -> net::awaitable<std::size_t>
            {
                std::error_code ec;
                const auto n = co_await next_layer_->async_read_some(
                    {buf.recv.data(), buf.recv.size()}, ec);
                if (ec || n == 0)
                {
                    co_return 0;
                }
                co_return n;
            };

            // 并行等待：读取数据或空闲超时，先到先得
            auto read_result = co_await (do_read() || idle_timer.async_wait(net::use_awaitable));

            // 超时分支
            if (read_result.index() == 1)
            {
                trace::debug("[Vless.UDP] Idle timeout");
                co_return;
            }

            const auto n = std::get<0>(read_result);
            idle_timer.cancel();

            if (n == 0)
            {
                trace::debug("[Vless.UDP] Read error or EOF");
                co_return;
            }

            auto [parse_ec, parsed] = format::parse_udp_packet(
                std::span<const std::byte>{buf.recv.data(), n});
            if (fault::failed(parse_ec))
            {
                trace::warn("[Vless.UDP] Packet parse failed");
                continue;
            }

            const auto target_host = to_string(parsed.destination_address, memory::current_resource());
            char port_buf[8];
            const auto [port_end, port_ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), parsed.destination_port);
            const std::string_view target_port(port_buf, std::distance(port_buf, port_end));

            auto [route_ec, target_ep] = co_await route_cb(target_host, target_port);
            if (fault::failed(route_ec))
            {
                trace::debug("[Vless.UDP] Route failed for {}:{}", target_host, target_port);
                continue;
            }

            const auto payload = std::span<const std::byte>(buf.recv.data() + parsed.payload_offset, parsed.payload_size);

            auto [relay_ec, resp_n, sender_ep] = co_await protocol::common::relay_udp_packet(
                udp_socket, target_ep, payload, buf);
            if (fault::failed(relay_ec))
            {
                continue;
            }

            if (!co_await send_vless_udp_response(*next_layer_, sender_ep, resp_n, buf))
            {
                co_return;
            }
        }
    }

} // namespace psm::protocol::vless

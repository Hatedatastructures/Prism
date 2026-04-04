/**
 * @file relay.cpp
 * @brief Trojan 协议中继器实现
 * @details 该文件实现了 relay 类的所有成员方法，包括构造函数、
 * 传输层操作、握手流程和辅助方法。从 relay.hpp 分离出来，
 * 使头文件只保留声明，提高代码组织清晰度。
 */

#include <prism/protocol/trojan/relay.hpp>
#include <prism/memory/container.hpp>
#include <prism/trace.hpp>
#include <array>
#include <string_view>
#include <algorithm>

constexpr std::string_view udp_tag = "[Trojan.UDP]";

namespace psm::protocol::trojan
{

    /**
     * @brief 批量读取至少指定数量的字节
     * @param transport 传输层
     * @param buffer 输出缓冲区
     * @param min_size 最小读取字节数
     * @return 错误码和实际读取字节数
     */
    inline auto read_at_least(channel::transport::transmission &transport, const std::span<std::byte> buffer,
                              const std::size_t min_size)
        -> net::awaitable<std::pair<fault::code, std::size_t>>
    {
        std::size_t total = 0;
        while (total < min_size)
        {
            std::error_code ec;
            const auto n = co_await transport.async_read_some(buffer.subspan(total), ec);
            if (ec)
            {
                co_return std::pair{fault::to_code(ec), total};
            }
            if (n == 0)
            {
                co_return std::pair{fault::code::eof, total};
            }
            total += n;
        }
        co_return std::pair{fault::code::success, total};
    }

    /**
     * @brief 精确补读剩余字节
     * @param transport 传输层
     * @param buffer 输出缓冲区
     * @param current 当前已读字节数
     * @param target 目标字节数
     * @return 错误码和最终读取字节数
     */
    inline auto read_remaining(channel::transport::transmission &transport, const std::span<std::byte> buffer,
                               std::size_t current, const std::size_t target)
        -> net::awaitable<std::pair<fault::code, std::size_t>>
    {
        while (current < target)
        {
            std::error_code ec;
            const auto n = co_await transport.async_read_some(buffer.subspan(current), ec);
            if (ec)
            {
                co_return std::pair{fault::to_code(ec), current};
            }
            if (n == 0)
            {
                co_return std::pair{fault::code::eof, current};
            }
            current += n;
        }
        co_return std::pair{fault::code::success, current};
    }

    /**
     * @brief 验证命令并确定传输形式
     * @param cmd 命令类型
     * @param cfg 配置
     * @return 错误码和传输形式
     */
    inline auto validate_command(const command cmd, const config &cfg)
        -> std::pair<fault::code, form>
    {
        switch (cmd)
        {
        case command::connect:
            if (!cfg.enable_tcp)
            {
                return {fault::code::forbidden, form::stream};
            }
            return {fault::code::success, form::stream};
        case command::udp_associate:
            if (!cfg.enable_udp)
            {
                return {fault::code::forbidden, form::datagram};
            }
            return {fault::code::success, form::datagram};
        case command::mux:
            return {fault::code::success, form::stream};
        default:
            return {fault::code::unsupported_command, form::stream};
        }
    }

    /**
     * @brief 从缓冲区解析地址
     * @param buffer 数据缓冲区
     * @param offset 起始偏移
     * @param atyp 地址类型
     * @return 错误码、地址、消耗字节数
     */
    inline auto parse_address_from_buffer(const std::span<const std::uint8_t> buffer, const std::size_t offset, const address_type atyp)
        -> std::tuple<fault::code, address, std::size_t>
    {
        switch (atyp)
        {
        case address_type::ipv4:
        {
            if (buffer.size() < offset + 4)
            {
                return {fault::code::bad_message, address{}, 0};
            }
            auto [ec, addr] = format::parse_ipv4(buffer.subspan(offset, 4));
            return {ec, address{addr}, 4};
        }
        case address_type::ipv6:
        {
            if (buffer.size() < offset + 16)
            {
                return {fault::code::bad_message, address{}, 0};
            }
            auto [ec, addr] = format::parse_ipv6(buffer.subspan(offset, 16));
            return {ec, address{addr}, 16};
        }
        case address_type::domain:
        {
            if (buffer.size() < offset + 1)
            {
                return {fault::code::bad_message, address{}, 0};
            }
            const std::uint8_t len = buffer[offset];
            if (buffer.size() < offset + 1 + len)
            {
                return {fault::code::bad_message, address{}, 0};
            }
            auto [ec, addr] = format::parse_domain(buffer.subspan(offset, 1 + len));
            return {ec, address{addr}, 1 + len};
        }
        default:
            return {fault::code::unsupported_address, address{}, 0};
        }
    }

    /**
     * @brief UDP 会话缓冲区集合
     * @details 封装 UDP 帧循环所需的所有缓冲区，避免重复分配
     */
    struct udp_buffers
    {
        memory::vector<std::byte> recv;     ///< 接收缓冲区
        memory::vector<std::byte> send;     ///< 发送缓冲区
        memory::vector<std::byte> response; ///< 响应缓冲区

        explicit udp_buffers(const std::size_t max_datagram)
            : recv(max_datagram, memory::current_resource()),
              send(memory::current_resource()),
              response(max_datagram, memory::current_resource())
        {
        }
    };

    /**
     * @brief 转发 UDP 数据包到目标并接收响应
     * @param executor 执行器
     * @param target_ep 目标端点
     * @param payload 载荷数据
     * @param buf 缓冲区集合
     * @return 错误码、响应数据长度、发送者端点
     */
    inline auto relay_udp_packet(net::any_io_executor executor, const net::ip::udp::endpoint &target_ep,
                                 std::span<const std::byte> payload, udp_buffers &buf)
        -> net::awaitable<std::tuple<fault::code, std::size_t, net::ip::udp::endpoint>>
    {
        boost::system::error_code udp_ec;
        net::ip::udp::socket udp_socket(executor);
        udp_socket.open(target_ep.protocol(), udp_ec);
        if (udp_ec)
        {
            trace::warn("{} Socket open failed: {}", udp_tag, udp_ec.message());
            co_return std::tuple{fault::to_code(udp_ec), 0, net::ip::udp::endpoint{}};
        }

        auto token = net::redirect_error(net::use_awaitable, udp_ec);
        co_await udp_socket.async_send_to(net::buffer(payload.data(), payload.size()), target_ep, token);
        if (udp_ec)
        {
            trace::debug("{} Send failed: {}", udp_tag, udp_ec.message());
            co_return std::tuple{fault::to_code(udp_ec), 0, net::ip::udp::endpoint{}};
        }

        net::ip::udp::endpoint sender_ep;
        const auto resp_n = co_await udp_socket.async_receive_from(
            net::buffer(buf.response.data(), buf.response.size()), sender_ep,
            net::redirect_error(net::use_awaitable, udp_ec));
        if (udp_ec)
        {
            trace::debug("{} Receive failed: {}", udp_tag, udp_ec.message());
            co_return std::tuple{fault::to_code(udp_ec), 0, net::ip::udp::endpoint{}};
        }

        co_return std::tuple{fault::code::success, resp_n, sender_ep};
    }

    /**
     * @brief 构建并发送 UDP 响应
     * @param transport 传输层
     * @param sender_ep 发送者端点
     * @param resp_n 响应数据长度
     * @param buf 缓冲区集合
     * @return 是否成功（失败应终止循环）
     */
    inline auto send_udp_response(channel::transport::transmission &transport, const net::ip::udp::endpoint &sender_ep,
                                  std::size_t resp_n, udp_buffers &buf)
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
            trace::debug("{} Write response failed: {}", udp_tag, write_ec.message());
            co_return false;
        }
        co_return true;
    }

    relay::relay(channel::transport::shared_transmission next_layer, const config &cfg,
                 std::function<bool(std::string_view)> credential_verifier)
        : next_layer_(std::move(next_layer)), config_(cfg), verifier_(std::move(credential_verifier))
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

    auto relay::handshake() const -> net::awaitable<std::pair<fault::code, request>>
    {
        // 缓冲区足够容纳最大请求
        std::array<std::uint8_t, 320> buffer{};
        const auto byte_span = std::span(reinterpret_cast<std::byte *>(buffer.data()), buffer.size());
        const auto data_span = std::span<const std::uint8_t>(buffer.data(), buffer.size());

        // 最小请求长度：56(凭据) + 2(CRLF) + 1(CMD) + 1(ATYP) + 4(IPv4) + 2(PORT) + 2(CRLF) = 68 字节
        static constexpr std::size_t k_min_request_size = 68;

        // 第一次批量读取：至少 68 字节
        auto [read_ec, total] = co_await read_at_least(*next_layer_, byte_span, k_min_request_size);
        if (fault::failed(read_ec))
        {
            co_return std::pair{read_ec, request{}};
        }

        // 解析凭据 (0-55)
        auto [cred_ec, credential] = format::parse_credential(data_span.subspan(0, 56));
        if (fault::failed(cred_ec))
        {
            co_return std::pair{cred_ec, request{}};
        }

        // 验证凭据
        if (verifier_)
        {
            const std::string_view cred_view(credential.data(), 56);
            if (!verifier_(cred_view))
            {
                co_return std::pair{fault::code::auth_failed, request{}};
            }
        }

        // 验证第一个 CRLF (56-57)
        auto crlf1_ec = format::parse_crlf(data_span.subspan(56, 2));
        if (fault::failed(crlf1_ec))
        {
            co_return std::pair{crlf1_ec, request{}};
        }

        // 解析命令和地址类型 (58-59)
        auto [header_ec, header] = format::parse_cmd_atyp(data_span.subspan(58, 2));
        if (fault::failed(header_ec))
        {
            co_return std::pair{header_ec, request{}};
        }

        // 根据地址类型计算完整请求长度
        std::size_t offset = 60;
        std::size_t required_total = offset;

        switch (header.atyp)
        {
        case address_type::ipv4:
            required_total = 60 + 4 + 2 + 2;
            break;
        case address_type::ipv6:
            required_total = 60 + 16 + 2 + 2;
            break;
        case address_type::domain:
        {
            const std::uint8_t domain_len = buffer[60];
            required_total = 60 + 1 + domain_len + 2 + 2;
            break;
        }
        default:
            co_return std::pair{fault::code::unsupported_address, request{}};
        }

        // 如果数据不足，补读剩余字节
        if (total < required_total)
        {
            auto [rem_ec, new_total] = co_await read_remaining(*next_layer_, byte_span, total, required_total);
            if (fault::failed(rem_ec))
            {
                co_return std::pair{rem_ec, request{}};
            }
            total = new_total;
        }

        // 解析目标地址
        auto [addr_ec, dest_addr, addr_size] = parse_address_from_buffer(data_span, offset, header.atyp);
        if (fault::failed(addr_ec))
        {
            co_return std::pair{addr_ec, request{}};
        }
        offset += addr_size;

        // 解析端口
        if (offset + 2 > total)
        {
            co_return std::pair{fault::code::bad_message, request{}};
        }
        auto [port_ec, port] = format::parse_port(data_span.subspan(offset, 2));
        if (fault::failed(port_ec))
        {
            co_return std::pair{port_ec, request{}};
        }
        offset += 2;

        // 验证结束 CRLF
        if (offset + 2 > total)
        {
            co_return std::pair{fault::code::bad_message, request{}};
        }
        auto crlf2_ec = format::parse_crlf(data_span.subspan(offset, 2));
        if (fault::failed(crlf2_ec))
        {
            co_return std::pair{crlf2_ec, request{}};
        }

        // 验证命令
        auto [cmd_ec, req_form] = validate_command(header.cmd, config_);
        if (fault::failed(cmd_ec))
        {
            co_return std::pair{cmd_ec, request{}};
        }

        // 构建请求
        request req;
        req.cmd = header.cmd;
        req.destination_address = dest_addr;
        req.port = port;
        req.form = req_form;
        std::ranges::copy(credential, req.credential.begin());

        co_return std::pair{fault::code::success, req};
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

    auto relay::udp_frame_loop(route_callback &route_cb, net::steady_timer &idle_timer) const
        -> net::awaitable<void>
    {
        udp_buffers buf(config_.udp_max_datagram);

        while (true)
        {
            idle_timer.expires_after(std::chrono::seconds(config_.udp_idle_timeout));

            std::error_code read_ec;
            const auto n = co_await next_layer_->async_read_some({buf.recv.data(), buf.recv.size()}, read_ec);
            if (read_ec || n == 0)
            {
                trace::debug("{} Read error or EOF: {}", udp_tag, read_ec.message());
                co_return;
            }

            auto [parse_ec, parsed] = format::parse_udp_packet({buf.recv.data(), n});
            if (fault::failed(parse_ec))
            {
                trace::warn("{} Packet parse failed", udp_tag);
                continue;
            }

            const auto target_host = to_string(parsed.destination_address, memory::current_resource());
            const auto target_port = std::to_string(parsed.destination_port);

            auto [route_ec, target_ep] = co_await route_cb(target_host, target_port);
            if (fault::failed(route_ec))
            {
                trace::debug("{} Route failed for {}:{}", udp_tag, target_host, target_port);
                continue;
            }

            const auto payload = std::span<const std::byte>(buf.recv.data() + parsed.payload_offset, parsed.payload_size);

            auto [relay_ec, resp_n, sender_ep] = co_await relay_udp_packet(
                next_layer_->executor(), target_ep, payload, buf);
            if (fault::failed(relay_ec))
            {
                continue;
            }

            if (!co_await send_udp_response(*next_layer_, sender_ep, resp_n, buf))
            {
                co_return;
            }
        }
    }

} // namespace psm::protocol::trojan
#include <prism/protocol/socks5/conn.hpp>
#include <prism/stats/traffic.hpp>
namespace psm::protocol::socks5
{

    auto conn::resolve_address(net::steady_timer &deadline, const address_type atyp, request &req)
        -> net::awaitable<fault::code>
    {
        switch (atyp)
        {
        case address_type::ipv4:
        {
            auto [ec, addr, port] = co_await read_address<4>(wire::parse_ipv4);
            if (fault::failed(ec))
            {
                deadline.cancel();
                if (ec == fault::code::canceled || ec == fault::code::io_error)
                {
                    co_return fault::code::timeout;
                }
                co_return ec;
            }
            req.destination_address = addr;
            req.destination_port = port;
            break;
        }
        case address_type::ipv6:
        {
            auto [ec, addr, port] = co_await read_address<16>(wire::parse_ipv6);
            if (fault::failed(ec))
            {
                deadline.cancel();
                if (ec == fault::code::canceled || ec == fault::code::io_error)
                {
                    co_return fault::code::timeout;
                }
                co_return ec;
            }
            req.destination_address = addr;
            req.destination_port = port;
            break;
        }
        case address_type::domain:
        {
            auto [ec, addr, port] = co_await read_domain();
            if (fault::failed(ec))
            {
                deadline.cancel();
                if (ec == fault::code::canceled || ec == fault::code::io_error)
                {
                    co_return fault::code::timeout;
                }
                co_return ec;
            }
            req.destination_address = addr;
            req.destination_port = port;
            break;
        }
        default:
            deadline.cancel();
            co_return fault::code::unsupported_address;
        }
        co_return fault::code::success;
    }

    auto conn::resolve_command(net::steady_timer &deadline, const command cmd, request &req) const
        -> net::awaitable<fault::code>
    {
        switch (cmd)
        {
        case command::connect:
            if (!config_.enable_tcp)
            {
                deadline.cancel();
                co_await send_error(reply_code::connect_denied);
                co_return fault::code::not_supported;
            }
            req.transport = psm::protocol::form::stream;
            co_return fault::code::success;
        case command::udp_associate:
            if (!config_.enable_udp)
            {
                deadline.cancel();
                co_await send_error(reply_code::connect_denied);
                co_return fault::code::not_supported;
            }
            req.transport = psm::protocol::form::datagram;
            co_return fault::code::success;
        case command::bind:
            if (!config_.enable_bind)
            {
                deadline.cancel();
                co_await send_error(reply_code::cmd_unsupported);
                co_return fault::code::unsupported_command;
            }
            req.transport = psm::protocol::form::stream;
            co_return fault::code::success;
        default:
            deadline.cancel();
            co_await send_error(reply_code::cmd_unsupported);
            co_return fault::code::unsupported_command;
        }
    }

    auto conn::handshake()
        -> net::awaitable<std::pair<fault::code, request>>
    {
        // 握手超时保护：30 秒内必须完成
        net::steady_timer deadline(next_layer_->executor(), std::chrono::seconds(30));
        deadline.async_wait(
            [this](const boost::system::error_code &ec)
            {
                if (!ec)
                {
                    next_layer_->cancel();
                }
            });

        const auto [negotiation_ec, method] = co_await negotiated_authentication();
        if (fault::failed(negotiation_ec))
        {
            deadline.cancel();
            if (negotiation_ec == fault::code::canceled)
            {
                co_return std::pair{fault::code::timeout, request{}};
            }
            co_return std::pair{negotiation_ec, request{}};
        }

        auto [read_ec, header] = co_await read_req_hdr();
        if (fault::failed(read_ec))
        {
            deadline.cancel();
            if (read_ec == fault::code::canceled)
            {
                co_return std::pair{fault::code::timeout, request{}};
            }
            co_return std::pair{read_ec, request{}};
        }

        request req{};
        req.cmd = header.cmd;

        const auto cmd_ec = co_await resolve_command(deadline, header.cmd, req);
        if (fault::failed(cmd_ec))
        {
            co_return std::pair{cmd_ec, request{}};
        }

        const auto addr_ec = co_await resolve_address(deadline, header.atyp, req);
        if (fault::failed(addr_ec))
        {
            co_return std::pair{addr_ec, request{}};
        }

        deadline.cancel();
        co_return std::pair{fault::code::success, req};
    }

    auto conn::negotiated_authentication()
        -> net::awaitable<std::pair<fault::code, auth_method>>
    {
        std::array<std::uint8_t, 258> methods_buffer{};

        std::error_code ec;
        // safe: casting uint8_t array to byte span for SOCKS5 method negotiation read
        co_await recv_impl(std::span(reinterpret_cast<std::byte *>(methods_buffer.data()), 2), ec);
        if (ec)
        {
            co_return std::pair{fault::to_code(ec), auth_method::no_acceptable};
        }

        if (methods_buffer[0] != 0x05)
        {
            co_return std::pair{fault::code::protocol_error, auth_method::no_acceptable};
        }

        const std::uint8_t nmethods = methods_buffer[1];

        // safe: casting uint8_t array region to byte span for reading method list
        co_await recv_impl(std::span(reinterpret_cast<std::byte *>(methods_buffer.data() + 2), nmethods), ec);
        if (ec)
        {
            co_return std::pair{fault::to_code(ec), auth_method::no_acceptable};
        }

        bool no_auth_supported = false;
        bool password_supported = false;
        const std::span<const std::uint8_t> methods(methods_buffer.data() + 2, nmethods);
        for (const auto method : methods)
        {
            if (method == static_cast<std::uint8_t>(auth_method::no_auth))
            {
                no_auth_supported = true;
            }
            else if (method == static_cast<std::uint8_t>(auth_method::password))
            {
                password_supported = true;
            }
        }

        // 启用认证且有账户目录：优先选择密码认证
        if (config_.enable_auth && acct_dir_ && password_supported)
        {
            constexpr std::uint8_t response[] = {0x05, static_cast<std::uint8_t>(auth_method::password)};
            // safe: casting uint8_t array to byte span for SOCKS5 method selection write
            co_await send_impl(std::span(reinterpret_cast<const std::byte *>(response), 2), ec);
            if (ec)
            {
                co_return std::pair{fault::to_code(ec), auth_method::no_acceptable};
            }

            auto [auth_ec, success] = co_await password_auth();
            if (fault::failed(auth_ec) || !success)
            {
                co_return std::pair{auth_ec, auth_method::no_acceptable};
            }
            co_return std::pair{fault::code::success, auth_method::password};
        }

        // 未启用认证或客户端不支持密码认证：回退到无认证
        if (no_auth_supported && !config_.enable_auth)
        {
            constexpr std::uint8_t response[] = {0x05, 0x00};
            // safe: casting uint8_t array to byte span for SOCKS5 no-auth response write
            co_await send_impl(std::span(reinterpret_cast<const std::byte *>(response), 2), ec);
            if (ec)
            {
                co_return std::pair{fault::to_code(ec), auth_method::no_acceptable};
            }
            co_return std::pair{fault::code::success, auth_method::no_auth};
        }

        // 启用了认证但客户端不支持，或无可用方法
        constexpr std::uint8_t response[] = {0x05, 0xFF};
        // safe: casting uint8_t array to byte span for SOCKS5 method rejection write
        co_await send_impl(std::span(reinterpret_cast<const std::byte *>(response), 2), ec);
        if (ec)
        {
            co_return std::pair{fault::to_code(ec), auth_method::no_acceptable};
        }
        co_return std::pair{fault::code::not_supported, auth_method::no_acceptable};
    }

    auto conn::password_auth()
        -> net::awaitable<std::pair<fault::code, bool>>
    {
        // RFC 1929 最大请求长度: VER(1) + ULEN(1) + UNAME(255) + PLEN(1) + PASSWD(255) = 513
        std::array<std::uint8_t, 513> auth_buffer{};

        std::error_code ec;
        // safe: casting uint8_t array to byte span for RFC 1929 auth version/ulen read
        co_await recv_impl(std::span(reinterpret_cast<std::byte *>(auth_buffer.data()), 2), ec);
        if (ec)
        {
            co_return std::pair{fault::to_code(ec), false};
        }

        const auto ulen = auth_buffer[1];
        if (ulen == 0)
        {
            const auto response = wire::build_pw_auth_response(wire::auth_result::failed);
            // safe: casting uint8_t vector to byte span for auth rejection write
            co_await send_impl(std::span(reinterpret_cast<const std::byte *>(response.data()), response.size()), ec);
            co_return std::pair{fault::code::bad_message, false};
        }

        // 读取用户名 + PLEN + 密码
        const auto remaining = static_cast<std::size_t>(ulen + 1 + 255);
        // safe: casting uint8_t array region to byte span for remaining auth fields read
        co_await recv_impl(std::span(reinterpret_cast<std::byte *>(auth_buffer.data() + 2), remaining), ec);
        if (ec)
        {
            co_return std::pair{fault::to_code(ec), false};
        }

        // 解析认证请求
        const auto total_len = static_cast<std::size_t>(2 + ulen + 1 + auth_buffer[2 + ulen]);
        const auto [parse_ec, auth_req] = wire::parse_pw_auth(
            std::span<const std::uint8_t>(auth_buffer.data(), total_len));
        if (fault::failed(parse_ec))
        {
            const auto response = wire::build_pw_auth_response(wire::auth_result::failed);
            // safe: casting uint8_t vector to byte span for auth rejection write
            co_await send_impl(std::span(reinterpret_cast<const std::byte *>(response.data()), response.size()), ec);
            co_return std::pair{parse_ec, false};
        }

        // 使用 SHA224 哈希密码后验证凭证
        const auto credential = crypto::sha224(auth_req.password);
        auto lease = psm::account::try_acquire(*acct_dir_, credential);

        if (!lease)
        {
            const auto response = wire::build_pw_auth_response(wire::auth_result::failed);
            // safe: casting uint8_t vector to byte span for auth failure write
            co_await send_impl(std::span(reinterpret_cast<const std::byte *>(response.data()), response.size()), ec);
            co_return std::pair{fault::code::success, false};
        }

        // 认证成功，保存租约
        account_lease_ = std::move(lease);

        const auto response = wire::build_pw_auth_response(wire::auth_result::success);
        // safe: casting uint8_t vector to byte span for auth success write
        co_await send_impl(std::span(reinterpret_cast<const std::byte *>(response.data()), response.size()), ec);
        if (ec)
        {
            co_return std::pair{fault::to_code(ec), false};
        }

        co_return std::pair{fault::code::success, true};
    }

    auto conn::relay_datagram(relay_context ctx,
                                      std::span<const std::byte> ingress_packet,
                                      const net::ip::udp::endpoint &client_endpoint) const
        -> net::awaitable<void>
    {
        // safe: casting byte span to uint8_t span for SOCKS5 UDP header decoding
        const auto ingress_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(ingress_packet.data()), ingress_packet.size());
        const auto [decode_ec, parsed] = wire::decode_hdr(ingress_bytes);
        if (fault::failed(decode_ec))
        {
            co_return;
        }

        const auto target_host = to_string(parsed.header.destination_address, memory::current_resource());
        char port_buf[8];
        const auto [port_end, port_ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), parsed.header.destination_port);
        const std::string_view target_port(port_buf, std::distance(port_buf, port_end));
        auto [route_ec, target_endpoint] = co_await ctx.route_cb(target_host, target_port);
        if (fault::failed(route_ec))
        {
            co_return;
        }

        if (parsed.header_size >= ingress_packet.size())
        {
            co_return;
        }

        // 惰性打开出站 socket：仅在首次使用或协议族变更时打开
        boost::system::error_code io_ec;
        if (!ctx.egress.is_open())
        {
            ctx.egress.open(target_endpoint.protocol(), io_ec);
            if (io_ec)
            {
                co_return;
            }
        }

        auto token = net::redirect_error(net::use_awaitable, io_ec);

        const auto payload = ingress_packet.subspan(parsed.header_size);
        co_await ctx.egress.async_send_to(net::buffer(payload.data(), payload.size()), target_endpoint, token);
        if (io_ec)
        {
            co_return;
        }

        udp_uplink_.fetch_add(static_cast<std::uint64_t>(payload.size()), std::memory_order_relaxed);

        net::ip::udp::endpoint sender_endpoint;
        const auto target_n = co_await ctx.egress.async_receive_from(
            net::buffer(ctx.target_buf.data(), ctx.target_buf.size()), sender_endpoint, token);
        if (io_ec)
        {
            co_return;
        }

        wire::udp_header response_header{};
        response_header.destination_address = ep_to_addr(sender_endpoint);
        response_header.destination_port = sender_endpoint.port();
        response_header.frag = 0;

        memory::vector<std::uint8_t> response_datagram(memory::current_resource());
        response_datagram.reserve(target_n + 64);
        // safe: casting byte buffer to uint8_t span for UDP datagram payload encoding
        const auto target_payload = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(ctx.target_buf.data()), target_n);
        if (fault::failed(wire::encode_dgram(response_header, target_payload, response_datagram)))
        {
            co_return;
        }

        co_await ctx.ingress.async_send_to(net::buffer(response_datagram.data(), response_datagram.size()), client_endpoint, token);

        if (!io_ec)
        {
            udp_downlink_.fetch_add(static_cast<std::uint64_t>(response_datagram.size()), std::memory_order_relaxed);
        }
    }

    auto conn::associate_loop(net::ip::udp::socket &ingress_socket, route_callback &route_callback, net::steady_timer &idle_timer) const
        -> net::awaitable<void>
    {
        memory::vector<std::byte> ingress_buffer(config_.max_dgram, memory::current_resource());
        memory::vector<std::byte> target_buffer(config_.max_dgram, memory::current_resource());
        net::ip::udp::socket egress_socket(executor());
        while (true)
        {
            idle_timer.expires_after(std::chrono::seconds(config_.idle_timeout));
            boost::system::error_code read_ec;
            auto token = net::redirect_error(net::use_awaitable, read_ec);
            net::ip::udp::endpoint client_endpoint;

            using boost::asio::experimental::awaitable_operators::operator||;
            auto buf = net::buffer(ingress_buffer.data(), ingress_buffer.size());
            auto result = co_await (ingress_socket.async_receive_from(buf, client_endpoint, token) || idle_timer.async_wait(net::use_awaitable));

            if (result.index() == 1)
            {
                // 空闲超时，关闭 UDP 关联
                co_return;
            }

            if (read_ec)
            {
                if (read_ec == net::error::operation_aborted)
                {
                    co_return;
                }
                continue;
            }
            const auto ingress_n = std::get<0>(result);
            idle_timer.cancel();

            co_await relay_datagram(
                relay_context{ingress_socket, egress_socket, route_callback, target_buffer},
                {ingress_buffer.data(), ingress_n}, client_endpoint);
        }
    }

    auto conn::async_associate(const request &request_info, route_callback route_callback) const
        -> net::awaitable<fault::code>
    {
        if (!config_.enable_udp || request_info.transport != form::datagram)
        {
            co_return fault::code::not_supported;
        }

        auto [open_ec, ingress_socket] = co_await bind_datagram_port();
        if (fault::failed(open_ec))
        {
            co_await send_error(reply_code::server_failure);
            co_return open_ec;
        }

        boost::system::error_code endpoint_ec;
        const auto local_endpoint = ingress_socket.local_endpoint(endpoint_ec);
        if (endpoint_ec)
        {
            co_await send_error(reply_code::server_failure);
            co_return fault::to_code(endpoint_ec);
        }

        if (fault::failed(co_await send_assoc_ok(request_info, local_endpoint)))
        {
            boost::system::error_code ignore_ec;
            ingress_socket.close(ignore_ec);
            co_return fault::code::io_error;
        }

        // 空闲超时：客户端在 idle_timeout 秒内不发送 UDP 数据，主动关闭关联
        net::steady_timer idle_timer(ingress_socket.get_executor());
        idle_timer.expires_after(std::chrono::seconds(config_.idle_timeout));

        using boost::asio::experimental::awaitable_operators::operator||;
        co_await (associate_loop(ingress_socket, route_callback, idle_timer) || wait_ctrl_close(ingress_socket));

        if (traffic_)
        {
            const auto up = udp_uplink_.exchange(0, std::memory_order_relaxed);
            const auto down = udp_downlink_.exchange(0, std::memory_order_relaxed);
            traffic_->flush_traffic(proto_, up, down);
        }

        co_return fault::code::success;
    }

    auto conn::read_req_hdr() const
        -> net::awaitable<std::pair<fault::code, wire::header_parse>>
    {
        std::array<std::uint8_t, 4> request_header{};
        std::error_code ec;
        // safe: casting uint8_t array to byte span for SOCKS5 request header read
        co_await recv_impl(std::span(reinterpret_cast<std::byte *>(request_header.data()), 4), ec);

        if (ec)
        {
            co_return std::pair{fault::to_code(ec), wire::header_parse{}};
        }

        auto [header_ec, header] = wire::parse_header(request_header);
        if (fault::failed(header_ec))
        {
            co_return std::pair{header_ec, wire::header_parse{}};
        }
        co_return std::pair{fault::code::success, header};
    }

    auto conn::read_domain() const
        -> net::awaitable<std::tuple<fault::code, address, std::uint16_t>>
    {
        std::uint8_t len = 0;
        std::error_code io_ec;
        // safe: casting uint8_t to byte span for domain length read, single byte has no alignment issue
        co_await recv_impl(std::span(reinterpret_cast<std::byte *>(&len), 1), io_ec);
        if (io_ec)
        {
            co_return std::tuple<fault::code, address, std::uint16_t>{fault::code::io_error, address{}, 0};
        }

        std::array<std::uint8_t, 258> buffer{};
        buffer[0] = len;

        // safe: casting uint8_t array region to byte span for domain address + port read
        co_await recv_impl(std::span(reinterpret_cast<std::byte *>(buffer.data() + 1), len + 2), io_ec);
        if (io_ec)
        {
            co_return std::tuple<fault::code, address, std::uint16_t>{fault::code::io_error, address{}, 0};
        }

        auto [ec_domain, domain] = wire::parse_domain(std::span<const std::uint8_t>(buffer.data(), len + 1));
        if (fault::failed(ec_domain))
        {
            co_return std::tuple<fault::code, address, std::uint16_t>{ec_domain, address{}, 0};
        }

        auto [ec_port, port] = wire::decode_port(std::span<const std::uint8_t>(buffer.data() + 1 + len, 2));
        if (fault::failed(ec_port))
        {
            co_return std::tuple<fault::code, address, std::uint16_t>{ec_port, address{}, 0};
        }

        co_return std::tuple{fault::code::success, address{domain}, port};
    }

    auto conn::build_ok_resp(const request &req, std::span<std::uint8_t> buffer)
        -> std::size_t
    {
        std::size_t offset = 0;
        buffer[offset++] = 0x05;
        buffer[offset++] = static_cast<std::uint8_t>(reply_code::succeeded);
        buffer[offset++] = 0x00;

        std::visit([&buffer, &offset]<typename Address>(const Address &addr)
                   {
            if constexpr (std::is_same_v<Address, ipv4_address>)
            {
                buffer[offset++] = 0x01;
                std::copy_n(addr.bytes.begin(), 4, buffer.subspan(offset).begin());
                offset += 4;
            }
            else if constexpr (std::is_same_v<Address, ipv6_address>)
            {
                buffer[offset++] = 0x04;
                std::copy_n(addr.bytes.begin(), 16, buffer.subspan(offset).begin());
                offset += 16;
            }
            else if constexpr (std::is_same_v<Address, domain_address>)
            {
                buffer[offset++] = 0x03;
                buffer[offset++] = addr.length;
                std::copy_n(addr.value.begin(), addr.length, buffer.subspan(offset).begin());
                offset += addr.length;
            } }, req.destination_address);

        buffer[offset++] = static_cast<std::uint8_t>((req.destination_port >> 8) & 0xFF);
        buffer[offset++] = static_cast<std::uint8_t>(req.destination_port & 0xFF);

        return offset;
    }

    auto conn::send_impl(const std::span<const std::byte> buffer, std::error_code &ec) const
        -> net::awaitable<std::size_t>
    {
        std::size_t total = 0;
        while (total < buffer.size())
        {
            const auto n = co_await next_layer_->async_write_some(buffer.subspan(total), ec);
            if (ec)
            {
                co_return total;
            }
            total += n;
        }
        co_return total;
    }

    auto conn::bind_datagram_port() const
        -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>
    {
        boost::system::error_code ec;
        net::ip::udp::socket ingress_socket(executor());
        ingress_socket.open(net::ip::udp::v4(), ec);
        if (ec)
        {
            co_return std::pair{fault::to_code(ec), net::ip::udp::socket(executor())};
        }

        ingress_socket.bind(net::ip::udp::endpoint(net::ip::udp::v4(), config_.bind_port), ec);
        if (ec)
        {
            co_return std::pair{fault::to_code(ec), net::ip::udp::socket(executor())};
        }

        co_return std::pair{fault::code::success, std::move(ingress_socket)};
    }

    auto conn::send_assoc_ok(const request &request_info, const net::ip::udp::endpoint &local_endpoint) const
        -> net::awaitable<fault::code>
    {
        request response_info = request_info;
        response_info.destination_address = ep_to_addr(local_endpoint);
        response_info.destination_port = local_endpoint.port();
        co_return co_await send_success(response_info);
    }

    auto conn::wait_ctrl_close(net::ip::udp::socket &ingress_socket) const
        -> net::awaitable<void>
    {
        std::array<std::byte, 1> dummy{};
        std::error_code control_ec;
        co_await next_layer_->async_read_some(std::span<std::byte>(dummy), control_ec);
        boost::system::error_code ignore_ec;
        ingress_socket.cancel(ignore_ec);
        ingress_socket.close(ignore_ec);
    }

    auto conn::send_success(const request &info) const
        -> net::awaitable<fault::code>
    {
        std::array<std::uint8_t, 262> buffer{};
        const std::size_t len = build_ok_resp(info, buffer);
        std::error_code ec;
        // safe: casting uint8_t array to byte span for SOCKS5 success response write
        co_await send_impl(std::span(reinterpret_cast<const std::byte *>(buffer.data()), len), ec);
        co_return fault::to_code(ec);
    }

    auto conn::send_error(reply_code code) const
        -> net::awaitable<fault::code>
    {
        const std::array<std::uint8_t, 10> response = {
            0x05, static_cast<std::uint8_t>(code), 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00};
        std::error_code ec;
        // safe: casting uint8_t array to byte span for SOCKS5 error response write
        co_await send_impl(std::span(reinterpret_cast<const std::byte *>(response.data()), response.size()), ec);
        co_return fault::to_code(ec);
    }

}

#include <prism/protocol/vless/conn.hpp>
#include <prism/protocol/vless/framing.hpp>
#include <prism/fault/handling.hpp>
#include <prism/protocol/common/read.hpp>
#include <prism/protocol/common/udp_relay.hpp>
#include <prism/trace.hpp>
#include <prism/transport/transmission.hpp>
#include <prism/stats/traffic.hpp>
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
    static auto uuid_to_string(const std::array<uint8_t, 16> &uuid)
        -> std::string
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

    conn::conn(transport::shared_transmission next_layer, const config &cfg,
                 std::function<bool(std::string_view)> verifier)
        : next_layer_(std::move(next_layer)), config_(cfg), verifier_(std::move(verifier))
    {
    }

    conn::executor_type conn::executor() const
    {
        return next_layer_->executor();
    }

    auto conn::async_read_some(const std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        co_return co_await next_layer_->async_read_some(buffer, ec);
    }

    auto conn::async_write_some(const std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        co_return co_await next_layer_->async_write_some(buffer, ec);
    }

    void conn::close()
    {
        next_layer_->close();
    }

    void conn::cancel()
    {
        next_layer_->cancel();
    }

    auto conn::handshake()
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
        co_await transport::async_write(*next_layer_, {response.data(), response.size()}, write_ec);
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
        req.transport = (cmd == command::udp) ? psm::protocol::form::datagram : psm::protocol::form::stream;

        co_return std::pair{fault::code::success, std::move(req)};
    }

    transport::transmission &conn::underlying() noexcept
    {
        return *next_layer_;
    }

    const transport::transmission &conn::underlying() const noexcept
    {
        return *next_layer_;
    }

    transport::shared_transmission conn::release()
    {
        return std::move(next_layer_);
    }

    auto conn::async_associate(route_callback route_cb) const
        -> net::awaitable<fault::code>
    {
        if (!config_.enable_udp)
        {
            co_return fault::code::not_supported;
        }

        struct traffic_context
        {
            stats::traffic::traffic_state *traffic;
            protocol::protocol_type proto;
        };
        auto *tc = traffic_ ? new traffic_context{traffic_, proto_} : nullptr;

        net::steady_timer idle_timer(next_layer_->executor());

        co_await protocol::common::udp_over_tls_frame_loop<
            decltype(format::parse_udp_packet),
            decltype(format::build_udp_packet),
            format::udp_frame,
            format::udp_parse_result>(
            *next_layer_,
            format::parse_udp_packet,
            format::build_udp_packet,
            std::move(route_cb),
            protocol::common::udp_loop_config{
                idle_timer,
                "[Vless.UDP]",
                config_.udp_idle_timeout,
                config_.udp_max_datagram,
                tc ? [](void *ctx, std::uint64_t up, std::uint64_t down) noexcept {
                    auto *tc = static_cast<traffic_context*>(ctx);
                    tc->traffic->flush_traffic(tc->proto, up, down);
                    delete tc;
                } : nullptr,
                tc
            });
        co_return fault::code::success;
    }

} // namespace psm::protocol::vless

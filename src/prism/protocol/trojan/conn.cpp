#include <prism/protocol/trojan/conn.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/protocol/trojan/constants.hpp>
#include <prism/protocol/trojan/framing.hpp>
#include <prism/fault/handling.hpp>
#include <prism/protocol/common/read.hpp>
#include <prism/protocol/common/udprelay.hpp>
#include <prism/memory/container.hpp>
#include <prism/trace.hpp>
#include <prism/stats/traffic.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <array>
#include <charconv>
#include <string_view>
#include <algorithm>

constexpr std::string_view udp_tag = "[Trojan.UDP]";

namespace psm::protocol::trojan
{
    // 引用共享读取工具函数
    using protocol::common::read_at_least;
    using protocol::common::read_remaining;

    // 验证命令并确定传输形式
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

    // 从缓冲区解析地址
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

    conn::conn(transport::shared_transmission next_layer, const config &cfg,
                 std::function<bool(std::string_view)> credential_verifier)
        : next_layer_(std::move(next_layer)), config_(cfg), verifier_(std::move(credential_verifier))
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

    auto conn::handshake() const
        -> net::awaitable<std::pair<fault::code, request>>
    {
        // 缓冲区足够容纳最大请求
        std::array<std::uint8_t, 320> buffer{};
        // safe: casting uint8_t array to byte span for async read, same memory layout
        const auto byte_span = std::span(reinterpret_cast<std::byte *>(buffer.data()), buffer.size());
        const auto data_span = std::span<const std::uint8_t>(buffer.data(), buffer.size());

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

        // 最小请求长度：56(凭据) + 2(CRLF) + 1(CMD) + 1(ATYP) + 4(IPv4) + 2(PORT) + 2(CRLF) = 68 字节
        static constexpr std::size_t k_min_request_size = 68;

        // 第一次批量读取：至少 68 字节
        auto [read_ec, total] = co_await read_at_least(*next_layer_, byte_span, k_min_request_size);
        if (fault::failed(read_ec))
        {
            deadline.cancel();
            if (read_ec == fault::code::canceled)
            {
                co_return std::pair{fault::code::timeout, request{}};
            }
            co_return std::pair{read_ec, request{}};
        }

        // 解析凭据 (0-55)
        auto [cred_ec, credential] = format::parse_credential(data_span.subspan(0, 56));
        if (fault::failed(cred_ec))
        {
            deadline.cancel();
            co_return std::pair{cred_ec, request{}};
        }

        // 验证凭据
        if (verifier_)
        {
            const std::string_view cred_view(credential.data(), 56);
            if (!verifier_(cred_view))
            {
                deadline.cancel();
                co_return std::pair{fault::code::auth_failed, request{}};
            }
        }

        // 验证第一个 CRLF (56-57)
        auto crlf1_ec = format::parse_crlf(data_span.subspan(56, 2));
        if (fault::failed(crlf1_ec))
        {
            deadline.cancel();
            co_return std::pair{crlf1_ec, request{}};
        }

        // 解析命令和地址类型 (58-59)
        auto [header_ec, header] = format::parse_cmd_atyp(data_span.subspan(58, 2));
        if (fault::failed(header_ec))
        {
            deadline.cancel();
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
            deadline.cancel();
            co_return std::pair{fault::code::unsupported_address, request{}};
        }

        // 如果数据不足，补读剩余字节
        if (total < required_total)
        {
            auto [rem_ec, new_total] = co_await read_remaining(*next_layer_, byte_span, total, required_total);
            if (fault::failed(rem_ec))
            {
                deadline.cancel();
                if (rem_ec == fault::code::canceled)
                {
                    co_return std::pair{fault::code::timeout, request{}};
                }
                co_return std::pair{rem_ec, request{}};
            }
            total = new_total;
        }

        // 解析目标地址
        auto [addr_ec, dest_addr, addr_size] = parse_address_from_buffer(data_span, offset, header.atyp);
        if (fault::failed(addr_ec))
        {
            deadline.cancel();
            co_return std::pair{addr_ec, request{}};
        }
        offset += addr_size;

        // 解析端口
        if (offset + 2 > total)
        {
            deadline.cancel();
            co_return std::pair{fault::code::bad_message, request{}};
        }
        auto [port_ec, port] = format::parse_port(data_span.subspan(offset, 2));
        if (fault::failed(port_ec))
        {
            deadline.cancel();
            co_return std::pair{port_ec, request{}};
        }
        offset += 2;

        // 验证结束 CRLF
        if (offset + 2 > total)
        {
            deadline.cancel();
            co_return std::pair{fault::code::bad_message, request{}};
        }
        auto crlf2_ec = format::parse_crlf(data_span.subspan(offset, 2));
        if (fault::failed(crlf2_ec))
        {
            deadline.cancel();
            co_return std::pair{crlf2_ec, request{}};
        }

        // 验证命令
        auto [cmd_ec, req_form] = validate_command(header.cmd, config_);
        if (fault::failed(cmd_ec))
        {
            deadline.cancel();
            co_return std::pair{cmd_ec, request{}};
        }

        deadline.cancel();

        // 构建请求
        request req;
        req.cmd = header.cmd;
        req.destination_address = dest_addr;
        req.port = port;
        req.transport = req_form;
        std::ranges::copy(credential, req.credential.begin());

        co_return std::pair{fault::code::success, req};
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

        co_await protocol::common::udp_frame_loop<
            decltype(format::parse_udp_pkt),
            decltype(format::build_udp_pkt),
            format::udp_routed,
            format::udp_parse_result>(
            *next_layer_,
            protocol::common::udp_frame_ctx<
                decltype(format::parse_udp_pkt),
                decltype(format::build_udp_pkt),
                format::udp_routed,
                format::udp_parse_result>{
                format::parse_udp_pkt,
                format::build_udp_pkt,
                std::move(route_cb)
            },
            protocol::common::udp_loop_cfg{
                idle_timer,
                udp_tag,
                config_.udp_idle_timeout,
                config_.udp_max_dgram,
                tc ? [](void *ctx, std::uint64_t up, std::uint64_t down) noexcept {
                    auto *tc = static_cast<traffic_context*>(ctx);
                    tc->traffic->flush_traffic(tc->proto, up, down);
                    delete tc;
                } : nullptr,
                tc
            });
        co_return fault::code::success;
    }

} // namespace psm::protocol::trojan
#include <prism/protocol/trojan/conn.hpp>
#include <prism/fault/handling.hpp>
#include <prism/memory/container.hpp>
#include <prism/protocol/common/form.hpp>
#include <prism/protocol/common/read.hpp>
#include <prism/protocol/common/udprelay.hpp>
#include <prism/protocol/trojan/constants.hpp>
#include <prism/protocol/trojan/framing.hpp>
#include <prism/stats/traffic.hpp>
#include <prism/trace.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <string_view>

constexpr std::string_view udp_tag = "[Trojan.UDP]";

namespace psm::protocol::trojan
{

    // 引用共享读取工具函数
    using protocol::common::read_min;
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


    // 验证凭据和首个 CRLF (bytes 0-57)
    inline auto verify_credential(
        const std::span<const std::uint8_t> data,
        const std::function<bool(std::string_view)> &verifier,
        std::array<char, 56> &credential_out) -> fault::code
    {
        auto [cred_ec, credential] = format::parse_credential(data.subspan(0, 56));
        if (fault::failed(cred_ec))
        {
            return cred_ec;
        }
        if (verifier)
        {
            const std::string_view cred_view(credential.data(), 56);
            if (!verifier(cred_view))
            {
                return fault::code::auth_failed;
            }
        }
        const auto crlf_ec = format::parse_crlf(data.subspan(56, 2));
        if (fault::failed(crlf_ec))
        {
            return crlf_ec;
        }
        std::ranges::copy(credential, credential_out.begin());
        return fault::code::success;
    }


    // 解析目标地址、端口和结束 CRLF
    inline auto parse_request_target(
        const std::span<const std::uint8_t> data,
        const std::size_t offset,
        const address_type atyp,
        const std::size_t total) -> std::tuple<fault::code, address, std::uint16_t>
    {
        auto [addr_ec, dest_addr, addr_size] = parse_address_from_buffer(data, offset, atyp);
        if (fault::failed(addr_ec))
        {
            return {addr_ec, address{}, 0};
        }
        auto cur = offset + addr_size;

        if (cur + 2 > total)
        {
            return {fault::code::bad_message, address{}, 0};
        }
        auto [port_ec, port] = format::parse_port(data.subspan(cur, 2));
        if (fault::failed(port_ec))
        {
            return {port_ec, address{}, 0};
        }
        cur += 2;

        if (cur + 2 > total)
        {
            return {fault::code::bad_message, address{}, 0};
        }
        const auto crlf_ec = format::parse_crlf(data.subspan(cur, 2));
        if (fault::failed(crlf_ec))
        {
            return {crlf_ec, address{}, 0};
        }
        return {fault::code::success, dest_addr, port};
    }


    conn::conn(transport::shared_transmission next_layer, const config &cfg,
                 std::function<bool(std::string_view)> credential_verifier)
        : next_layer_(std::move(next_layer)), config_(cfg), verifier_(std::move(credential_verifier))
    {
    }


    auto conn::executor() const
        -> executor_type
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
        auto on_deadline = [this](const boost::system::error_code &ec)
        {
            if (!ec) next_layer_->cancel();
        };
        deadline.async_wait(std::move(on_deadline));

        // 最小请求长度：56(凭据) + 2(CRLF) + 1(CMD) + 1(ATYP) + 4(IPv4) + 2(PORT) + 2(CRLF) = 68 字节
        static constexpr std::size_t k_min_request_size = 68;

        // 第一次批量读取：至少 68 字节
        auto [read_ec, total] = co_await read_min(*next_layer_, byte_span, k_min_request_size);
        if (fault::failed(read_ec))
        {
            deadline.cancel();
            auto result_ec = read_ec;
            if (read_ec == fault::code::canceled)
                result_ec = fault::code::timeout;
            co_return std::pair{result_ec, request{}};
        }

        // 解析凭据 + 验证 + 首个 CRLF
        std::array<char, 56> credential{};
        if (const auto ec = verify_credential(data_span, verifier_, credential); fault::failed(ec))
        {
            deadline.cancel();
            co_return std::pair{ec, request{}};
        }

        // 解析命令和地址类型 (58-59)
        auto [header_ec, header] = format::parse_cmd_atyp(data_span.subspan(58, 2));
        if (fault::failed(header_ec))
        {
            deadline.cancel();
            co_return std::pair{header_ec, request{}};
        }

        // 根据地址类型计算完整请求长度
        const std::size_t offset = 60;
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
            auto [rem_ec, new_total] = co_await read_remaining({*next_layer_, byte_span, total, required_total});
            if (fault::failed(rem_ec))
            {
                deadline.cancel();
                auto rem_result_ec = rem_ec;
                if (rem_ec == fault::code::canceled)
                    rem_result_ec = fault::code::timeout;
                co_return std::pair{rem_result_ec, request{}};
            }
            total = new_total;
        }

        // 解析目标地址、端口和结束 CRLF
        auto [target_ec, dest_addr, port] = parse_request_target(data_span, offset, header.atyp, total);
        if (fault::failed(target_ec))
        {
            deadline.cancel();
            co_return std::pair{target_ec, request{}};
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
        auto *tc = [&]() -> traffic_context * {
            if (traffic_)
                return new traffic_context{traffic_, proto_};
            return nullptr;
        }();

        net::steady_timer idle_timer(next_layer_->executor());

        co_await protocol::common::frame_loop<
            decltype(format::parse_udp_pkt),
            decltype(format::build_udp_pkt),
            format::udp_routed,
            format::udp_parse_result>(
            *next_layer_,
            protocol::common::frame_ctx<
                decltype(format::parse_udp_pkt),
                decltype(format::build_udp_pkt),
                format::udp_routed,
                format::udp_parse_result>{
                format::parse_udp_pkt,
                format::build_udp_pkt,
                std::move(route_cb)
            },
            protocol::common::loop_cfg{
                idle_timer,
                udp_tag,
                config_.idle_timeout,
                config_.max_dgram,
                [](void *ctx, std::uint64_t up, std::uint64_t down) noexcept {
                    auto *tc = static_cast<traffic_context*>(ctx);
                    tc->traffic->flush_traffic(tc->proto, up, down);
                    delete tc;
                },
                tc
            });

        if (!tc)
        {
            // No traffic callback, UDP loop won't report stats
        }
        co_return fault::code::success;
    }

} // namespace psm::protocol::trojan

#include <prism/protocol/vless/conn.hpp>
#include <prism/fault/handling.hpp>
#include <prism/protocol/common/read.hpp>
#include <prism/protocol/common/udprelay.hpp>
#include <prism/protocol/vless/framing.hpp>
#include <prism/stats/traffic.hpp>
#include <prism/trace.hpp>
#include <prism/transport/transmission.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstring>
#include <cstdint>
#include <string>

namespace psm::protocol::vless
{

    namespace
    {
        auto uuid_to_string(const std::array<std::uint8_t, 16> &uuid)
            -> std::string
        {
            std::array<char, 37> buf;
            static constexpr std::int32_t groups[] = {4, 2, 2, 2, 6};
            std::size_t pos = 0;
            std::size_t byte_idx = 0;
            for (std::size_t g = 0; g < 5; ++g)
            {
                for (std::int32_t i = 0; i < groups[g]; ++i)
                {
                    const std::uint8_t b = uuid[byte_idx++];
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
    } // namespace

    using protocol::common::read_min;
    using protocol::common::read_remaining;
    using protocol::common::remaining_opts;

    conn::conn(transport::shared_transmission next_layer, const config &cfg,
                 std::function<bool(std::string_view)> verifier)
        : next_layer_(std::move(next_layer)), config_(cfg), verifier_(std::move(verifier))
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


    auto conn::parse_header(std::array<std::uint8_t, 320> &buffer, const std::span<std::byte> byte_span, net::steady_timer &deadline)
        -> net::awaitable<std::tuple<fault::code, std::array<std::uint8_t, 16>, command, std::uint16_t, address_type, std::size_t>>
    {
        // 最小请求长度：Version(1) + UUID(16) + AddnlInfoLen(1) + Cmd(1) + Port(2) + Atyp(1) + IPv4(4) = 26
        static constexpr std::size_t k_min_request_size = 26;

        auto [read_ec, total] = co_await read_min(*next_layer_, byte_span.first(k_min_request_size), k_min_request_size);
        if (fault::failed(read_ec))
        {
            deadline.cancel();
            if (read_ec == fault::code::canceled)
            {
                co_return std::tuple{
                    fault::code::timeout,
                    std::array<std::uint8_t, 16>{},
                    command{},
                    std::uint16_t{0},
                    address_type{},
                    std::size_t{0}};
            }
            co_return std::tuple{
                read_ec,
                std::array<std::uint8_t, 16>{},
                command{},
                std::uint16_t{0},
                address_type{},
                std::size_t{0}};
        }

        // 校验版本号
        if (buffer[0] != version)
        {
            deadline.cancel();
            co_return std::tuple{
                fault::code::bad_message,
                std::array<std::uint8_t, 16>{},
                command{},
                std::uint16_t{0},
                address_type{},
                std::size_t{0}};
        }

        // 解析 UUID (offset 1-16)
        std::array<std::uint8_t, 16> uuid;
        std::memcpy(uuid.data(), buffer.data() + 1, 16);

        // 解析附加信息长度 (offset 17)
        const std::uint8_t addnl_len = buffer[17];
        if (addnl_len != 0)
        {
            deadline.cancel();
            co_return std::tuple{
                fault::code::bad_message,
                std::array<std::uint8_t, 16>{},
                command{},
                std::uint16_t{0},
                address_type{},
                std::size_t{0}};
        }

        // 解析命令 (offset 18)
        const auto cmd = static_cast<command>(buffer[18]);
        switch (cmd)
        {
        case command::tcp:
        case command::mux:
        case command::udp:
            break;
        default:
            deadline.cancel();
            co_return std::tuple{
                fault::code::unsupported_command,
                std::array<std::uint8_t, 16>{},
                command{},
                std::uint16_t{0},
                address_type{},
                std::size_t{0}};
        }

        // 解析端口 (offset 19-20)
        const std::uint16_t port = static_cast<std::uint16_t>(buffer[19]) << 8 | static_cast<std::uint16_t>(buffer[20]);

        // 解析地址类型 (offset 21)
        const auto atyp = static_cast<address_type>(buffer[21]);

        co_return std::tuple{fault::code::success, uuid, cmd, port, atyp, total};
    }


    auto conn::process_target(target_opts opts)
        -> net::awaitable<std::tuple<fault::code, address, std::size_t>>
    {
        auto &buffer = opts.buffer;
        auto &byte_span = opts.byte_span;
        const auto atyp = opts.atyp;
        auto &deadline = opts.deadline;
        std::size_t offset = 22;
        std::size_t total = opts.initial_total;
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
                remaining_opts read_opts{*next_layer_, byte_span.first(offset + 1), total, offset + 1};
                auto [rem_ec, new_total] = co_await read_remaining(read_opts);
                if (fault::failed(rem_ec))
                {
                    deadline.cancel();
                    if (rem_ec == fault::code::canceled)
                    {
                        co_return std::tuple{fault::code::timeout, address{}, std::size_t{0}};
                    }
                    co_return std::tuple{rem_ec, address{}, std::size_t{0}};
                }
                total = new_total;
            }
            const std::uint8_t domain_len = buffer[offset];
            required_total = offset + 1 + domain_len;
            break;
        }
        default:
            deadline.cancel();
            co_return std::tuple{fault::code::unsupported_address, address{}, std::size_t{0}};
        }

        if (total < required_total)
        {
            remaining_opts read_opts{*next_layer_, byte_span.first(required_total), total, required_total};
            auto [rem_ec, new_total] = co_await read_remaining(read_opts);
            if (fault::failed(rem_ec))
            {
                deadline.cancel();
                if (rem_ec == fault::code::canceled)
                {
                    co_return std::tuple{fault::code::timeout, address{}, std::size_t{0}};
                }
                co_return std::tuple{rem_ec, address{}, std::size_t{0}};
            }
            total = new_total;
        }

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
            deadline.cancel();
            co_return std::tuple{fault::code::unsupported_address, address{}, std::size_t{0}};
        }

        co_return std::tuple{fault::code::success, dest_addr, total};
    }


    auto conn::send_response(const std::array<std::uint8_t, 16> &uuid, net::steady_timer &deadline)
        -> net::awaitable<fault::code>
    {
        if (verifier_)
        {
            const auto uuid_str = uuid_to_string(uuid);
            if (!verifier_(uuid_str))
            {
                deadline.cancel();
                trace::warn("[Vless] UUID verification failed");
                co_return fault::code::auth_failed;
            }
        }

        const auto response = format::make_response();
        std::error_code write_ec;
        co_await transport::async_write(*next_layer_, {response.data(), response.size()}, write_ec);
        deadline.cancel();
        if (write_ec)
        {
            co_return fault::to_code(write_ec);
        }
        co_return fault::code::success;
    }


    auto conn::handshake()
        -> net::awaitable<std::pair<fault::code, request>>
    {
        // 缓冲区足够容纳最大 VLESS 请求
        std::array<std::uint8_t, 320> buffer{};
        const auto byte_span = std::span(reinterpret_cast<std::byte *>(buffer.data()), buffer.size());

        // 握手超时保护：30 秒内必须完成
        net::steady_timer deadline(next_layer_->executor(), std::chrono::seconds(30));
        auto on_deadline = [this](const boost::system::error_code &ec)
        {
            if (!ec) next_layer_->cancel();
        };
        deadline.async_wait(std::move(on_deadline));

        // 步骤 1: 解析固定头部
        auto [hdr_ec, uuid, cmd, port, atyp, total] = co_await parse_header(buffer, byte_span, deadline);
        if (fault::failed(hdr_ec))
        {
            co_return std::pair{hdr_ec, request{}};
        }

        // 步骤 2: 解析目标地址
        auto [addr_ec, dest_addr, new_total] = co_await process_target({buffer, byte_span, atyp, total, deadline});
        if (fault::failed(addr_ec))
        {
            co_return std::pair{addr_ec, request{}};
        }

        // 步骤 3: 验证 UUID 并发送响应
        const auto resp_ec = co_await send_response(uuid, deadline);
        if (fault::failed(resp_ec))
        {
            co_return std::pair{resp_ec, request{}};
        }

        // 步骤 4: 构建请求
        request req;
        req.uuid = uuid;
        req.cmd = cmd;
        req.port = port;
        req.destination_address = dest_addr;
        if (cmd == command::udp)
            req.transport = psm::protocol::form::datagram;
        else
            req.transport = psm::protocol::form::stream;

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
                "[Vless.UDP]",
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

} // namespace psm::protocol::vless

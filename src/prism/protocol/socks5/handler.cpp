/**
 * @file handler.cpp
 * @brief SOCKS5 协议处理器实现
 */

#include <prism/protocol/socks5/handler.hpp>

#include <prism/config/config.hpp>
#include <prism/net/connect/outbound/dial.hpp>
#include <prism/net/connect/dial/connector.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/net/connect/outbound/proxy.hpp>
#include <prism/net/connect/target.hpp>
#include <prism/protocol/socks5/conn.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>

#include <charconv>
#include <utility>

namespace psm::protocol::socks5
{
    using namespace psm::trace;

    handler::handler(protocol::handler_params params) noexcept
        : res_(params.res)
        , data_(params.data)
    {
    }

    auto handler::run() -> net::awaitable<void>
    {
        auto trace = res_.trace;

        auto inbound = psm::transport::wrap_with_preview(std::move(res_.inbound), data_);
        res_.inbound = nullptr;
        if (!inbound)
        {
            if (trace)
                trace::warn<flt::conn | flt::protocol>(trace, "inbound missing");
            co_return;
        }

        const auto agent = make_conn(
            std::move(inbound), res_.worker->process->cfg->protocol.socks5, &*res_.worker->process->accounts);
        agent->set_traffic(&res_.worker->traffic, res_.detected);

        auto [ec, request] = co_await agent->handshake();
        if (fault::failed(ec))
        {
            if (trace)
                trace::error<flt::conn | flt::protocol>(trace,
                    "handshake failed: {}", fault::cached_message(ec));
            co_return;
        }

        switch (request.cmd)
        {
        case command::connect:
        {
            target target(res_.arena.get());
            target.host = to_string(request.destination_address, res_.arena.get());
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(
                port_buf, port_buf + sizeof(port_buf),
                request.destination_port);
            target.port.assign(port_buf, std::distance(port_buf, pe));
            target.positive = true;
            if (trace)
                trace::info<flt::conn | flt::protocol>(trace,
                    "CONNECT -> {}:{}", target.host, target.port);

            psm::outbound::dial_options dial_opts;
            dial_opts.trace = trace;
            auto dial_res = co_await psm::outbound::dial(
                {*res_.worker->outbound, res_.worker->ioc, res_.worker->traffic}, target, dial_opts);
            const auto dial_ec = dial_res.code;
            auto outbound = std::move(dial_res.transport);
            if (fault::failed(dial_ec) || !outbound)
            {
                if (dial_ec == fault::code::ipv6_disabled)
                {
                    if (trace)
                        trace::debug<flt::conn | flt::protocol>(trace,
                            "IPv6 disabled: {}:{}", target.host, target.port);
                    co_await agent->send_error(reply_code::network_unreachable);
                }
                else
                {
                    if (trace)
                        trace::warn<flt::conn | flt::protocol>(trace,
                            "dial failed: {}, target: {}:{}",
                            fault::describe(dial_ec), target.host, target.port);
                    co_await agent->send_error(reply_code::host_unreachable);
                }
                co_return;
            }

            if (fault::failed(co_await agent->send_success(request)))
                co_return;

            auto t_opts = psm::connect::tunnel_options{};
            t_opts.inbound = agent->release();
            t_opts.outbound = outbound;
            t_opts.trace = trace;
            t_opts.buffer_size = res_.buffer;
            t_opts.traffic = &res_.worker->traffic;
            t_opts.detected = res_.detected;
            t_opts.lease = &res_.lease;
            co_await psm::connect::tunnel(std::move(t_opts));
            break;
        }
        case command::udp_associate:
        {
            const auto target_host = to_string(
                request.destination_address, res_.arena.get());
            char udp_port_buf[8];
            const auto [upe, upec] = std::to_chars(
                udp_port_buf, udp_port_buf + sizeof(udp_port_buf),
                request.destination_port);
            const auto target_port = std::string_view(
                udp_port_buf, std::distance(udp_port_buf, upe));
            if (trace)
                trace::info<flt::conn | flt::protocol>(trace,
                    "UDP_ASSOCIATE -> {}:{}", target_host, target_port);

            auto datagram_router = res_.worker->outbound->make_router();

            const auto associate_ec = co_await agent->async_associate(
                request, std::move(datagram_router));
            if (fault::failed(associate_ec))
            {
                if (trace)
                    trace::warn<flt::conn | flt::protocol>(trace,
                        "UDP_ASSOCIATE failed: {}", fault::describe(associate_ec));
            }
            break;
        }
        default:
            if (trace)
                trace::warn<flt::conn | flt::protocol>(trace, "BIND not supported");
            co_await agent->send_error(reply_code::cmd_unsupported);
            break;
        }
    }
} // namespace psm::protocol::socks5

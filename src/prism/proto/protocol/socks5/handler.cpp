/**
 * @file handler.cpp
 * @brief SOCKS5 协议处理器实现
 */

#include <prism/proto/protocol/socks5/handler.hpp>

#include <prism/config/config.hpp>
#include <prism/context/context.hpp>
#include <prism/instance/outbound/dial.hpp>
#include <prism/net/connect/dial/dial.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/instance/outbound/proxy.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/proto/protocol/socks5/conn.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>

#include <charconv>
#include <utility>

namespace psm::protocol::socks5
{
    using namespace psm::trace;

    handler::handler(protocol::handler_params params) noexcept
        : ctx_(params.ctx)
        , data_(params.data)
        , prefix_(std::move(params.trace))
    {
    }

    auto handler::run() -> net::awaitable<void>
    {

        auto wr = ctx_.worker_ctx.resources.lock();
        if (!wr)
        {
            trace::warn<flt::conn | flt::protocol>(*prefix_, "worker resources expired");
            co_return;
        }

        auto inbound = psm::transport::wrap_with_preview(
            std::move(ctx_.inbound), data_);
        ctx_.inbound = nullptr;
        if (!inbound)
        {
            trace::warn<flt::conn | flt::protocol>(*prefix_, "inbound missing");
            co_return;
        }

        const auto agent = make_conn(
            std::move(inbound), ctx_.server_ctx.config().protocol.socks5,
            ctx_.server_ctx.account_store.get());
        agent->set_traffic(&wr->traffic(), ctx_.detected_protocol);

        auto [ec, request] = co_await agent->handshake();
        if (fault::failed(ec))
        {
            trace::error<flt::conn | flt::protocol>(*prefix_,
                "handshake failed: {}", fault::cached_message(ec));
            co_return;
        }

        switch (request.cmd)
        {
        case command::connect:
        {
            target target(ctx_.frame_arena.get());
            target.host = to_string(request.destination_address,
                ctx_.frame_arena.get());
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(
                port_buf, port_buf + sizeof(port_buf),
                request.destination_port);
            target.port.assign(port_buf, std::distance(port_buf, pe));
            target.positive = true;
            trace::info<flt::conn | flt::protocol>(*prefix_,
                "CONNECT -> {}:{}", target.host, target.port);

            // 通过 outbound::dial 统一入口拨号
            psm::outbound::dial_options dial_opts;
            dial_opts.trace = prefix_;
            auto dial_res = co_await psm::outbound::dial(wr, target, dial_opts);
            const auto dial_ec = dial_res.code;
            auto outbound = std::move(dial_res.transport);
            if (fault::failed(dial_ec) || !outbound)
            {
                if (dial_ec == fault::code::ipv6_disabled)
                {
                    trace::debug<flt::conn | flt::protocol>(*prefix_,
                        "IPv6 disabled: {}:{}", target.host, target.port);
                    co_await agent->send_error(reply_code::network_unreachable);
                }
                else
                {
                    trace::warn<flt::conn | flt::protocol>(*prefix_,
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
            t_opts.trace = prefix_;
            t_opts.buffer_size = ctx_.buffer_size;
            t_opts.traffic = &wr->traffic();
            t_opts.detected = ctx_.detected_protocol;
            t_opts.lease = &ctx_.account_lease;
            co_await psm::connect::tunnel(std::move(t_opts));
            break;
        }
        case command::udp_associate:
        {
            const auto target_host = to_string(
                request.destination_address, ctx_.frame_arena.get());
            char udp_port_buf[8];
            const auto [upe, upec] = std::to_chars(
                udp_port_buf, udp_port_buf + sizeof(udp_port_buf),
                request.destination_port);
            const auto target_port = std::string_view(
                udp_port_buf, std::distance(udp_port_buf, upe));
            trace::info<flt::conn | flt::protocol>(*prefix_,
                "UDP_ASSOCIATE -> {}:{}", target_host, target_port);

            // 通过 outbound 接口获取 UDP 路由回调（worker::resources 保证有效）
            auto datagram_router = wr->outbound().make_router();

            const auto associate_ec = co_await agent->async_associate(
                request, std::move(datagram_router));
            if (fault::failed(associate_ec))
            {
                trace::warn<flt::conn | flt::protocol>(*prefix_,
                    "UDP_ASSOCIATE failed: {}", fault::describe(associate_ec));
            }
            break;
        }
        default:
            trace::warn<flt::conn | flt::protocol>(*prefix_, "BIND not supported");
            co_await agent->send_error(reply_code::cmd_unsupported);
            break;
        }
    }
} // namespace psm::protocol::socks5

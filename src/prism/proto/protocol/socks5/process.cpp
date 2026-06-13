#include <prism/proto/protocol/socks5/process.hpp>
#include <prism/config/config.hpp>
#include <prism/net/connect/dial/dial.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/instance/outbound/proxy.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/proto/protocol/socks5/conn.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>

#include <charconv>

using namespace psm::trace;

namespace psm::protocol::socks5
{

    auto handle(context::session &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 取出入站传输对象
        auto inbound = psm::transport::wrap_with_preview(std::move(ctx.inbound), data, ctx.frame_arena.get());
        ctx.inbound = nullptr;
        if (!inbound)
        {
            trace::warn<flt::conn | flt::protocol>("inbound missing");
            co_return;
        }

        // 创建 SOCKS5 中继代理并执行握手
        const auto agent = make_conn(
            std::move(inbound), ctx.server_ctx.config().protocol.socks5, ctx.account_directory);

        agent->set_traffic(ctx.worker_ctx.traffic, ctx.detected_protocol);

        auto [ec, request] = co_await agent->handshake();
        if (fault::failed(ec))
        {
            trace::error<flt::conn | flt::protocol>("handshake failed: {}", fault::cached_message(ec));
            co_return;
        }

        // 根据命令类型分发处理
        switch (request.cmd)
        {
        case command::connect:
        {
            // TCP 连接请求：解析目标地址
            target target(ctx.frame_arena.get());
            target.host = to_string(request.destination_address, ctx.frame_arena.get());
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), request.destination_port);
            target.port.assign(port_buf, std::distance(port_buf, pe));
            target.positive = true;
            trace::info<flt::conn | flt::protocol>("CONNECT -> {}:{}", target.host, target.port);

            // 先拨号上游 — 失败时返回 SOCKS5 错误码（RFC 1928 语义）
            std::pair<fault::code, psm::connect::shared_transmission> dial_result;
            if (ctx.outbound_proxy)
            {
                dial_result = co_await psm::connect::dial(
                    *ctx.outbound_proxy, target, ctx.worker_ctx.io_context.get_executor());
            }
            else
            {
                dial_result = co_await psm::connect::dial(
                    ctx.worker_ctx.router, {"SOCKS5", target});
            }
            const auto dial_ec = dial_result.first;
            const auto outbound = dial_result.second;
            if (fault::failed(dial_ec) || !outbound)
            {
                if (dial_ec == fault::code::ipv6_disabled)
                {
                    trace::debug<flt::conn | flt::protocol>("IPv6 disabled: {}:{}", target.host, target.port);
                    co_await agent->send_error(reply_code::network_unreachable);
                }
                else
                {
                    auto err_desc = fault::describe(dial_ec);
                    trace::warn<flt::conn | flt::protocol>("dial failed: {}, target: {}:{}", err_desc, target.host, target.port);
                    co_await agent->send_error(reply_code::host_unreachable);
                }
                co_return;
            }

            // 拨号成功，发送 SOCKS5 成功响应
            if (fault::failed(co_await agent->send_success(request)))
            {
                co_return;
            }

            // 进入双向隧道转发
            co_await psm::connect::tunnel({agent->release(), outbound, ctx});
            break;
        }
        case command::udp_associate:
        {
            // UDP 关联请求：解析目标地址并进入 UDP 转发模式
            const auto target_host = to_string(request.destination_address, ctx.frame_arena.get());
            char udp_port_buf[8];
            const auto [upe, upec] = std::to_chars(udp_port_buf, udp_port_buf + sizeof(udp_port_buf), request.destination_port);
            const auto target_port = std::string_view(udp_port_buf, std::distance(udp_port_buf, upe));
            trace::info<flt::conn | flt::protocol>("UDP_ASSOCIATE -> {}:{}", target_host, target_port);

            // 启动 UDP 关联处理
            psm::outbound::router_fn datagram_router;
            if (ctx.outbound_proxy)
            {
                datagram_router = ctx.outbound_proxy->make_router();
            }
            else
            {
                datagram_router = psm::connect::make_router(ctx.worker_ctx.router);
            }
            const auto associate_ec = co_await agent->async_associate(request, std::move(datagram_router));
            if (fault::failed(associate_ec))
            {
                trace::warn<flt::conn | flt::protocol>("UDP_ASSOCIATE failed: {}", fault::describe(associate_ec));
            }
            break;
        }
        default:
            // BIND 命令不支持
            trace::warn<flt::conn | flt::protocol>("BIND not supported");
            co_await agent->send_error(reply_code::cmd_unsupported);
            break;
        }
    }

} // namespace psm::protocol::socks5

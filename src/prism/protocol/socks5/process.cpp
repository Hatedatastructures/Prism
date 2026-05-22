#include <prism/protocol/socks5/process.hpp>
#include <prism/protocol/socks5/conn.hpp>
#include <prism/protocol/common/target.hpp>
#include <prism/trace.hpp>
#include <prism/connect/dial/dial.hpp>
#include <prism/connect/tunnel/tunnel.hpp>
#include <prism/transport/preview.hpp>
#include <prism/outbound/proxy.hpp>
#include <prism/config.hpp>
#include <charconv>

constexpr std::string_view Socks5Str = "[Protocol.Socks5]";

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
            trace::warn("{} inbound missing", Socks5Str);
            co_return;
        }

        // 创建 SOCKS5 中继代理并执行握手
        const auto agent = make_conn(
            std::move(inbound), ctx.server_ctx.config().protocol.socks5, ctx.account_directory);
        auto [ec, request] = co_await agent->handshake();
        if (fault::failed(ec))
        {
            trace::error("{} handshake failed: {}", Socks5Str, fault::cached_message(ec));
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
            trace::info("{} CONNECT -> {}:{}", Socks5Str, target.host, target.port);

            // 先拨号上游 — 失败时返回 SOCKS5 错误码（RFC 1928 语义）
            const auto [dial_ec, outbound] = ctx.outbound_proxy
                ? co_await psm::connect::dial(
                      *ctx.outbound_proxy, target, ctx.worker_ctx.io_context.get_executor())
                : co_await psm::connect::dial(
                      ctx.worker_ctx.router, "SOCKS5", target, true, true);
            if (fault::failed(dial_ec) || !outbound)
            {
                if (dial_ec == fault::code::ipv6_disabled)
                {
                    trace::debug("{} IPv6 disabled: {}:{}", Socks5Str, target.host, target.port);
                    co_await agent->async_write_error(reply_code::network_unreachable);
                }
                else
                {
                    trace::warn("{} dial failed: {}, target: {}:{}", Socks5Str, fault::describe(dial_ec), target.host, target.port);
                    co_await agent->async_write_error(reply_code::host_unreachable);
                }
                co_return;
            }

            // 拨号成功，发送 SOCKS5 成功响应
            if (fault::failed(co_await agent->async_write_success(request)))
            {
                co_return;
            }

            // 进入双向隧道转发
            co_await psm::connect::tunnel(agent->release(), std::move(outbound), ctx);
            break;
        }
        case command::udp_associate:
        {
            // UDP 关联请求：解析目标地址并进入 UDP 转发模式
            const auto target_host = to_string(request.destination_address, ctx.frame_arena.get());
            char udp_port_buf[8];
            const auto [upe, upec] = std::to_chars(udp_port_buf, udp_port_buf + sizeof(udp_port_buf), request.destination_port);
            const auto target_port = std::string_view(udp_port_buf, std::distance(udp_port_buf, upe));
            trace::info("{} UDP_ASSOCIATE -> {}:{}", Socks5Str, target_host, target_port);

            // 启动 UDP 关联处理
            auto datagram_router = ctx.outbound_proxy
                ? ctx.outbound_proxy->make_datagram_router()
                : psm::connect::make_datagram_router(ctx.worker_ctx.router);
            const auto associate_ec = co_await agent->async_associate(request, std::move(datagram_router));
            if (fault::failed(associate_ec))
            {
                trace::warn("{} UDP_ASSOCIATE failed: {}", Socks5Str, fault::describe(associate_ec));
            }
            break;
        }
        default:
            // BIND 命令不支持
            trace::warn("{} BIND not supported", Socks5Str);
            co_await agent->async_write_error(reply_code::command_not_supported);
            break;
        }
    }
} // namespace psm::protocol::socks5

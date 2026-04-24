#include <prism/pipeline/protocols/socks5.hpp>
#include <protocol.hpp>
#include <prism/memory/container.hpp>
#include <prism/trace.hpp>
#include <charconv>

constexpr std::string_view Socks5Str = "[Pipeline.Socks5]";

namespace psm::pipeline
{
    using primitives::shared_transmission;
    auto socks5(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 取出入站传输对象
        auto inbound = primitives::wrap_with_preview(ctx, data);
        // 检查入站传输对象是否存在，SOCKS5 协议需要它来完成握手和数据转发
        if (!inbound)
        {
            trace::warn("{} inbound missing", Socks5Str);
            co_return;
        }

        // 创建 SOCKS5 中继代理并执行握手
        const auto agent = protocol::socks5::make_relay(
            std::move(inbound), ctx.server.config().protocol.socks5, ctx.account_directory_ptr);
        auto [ec, request] = co_await agent->handshake();
        // 协商失败，退出处理流程，agent 对象通过 RAII 自动清理
        if (fault::failed(ec))
        {
            trace::error("{} handshake failed: {}", Socks5Str, fault::cached_message(ec));
            co_return;
        }

        // 根据命令类型分发处理
        switch (request.cmd)
        {
        case protocol::socks5::command::connect:
        {
            // TCP 连接请求：解析目标地址
            protocol::analysis::target target(ctx.frame_arena.get());
            target.host = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), request.destination_port);
            target.port.assign(port_buf, std::distance(port_buf, pe));
            target.positive = true;
            trace::info("{} CONNECT -> {}:{}", Socks5Str, target.host, target.port);

            // 先拨号上游 — 失败时返回 SOCKS5 错误码（RFC 1928 语义）
            const auto [dial_ec, outbound] = ctx.outbound_proxy
                ? co_await primitives::dial(
                      *ctx.outbound_proxy, target, ctx.worker.io_context.get_executor())
                : co_await primitives::dial(
                      ctx.worker.router, "SOCKS5", target, true, true);
            if (fault::failed(dial_ec) || !outbound)
            {
                if (dial_ec == fault::code::ipv6_disabled)
                {
                    trace::debug("{} IPv6 disabled: {}:{}", Socks5Str, target.host, target.port);
                    co_await agent->async_write_error(protocol::socks5::reply_code::network_unreachable);
                }
                else
                {
                    trace::warn("{} dial failed: {}, target: {}:{}", Socks5Str, fault::describe(dial_ec), target.host, target.port);
                    co_await agent->async_write_error(protocol::socks5::reply_code::host_unreachable);
                }
                co_return;
            }

            // 拨号成功，发送 SOCKS5 成功响应
            if (fault::failed(co_await agent->async_write_success(request)))
            {
                co_return;
            }

            // 进入双向隧道转发
            co_await primitives::tunnel(agent->release(), std::move(outbound), ctx);
            break;
        }
        case protocol::socks5::command::udp_associate:
        {
            // UDP 关联请求：解析目标地址并进入 UDP 转发模式
            const auto target_host = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
            char udp_port_buf[8];
            const auto [upe, upec] = std::to_chars(udp_port_buf, udp_port_buf + sizeof(udp_port_buf), request.destination_port);
            const auto target_port = std::string_view(udp_port_buf, std::distance(udp_port_buf, upe));
            trace::info("{} UDP_ASSOCIATE -> {}:{}", Socks5Str, target_host, target_port);

            // 启动 UDP 关联处理
            auto datagram_router = ctx.outbound_proxy
                ? ctx.outbound_proxy->make_datagram_router()
                : primitives::make_datagram_router(ctx.worker.router);
            const auto associate_ec = co_await agent->async_associate(request, std::move(datagram_router));
            if (fault::failed(associate_ec))
            {
                trace::warn("{} UDP_ASSOCIATE failed: {}", Socks5Str, fault::describe(associate_ec));
            }
            break;
        }
        default:
            // BIND 命令不支持，返回错误响应
            trace::warn("{} BIND not supported", Socks5Str);
            co_await agent->async_write_error(protocol::socks5::reply_code::command_not_supported);
            break;
        }
    }
} // namespace psm::pipeline

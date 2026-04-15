#include <prism/pipeline/protocols/socks5.hpp>
#include <protocol.hpp>
#include <prism/memory/container.hpp>
#include <charconv>

constexpr std::string_view Socks5Str = "[Pipeline.Socks5]";

namespace psm::pipeline
{
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
            std::move(inbound), ctx.server.cfg.socks5, ctx.account_directory_ptr);
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
            // TCP 连接请求：解析目标地址并建立连接
            protocol::analysis::target target(ctx.frame_arena.get());
            target.host = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), request.destination_port);
            target.port.assign(port_buf, std::distance(port_buf, pe));
            target.positive = true;
            trace::info("{} CONNECT -> {}:{}", Socks5Str, target.host, target.port);

            // 通过路由器建立到目标的连接
            auto [conn_ec, outbound] = co_await primitives::dial(ctx.worker.router, "SOCKS5", target, true, true);
            if (fault::failed(conn_ec) || !outbound)
            {
                trace::warn("{} failed: {}, target: {}:{}", Socks5Str, fault::describe(conn_ec), target.host, target.port);
                // 连接失败，返回主机不可达错误
                co_await agent->async_write_error(protocol::socks5::reply_code::host_unreachable);
                co_return;
            }

            // 连接成功，发送成功响应给客户端
            if (fault::failed(co_await agent->async_write_success(request)))
            {
                co_return;
            }
            // 释放传输对象并进入双向隧道转发
            auto trans = agent->release();
            trace::debug("{} tunnel opened: {}:{}", Socks5Str, target.host, target.port);
            co_await primitives::tunnel(std::move(trans), std::move(outbound), ctx);
            trace::debug("{} tunnel closed: {}:{}", Socks5Str, target.host, target.port);
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

            // 创建路由回调函数，用于解析 UDP 数据报目标地址
            const auto router_ptr = std::shared_ptr<resolve::router>(&ctx.worker.router, [](resolve::router *) {});
            auto route_callback = [router_ptr](const std::string_view host, const std::string_view port)
                -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
            {
                co_return co_await router_ptr->resolve_datagram_target(host, port);
            };
            // 启动 UDP 关联处理
            const auto associate_ec = co_await agent->async_associate(request, std::move(route_callback));
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

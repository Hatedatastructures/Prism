/**
 * @file vless.cpp
 * @brief VLESS 协议处理管道实现
 * @details 实现 VLESS 协议的会话处理，包括握手解析、UUID 验证、
 * 命令分发和多路复用引导。参考 trojan.cpp 的完整结构。
 */

#include <prism/pipeline/protocols/vless.hpp>
#include <protocol.hpp>
#include <prism/multiplex/bootstrap.hpp>
#include <prism/memory/container.hpp>
#include <string_view>

constexpr std::string_view VlessStr = "[Pipeline.Vless]";

namespace psm::pipeline
{
    auto vless(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 包装传输层（data 通过 preview 重放）
        auto inbound = std::move(ctx.inbound);
        if (!data.empty())
        {
            inbound = std::make_shared<primitives::preview>(std::move(inbound), data, nullptr);
        }

        // 创建 VLESS 中继代理并执行握手
        const auto agent = protocol::vless::make_relay(std::move(inbound), ctx.server.cfg.vless);

        auto [vless_ec, req] = co_await agent->handshake();
        if (fault::failed(vless_ec))
        {
            trace::warn("{} handshake failed: {}", VlessStr, fault::describe(vless_ec));
            co_return;
        }

        // 根据命令类型处理请求
        switch (req.cmd)
        {
        case protocol::vless::command::tcp:
        case protocol::vless::command::mux:
        {
            // 解析目标地址
            protocol::analysis::target target(ctx.frame_arena.get());
            target.host = protocol::vless::to_string(req.destination_address, ctx.frame_arena.get());
            target.port = std::to_string(static_cast<unsigned int>(req.port));

            // Mihomo smux 兼容：客户端用 mux 命令或虚假地址标记多路复用连接
            if (ctx.server.cfg.mux.enabled && target.host.size() >= 18 && target.host.substr(target.host.size() - 18) == ".mux.sing-box.arpa")
            {
                trace::info("{} mux session started", VlessStr);
                ctx.active_stream_close = nullptr;
                ctx.active_stream_cancel = nullptr;
                auto muxprotocol = co_await multiplex::bootstrap(agent->release(), ctx.worker.router, ctx.server.cfg.mux);
                if (muxprotocol)
                {
                    muxprotocol->start();
                }
                co_return;
            }

            target.positive = true;
            trace::info("{} CONNECT -> {}:{}", VlessStr, target.host, target.port);

            // 通过路由器建立到目标的连接
            const std::shared_ptr<resolve::router> router_ptr(&ctx.worker.router, [](resolve::router *) {});
            auto [dial_ec, outbound] = co_await primitives::dial(router_ptr, "Vless", target, true, true);
            if (fault::failed(dial_ec) || !outbound)
            {
                if (dial_ec == fault::code::ipv6_disabled)
                {
                    trace::debug("{} IPv6 disabled: {}:{}", VlessStr, target.host, target.port);
                }
                else
                {
                    trace::warn("{} dial failed: {}, target: {}:{}", VlessStr, fault::describe(dial_ec), target.host, target.port);
                }
                co_return;
            }

            // 释放传输对象并进入双向隧道转发
            auto raw_trans = agent->release();
            co_await primitives::tunnel(std::move(raw_trans), std::move(outbound), ctx);
            break;
        }
        case protocol::vless::command::udp:
        {
            trace::warn("{} UDP not yet supported", VlessStr);
            break;
        }
        default:
            trace::warn("{} unknown command: {}", VlessStr, static_cast<int>(req.cmd));
            break;
        }
    }
} // namespace psm::pipeline

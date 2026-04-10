#include <prism/pipeline/protocols/trojan.hpp>
#include <protocol.hpp>
#include <prism/multiplex/bootstrap.hpp>
#include <prism/agent/account/directory.hpp>
#include <prism/memory/container.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <string_view>

constexpr std::string_view TrojanStr = "[Pipeline.Trojan]";

namespace psm::pipeline
{
    namespace account = psm::agent::account;
    auto trojan(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 包装传输层（与 HTTP handler 相同模式：data 通过 preview 重放）
        // TLS 已在 session 层剥离，ctx.inbound 可能是 encrypted transport 或原始 TCP
        auto inbound = std::move(ctx.inbound);
        if (!data.empty())
        {
            // mux 模式下 inbound 会被移交给 smux_craft 并脱离 session 生命周期
            // 使用全局内存池(nullptr)避免 smux_craft 析构时 UAF
            inbound = std::make_shared<primitives::preview>(std::move(inbound), data, nullptr);
        }

        // 创建凭证验证器，检查账户目录和连接限制
        auto verifier = [&ctx](const std::string_view credential) -> bool
        {
            if (!ctx.account_directory_ptr)
            {
                trace::warn("{} account directory not configured", TrojanStr);
                return false;
            }
            // 尝试获取账户租约，验证凭证并检查连接限制
            auto lease = account::try_acquire(*ctx.account_directory_ptr, credential);
            if (!lease)
            {
                trace::warn("{} credential verification failed", TrojanStr);
                return false;
            }
            ctx.account_lease = std::move(lease);
            return true;
        };

        // 创建 Trojan 中继代理并执行握手
        const auto agent = protocol::trojan::make_relay(std::move(inbound), ctx.server.cfg.trojan, std::move(verifier));

        auto [trojan_ec, req] = co_await agent->handshake();
        if (fault::failed(trojan_ec))
        {
            trace::warn("{} handshake failed: {}", TrojanStr, fault::describe(trojan_ec));
            co_return;
        }

        // 根据命令类型处理请求
        switch (req.cmd)
        {
        case protocol::trojan::command::connect:
        {
            // 解析目标地址
            protocol::analysis::target target(ctx.frame_arena.get());
            target.host = protocol::trojan::to_string(req.destination_address, ctx.frame_arena.get());
            target.port = std::to_string(req.port);

            // Mihomo smux 兼容：客户端用 CONNECT + 虚假地址标记 mux 连接
            // 检测 mux 标记地址，命中则走 smux 多路复用逻辑
            if (ctx.server.cfg.mux.enabled && target.host.size() >= 18 && target.host.substr(target.host.size() - 18) == ".mux.sing-box.arpa")
            {
                trace::info("{} mux session started", TrojanStr);
                // 清除 session 流关闭回调，transport 生命周期由 multiplexer 接管
                ctx.active_stream_close = nullptr;
                ctx.active_stream_cancel = nullptr;
                // 创建多路复用会话（内部执行 sing-mux 协商，根据客户端选择协议）
                auto muxprotocol = co_await multiplex::bootstrap(agent->release(), ctx.worker.router, ctx.server.cfg.mux);
                if (muxprotocol)
                {
                    muxprotocol->start();
                }
                co_return;
            }

            target.positive = true;
            trace::info("{} CONNECT -> {}:{}", TrojanStr, target.host, target.port);

            // 通过路由器建立到目标的连接
            const std::shared_ptr<resolve::router> router_ptr(&ctx.worker.router, [](resolve::router *) {});
            auto [dial_ec, outbound] = co_await primitives::dial(router_ptr, "Trojan", target, true, true);
            if (fault::failed(dial_ec) || !outbound)
            {
                // IPv6 被禁用是预期行为，使用 debug 级别
                if (dial_ec == fault::code::ipv6_disabled)
                {
                    trace::debug("{} IPv6 disabled: {}:{}", TrojanStr, target.host, target.port);
                }
                else
                {
                    trace::warn("{} dial failed: {}, target: {}:{}", TrojanStr, fault::describe(dial_ec), target.host, target.port);
                }
                co_return;
            }

            // 释放传输对象并进入双向隧道转发
            auto raw_trans = agent->release();
            co_await primitives::tunnel(std::move(raw_trans), std::move(outbound), ctx);
            break;
        }
        case protocol::trojan::command::udp_associate:
        {
            trace::info("{} UDP_ASSOCIATE started", TrojanStr);

            // 创建路由回调函数，用于解析 UDP 数据报目标地址
            const auto router_ptr = std::shared_ptr<resolve::router>(&ctx.worker.router, [](resolve::router *) {});
            auto route_callback = [router_ptr](const std::string_view host, const std::string_view port)
                -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
            {
                co_return co_await router_ptr->resolve_datagram_target(host, port);
            };

            // 启动 UDP 关联处理
            const auto associate_ec = co_await agent->async_associate(std::move(route_callback));
            if (fault::failed(associate_ec))
            {
                trace::warn("{} UDP_ASSOCIATE failed: {}", TrojanStr, fault::describe(associate_ec));
            }
            else
            {
                trace::info("{} UDP_ASSOCIATE completed", TrojanStr);
            }
            break;
        }
        default:
            // 未知命令类型
            trace::warn("{} unknown command: {}", TrojanStr, static_cast<int>(req.cmd));
            break;
        }
    }
} // namespace psm::pipeline

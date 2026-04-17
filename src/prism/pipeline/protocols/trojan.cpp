#include <prism/pipeline/protocols/trojan.hpp>
#include <protocol.hpp>
#include <prism/multiplex/bootstrap.hpp>
#include <prism/agent/account/directory.hpp>
#include <prism/memory/container.hpp>
#include <prism/trace.hpp>
#include <charconv>
#include <string_view>

constexpr std::string_view TrojanStr = "[Pipeline.Trojan]";

namespace psm::pipeline
{
    namespace account = psm::agent::account;
    auto trojan(session_context &ctx, const std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 包装传输层（data 通过 preview 重放）
        // mux 模式下 inbound 会被移交给 smux_craft 并脱离 session 生命周期
        // 使用全局内存池避免 smux_craft 析构时 UAF
        auto inbound = primitives::wrap_with_preview(ctx, data, true);

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
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), req.port);
            target.port.assign(port_buf, std::distance(port_buf, pe));

            // Mihomo smux 兼容：客户端用 CONNECT + 虚假地址标记 mux 连接
            if (primitives::is_mux_target(target.host, ctx.server.cfg.mux.enabled))
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

            // 拨号 + 隧道转发
            co_await primitives::forward(ctx, "Trojan", target, agent->release());
            break;
        }
        case protocol::trojan::command::udp_associate:
        {
            trace::info("{} UDP_ASSOCIATE started", TrojanStr);

            // 启动 UDP 关联处理
            const auto associate_ec = co_await agent->async_associate(primitives::make_datagram_router(ctx.worker.router));
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
        case protocol::trojan::command::mux:
        {
            // Trojan mux (cmd=0x7F)：直接进入多路复用模式
            trace::info("{} mux session started (cmd=0x7F)", TrojanStr);
            ctx.active_stream_close = nullptr;
            ctx.active_stream_cancel = nullptr;
            auto muxprotocol = co_await multiplex::bootstrap(
                agent->release(), ctx.worker.router, ctx.server.cfg.mux);
            if (muxprotocol)
            {
                muxprotocol->start();
            }
            co_return;
        }
        default:
            // 未知命令类型
            trace::warn("{} unknown command: {}", TrojanStr, static_cast<int>(req.cmd));
            break;
        }
    }
} // namespace psm::pipeline

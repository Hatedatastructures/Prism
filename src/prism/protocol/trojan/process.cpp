#include <prism/protocol/trojan/process.hpp>
#include <prism/account/directory.hpp>
#include <prism/config.hpp>
#include <prism/connect/dial/dial.hpp>
#include <prism/connect/tunnel/forward.hpp>
#include <prism/connect/util.hpp>
#include <prism/memory/container.hpp>
#include <prism/multiplex/bootstrap.hpp>
#include <prism/outbound/proxy.hpp>
#include <prism/protocol/trojan/conn.hpp>
#include <prism/trace.hpp>
#include <prism/transport/preview.hpp>

#include <charconv>
#include <string_view>

constexpr std::string_view TrojanStr = "[Protocol.Trojan]";

namespace psm::protocol::trojan
{

    namespace account = psm::account;

    auto handle(context::session &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 包装传输层（data 通过 preview 重放）
        auto inbound = psm::transport::wrap_with_preview(std::move(ctx.inbound), data, ctx.frame_arena.get());
        ctx.inbound = nullptr;

        // 创建凭证验证器，检查账户目录和连接限制
        auto verifier = [&ctx](const std::string_view credential) -> bool
        {
            if (!ctx.account_directory)
            {
                trace::warn("{} account directory not configured", TrojanStr);
                return false;
            }
            auto lease = account::try_acquire(*ctx.account_directory, credential);
            if (!lease)
            {
                trace::warn("{} credential verification failed", TrojanStr);
                return false;
            }
            ctx.account_lease = std::move(lease);
            return true;
        };

        // 创建 Trojan 中继代理并执行握手
        const auto agent = make_conn(std::move(inbound), ctx.server_ctx.config().protocol.trojan, std::move(verifier));

        agent->set_traffic(ctx.worker_ctx.traffic, ctx.detected_protocol);

        auto [trojan_ec, req] = co_await agent->handshake();
        if (fault::failed(trojan_ec))
        {
            trace::warn("{} handshake failed: {}", TrojanStr, fault::describe(trojan_ec));
            co_return;
        }

        // 根据命令类型处理请求
        switch (req.cmd)
        {
        case command::connect:
        {
            // 解析目标地址
            target target(ctx.frame_arena.get());
            target.host = to_string(req.destination_address, ctx.frame_arena.get());
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), req.port);
            target.port.assign(port_buf, std::distance(port_buf, pe));

            // Mihomo smux 兼容：客户端用 CONNECT + 虚假地址标记 mux 连接
            auto mux_sw = psm::connect::mux_switch::off;
            if (ctx.server_ctx.config().mux.enabled)
                mux_sw = psm::connect::mux_switch::on;
            if (psm::connect::is_mux(target.host, mux_sw))
            {
                trace::info("{} mux session started", TrojanStr);
                ctx.stream_close = nullptr;
                ctx.stream_cancel = nullptr;
                auto muxprotocol = co_await multiplex::bootstrap(
                    multiplex::bootstrap_context{
                        .transport = agent->release(),
                        .router = ctx.worker_ctx.router,
                        .cfg = ctx.server_ctx.config().mux,
                        .traffic = ctx.worker_ctx.traffic,
                        .proto = ctx.detected_protocol
                    });
                if (muxprotocol)
                {
                    muxprotocol->start();
                }
                co_return;
            }

            target.positive = true;
            trace::info("{} CONNECT -> {}:{}", TrojanStr, target.host, target.port);

            // 拨号 + 隧道转发
            co_await psm::connect::forward(ctx, {"Trojan", target, agent->release()});
            break;
        }
        case command::udp_associate:
        {
            trace::info("{} UDP_ASSOCIATE started", TrojanStr);

            using dgram_result = std::pair<fault::code, net::ip::udp::endpoint>;
            using route_fn = std::function<net::awaitable<dgram_result>(std::string_view, std::string_view)>;
            route_fn dgram_router;
            if (ctx.outbound_proxy)
            {
                dgram_router = ctx.outbound_proxy->make_router();
            }
            else
            {
                dgram_router = psm::connect::make_router(ctx.worker_ctx.router);
            }
            const auto associate_ec = co_await agent->async_associate(std::move(dgram_router));
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
        case command::mux:
        {
            // Trojan mux (cmd=0x7F)：直接进入多路复用模式
            trace::info("{} mux session started (cmd=0x7F)", TrojanStr);
            ctx.stream_close = nullptr;
            ctx.stream_cancel = nullptr;
            auto muxprotocol = co_await multiplex::bootstrap(
                multiplex::bootstrap_context{
                    .transport = agent->release(),
                    .router = ctx.worker_ctx.router,
                    .cfg = ctx.server_ctx.config().mux,
                    .traffic = ctx.worker_ctx.traffic,
                    .proto = ctx.detected_protocol
                });
            if (muxprotocol)
            {
                muxprotocol->start();
            }
            co_return;
        }
        default:
            trace::warn("{} unknown command: {}", TrojanStr, static_cast<int>(req.cmd));
            break;
        }
    }

} // namespace psm::protocol::trojan

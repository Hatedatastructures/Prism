#include <prism/protocol/vless/process.hpp>
#include <prism/account/directory.hpp>
#include <prism/config.hpp>
#include <prism/connect/dial/dial.hpp>
#include <prism/connect/tunnel/forward.hpp>
#include <prism/connect/util.hpp>
#include <prism/memory/container.hpp>
#include <prism/multiplex/bootstrap.hpp>
#include <prism/outbound/proxy.hpp>
#include <prism/protocol/common/mux.hpp>
#include <prism/protocol/vless/conn.hpp>
#include <prism/trace.hpp>
#include <prism/transport/preview.hpp>

#include <cstdint>
#include <string_view>

constexpr std::string_view VlessStr = "[Protocol.Vless]";

namespace psm::protocol::vless
{

    namespace account = psm::account;

    auto handle(context::session &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 包装传输层（data 通过 preview 重放）
        auto inbound = psm::transport::wrap_with_preview(std::move(ctx.inbound), data, ctx.frame_arena.get());
        ctx.inbound = nullptr;

        // 创建 UUID 验证回调，通过 account::directory 统一认证和连接数限制
        auto verifier = [&ctx](const std::string_view credential) -> bool
        {
            if (!ctx.account_directory)
            {
                trace::warn("{} account directory not configured", VlessStr);
                return false;
            }
            auto lease = account::try_acquire(*ctx.account_directory, credential);
            if (!lease)
            {
                trace::warn("{} credential verification failed", VlessStr);
                return false;
            }
            ctx.account_lease = std::move(lease);
            return true;
        };

        // 创建 VLESS 中继代理并执行握手
        const auto agent = make_conn(std::move(inbound), ctx.server_ctx.config().protocol.vless, std::move(verifier));

        agent->set_traffic(ctx.worker_ctx.traffic, ctx.detected_protocol);

        auto [vless_ec, req] = co_await agent->handshake();
        if (fault::failed(vless_ec))
        {
            trace::warn("{} handshake failed: {}", VlessStr, fault::describe(vless_ec));
            co_return;
        }

        // 根据命令类型处理请求
        switch (req.cmd)
        {
        case command::tcp:
        case command::mux:
        {
            // 解析目标地址
            target target(ctx.frame_arena.get());
            target.host = to_string(req.destination_address, ctx.frame_arena.get());
            char port_buf[8];
            const auto [pe, pec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), static_cast<std::uint32_t>(req.port));
            target.port.assign(port_buf, std::distance(port_buf, pe));

            // Mihomo smux 兼容：客户端用 mux 命令或虚假地址标记多路复用连接
            auto mux_sw = psm::connect::mux_switch::off;
            if (ctx.server_ctx.config().mux.enabled)
                mux_sw = psm::connect::mux_switch::on;
            if (psm::connect::is_mux(target.host, mux_sw))
            {
                trace::info("{} mux session started", VlessStr);
                ctx.stream_close = nullptr;
                ctx.stream_cancel = nullptr;
                auto muxprotocol = co_await multiplex::bootstrap(
                    multiplex::bootstrap_context{
                        .transport = agent->release(),
                        .router = ctx.worker_ctx.router,
                        .cfg = ctx.server_ctx.config().mux,
                        .traffic = ctx.worker_ctx.traffic,
                        .proto = ctx.detected_protocol,
                    });
                if (muxprotocol)
                {
                    muxprotocol->start();
                }
                // mux 已接管 transport，清除 inbound 防止 release_resources() 关闭 mux 使用的连接
                ctx.inbound = nullptr;
                co_return;
            }

            target.positive = true;
            trace::info("{} CONNECT -> {}:{}", VlessStr, target.host, target.port);

            // 拨号 + 隧道转发
            co_await psm::connect::forward(ctx, {"Vless", target, agent->release()});
            break;
        }
        case command::udp:
        {
            trace::info("{} UDP associate started", VlessStr);
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
                trace::warn("{} UDP associate failed: {}", VlessStr, fault::describe(associate_ec));
            }
            else
            {
                trace::info("{} UDP associate completed", VlessStr);
            }
            break;
        }
        default:
            trace::warn("{} unknown command: {}", VlessStr, static_cast<int>(req.cmd));
            break;
        }
    }

} // namespace psm::protocol::vless

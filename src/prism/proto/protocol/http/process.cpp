#include <prism/proto/protocol/http/process.hpp>
#include <prism/config/config.hpp>
#include <prism/net/connect/dial/dial.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/instance/outbound/proxy.hpp>
#include <prism/proto/protocol/http/conn.hpp>
#include <prism/proto/protocol/common/target.hpp>
#include <prism/proto/protocol/types.hpp>
#include <prism/stealth/recognition/target.hpp>
#include <prism/trace/trace.hpp>
#include <prism/net/transport/preview.hpp>

#include <string_view>

using namespace psm::trace;

namespace psm::protocol::http
{

    auto handle(context::session &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 重置帧内存池
        ctx.frame_arena.reset();

        // 包装入站传输（如有预读数据则用 preview 装饰器重放）
        auto inbound = psm::transport::wrap_with_preview(std::move(ctx.inbound), data, ctx.frame_arena.get());
        ctx.inbound = nullptr;

        // 创建 HTTP 中继并握手（读取请求头 + 解析 + 认证）
        auto relay = make_conn(std::move(inbound), ctx.account_directory);
        auto [ec, req] = co_await relay->handshake();
        if (fault::failed(ec))
        {
            trace::warn<flt::conn | flt::protocol>("handshake failed: {}", fault::describe(ec));
            co_return;
        }

        // 解析目标地址
        const auto target = recognition::resolve(req);
        trace::info<flt::conn | flt::protocol>("{} {} -> {}:{}", req.method, req.target, target.host, target.port);

        // 连接目标服务器
        psm::transport::shared_transmission outbound;
        fault::code dial_ec;
        if (ctx.outbound_proxy)
        {
            auto [ec, trans] = co_await psm::connect::dial(
                *ctx.outbound_proxy, target, ctx.worker_ctx.io_context.get_executor());
            dial_ec = ec;
            outbound = std::move(trans);
        }
        else
        {
            auto [ec, trans] = co_await psm::connect::dial(
                ctx.worker_ctx.router, psm::connect::dial_options{"HTTP", target, psm::connect::dial_options::flag::no_open});
            dial_ec = ec;
            outbound = std::move(trans);
        }
        if (fault::failed(dial_ec) || !outbound)
        {
            trace::warn<flt::conn | flt::protocol>("dial failed: {}:{}", target.host, target.port);
            co_await relay->send_gateway_err();
            co_return;
        }

        // 按方法分发
        if (req.method == "CONNECT")
        {   // HTTPS 分支
            // CONNECT：发送 200 响应，释放传输层，进入隧道
            if (fault::failed(co_await relay->send_ok()))
            {
                co_return;
            }
            co_await psm::connect::tunnel({relay->release(), outbound, ctx});
        }
        else
        {
            // 普通 HTTP：重写 URI 后转发原始数据，然后进入隧道
            co_await relay->forward(req, outbound, ctx.frame_arena.get());
            co_await psm::connect::tunnel({relay->release(), outbound, ctx});
        }
    }
} // namespace psm::protocol::http

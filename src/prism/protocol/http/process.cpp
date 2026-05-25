#include <prism/protocol/http/process.hpp>
#include <prism/protocol/http/conn.hpp>
#include <prism/protocol/types.hpp>
#include <prism/protocol/common/target.hpp>
#include <prism/recognition/target.hpp>
#include <prism/trace.hpp>
#include <prism/connect/dial/dial.hpp>
#include <prism/connect/tunnel/tunnel.hpp>
#include <prism/transport/preview.hpp>
#include <prism/outbound/proxy.hpp>
#include <prism/config.hpp>
#include <string_view>

constexpr std::string_view HttpStr = "[Protocol.Http]";

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
            trace::warn("{} handshake failed: {}", HttpStr, fault::describe(ec));
            co_return;
        }

        // 解析目标地址
        const auto target = recognition::resolve(req);
        trace::info("{} {} {} -> {}:{}", HttpStr, req.method, req.target, target.host, target.port);

        // 连接目标服务器
        const auto [dial_ec, outbound] = ctx.outbound_proxy
            ? co_await psm::connect::dial(
                  *ctx.outbound_proxy, target, ctx.worker_ctx.io_context.get_executor())
            : co_await psm::connect::dial(
                  ctx.worker_ctx.router, "HTTP", target, {.allow_reverse = true, .require_open = false});
        if (fault::failed(dial_ec) || !outbound)
        {
            trace::warn("{} dial failed: {}:{}", HttpStr, target.host, target.port);
            co_await relay->send_bad_gateway();
            co_return;
        }

        // 按方法分发
        if (req.method == "CONNECT")
        {   // https
            // CONNECT：发送 200 响应，释放传输层，进入隧道
            if (fault::failed(co_await relay->send_connect_ok()))
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

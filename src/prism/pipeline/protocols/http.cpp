#include <prism/pipeline/protocols/http.hpp>
#include <prism/protocol/http/relay.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/trace.hpp>

constexpr std::string_view HttpStr = "[Pipeline.Http]";

namespace psm::pipeline
{
    auto http(session_context &ctx, std::span<const std::byte> data)
        -> net::awaitable<void>
    {
        // 重置帧内存池
        ctx.frame_arena.reset();

        // 包装入站传输（如有预读数据则用 preview 装饰器重放）
        auto inbound = primitives::wrap_with_preview(ctx, data);

        // 创建 HTTP 中继并握手（读取请求头 + 解析 + 认证）
        auto relay = protocol::http::make_relay(std::move(inbound), ctx.account_directory_ptr);
        auto [ec, req] = co_await relay->handshake();
        if (fault::failed(ec))
        {
            trace::warn("{} handshake failed: {}", HttpStr, fault::describe(ec));
            co_return;
        }

        // 解析目标地址
        const auto target = protocol::analysis::resolve(req);
        trace::info("{} {} {} -> {}:{}", HttpStr, req.method, req.target, target.host, target.port);

        // 连接目标服务器
        auto [dial_ec, outbound] = co_await primitives::dial(ctx.worker.router, "HTTP", target, true, false);
        if (fault::failed(dial_ec) || !outbound)
        {
            trace::warn("{} dial failed: {}:{}", HttpStr, target.host, target.port);
            co_await relay->write_bad_gateway();
            co_return;
        }

        // 按方法分发
        if (req.method == "CONNECT")
        {   // https
            // CONNECT：发送 200 响应，释放传输层，进入隧道
            if (fault::failed(co_await relay->write_connect_success()))
            {
                co_return;
            }
            co_await primitives::tunnel(relay->release(), std::move(outbound), ctx);
        }
        else
        {
            // 普通 HTTP：重写 URI 后转发原始数据，然后进入隧道
            co_await relay->forward(req, outbound, ctx.frame_arena.get());
            co_await primitives::tunnel(relay->release(), std::move(outbound), ctx);
        }
    }
} // namespace psm::pipeline

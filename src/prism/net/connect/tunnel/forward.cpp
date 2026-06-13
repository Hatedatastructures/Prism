#include <prism/net/connect/tunnel/forward.hpp>

#include <prism/net/connect/dial/dial.hpp>
#include <prism/net/connect/dial/router.hpp>
#include <prism/net/connect/tunnel/tunnel.hpp>
#include <prism/trace/trace.hpp>

using namespace psm::trace;

namespace psm::connect
{

    // 协议级转发入口：有出站代理走代理连接上游，否则通过路由器直连
    // 建立出站连接后调用 tunnel() 进行双向数据转发
    auto forward(context::session &ctx, forward_options opts)
        -> net::awaitable<void>
    {
        const auto &label = opts.label;
        const auto &target = opts.target;

        // 有出站代理走代理，否则走路由器直连
        if (ctx.outbound_proxy)
        {
            auto [ec, outbound] = co_await dial(*ctx.outbound_proxy, target,
                                                 ctx.worker_ctx.io_context.get_executor());
            if (fault::failed(ec) || !outbound)
            {
                if (ec == fault::code::ipv6_disabled)
                    trace::debug<flt::conn | flt::protocol>("IPv6 disabled: {}:{}", target.host, target.port);
                else
                    trace::warn<flt::conn | flt::protocol>("dial failed: {}, target: {}:{}", fault::describe(ec), target.host, target.port);
                co_return;
            }
            co_await tunnel({std::move(opts.inbound), std::move(outbound), ctx});
            co_return;
        }

        auto [ec, outbound] = co_await dial(ctx.worker_ctx.router, {label, target});
        if (fault::failed(ec) || !outbound)
        {
            if (ec == fault::code::ipv6_disabled)
                trace::debug<flt::conn | flt::protocol>("IPv6 disabled: {}:{}", target.host, target.port);
            else
                trace::warn<flt::conn | flt::protocol>("dial failed: {}, target: {}:{}", fault::describe(ec), target.host, target.port);
            co_return;
        }
        co_await tunnel({std::move(opts.inbound), std::move(outbound), ctx});
    }

} // namespace psm::connect

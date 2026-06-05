#include <prism/connect/tunnel/forward.hpp>

#include <prism/connect/dial/dial.hpp>
#include <prism/connect/dial/router.hpp>
#include <prism/connect/tunnel/tunnel.hpp>
#include <prism/trace.hpp>

using namespace psm::trace;

namespace psm::connect
{

    auto forward(context::session &ctx, forward_options opts)
        -> net::awaitable<void>
    {
        const auto &label = opts.label;
        const auto &target = opts.target;

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

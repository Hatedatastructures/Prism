/**
 * @file forward_relay.cpp
 * @brief 正向代理转发器实现（委托 forward_pipeline）
 */

#include <prism/net/connect/tunnel/forward_relay.hpp>

#include <prism/net/connect/tunnel/forward/pipeline.hpp>
#include <prism/trace/trace.hpp>

using namespace psm::trace;

namespace psm::connect
{

    forward_relay::forward_relay(context::session &ctx, forward_options opts) noexcept
        : ctx_(ctx)
        , opts_(std::move(opts))
    {
    }

    auto forward_relay::run() -> net::awaitable<void>
    {
        auto wr = ctx_.worker_ctx.resources.lock();
        if (!wr)
        {
            trace::warn<flt::conn | flt::protocol>(opts_.trace,
                "forward_relay: worker resources expired");
            co_return;
        }
        co_await forward_pipeline(
            wr, ctx_,
            pipeline_options{std::move(opts_.inbound), opts_.target, opts_.trace});
    }

} // namespace psm::connect

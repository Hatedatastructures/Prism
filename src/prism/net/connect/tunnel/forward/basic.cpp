#include <prism/net/connect/tunnel/forward/basic.hpp>

#include <prism/net/connect/tunnel/forward/pipeline.hpp>
#include <prism/trace/trace.hpp>

using namespace psm::trace;

namespace psm::connect
{

    // forward 委托 forward_pipeline（P3 引入），消除对 connect::dial 的直接依赖。
    // 保留接口兼容性，调用方（anytls/subsequent_stream 等）无需改动。
    auto forward(context::session &ctx, forward_options opts)
        -> net::awaitable<void>
    {
        auto wr = ctx.worker_ctx.resources.lock();
        if (!wr)
        {
            trace::warn<flt::conn | flt::protocol>(opts.trace,
                "forward: worker resources expired");
            co_return;
        }
        co_await forward_pipeline(
            wr, ctx,
            pipeline_options{std::move(opts.inbound), opts.target, opts.trace});
    }

} // namespace psm::connect

#include <prism/net/connect/tunnel/forward/basic.hpp>

#include <prism/net/connect/tunnel/forward/pipeline.hpp>
#include <prism/trace/trace.hpp>

using namespace psm::trace;

namespace psm::connect
{

    auto forward(psm::resource::session &res, forward_options opts)
        -> net::awaitable<void>
    {
        co_await forward_pipeline(
            res, opts.target,
            pipeline_options{std::move(opts.inbound), opts.trace});
    }

} // namespace psm::connect

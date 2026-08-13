#include <prism/diagnose/diagnose.hpp>
#include <prism/net/connection/tunnel/forward/basic.hpp>
#include <prism/net/connection/tunnel/forward/pipeline.hpp>

using namespace psm::diagnose;

namespace psm::connect
{

    auto forward(psm::resource::session &res, forward_options opts) -> net::awaitable<void>
    {
        co_await forward_pipeline(res, opts.target, pipeline_options{std::move(opts.inbound), opts.trace});
    }

} // namespace psm::connect

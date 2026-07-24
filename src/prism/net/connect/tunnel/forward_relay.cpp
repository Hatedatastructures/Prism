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

    forward_relay::forward_relay(psm::resource::session &res, forward_options opts) noexcept
        : res_(res)
        , opts_(std::move(opts))
    {
    }

    auto forward_relay::run() -> net::awaitable<void>
    {
        co_await forward_pipeline(
            res_, opts_.target,
            pipeline_options{std::move(opts_.inbound), opts_.trace});
    }

} // namespace psm::connect

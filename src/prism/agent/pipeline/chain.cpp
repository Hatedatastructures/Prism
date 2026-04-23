/**
 * @file stage_chain.cpp
 * @brief 协议 Stage 链编排器实现
 */

#include <prism/agent/pipeline/chain.hpp>
#include <prism/trace.hpp>

namespace psm::agent::pipeline
{
    void stage_chain::push_back(shared_stage stage)
    {
        stages_.push_back(std::move(stage));
    }

    auto stage_chain::execute(agent::session_context &ctx,
                               protocol::detection_result &detect_result,
                               std::span<const std::byte> &span)
        -> net::awaitable<stage_result>
    {
        for (const auto &stage : stages_)
        {
            if (!stage->applicable(ctx.server.config()))
            {
                trace::debug("[StageChain] Stage '{}' not applicable, skipping", stage->name());
                continue;
            }

            trace::debug("[StageChain] Executing stage '{}'", stage->name());

            auto result = co_await stage->process(ctx, detect_result, span);

            switch (result.type)
            {
            case stage_result_type::success:
                trace::debug("[StageChain] Stage '{}' succeeded, protocol: {}",
                              stage->name(), protocol::to_string_view(result.detected_protocol));
                if (result.outbound_inbound)
                {
                    ctx.inbound = std::move(result.outbound_inbound);
                }
                co_return result;

            case stage_result_type::fallback_complete:
                trace::debug("[StageChain] Stage '{}' completed with fallback", stage->name());
                co_return result;

            case stage_result_type::failed:
                trace::warn("[StageChain] Stage '{}' failed", stage->name());
                co_return result;

            case stage_result_type::not_applicable:
                trace::debug("[StageChain] Stage '{}' not applicable during process", stage->name());
                break;
            }
        }

        stage_result result;
        result.type = stage_result_type::failed;
        co_return result;
    }
} // namespace psm::agent::pipeline

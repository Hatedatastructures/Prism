/**
 * @file reality_stage.hpp
 * @brief Reality TLS 伪装 Stage
 */
#pragma once

#include <prism/agent/pipeline/stage.hpp>

namespace psm::agent::pipeline::stages
{
    class reality_stage : public protocol_stage
    {
    public:
        [[nodiscard]] auto applicable(const agent::config &cfg) const noexcept -> bool override
        {
            return cfg.reality.enabled();
        }

        [[nodiscard]] auto process(agent::session_context &ctx, protocol::detection_result &detect_result,
                                   std::span<const std::byte> &span)
            -> net::awaitable<stage_result> override;

        [[nodiscard]] auto name() const noexcept -> std::string_view override
        {
            return "reality";
        }
    };
} // namespace psm::agent::pipeline::stages

/**
 * @file standard_tls_stage.hpp
 * @brief 标准 TLS 剥离 Stage
 */
#pragma once

#include <prism/agent/pipeline/stage.hpp>

namespace psm::agent::pipeline::stages
{
    class standard_tls_stage : public protocol_stage
    {
    public:
        [[nodiscard]] auto applicable([[maybe_unused]] const agent::config &cfg) const noexcept -> bool override
        {
            return true;
        }

        [[nodiscard]] auto process(agent::session_context &ctx, protocol::detection_result &detect_result,
                                   std::span<const std::byte> &span)
            -> net::awaitable<stage_result> override;

        [[nodiscard]] auto name() const noexcept -> std::string_view override
        {
            return "standard_tls";
        }
    };
} // namespace psm::agent::pipeline::stages

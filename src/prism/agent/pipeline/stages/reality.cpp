/**
 * @file reality_stage.cpp
 * @brief Reality TLS 伪装 Stage 实现
 * @details 将 session.cpp 中 lines 178-224 的 Reality 逻辑迁移到此。
 */

#include <prism/agent/pipeline/stages/reality.hpp>
#include <prism/agent/session/session.hpp>
#include <prism/stealth/reality/handshake.hpp>
#include <prism/trace.hpp>
#include <prism/protocol/probe.hpp>

namespace psm::agent::pipeline::stages
{
    auto reality_stage::process(agent::session_context &ctx, protocol::detection_result &detect_result,
                                std::span<const std::byte> &span)
        -> net::awaitable<stage_result>
    {
        auto result = co_await stealth::reality::handshake(ctx, span);

        stage_result stage_res;

        switch (result.type)
        {
        case stealth::reality::handshake_result_type::authenticated:
        {
            ctx.inbound = std::move(result.encrypted_transport);
            span = std::span<const std::byte>(result.inner_preread.data(), result.inner_preread.size());
            detect_result.type = protocol::protocol_type::vless;
            stage_res.type = stage_result_type::success;
            stage_res.outbound_inbound = ctx.inbound;
            stage_res.detected_protocol = protocol::protocol_type::vless;
            stage_res.preread_data.assign(result.inner_preread.begin(), result.inner_preread.end());
            trace::debug("[RealityStage] Authenticated, dispatching to VLESS");
            break;
        }

        case stealth::reality::handshake_result_type::not_reality:
            // SNI 不匹配，让下一个 Stage 处理
            span = std::span<const std::byte>(result.raw_tls_record.data(), result.raw_tls_record.size());
            stage_res.type = stage_result_type::not_applicable;
            trace::debug("[RealityStage] Not Reality, passing to next stage");
            break;

        case stealth::reality::handshake_result_type::fallback:
            // 透明代理已完成
            stage_res.type = stage_result_type::fallback_complete;
            trace::debug("[RealityStage] Fallback complete");
            break;

        case stealth::reality::handshake_result_type::failed:
        {
            if (result.error == fault::code::reality_tls_record_error)
            {
                // TLS 记录错误，可能是 SS2022，不适用
                stage_res.type = stage_result_type::not_applicable;
                detect_result.type = protocol::protocol_type::shadowsocks;
                trace::debug("[RealityStage] TLS record error, not applicable");
                break;
            }
            stage_res.type = stage_result_type::failed;
            stage_res.error = std::make_error_code(std::errc::protocol_error);
            trace::warn("[RealityStage] Handshake failed: {}", fault::describe(result.error));
            break;
        }
        }

        co_return stage_res;
    }
} // namespace psm::agent::pipeline::stages

/**
 * @file shadowtls_stage.cpp
 * @brief ShadowTLS v3 伪装 Stage 实现
 * @details 将 session.cpp 中 ShadowTLS 逻辑迁移到此。
 *
 * 注意：ShadowTLS handshake 需要直接操作 TCP socket，
 * 当前 Stage Chain 架构下，probe 已经消费了前 24 字节数据，
 * ShadowTLS 无法正确读取完整的 ClientHello。
 * 因此当 handshake_dest 未配置时，直接跳过不读取任何数据。
 */

#include <prism/agent/pipeline/stages/shadowtls.hpp>
#include <prism/stealth/shadowtls/handshake.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/trace.hpp>

namespace psm::agent::pipeline::stages
{
    auto shadowtls_stage::process(agent::session_context &ctx, protocol::detection_result &detect_result,
                                  std::span<const std::byte> &span)
        -> net::awaitable<stage_result>
    {
        const auto &cfg = ctx.server.config().shadowtls;

        // 如果 handshake_dest 未配置，说明 ShadowTLS 未真正启用
        // 直接跳过，不读取任何数据
        if (cfg.handshake_dest.empty() || cfg.users.empty())
        {
            trace::debug("[ShadowTlsStage] Not configured, skipping");
            stage_result result;
            result.type = stage_result_type::not_applicable;
            co_return result;
        }

        auto stls_result = co_await stealth::shadowtls::handshake(ctx, cfg);

        stage_result result;

        if (stls_result.authenticated)
        {
            auto &first_frame = stls_result.client_first_frame;
            if (!first_frame.empty())
            {
                const auto inner_view = std::string_view(
                    reinterpret_cast<const char *>(first_frame.data()), first_frame.size());
                detect_result.type = protocol::analysis::detect_tls(inner_view);

                if (detect_result.type != protocol::protocol_type::unknown)
                {
                    auto preview_ptr = std::shared_ptr<psm::pipeline::primitives::preview>(
                        new psm::pipeline::primitives::preview(
                            std::move(ctx.inbound),
                            std::span<const std::byte>(first_frame.data(), first_frame.size())));
                    ctx.inbound = std::move(preview_ptr);
                    span = std::span<const std::byte>(first_frame.data(), first_frame.size());

                    result.type = stage_result_type::success;
                    result.outbound_inbound = ctx.inbound;
                    result.detected_protocol = detect_result.type;
                    result.preread_data.assign(first_frame.begin(), first_frame.end());
                    trace::debug("[ShadowTlsStage] Authenticated (user: {}), inner protocol: {}",
                                 stls_result.matched_user, protocol::to_string_view(detect_result.type));
                }
                else
                {
                    result.type = stage_result_type::not_applicable;
                }
            }
            else
            {
                result.type = stage_result_type::not_applicable;
            }
        }
        else
        {
            trace::debug("[ShadowTlsStage] Not a ShadowTLS client, passing to next stage");
            result.type = stage_result_type::not_applicable;
        }

        co_return result;
    }
} // namespace psm::agent::pipeline::stages

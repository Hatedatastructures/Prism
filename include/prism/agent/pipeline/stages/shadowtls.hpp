/**
 * @file shadowtls_stage.hpp
 * @brief ShadowTLS v3 伪装 Stage
 */
#pragma once

#include <prism/agent/pipeline/stage.hpp>

namespace psm::agent::pipeline::stages
{
    class shadowtls_stage : public protocol_stage
    {
    public:
        [[nodiscard]] auto applicable([[maybe_unused]] const agent::config &cfg) const noexcept -> bool override
        {
            // 暂时禁用：ShadowTLS handshake 直接操作 TCP socket，
            // 与 probe 预读数据冲突，会导致后续 Standard TLS 握手失败。
            // 修复方案：重写 shadowtls::handshake 支持 pre-read 数据回放。
            return false;
        }

        [[nodiscard]] auto process(agent::session_context &ctx, protocol::detection_result &detect_result,
                                   std::span<const std::byte> &span)
            -> net::awaitable<stage_result> override;

        [[nodiscard]] auto name() const noexcept -> std::string_view override
        {
            return "shadowtls";
        }
    };
} // namespace psm::agent::pipeline::stages

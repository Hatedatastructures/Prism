/**
 * @file scheme.cpp
 * @brief ShadowTLS v3 伪装方案实现
 */

#include <prism/stealth/shadowtls/scheme.hpp>
#include <prism/stealth/shadowtls/handshake.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/trace.hpp>

namespace psm::stealth::shadowtls
{
    auto scheme::is_enabled(const psm::config &cfg) const noexcept -> bool
    {
        const auto &st_cfg = cfg.stealth.shadowtls;
        // v3: 需要至少一个用户和握手目标
        if (st_cfg.version == 3)
            return !st_cfg.users.empty() && !st_cfg.handshake_dest.empty();
        // v2: 需要密码和握手目标
        return !st_cfg.password.empty() && !st_cfg.handshake_dest.empty();
    }

    auto scheme::name() const noexcept -> std::string_view
    {
        return "shadowtls";
    }

    auto scheme::detect(const protocol::tls::client_hello_features &features,
                        const psm::config &cfg) const -> detection_result
    {
        if (!is_enabled(cfg))
            return {.confidence = recognition::confidence::none,
                    .reason = "ShadowTLS disabled"};

        // ShadowTLS v3 使用 session_id 携带 HMAC 标记
        // 仅靠 ClientHello 特征无法完全确认，需要 execute() 阶段验证
        // 启发式：session_id 非空且长度不是标准 32 字节时可能是 ShadowTLS
        // 注意：标准 TLS 1.2 实现也可使用 0-32 任意长度的 session_id，因此这只是启发式判断
        if (!features.session_id.empty() && features.session_id_len != 32)
        {
            trace::debug("[ShadowTLS] Non-standard session_id length: {}", features.session_id_len);
            return {.confidence = recognition::confidence::medium,
                    .reason = "non-standard session_id length"};
        }

        // session_id 为空或标准长度时，无法区分
        return {.confidence = recognition::confidence::low,
                .reason = "standard TLS, cannot distinguish from ClientHello alone"};
    }

    auto scheme::execute(scheme_context ctx)
        -> net::awaitable<scheme_result>
    {
        scheme_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        // 获取底层 reliable transmission
        // 如果 inbound 已被 preview 等包装，dynamic_cast 会失败
        // 这不是致命错误，只是说明 ShadowTLS 无法在此环境下执行
        auto *rel = dynamic_cast<channel::transport::reliable *>(ctx.session->inbound.get());
        if (!rel)
        {
            trace::debug("[ShadowTlsScheme] Cannot access reliable transport (wrapped by another scheme), pass to next scheme");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(ctx.inbound);
            co_return result;
        }

        auto hs = co_await stealth::shadowtls::handshake(*ctx.session, ctx.cfg->stealth.shadowtls);

        if (hs.authenticated)
        {
            auto &first_frame = hs.client_first_frame;
            if (!first_frame.empty())
            {
                auto inner_view = std::string_view(
                    reinterpret_cast<const char *>(first_frame.data()), first_frame.size());
                result.detected = protocol::analysis::detect_tls(inner_view);

                if (result.detected != protocol::protocol_type::unknown)
                {
                    result.transport = std::make_shared<pipeline::primitives::preview>(
                        std::move(ctx.session->inbound),
                        std::span<const std::byte>(first_frame.data(), first_frame.size()));
                    result.preread.assign(first_frame.begin(), first_frame.end());
                    trace::debug("[ShadowTlsScheme] Authenticated (user: {}), inner protocol: {}",
                                 hs.matched_user, protocol::to_string_view(result.detected));
                }
                else
                {
                    result.preread.assign(first_frame.begin(), first_frame.end());
                }
            }
        }
        else
        {
            result.detected = protocol::protocol_type::tls;
            trace::debug("[ShadowTlsScheme] Not ShadowTLS, pass to next scheme");
        }

        co_return result;
    }
} // namespace psm::stealth::shadowtls

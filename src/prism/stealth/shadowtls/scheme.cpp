/**
 * @file scheme.cpp
 * @brief ShadowTLS v3 伪装方案实现
 */

#include <prism/stealth/shadowtls/scheme.hpp>
#include <prism/stealth/shadowtls/handshake.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/trace.hpp>

namespace psm::stealth::shadowtls
{
    auto scheme::is_enabled([[maybe_unused]] const psm::config &cfg) const noexcept -> bool
    {
        // 暂时禁用：ShadowTLS v3 尚未调通，后续完善
        return false;
    }

    auto scheme::name() const noexcept -> std::string_view
    {
        return "shadowtls";
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

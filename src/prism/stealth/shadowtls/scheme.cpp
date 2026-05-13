/**
 * @file scheme.cpp
 * @brief ShadowTLS v3 伪装方案实现
 * @details ShadowTLS 是 Tier 1 方案，需要 HMAC 验证确认身份。
 */

#include <prism/stealth/shadowtls/scheme.hpp>
#include <prism/stealth/shadowtls/handshake.hpp>
#include <prism/stealth/shadowtls/auth.hpp>
#include <prism/channel/transport/reliable.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/protocol/analysis.hpp>
#include <prism/trace.hpp>

namespace psm::stealth::shadowtls
{
    auto scheme::active(const psm::config &cfg) const noexcept -> bool
    {
        const auto &st_cfg = cfg.stealth.shadowtls;
        // v3: 需要至少一个用户、握手目标和 SNI 白名单
        if (st_cfg.version == 3)
            return !st_cfg.users.empty() && !st_cfg.handshake_dest.empty() && !st_cfg.server_names.empty();
        // v2: 需要密码、握手目标和 SNI 白名单
        return !st_cfg.password.empty() && !st_cfg.handshake_dest.empty() && !st_cfg.server_names.empty();
    }

    auto scheme::name() const noexcept -> std::string_view
    {
        return "shadowtls";
    }

    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        memory::vector<memory::string> names;
        for (const auto &name : cfg.stealth.shadowtls.server_names)
            names.push_back(memory::string(name));
        return names;
    }

    auto scheme::sniff(std::uint32_t bitmap,
                       const protocol::tls::client_hello_features &features) const
        -> sniff_result
    {
        using namespace protocol::tls;

        // Tier 0: 非标准 session_id 长度（零成本）
        if (has_feature(bitmap, session_id_non_standard))
        {
            return {
                .hit = true,
                .solo = false,  // 不能独占，需要 Tier 1 HMAC 验证
                .hint = 150,
                .note = "non-standard session_id length"};
        }

        return {.hit = false};
    }

    auto scheme::verify(const protocol::tls::client_hello_features &features,
                         std::span<const std::byte> raw,
                         const psm::config &cfg) const
        -> verify_result
    {
        const auto &st_cfg = cfg.stealth.shadowtls;

        // Tier 1: HMAC 验证（延迟执行）
        // 需要 session_id_len == 32 且 raw_client_hello >= 76 字节
        if (raw.size() >= 76 && features.session_id_len == 32)
        {
            if (st_cfg.version == 3)
            {
                for (const auto &user : st_cfg.users)
                {
                    if (user.password.empty())
                        continue;
                    if (verify_client_hello(raw, user.password))
                    {
                        trace::debug("[ShadowTLS] HMAC verified, user: {}", user.name);
                        return {
                            .score = 900,
                            .solo_flag = 0xFFFF,  // 独占
                            .note = memory::string("HMAC verified, user: ") + memory::string(user.name)};
                    }
                }
            }
            else if (!st_cfg.password.empty())
            {
                if (verify_client_hello(raw, st_cfg.password))
                {
                    trace::debug("[ShadowTLS] HMAC verified (v2)");
                    return {
                        .score = 900,
                        .solo_flag = 0xFFFF,
                        .note = "HMAC verified"};
                }
            }
        }

        // HMAC 不匹配
        return {.score = 50, .solo_flag = 0, .note = "HMAC not verified"};
    }

    auto scheme::handshake(stealth::handshake_context ctx)
        -> net::awaitable<stealth::handshake_result>
    {
        stealth::handshake_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        // 获取底层 reliable transport 的 raw socket
        // 穿透 snapshot/preview 包装层找到底层 TCP socket
        auto *rel = pipeline::primitives::find_reliable(ctx.inbound);
        if (!rel)
        {
            trace::debug("[ShadowTlsScheme] Cannot access reliable transport, pass to next scheme");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(ctx.inbound);
            co_return result;
        }

        // 使用 Recognition 层已读取的 ClientHello（不再从 socket 重复读取）
        auto hs = co_await stealth::shadowtls::handshake(
            rel->native_socket(),
            ctx.cfg->stealth.shadowtls,
            std::move(ctx.preread));

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
                        std::move(ctx.inbound),
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
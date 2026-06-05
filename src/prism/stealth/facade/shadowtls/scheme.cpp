#include <prism/stealth/facade/shadowtls/scheme.hpp>

#include <prism/connect/util.hpp>
#include <prism/protocol/types.hpp>
#include <prism/recognition/probe/analyzer.hpp>
#include <prism/recognition/tls/features.hpp>
#include <prism/stealth/facade/shadowtls/handshake.hpp>
#include <prism/stealth/facade/shadowtls/transport.hpp>
#include <prism/stealth/facade/shadowtls/util/auth.hpp>
#include <prism/trace.hpp>
#include <prism/transport/preview.hpp>
#include <prism/transport/reliable.hpp>
#include <prism/transport/snapshot.hpp>

using namespace psm::trace;

namespace psm::stealth::shadowtls
{

    using hello_features = protocol::tls::hello_features;

    auto scheme::active(const psm::config &cfg) const noexcept
        -> bool
    {
        const auto &st_cfg = cfg.stealth.shadowtls;
        if (st_cfg.version == 3)
            return !st_cfg.users.empty() && !st_cfg.handshake_dest.empty() && !st_cfg.server_names.empty();
        return !st_cfg.password.empty() && !st_cfg.handshake_dest.empty() && !st_cfg.server_names.empty();
    }


    auto scheme::name() const noexcept
        -> std::string_view
    {
        return "shadowtls";
    }


    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        return make_sni_list(cfg.stealth.shadowtls.server_names);
    }


    auto scheme::sniff(std::uint32_t bitmap,
                       const hello_features & /*features*/) const
        -> sniff_result
    {
        if (recognition::tls::has_feature(bitmap, recognition::tls::feature_bit::nonstd_session))
        {
            return {
                .hit = true,
                .solo = false,
                .hint = 150,
                .note = "non-standard session_id length"};
        }

        return {.hit = false};
    }


    auto scheme::verify(const hello_features &features,
                         std::span<const std::byte> raw,
                         const psm::config &cfg) const
        -> verify_result
    {
        const auto &st_cfg = cfg.stealth.shadowtls;

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
                        trace::debug<flt::conn | flt::protocol>("HMAC verified, user: {}", user.name);
                        return {
                            .score = 900,
                            .solo_flag = 0xFFFF,
                            .note = memory::string("HMAC verified, user: ") + memory::string(user.name)};
                    }
                }
            }
            else if (!st_cfg.password.empty())
            {
                if (verify_client_hello(raw, st_cfg.password))
                {
                    trace::debug<flt::conn | flt::protocol>("HMAC verified (v2)");
                    return {
                        .score = 900,
                        .solo_flag = 0xFFFF,
                        .note = "HMAC verified"};
                }
            }
        }

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

        auto *rel = ctx.inbound->lowest_layer<transport::reliable>();

        if (!rel)
        {
            trace::info<flt::conn | flt::protocol>("cannot access reliable transport, pass to next scheme");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(ctx.inbound);
            co_return result;
        }

        handshake_detail detail;
        auto hs_result = co_await stealth::shadowtls::handshake(
            stealth::shadowtls::handshake_opts{
                rel->native_socket(),
                ctx.cfg->stealth.shadowtls,
                std::move(ctx.preread),
                detail});

        if (fault::succeeded(hs_result.error) && !detail.client_firstframe.empty())
        {
            auto &first_frame = detail.client_firstframe;
            constexpr std::size_t local_tls_hdrsize = 5;
            if (first_frame.size() > local_tls_hdrsize)
            {
                auto payload = std::span<const std::byte>(
                    first_frame.data() + local_tls_hdrsize,
                    first_frame.size() - local_tls_hdrsize);

                trace::debug<flt::conn | flt::protocol>("first_frame TLS header stripped, payload_size={}", payload.size());

                auto inner_view = std::string_view(
                    reinterpret_cast<const char *>(payload.data()), payload.size());
                result.preread.assign(payload.begin(), payload.end());
                result.detected = protocol::protocol_type::unknown;

                auto raw_socket_opt = rel->release_socket();
                if (!raw_socket_opt)
                {
                    trace::warn<flt::conn | flt::protocol>("cannot release socket from reliable transport");
                    result.detected = protocol::protocol_type::tls;
                    result.transport = std::move(ctx.inbound);
                    co_return result;
                }
                auto raw_socket = std::move(*raw_socket_opt);

                auto shadowtls_trans = std::make_shared<shadowtls_transport>(
                    std::move(raw_socket),
                    shadowtls_handover{
                        detail.matched_password,
                        std::span<const std::byte>(detail.server_random.data(), detail.server_random.size()),
                        std::span<const std::byte>(),
                        std::move(detail.hmac_write_ctx),
                        std::move(detail.hmac_read_ctx)
                    });

                result.transport = shadowtls_trans;
                result.scheme = "shadowtls";

                // 认证成功写入 user
                auto *pfx = trace::active_prefix;
                if (pfx && !detail.matched_user.empty())
                {
                    std::strncpy(pfx->user, detail.matched_user.c_str(),
                                 sizeof(pfx->user) - 1);
                }

                trace::debug<flt::conn | flt::protocol>("authenticated, shadowtls_transport created (HMAC inherited)");
            }
            else
            {
                result.detected = protocol::protocol_type::tls;
                result.transport = std::move(ctx.inbound);
            }
        }
        else
        {
            result.detected = protocol::protocol_type::tls;
            result.error = hs_result.error;
            result.polluted = hs_result.polluted;
            trace::debug<flt::conn | flt::protocol>("not ShadowTLS, pass to next scheme");
        }

        co_return result;
    }
} // namespace psm::stealth::shadowtls

#include <prism/stealth/trusttunnel/scheme.hpp>

#include <prism/config.hpp>
#include <prism/connect/util.hpp>
#include <prism/context/context.hpp>
#include <prism/fault/handling.hpp>
#include <prism/memory/container.hpp>
#include <prism/multiplex/h2mux/craft.hpp>
#include <prism/protocol/types.hpp>
#include <prism/trace.hpp>
#include <prism/transport/encrypted.hpp>
#include <prism/transport/preview.hpp>

#include <boost/asio.hpp>
#include <openssl/evp.h>

namespace psm::stealth::trusttunnel
{

    namespace net = boost::asio;

    namespace
    {
        auto verify_basic_auth(
            std::string_view auth_header,
            const memory::vector<user> &users)
            -> bool
        {
            constexpr std::string_view prefix = "Basic ";
            if (auth_header.size() <= prefix.size() ||
                auth_header.substr(0, prefix.size()) != prefix)
            {
                return false;
            }

            auto b64_credentials = auth_header.substr(prefix.size());

            for (const auto &user : users)
            {
                memory::string expected_creds = user.username + ":" + user.password;
                auto creds_view = std::string_view(expected_creds.data(), expected_creds.size());

                // Base64 输出 = ceil(input/3)*4，256 字节缓冲区最多容纳 192 字节输入。
                // 超过此阈值会栈溢出 encode_buf，直接跳过并记录警告。
                constexpr std::size_t max_cred_len = 192;
                if (creds_view.size() > max_cred_len)
                {
                    trace::warn("trusttunnel: 凭据长度 {} 超过安全阈值 {}，跳过该用户",
                        creds_view.size(), max_cred_len);
                    continue;
                }

                std::array<std::uint8_t, 256> encode_buf{};
                // safe: SSL API requires uint8_t*, string data is read-only for base64 encoding
                auto encoded_len = EVP_EncodeBlock(
                    encode_buf.data(),
                    reinterpret_cast<const std::uint8_t *>(creds_view.data()),
                    static_cast<int>(creds_view.size()));

                // safe: casting uint8_t base64 output buffer to string_view for comparison
                auto encoded_str = std::string_view(
                    reinterpret_cast<const char *>(encode_buf.data()),
                    static_cast<std::size_t>(encoded_len));

                if (encoded_str == b64_credentials)
                {
                    return true;
                }
            }

            return false;
        }


        auto resolve_stream_target(
            std::int32_t stream_id,
            const multiplex::h2mux::h2_headers &headers)
            -> multiplex::h2mux::stream_info
        {
            multiplex::h2mux::stream_info info;

            auto authority = std::string_view(
                headers.authority.data(), headers.authority.size());
            auto host = std::string_view(
                headers.host.data(), headers.host.size());

            if (host.find("_check") != std::string_view::npos)
            {
                info.type = multiplex::h2mux::stream_type::check;
                info.valid = true;
                return info;
            }
            if (host.find("_udp2") != std::string_view::npos)
            {
                info.type = multiplex::h2mux::stream_type::udp;
            }
            else if (host.find("_icmp") != std::string_view::npos)
            {
                info.type = multiplex::h2mux::stream_type::icmp;
            }
            else
            {
                info.type = multiplex::h2mux::stream_type::tcp;
            }

            auto colon = authority.rfind(':');
            if (colon == std::string_view::npos)
            {
                return info;
            }

            info.host.assign(authority.substr(0, colon));
            auto port_view = authority.substr(colon + 1);
            auto port_val = std::uint16_t{0};
            auto [_, ec] = std::from_chars(
                port_view.data(), port_view.data() + port_view.size(), port_val);
            if (ec != std::errc())
            {
                return info;
            }

            info.port = port_val;
            info.valid = true;
            return info;
        }
    } // namespace


    auto scheme::active(const psm::config &cfg) const noexcept
        -> bool
    {
        return cfg.stealth.trusttunnel.enabled();
    }

    auto scheme::name() const noexcept
        -> std::string_view
    {
        return "trusttunnel";
    }

    auto scheme::snis(const psm::config &cfg) const
        -> memory::vector<memory::string>
    {
        return make_sni_list(cfg.stealth.trusttunnel.server_names);
    }

    auto scheme::guess(const psm::config &cfg) const
        -> verify_result
    {
        return {
            .score = 100,
            .solo_flag = 0,
            .note = "TrustTunnel: rely on SNI match"};
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

        if (!ctx.session->server_ctx.ssl_ctx)
        {
            trace::warn("[TrustTunnel] No SSL context configured");
            result.error = fault::code::not_supported;
            co_return result;
        }

        const auto &cfg = ctx.cfg->stealth.trusttunnel;

        auto raw = connect::peel(std::move(ctx.inbound));
        if (!raw)
        {
            trace::warn("[TrustTunnel] Cannot unwrap transport layers");
            result.error = fault::code::not_supported;
            co_return result;
        }

        // safe: nghttp2 ALPN API requires uint8_t*, literal string is used read-only
        SSL_CTX_set_alpn_protos(ctx.session->server_ctx.ssl_ctx->native_handle(),
                                reinterpret_cast<const std::uint8_t *>("\x2h2"), 3);

        auto preread_span = std::span<const std::byte>(ctx.preread.data(), ctx.preread.size());
        auto clean_inbound = transport::wrap_with_preview(
            std::move(raw), preread_span, ctx.session->frame_arena.get());

        auto [ssl_ec, ssl_stream, recovered] = co_await transport::encrypted::ssl_handshake(
            std::move(clean_inbound), *ctx.session->server_ctx.ssl_ctx);

        if (fault::failed(ssl_ec) || !ssl_stream)
        {
            ctx.inbound = std::move(recovered);
            result.error = ssl_ec;
            trace::warn("[TrustTunnel] TLS handshake failed: {}", fault::describe(ssl_ec));
            co_return result;
        }

        trace::debug("[TrustTunnel] TLS handshake succeeded");

        const std::uint8_t *alpn = nullptr;
        std::uint32_t alpn_len = 0;
        SSL_get0_alpn_selected(ssl_stream->native_handle(), &alpn, &alpn_len);
        if (!alpn || alpn_len != 2 || alpn[0] != 'h' || alpn[1] != '2')
        {
            trace::warn("[TrustTunnel] ALPN did not select h2");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::make_shared<transport::encrypted>(ssl_stream);
            co_return result;
        }

        auto encrypted_trans = std::make_shared<transport::encrypted>(ssl_stream);

        auto mux_cfg = ctx.cfg->mux;
        auto craft = std::make_shared<multiplex::h2mux::craft>(
            multiplex::core_options{encrypted_trans, ctx.session->worker_ctx.router, mux_cfg},
            multiplex::h2mux::craft_init{
                ctx.session->worker_ctx.router,
                mux_cfg,
                resolve_stream_target
            });

        craft->start();

        auto first_opt = co_await craft->wait_first_connect();
        if (!first_opt)
        {
            trace::warn("[TrustTunnel] No CONNECT request received");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(encrypted_trans);
            co_return result;
        }

        auto &first = *first_opt;

        auto auth_view = std::string_view(
            first.proxy_auth.data(), first.proxy_auth.size());
        if (cfg.users.empty() || !verify_basic_auth(auth_view, cfg.users))
        {
            trace::warn("[TrustTunnel] Authentication failed");
            (void)craft->respond_connect(first.stream_id, 407);
            co_await craft->send_pending();
            result.error = fault::code::auth_failed;
            co_return result;
        }

        trace::debug("[TrustTunnel] Authenticated, authority={}", first.authority);

        (void)craft->respond_connect(first.stream_id, 200);
        co_await craft->send_pending();
        co_await craft->activate_stream(first.stream_id);

        result.detected = protocol::protocol_type::tls;

        trace::debug("[TrustTunnel] Handshake complete, craft managing all streams");

        co_return result;
    }
} // namespace psm::stealth::trusttunnel

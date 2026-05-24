/**
 * @file scheme.cpp
 * @brief TrustTunnel 伪装方案实现
 * @details Path A TLS 终结 + h2mux HTTP/2 CONNECT 多路复用。
 * SSL 握手（ALPN=h2）→ h2mux::craft → CONNECT → Basic auth → 200 OK → duct/parcel。
 * 所有 stream 由 craft 内部管理，不经过 session::diversion() 分发。
 */

#include <prism/stealth/trusttunnel/scheme.hpp>
#include <prism/multiplex/h2mux/craft.hpp>
#include <prism/connect/util.hpp>
#include <prism/config.hpp>
#include <prism/context/context.hpp>
#include <prism/transport/encrypted.hpp>
#include <prism/transport/preview.hpp>
#include <prism/protocol/protocol_type.hpp>
#include <prism/trace.hpp>
#include <prism/fault/handling.hpp>
#include <prism/memory/container.hpp>

#include <boost/asio.hpp>
#include <openssl/evp.h>

namespace psm::stealth::trusttunnel
{
    namespace net = boost::asio;

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

    static auto verify_basic_auth(
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

        // Step 1: TLS 握手（Path A 终结模式）
        auto raw = connect::peel_to_raw(std::move(ctx.inbound));
        if (!raw)
        {
            trace::warn("[TrustTunnel] Cannot unwrap transport layers");
            result.error = fault::code::not_supported;
            co_return result;
        }

        // 设置 ALPN 为 h2
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

        // 验证 ALPN
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

        // Step 2: 创建 h2mux::craft，注入 TrustTunnel resolver
        auto trusttunnel_resolver = [](int32_t, const multiplex::h2mux::h2_headers &headers)
            -> multiplex::h2mux::h2_stream_info
        {
            multiplex::h2mux::h2_stream_info info;

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
        };

        auto mux_cfg = ctx.cfg->mux;
        auto craft = std::make_shared<multiplex::h2mux::craft>(
            encrypted_trans, ctx.session->worker_ctx.router, mux_cfg,
            trusttunnel_resolver);

        // Step 3: 启动 craft（nghttp2 session 初始化 + frame_loop）
        craft->start();

        // Step 4: 等待第一个 CONNECT
        auto first_opt = co_await craft->wait_first_connect();
        if (!first_opt)
        {
            trace::warn("[TrustTunnel] No CONNECT request received");
            result.detected = protocol::protocol_type::tls;
            result.transport = std::move(encrypted_trans);
            co_return result;
        }

        auto &first = *first_opt;

        // Step 5: 验证 Basic Auth
        auto auth_view = std::string_view(
            first.proxy_auth.data(), first.proxy_auth.size());
        if (cfg.users.empty() || !verify_basic_auth(auth_view, cfg.users))
        {
            trace::warn("[TrustTunnel] Authentication failed");
            craft->respond_connect(first.stream_id, 407);
            co_await craft->send_pending();
            result.error = fault::code::auth_failed;
            co_return result;
        }

        trace::debug("[TrustTunnel] Authenticated, authority={}", first.authority);

        // Step 6: 回复 200 OK + 激活第一个 stream
        craft->respond_connect(first.stream_id, 200);
        co_await craft->send_pending();
        co_await craft->activate_stream(first.stream_id);

        // Step 7: craft 持有 encrypted_trans 的 shared_ptr，
        // frame_loop 已启动并自动处理后续 CONNECT stream。
        // 返回 detected=tls 让 session 不再做 protocol dispatch。
        result.detected = protocol::protocol_type::tls;

        trace::debug("[TrustTunnel] Handshake complete, craft managing all streams");

        co_return result;
    }
} // namespace psm::stealth::trusttunnel

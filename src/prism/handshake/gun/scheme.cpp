/**
 * @file scheme.cpp
 * @brief gRPC (gun) 伪装方案实现
 */

#include <prism/handshake/gun/scheme.hpp>
#include <prism/handshake/gun/session.hpp>

#include <prism/settings/settings.hpp>
#include <prism/net/connection/util.hpp>
#include <prism/resource/session.hpp>
#include <prism/foundation/fault/handling.hpp>
#include <prism/net/connection/types.hpp>
#include <prism/diagnose/diagnose.hpp>
#include <prism/net/transport/encrypted.hpp>
#include <prism/net/transport/preview.hpp>

#include <boost/asio.hpp>
#include <openssl/ssl.h>

using namespace psm::diagnose;

namespace psm::handshake::gun
{

    namespace net = boost::asio;
    namespace ssl = net::ssl;

    auto scheme::name() const noexcept -> std::string_view
    {
        return "gun";
    }

    auto scheme::active(const psm::settings &cfg) const noexcept -> bool
    {
        return cfg.stealth.gun.enabled();
    }

    auto scheme::snis(const psm::settings &cfg) const
        -> memory::vector<memory::string>
    {
        return make_sni_list(cfg.stealth.gun.server_names);
    }

    auto scheme::guess(const psm::settings &cfg) const -> verify_result
    {
        return {
            .score = 100,
            .solo_flag = 0,
            .note = "gun: rely on SNI match"};
    }

    auto scheme::handshake(handshake::handshake_context ctx)
        -> net::awaitable<handshake::handshake_result>
    {
        handshake::handshake_result result;

        if (!ctx.session)
        {
            result.error = fault::code::not_supported;
            co_return result;
        }

        if (!ctx.session->worker->process->ssl)
        {
            diagnose::warn(prefix_, "No SSL context configured");
            result.error = fault::code::not_supported;
            co_return result;
        }

        const auto &cfg = ctx.session->worker->process->cfg->stealth.gun;

        auto raw = connect::peel(std::move(ctx.transport));
        if (!raw)
        {
            diagnose::debug(prefix_, "Cannot unwrap transport layers");
            result.error = fault::code::not_supported;
            co_return result;
        }

        // 独立 SSL_CTX（ALPN 强制 h2）
        auto gun_ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv13);
        {
            auto &src_ctx = *ctx.session->worker->process->ssl;
            auto *src_native = src_ctx.native_handle();
            auto *dst_native = gun_ssl_ctx->native_handle();

            SSL_CTX_use_certificate(dst_native, SSL_CTX_get0_certificate(src_native));
            SSL_CTX_use_PrivateKey(dst_native, SSL_CTX_get0_privatekey(src_native));
            SSL_CTX_set_min_proto_version(dst_native, SSL_CTX_get_min_proto_version(src_native));
            SSL_CTX_set_max_proto_version(dst_native, SSL_CTX_get_max_proto_version(src_native));
            SSL_CTX_set_session_cache_mode(dst_native, SSL_CTX_get_session_cache_mode(src_native));

            // ALPN 仅选择 h2
            SSL_CTX_set_alpn_select_cb(dst_native,
                [](SSL *, const unsigned char **out, unsigned char *outlen,
                   const unsigned char *in, unsigned int inlen, void *) -> int
                {
                    if (SSL_select_next_proto(const_cast<unsigned char **>(out), outlen,
                        reinterpret_cast<const unsigned char *>("\x2h2"), 3,
                        in, inlen) == OPENSSL_NPN_NEGOTIATED)
                    {
                        return SSL_TLSEXT_ERR_OK;
                    }
                    return SSL_TLSEXT_ERR_NOACK;
                }, nullptr);
        }

        auto preread_span = std::span<const std::byte>(ctx.preread.data(), ctx.preread.size());
        auto clean_inbound = psm::transport::wrap_with_preview(std::move(raw), preread_span);

        auto [ssl_ec, ssl_stream, recovered] = co_await psm::transport::encrypted::ssl_handshake(
            std::move(clean_inbound), *gun_ssl_ctx);

        if (fault::failed(ssl_ec) || !ssl_stream)
        {
            ctx.transport = std::move(recovered);
            result.error = ssl_ec;
            diagnose::debug(prefix_, "TLS handshake failed: {}", fault::describe(ssl_ec));
            co_return result;
        }

        // 校验 ALPN h2
        const std::uint8_t *alpn = nullptr;
        std::uint32_t alpn_len = 0;
        SSL_get0_alpn_selected(ssl_stream->native_handle(), &alpn, &alpn_len);
        if (!alpn || alpn_len != 2 || alpn[0] != 'h' || alpn[1] != '2')
        {
            diagnose::debug(prefix_, "ALPN did not select h2");
            result.detected = psm::connect::protocol_type::tls;
            result.transport = std::make_shared<psm::transport::encrypted>(ssl_stream);
            co_return result;
        }

        auto encrypted_trans = std::make_shared<psm::transport::encrypted>(ssl_stream);

        // 建立 gun HTTP/2 会话并等待流匹配
        auto gun_session = make_session(encrypted_trans, cfg, memory::current_resource(), prefix_);
        gun_session->start();

        auto gun_transport = co_await gun_session->wait_transport();
        if (!gun_transport)
        {
            diagnose::debug(prefix_, "gun: no stream matched");
            result.detected = psm::connect::protocol_type::tls;
            result.transport = std::move(encrypted_trans);
            gun_session->close();
            co_return result;
        }

        diagnose::debug(prefix_, "gun: stream established");

        // 返回 gun 传输层，executor 二次探测内层协议
        result.transport = std::static_pointer_cast<psm::transport::transmission>(gun_transport);
        result.detected = psm::connect::protocol_type::unknown;
        result.error = fault::code::success;
        co_return result;
    }

} // namespace psm::handshake::gun

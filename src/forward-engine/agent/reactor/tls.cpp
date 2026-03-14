#include <forward-engine/agent/reactor/tls.hpp>

namespace ngx::agent::reactor::tls
{
    void configure(ssl::context &ctx, std::string_view cert, std::string_view key)
    {
        const std::string cert_path(cert.data(), cert.size());
        const std::string key_path(key.data(), key.size());

        boost::system::error_code ec;
        ctx.use_certificate_chain_file(cert_path, ec);
        if (ec)
        {
            trace::error("ssl cert load failed: {}", ec.message());
            throw abnormal::protocol("ssl cert load failed: {}", ec.message());
        }

        ctx.use_private_key_file(key_path, ssl::context::pem, ec);
        if (ec)
        {
            trace::error("ssl key load failed: {}", ec.message());
            throw abnormal::protocol("ssl key load failed: {}", ec.message());
        }

        SSL_CTX_set_grease_enabled(ctx.native_handle(), 1);
        constexpr unsigned char alpn[] = "\x02h2\x08http/1.1";
        SSL_CTX_set_alpn_protos(ctx.native_handle(), alpn, sizeof(alpn) - 1);
    }

    auto make(const agent::config &cfg)
        -> context_ptr
    {
        const auto &cert = cfg.certificate.cert;
        const auto &key = cfg.certificate.key;
        if (cert.empty() || key.empty())
        {
            trace::warn("No certificate or key provided, running in plain HTTP mode");
            return {};
        }

        auto ctx = std::make_shared<ssl::context>(ssl::context::tls);
        try
        {
            configure(*ctx, std::string_view(cert.data(), cert.size()), std::string_view(key.data(), key.size()));
            return ctx;
        }
        catch (const abnormal::protocol &)
        {
            throw;
        }
        catch (const std::exception &e)
        {
            trace::error("SSL init failed: {}", e.what());
            throw;
        }
    }
} // namespace ngx::agent::reactor::tls

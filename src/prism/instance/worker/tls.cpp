#include <prism/instance/worker/tls.hpp>
#include <prism/trace.hpp>
#include <prism/exception.hpp>
#include <cstdint>

namespace psm::instance::worker::tls
{
    void configure(ssl::context &ctx, std::string_view cert, std::string_view key)
    {
        const std::string cert_path(cert.data(), cert.size());
        const std::string key_path(key.data(), key.size());

        boost::system::error_code ec;

        // 加载证书链文件
        ctx.use_certificate_chain_file(cert_path, ec);
        if (ec)
        {
            trace::error("ssl cert load failed: {}", ec.message());
            throw exception::protocol("ssl cert load failed: {}", ec.message());
        }

        // 加载私钥文件
        ctx.use_private_key_file(key_path, ssl::context::pem, ec);
        if (ec)
        {
            trace::error("ssl key load failed: {}", ec.message());
            throw exception::protocol("ssl key load failed: {}", ec.message());
        }

        // 获取原生 SSL_CTX 指针
        auto *native = ctx.native_handle();

        // 设置 ALPN 协议回调（服务端 API）
        // 根据客户端提供的 ALPN 列表选择协议，支持 h2 和 http/1.1
        // 注意：SSL_CTX_set_alpn_protos 是客户端 API，服务端应使用 SSL_CTX_set_alpn_select_cb
        SSL_CTX_set_alpn_select_cb(native,
            [](SSL*, const unsigned char **out, unsigned char *outlen,
               const unsigned char *in, unsigned int inlen, void*) -> int {
                // 服务端支持的协议列表：h2 + http/1.1
                constexpr std::uint8_t server_protos[] = "\x02h2\x08http/1.1";
                if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen,
                        server_protos, sizeof(server_protos) - 1,
                        in, inlen) == OPENSSL_NPN_NEGOTIATED)
                    return SSL_TLSEXT_ERR_OK;
                return SSL_TLSEXT_ERR_NOACK;
            }, nullptr);

        // 设置协议版本范围：TLS 1.2 ~ TLS 1.3
        SSL_CTX_set_min_proto_version(native, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(native, TLS1_3_VERSION);

        // 启用 Session 缓存（服务端）
        // 允许客户端复用之前的 TLS 会话，减少握手开销
        SSL_CTX_set_session_cache_mode(native, SSL_SESS_CACHE_SERVER);
        SSL_CTX_sess_set_cache_size(native, 2048);      // 缓存最多 2048 个会话
        SSL_CTX_set_timeout(native, 300);               // 会话超时 5 分钟

        // 启用 Session Ticket（无状态会话复用）
        // 客户端可以携带之前的 ticket，服务端无需维护会话状态

        // 设置加密套件（性能优化）
        // BoringSSL 统一使用 SSL_CTX_set_cipher_list 管理 TLS 1.2 和 TLS 1.3 套件，
        // 不提供 OpenSSL 1.1.1+ 的 SSL_CTX_set_ciphersuites API。
        // TLS 1.3 套件（AES-GCM / ChaCha20-Poly1305）
        // TLS 1.2 套件（优先 AES-GCM 有硬件加速，ChaCha20 移动设备友好）
        SSL_CTX_set_cipher_list(native,
            "TLS_AES_128_GCM_SHA256:"
            "TLS_AES_256_GCM_SHA384:"
            "TLS_CHACHA20_POLY1305_SHA256:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305"
        );

        // 禁用重协商（BoringSSL 默认禁用，此为防御性标记）
        SSL_CTX_set_options(native, SSL_OP_NO_RENEGOTIATION);

        // 设置 ECDHE 曲线（密钥交换）
        SSL_CTX_set1_curves_list(native, "X25519:P-256:P-384");

        // 禁用压缩（安全考虑，CRIME 攻击）
        SSL_CTX_set_options(native, SSL_OP_NO_COMPRESSION);
    }

    auto make(const instance::config &cfg)
        -> shared_context
    {
        const auto &cert = cfg.cert.cert;
        const auto &key = cfg.cert.key;

        // 如果未配置证书或密钥，返回空指针表示运行在纯 HTTP 模式
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
        catch (const exception::protocol &)
        {
            throw;
        }
        catch (const std::exception &e)
        {
            trace::error("SSL init failed: {}", e.what());
            throw;
        }
    }
} // namespace psm::instance::worker::tls

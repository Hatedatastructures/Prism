/**
 * @file XhttpE2E.cpp
 * @brief XHTTP stream-one 端到端测试
 * @details 模拟 XHTTP 客户端：
 *          1. TLS 握手（ALPN h2）
 *          2. HTTP/2 POST /（stream-one）
 *          3. 请求体发送数据 → 服务端响应 200 + 数据回显
 *          4. 客户端验证回显
 */

#include <prism/foundation/foundation.hpp>
#include <prism/handshake/xhttp/session.hpp>
#include <prism/net/connection/dialer/dialer.hpp>
#include <prism/net/transport/encrypted.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/net/transport/adapter/connector.hpp>

#include <nghttp2/nghttp2.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include <gtest/gtest.h>

#include <memory>

namespace
{
    namespace xhttp = psm::handshake::xhttp;
    namespace net = boost::asio;
    using tcp = net::ip::tcp;
    using connector = psm::transport::connector;
    using ssl_stream_t = net::ssl::stream<connector>;

    void configure_self_signed(net::ssl::context &ctx)
    {
        auto *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY *pkey = nullptr;
        if (pkey_ctx && EVP_PKEY_keygen_init(pkey_ctx) > 0 && EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) > 0)
            EVP_PKEY_keygen(pkey_ctx, &pkey);
        EVP_PKEY_CTX_free(pkey_ctx);
        ASSERT_NE(pkey, nullptr);

        auto *x509 = X509_new();
        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 3600 * 24);

        auto *name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>("xhttp-e2e"), -1, -1, 0);
        X509_set_subject_name(x509, name);
        X509_set_issuer_name(x509, name);
        X509_NAME_free(name);

        X509_set_pubkey(x509, pkey);
        X509_sign(x509, pkey, EVP_sha256());

        SSL_CTX_use_certificate(ctx.native_handle(), x509);
        SSL_CTX_use_PrivateKey(ctx.native_handle(), pkey);

        X509_free(x509);
        EVP_PKEY_free(pkey);
    }

    struct client_ctx
    {
        nghttp2_session *session{nullptr};
        std::vector<std::byte> received;
        std::vector<std::byte> outbound;
        bool got_200{false};
    };

    auto on_client_send(nghttp2_session *, const uint8_t *data, const size_t len, int, void *user_data) -> ssize_t
    {
        auto *ctx = static_cast<client_ctx *>(user_data);
        ctx->outbound.insert(ctx->outbound.end(),
                             reinterpret_cast<const std::byte *>(data),
                             reinterpret_cast<const std::byte *>(data) + len);
        return static_cast<ssize_t>(len);
    }

    auto on_client_header(nghttp2_session *, const nghttp2_frame *frame, const uint8_t *name,
                          const size_t namelen, const uint8_t *value, const size_t valuelen,
                          uint8_t, void *user_data) -> int
    {
        auto *ctx = static_cast<client_ctx *>(user_data);
        if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
        {
            const std::string_view n(reinterpret_cast<const char *>(name), namelen);
            const std::string_view v(reinterpret_cast<const char *>(value), valuelen);
            if (n == ":status" && v == "200")
                ctx->got_200 = true;
        }
        return 0;
    }

    auto on_client_data(nghttp2_session *, uint8_t, const int32_t, const uint8_t *data,
                        const size_t len, void *user_data) -> int
    {
        auto *ctx = static_cast<client_ctx *>(user_data);
        ctx->received.insert(ctx->received.end(),
                             reinterpret_cast<const std::byte *>(data),
                             reinterpret_cast<const std::byte *>(data) + len);
        return 0;
    }

    struct data_source
    {
        const std::vector<std::byte> *buf;
        std::size_t offset{0};
    };

    auto source_read_cb(nghttp2_session *, int32_t, uint8_t *buf, const size_t length,
                        uint32_t *data_flags, nghttp2_data_source *source, void *) -> ssize_t
    {
        auto *ds = static_cast<data_source *>(source->ptr);
        const auto remaining = ds->buf->size() - ds->offset;
        if (remaining == 0)
        {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF | NGHTTP2_DATA_FLAG_NO_END_STREAM;
            return 0;
        }
        const auto to_copy = std::min(length, remaining);
        std::memcpy(buf, ds->buf->data() + ds->offset, to_copy);
        ds->offset += to_copy;
        return static_cast<ssize_t>(to_copy);
    }

    net::awaitable<void> DoXhttpClient(std::shared_ptr<ssl_stream_t> ssl_stream,
                                       const std::string &payload, std::shared_ptr<bool> ok)
    {
        boost::system::error_code hs_ec;
        co_await ssl_stream->async_handshake(net::ssl::stream_base::client,
                                             net::redirect_error(net::use_awaitable, hs_ec));
        if (hs_ec)
        {
            *ok = false;
            co_return;
        }

        client_ctx ctx;
        nghttp2_session_callbacks *callbacks = nullptr;
        nghttp2_session_callbacks_new(&callbacks);
        nghttp2_session_callbacks_set_send_callback(callbacks, on_client_send);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_client_header);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_client_data);
        nghttp2_session_client_new(&ctx.session, callbacks, &ctx);
        nghttp2_session_callbacks_del(callbacks);

        nghttp2_submit_settings(ctx.session, NGHTTP2_FLAG_NONE, nullptr, 0);
        std::array<nghttp2_nv, 3> nva{};
        const std::string method = "POST";
        const std::string path = "/";
        const std::string authority = "example.com";
        nva[0] = {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":method")),
                  const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(method.data())),
                  7, method.size(), NGHTTP2_NV_FLAG_NONE};
        nva[1] = {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":path")),
                  const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(path.data())),
                  5, path.size(), NGHTTP2_NV_FLAG_NONE};
        nva[2] = {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":authority")),
                  const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(authority.data())),
                  10, authority.size(), NGHTTP2_NV_FLAG_NONE};

        std::vector<std::byte> body;
        for (const auto c : payload)
            body.push_back(static_cast<std::byte>(c));

        std::unique_ptr<data_source> src = std::make_unique<data_source>(data_source{&body, 0});
        nghttp2_data_provider dp;
        dp.source.ptr = src.get();
        dp.read_callback = source_read_cb;
        const auto stream_id = nghttp2_submit_request(ctx.session, nullptr, nva.data(), nva.size(),
                                                      &dp, &ctx);
        if (stream_id < 0)
        {
            *ok = false;
            nghttp2_session_del(ctx.session);
            co_return;
        }

        ctx.outbound.clear();
        if (nghttp2_session_send(ctx.session) != 0)
        {
            *ok = false;
            nghttp2_session_del(ctx.session);
            co_return;
        }
        if (!ctx.outbound.empty())
        {
            co_await ssl_stream->async_write_some(net::buffer(ctx.outbound.data(), ctx.outbound.size()),
                                                  net::redirect_error(net::use_awaitable, hs_ec));
            if (hs_ec)
            {
                *ok = false;
                nghttp2_session_del(ctx.session);
                co_return;
            }
        }

        std::array<std::byte, 8192> buf{};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (ctx.received.size() < payload.size() && std::chrono::steady_clock::now() < deadline)
        {
            std::error_code r_ec;
            const auto n = co_await ssl_stream->async_read_some(net::buffer(buf.data(), buf.size()),
                                                                net::redirect_error(net::use_awaitable, hs_ec));
            if (hs_ec || n == 0)
                break;
            if (nghttp2_session_mem_recv(ctx.session,
                                         reinterpret_cast<const uint8_t *>(buf.data()), n) < 0)
                break;
            if (!ctx.outbound.empty())
            {
                auto pending = std::move(ctx.outbound);
                ctx.outbound.clear();
                co_await ssl_stream->async_write_some(net::buffer(pending.data(), pending.size()),
                                                      net::redirect_error(net::use_awaitable, hs_ec));
                if (hs_ec)
                    break;
            }
        }

        *ok = ctx.got_200
            && ctx.received.size() >= payload.size()
            && std::string_view(reinterpret_cast<const char *>(ctx.received.data()), payload.size()) == payload;

        nghttp2_session_del(ctx.session);
        co_return;
    }

    net::awaitable<void> DoXhttpServer(psm::transport::shared_transmission raw_trans,
                                       net::ssl::context &ssl_ctx, const std::string &payload,
                                       std::shared_ptr<bool> server_ok)
    {
        auto [ssl_ec, ssl_stream, recovered] = co_await psm::transport::encrypted::ssl_handshake(
            std::move(raw_trans), ssl_ctx);
        if (psm::fault::failed(ssl_ec) || !ssl_stream)
        {
            *server_ok = false;
            co_return;
        }

        auto encrypted_trans = std::make_shared<psm::transport::encrypted>(ssl_stream);

        xhttp::config cfg;
        cfg.server_names.push_back(psm::memory::string("example.com"));

        auto xh_session = xhttp::make_session(encrypted_trans, cfg, psm::memory::current_resource(), nullptr);
        xh_session->start();

        auto matched = co_await xh_session->wait_transport();
        if (!matched)
        {
            *server_ok = false;
            co_return;
        }

        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        const auto n = co_await matched->async_read_some(buf, ec);
        if (ec || n == 0)
        {
            *server_ok = false;
            co_return;
        }

        std::error_code w_ec;
        co_await matched->async_write_some(std::span<const std::byte>(buf.data(), n), w_ec);
        *server_ok = !w_ec;

        xh_session->close();
        co_return;
    }
} // namespace

TEST(XhttpE2E, StreamOneEcho)
{
    net::io_context ioc;

    net::ssl::context ssl_ctx(net::ssl::context::tlsv13);
    ssl_ctx.set_options(net::ssl::context::default_workarounds);
    configure_self_signed(ssl_ctx);

    net::ssl::context client_ctx(net::ssl::context::tlsv13);
    client_ctx.set_verify_mode(net::ssl::verify_none);

    tcp::acceptor acceptor(ioc, tcp::endpoint(net::ip::make_address("127.0.0.1"), 0));
    const auto ep = acceptor.local_endpoint();

    psm::transport::shared_transmission server_raw;
    std::shared_ptr<ssl_stream_t> client_ssl;
    auto pair_ready = std::make_shared<bool>(false);

    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        auto sock = co_await acceptor.async_accept(net::use_awaitable);
        server_raw = psm::transport::make_reliable(std::move(sock));
        *pair_ready = true;
    }, net::detached);
    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        tcp::socket sock(ioc);
        co_await sock.async_connect(ep, net::use_awaitable);
        auto trans = psm::transport::make_reliable(std::move(sock));
        client_ssl = std::make_shared<ssl_stream_t>(connector(trans), client_ctx);
    }, net::detached);

    const std::string payload = "xhttp stream-one echo";
    auto client_ok = std::make_shared<bool>(false);
    auto server_ok = std::make_shared<bool>(false);

    net::co_spawn(ioc, [&]() -> net::awaitable<void>
    {
        while (!*pair_ready || !client_ssl)
        {
            net::steady_timer t(ioc);
            t.expires_after(std::chrono::milliseconds(10));
            co_await t.async_wait(net::use_awaitable);
        }
        net::co_spawn(ioc, DoXhttpClient(client_ssl, payload, client_ok), net::detached);
        net::co_spawn(ioc, DoXhttpServer(server_raw, ssl_ctx, payload, server_ok), net::detached);

        net::steady_timer done(ioc);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
        while ((!*client_ok || !*server_ok) && std::chrono::steady_clock::now() < deadline)
        {
            done.expires_after(std::chrono::milliseconds(20));
            co_await done.async_wait(net::use_awaitable);
        }
        ioc.stop();
    }, net::detached);

    ioc.run();
    EXPECT_TRUE(*server_ok) << "xhttp: server echo";
    EXPECT_TRUE(*client_ok) << "xhttp: client verified 200 + echo";
}

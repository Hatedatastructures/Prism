/**
 * @file QuicE2E.cpp
 * @brief QUIC 握手回环测试
 * @details 本机 UDP socket pair + ngtcp2 server/client：
 *          1. 服务端 quic::server（自签名 TLS）
 *          2. 客户端 quic::client（verify none）
 *          3. 双向驱动握手 → 双方握手完成
 *          4. 客户端开流发数据 → 服务端流接收回调验证
 */

#include <prism/diagnose/log.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/net/transport/quic/server.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace quic = psm::quic;
    namespace net = boost::asio;
    using udp = net::ip::udp;

    void configure_self_signed(net::ssl::context &ctx)
    {
        auto *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY *pkey = nullptr;
        if (pkey_ctx && EVP_PKEY_keygen_init(pkey_ctx) > 0 &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) > 0)
        {
            EVP_PKEY_keygen(pkey_ctx, &pkey);
        }
        EVP_PKEY_CTX_free(pkey_ctx);
        ASSERT_NE(pkey, nullptr);

        auto *x509 = X509_new();
        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 3600 * 24);

        auto *name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>("quic-e2e"), -1, -1, 0);
        X509_set_subject_name(x509, name);
        X509_set_issuer_name(x509, name);
        X509_NAME_free(name);

        X509_set_pubkey(x509, pkey);
        X509_sign(x509, pkey, EVP_sha256());

        SSL_CTX_use_certificate(ctx.native_handle(), x509);
        SSL_CTX_use_PrivateKey(ctx.native_handle(), pkey);
        // QUIC TLS 强制 ALPN：服务端选择 h3
        SSL_CTX_set_alpn_select_cb(
            ctx.native_handle(),
            [](SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
               unsigned int inlen, void *) -> int
            {
                if (SSL_select_next_proto(const_cast<unsigned char **>(out), outlen,
                                          reinterpret_cast<const unsigned char *>("\x2h3"), 3, in,
                                          inlen) == OPENSSL_NPN_NEGOTIATED)
                {
                    return SSL_TLSEXT_ERR_OK;
                }
                return SSL_TLSEXT_ERR_NOACK;
            },
            nullptr);

        X509_free(x509);
        EVP_PKEY_free(pkey);
    }
} // namespace

TEST(QuicE2E, HandshakeAndStreamEcho)
{
    psm::diagnose::config trace_cfg;
    trace_cfg.log_level = "debug";
    trace_cfg.enable_console = true;
    trace_cfg.enable_file = false;
    psm::diagnose::init(trace_cfg);

    net::io_context ioc;

    // 服务端 SSL 上下文（自签名）
    net::ssl::context ssl_ctx(net::ssl::context::tlsv13);
    ssl_ctx.set_options(net::ssl::context::default_workarounds);
    configure_self_signed(ssl_ctx);
    // 客户端 SSL 上下文（不校验证书）
    net::ssl::context client_ctx(net::ssl::context::tlsv13);
    client_ctx.set_verify_mode(net::ssl::verify_none);
    // QUIC TLS 强制 ALPN：客户端声明 h3
    static const unsigned char h3_alpn[] = {0x02, 'h', '3'};
    SSL_CTX_set_alpn_protos(client_ctx.native_handle(), h3_alpn, sizeof(h3_alpn));

    // UDP socket pair：server_sock 绑 127.0.0.1:0，client_sock 也绑 127.0.0.1:0
    const auto loopback = net::ip::address_v4::loopback();
    auto server_sock = std::make_shared<udp::socket>(ioc, udp::endpoint(loopback, 0));
    auto client_sock = std::make_shared<udp::socket>(ioc, udp::endpoint(loopback, 0));
    const auto server_ep = server_sock->local_endpoint();

    auto server_ok = std::make_shared<bool>(false);
    auto client_ok = std::make_shared<bool>(false);
    auto stream_data_ok = std::make_shared<bool>(false);
    auto server_pkts = std::make_shared<std::size_t>(0);
    auto client_pkts = std::make_shared<std::size_t>(0);

    // 服务端
    auto qserver = quic::make_server(quic::server_options{
        .executor = ioc.get_executor(),
        .peer = client_sock->local_endpoint(),
        .udp = server_sock,
        .ssl_ctx = ssl_ctx.native_handle(),
        .mr = psm::memory::current_resource(),
        .prefix = std::make_shared<psm::diagnose::context>(),
    });
    qserver->on_handshake_complete = [server_ok]() { *server_ok = true; };
    qserver->on_stream = [qserver, stream_data_ok](quic::shared_stream st)
    {
        *stream_data_ok = true;
        // 服务器写回测试：先写 24 字节再写 34 字节
        net::co_spawn(
            st->executor(),
            [qserver, st]() -> net::awaitable<void>
            {
                std::array<std::byte, 1024> buf{};
                std::error_code ec;
                const auto n = co_await st->async_read_some(std::span<std::byte>(buf), ec);
                if (ec || n == 0)
                {
                    co_return;
                }
                std::string first(24, 'A');
                co_await st->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(first.data()),
                                               first.size()),
                    ec);
                std::string second(34, 'B');
                co_await st->async_write_some(
                    std::span<const std::byte>(reinterpret_cast<const std::byte *>(second.data()),
                                               second.size()),
                    ec);
            },
            net::detached);
    };

    // 客户端
    auto qclient = quic::make_client(quic::client_options{
        .executor = ioc.get_executor(),
        .peer = server_ep,
        .udp = client_sock,
        .ssl_ctx = client_ctx.native_handle(),
        .host = "quic-e2e",
        .mr = psm::memory::current_resource(),
        .prefix = std::make_shared<psm::diagnose::context>(),
    });
    qclient->on_handshake_complete = [client_ok]() { *client_ok = true; };
    qclient->on_stream_data = [](std::int64_t sid, std::span<const std::byte> data)
    {
        std::fprintf(stderr, "[quic e2e client] stream %lld got %zu bytes:", (long long)sid, data.size());
        for (std::size_t i = 0; i < std::min<std::size_t>(data.size(), 40); ++i)
        {
            std::fprintf(stderr, " %02x", static_cast<unsigned char>(data[i]));
        }
        std::fprintf(stderr, "\n");
        fflush(stderr);
    };

    // UDP 转发循环：把各自收到的数据报喂给对方连接
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            std::array<std::byte, 2048> buf{};
            while (true)
            {
                boost::system::error_code ec;
                udp::endpoint from;
                const auto n = co_await client_sock->async_receive_from(
                    net::buffer(buf.data(), buf.size()), from, net::redirect_error(net::use_awaitable, ec));
                if (ec || n == 0)
                {
                    break;
                }
                *client_pkts += 1;
                co_await qclient->handle_datagram(from, std::span<const std::byte>(buf.data(), n));
            }
        },
        net::detached);
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            std::array<std::byte, 2048> buf{};
            while (true)
            {
                boost::system::error_code ec;
                udp::endpoint from;
                const auto n = co_await server_sock->async_receive_from(
                    net::buffer(buf.data(), buf.size()), from, net::redirect_error(net::use_awaitable, ec));
                if (ec || n == 0)
                {
                    break;
                }
                *server_pkts += 1;
                co_await qserver->handle_datagram(from, std::span<const std::byte>(buf.data(), n));
            }
        },
        net::detached);

    // 主流程：启动双方 → 客户端发 initial → 等握手完成 → 开流发数据
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            qserver->start();
            qclient->start();

            // 客户端发出 initial 包
            co_await qclient->flush_handshake();

            net::steady_timer t(ioc);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while ((!*server_ok || !*client_ok) && std::chrono::steady_clock::now() < deadline)
            {
                t.expires_after(std::chrono::milliseconds(10));
                co_await t.async_wait(net::use_awaitable);
                co_await qclient->flush_handshake();
                co_await qserver->flush_handshake();
            }

            // 握手完成后：客户端开流发数据
            if (*server_ok && *client_ok)
            {
                const auto sid = qclient->open_stream();
                const std::string payload = "quic stream payload";
                co_await qclient->write_stream_data(
                    sid, std::span<const std::byte>(reinterpret_cast<const std::byte *>(payload.data()),
                                                    payload.size()));
                // 等待服务器回写
                const auto d3 = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                while (std::chrono::steady_clock::now() < d3)
                {
                    t.expires_after(std::chrono::milliseconds(10));
                    co_await t.async_wait(net::use_awaitable);
                    co_await qclient->flush_handshake();
                    co_await qserver->flush_handshake();
                }
                std::fprintf(stderr, "[e2e quic] server echo done\n");
                fflush(stderr);
                // 等待服务端流回调
                const auto d2 = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                while (!*stream_data_ok && std::chrono::steady_clock::now() < d2)
                {
                    t.expires_after(std::chrono::milliseconds(10));
                    co_await t.async_wait(net::use_awaitable);
                    co_await qclient->flush_handshake();
                    co_await qserver->flush_handshake();
                }
            }

            ioc.stop();
        },
        net::detached);

    ioc.run();

    EXPECT_TRUE(*server_ok) << "quic: server handshake completed";
    EXPECT_TRUE(*client_ok) << "quic: client handshake completed";
    EXPECT_TRUE(*stream_data_ok) << "quic: stream open callback";
}

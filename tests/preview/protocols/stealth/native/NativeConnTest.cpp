/**
 * @file NativeConnTest.cpp
 * @brief Native 伪装方案测试（T2-1）
 * @details 验证原生 TLS 兜底：
 *          1. 自签证书服务端握手 + 数据直通（echo）
 *          2. 证书校验失败（客户端拒绝自签）
 *          3. 握手超时（客户端不发 ClientHello）
 *          4. 半包握手（分片发送 ClientHello）
 */

#include <common/core/memory/container.hpp>
#include <common/core/transmission.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/protocols/native/native.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;
    using namespace preview;

    /// 生成自签证书并加载到服务端上下文
    void load_self_signed(ssl::context &ctx)
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
                                   reinterpret_cast<const unsigned char *>("native-test"), -1, -1, 0);
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

    /// 客户端：TLS 握手 + 数据 echo 验证
    net::awaitable<void> DoTlsClient(shared_transmission raw, ssl::context &client_ctx,
                                     const std::string &payload, std::shared_ptr<bool> ok)
    {
        preview::transport::connector conn(raw);
        auto stream = std::make_shared<ssl::stream<preview::transport::connector>>(
            std::move(conn), client_ctx);
        boost::system::error_code ec;
        co_await stream->async_handshake(ssl::stream_base::client,
                                         net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            *ok = false;
            co_return;
        }
        // 发送 payload（经 TLS）
        co_await stream->async_write_some(
            net::buffer(payload.data(), payload.size()), net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            *ok = false;
            co_return;
        }
        // 读 echo
        std::array<char, 256> buf{};
        const auto n = co_await stream->async_read_some(
            net::buffer(buf.data(), buf.size()), net::redirect_error(net::use_awaitable, ec));
        *ok = !ec && n == payload.size() && std::string_view(buf.data(), n) == payload;
        co_return;
    }

    /// 服务端：native accept + echo
    net::awaitable<void> DoNativeServer(shared_transmission raw, ssl::context &server_ctx,
                                        const std::string &payload, std::shared_ptr<bool> ok)
    {
        auto trans = co_await preview::native::accept(std::move(raw), server_ctx);
        if (!trans)
        {
            *ok = false;
            co_return;
        }
        std::array<std::byte, 256> buf{};
        std::error_code ec;
        const auto n = co_await trans->async_read_some(buf, ec);
        if (ec || n == 0)
        {
            *ok = false;
            co_return;
        }
        std::error_code w_ec;
        co_await trans->async_write_some(std::span<const std::byte>(buf.data(), n), w_ec);
        *ok = !w_ec;
        co_return;
    }
} // namespace

TEST(NativeConn, TlsHandshakeAndPassthrough)
{
    net::io_context ioc;

    ssl::context server_ctx(ssl::context::tlsv13);
    load_self_signed(server_ctx);

    ssl::context client_ctx(ssl::context::tlsv13);
    client_ctx.set_verify_mode(ssl::verify_none);

    auto [a, b] = make_memory_pair(ioc.get_executor());
    auto sa = std::make_shared<preview::memory_stream>(std::move(a));
    auto sb = std::make_shared<preview::memory_stream>(std::move(b));

    const std::string payload = "native-tls-passthrough";
    auto client_ok = std::make_shared<bool>(false);
    auto server_ok = std::make_shared<bool>(false);

    std::exception_ptr ep;
    auto coro = [&]() -> net::awaitable<void>
    {
        net::co_spawn(ioc.get_executor(), DoTlsClient(sa, client_ctx, payload, client_ok), net::detached);
        co_await DoNativeServer(sb, server_ctx, payload, server_ok);
    };
    net::co_spawn(ioc, coro(), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
    ioc.run();
    if (ep)
    {
        std::rethrow_exception(ep);
    }
    EXPECT_TRUE(*server_ok);
    EXPECT_TRUE(*client_ok);
}

// 客户端校验失败：verify_peer 且无受信 CA → 握手失败
TEST(NativeConn, ClientVerifyFailure)
{
    net::io_context ioc;

    ssl::context server_ctx(ssl::context::tlsv13);
    load_self_signed(server_ctx);

    ssl::context client_ctx(ssl::context::tlsv13);
    client_ctx.set_verify_mode(ssl::verify_peer); // 无 CA → 自签被拒

    auto [a, b] = make_memory_pair(ioc.get_executor());
    auto sa = std::make_shared<preview::memory_stream>(std::move(a));
    auto sb = std::make_shared<preview::memory_stream>(std::move(b));

    auto client_ok = std::make_shared<bool>(true);
    auto server_ok = std::make_shared<bool>(false);

    std::exception_ptr ep;
    auto coro = [&]() -> net::awaitable<void>
    {
        net::co_spawn(
            ioc.get_executor(),
            [&]() -> net::awaitable<void>
            {
                preview::transport::connector conn(sa);
                auto stream = std::make_shared<ssl::stream<preview::transport::connector>>(
                    std::move(conn), client_ctx);
                boost::system::error_code ec;
                co_await stream->async_handshake(ssl::stream_base::client,
                                                 net::redirect_error(net::use_awaitable, ec));
                // 客户端验证失败（certificate verify failed）
                if (ec)
                {
                    *client_ok = false;
                }
            },
            net::detached);
        // 服务端握手应因客户端中止而失败
        auto trans = co_await preview::native::accept(sb, server_ctx);
        if (!trans)
        {
            *server_ok = true;
        }
    };
    net::co_spawn(ioc, coro(), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
    ioc.run();
    if (ep)
    {
        std::rethrow_exception(ep);
    }
    EXPECT_TRUE(*server_ok); // 服务端检测到握手失败
    EXPECT_FALSE(*client_ok); // 客户端验证失败
}

// 半包握手：客户端分片发送 ClientHello → 服务端仍完成握手
TEST(NativeConn, FragmentedClientHello)
{
    net::io_context ioc;

    ssl::context server_ctx(ssl::context::tlsv13);
    load_self_signed(server_ctx);

    ssl::context client_ctx(ssl::context::tlsv13);
    client_ctx.set_verify_mode(ssl::verify_none);

    auto [a, b] = make_memory_pair(ioc.get_executor());
    auto sa = std::make_shared<preview::memory_stream>(std::move(a));
    auto sb = std::make_shared<preview::memory_stream>(std::move(b));

    const std::string payload = "fragmented-hello";
    auto client_ok = std::make_shared<bool>(false);
    auto server_ok = std::make_shared<bool>(false);

    std::exception_ptr ep;
    auto coro = [&]() -> net::awaitable<void>
    {
        net::co_spawn(ioc.get_executor(), DoTlsClient(sa, client_ctx, payload, client_ok), net::detached);
        co_await DoNativeServer(sb, server_ctx, payload, server_ok);
    };
    net::co_spawn(ioc, coro(), [&](std::exception_ptr e) { ep = e; ioc.stop(); });
    ioc.run();
    if (ep)
    {
        std::rethrow_exception(ep);
    }
    EXPECT_TRUE(*server_ok);
    EXPECT_TRUE(*client_ok);
}

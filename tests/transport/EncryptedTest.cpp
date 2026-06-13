/**
 * @file EncryptedTest.cpp
 * @brief 加密传输层测试
 * @details 测试 encrypted 类的 TLS 握手、读写代理、关闭/取消传播。
 */

#include <gtest/gtest.h>

#include <prism/core/fault/handling.hpp>
#include <prism/core/core.hpp>
#include <prism/net/transport/adapter/connector.hpp>
#include <prism/net/transport/encrypted.hpp>
#include <prism/net/transport/reliable.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <span>

#include "common/MockTransport.hpp"

// ── 加载自签名证书到 ssl::context 的辅助函数 ──

namespace
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;
    using namespace psm::transport;
    using namespace psm::testing;

    void load_self_signed_cert(ssl::context &ctx)
    {
        // 使用 RSA 2048 而非 Ed25519，避免 BoringSSL TLS 1.3
        // "NO_COMMON_SIGNATURE_ALGORITHMS" 错误
        auto *pkey = EVP_PKEY_new();
        auto *bn = BN_new();
        BN_set_word(bn, RSA_F4);
        auto *rsa = RSA_new();
        RSA_generate_key_ex(rsa, 2048, bn, nullptr);
        EVP_PKEY_assign_RSA(pkey, rsa);
        BN_free(bn);

        auto *x509 = X509_new();
        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 3600 * 24);

        auto *name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>("Test"), -1, -1, 0);
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
} // namespace

// ── ssl_handshake: null 入站 ──

TEST(Encrypted, SslHandshakeNullInbound)
{
    net::io_context ioc;
    std::atomic<bool> done{false};
    std::tuple<psm::fault::code, encrypted::shared_stream, shared_transmission> result;

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            ssl::context ctx(ssl::context::tls_server);
            result = co_await encrypted::ssl_handshake(nullptr, ctx);
            done = true;
        },
        net::detached);

    ioc.run();
    EXPECT_TRUE(done);

    auto &[code, stream, recovered] = result;
    EXPECT_EQ(code, psm::fault::code::io_error);
    EXPECT_EQ(stream, nullptr);
    EXPECT_EQ(recovered, nullptr);
}

// ── ssl_handshake: 握手成功（客户端-服务端真实 TLS 握手）──

TEST(Encrypted, SslHandshakeSuccess)
{
    net::io_context ioc;

    net::ip::tcp::acceptor acceptor(ioc, {net::ip::tcp::v4(), 0});
    const auto server_port = acceptor.local_endpoint().port();

    std::atomic<bool> done{false};
    std::tuple<psm::fault::code, encrypted::shared_stream, shared_transmission> result;

    // 服务端协程：接受连接 → ssl_handshake
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto socket = co_await acceptor.async_accept(net::use_awaitable);
            auto inbound = std::make_shared<reliable>(std::move(socket));

            ssl::context ctx(ssl::context::tls_server);
            load_self_signed_cert(ctx);

            result = co_await encrypted::ssl_handshake(
                std::shared_ptr<transmission>(std::move(inbound)), ctx);
            done = true;
        },
        net::detached);

    // 客户端协程：连接 → TLS 客户端握手
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto socket = net::ip::tcp::socket{ioc};
            auto ep = net::ip::tcp::endpoint{net::ip::make_address("127.0.0.1"), server_port};
            co_await socket.async_connect(ep, net::use_awaitable);

            ssl::context ctx(ssl::context::tls_client);
            ctx.set_verify_mode(ssl::context::verify_none);

            ssl::stream<net::ip::tcp::socket> tls_stream{std::move(socket), ctx};
            co_await tls_stream.async_handshake(ssl::stream_base::client, net::use_awaitable);
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(3000));
    EXPECT_TRUE(done);

    auto &[code, stream, recovered] = result;
    EXPECT_TRUE(psm::fault::succeeded(code));
    EXPECT_NE(stream, nullptr);
    EXPECT_EQ(recovered, nullptr);
}

// ── encrypted: transport_type 和 next_layer ──

TEST(Encrypted, TransportTypeAndNextLayer)
{
    net::io_context ioc;
    ssl::context ssl_ctx(ssl::context::tls_client);

    auto mock = std::make_shared<MockTransport>();
    encrypted::connector_type conn(std::move(mock), {});

    auto stream = std::make_shared<encrypted::stream_type>(std::move(conn), ssl_ctx);
    encrypted enc(stream);

    EXPECT_EQ(enc.transport_type(), transmission::type::tcp);
    EXPECT_EQ(enc.next_layer(), nullptr);

    auto &s = enc.stream();
    EXPECT_EQ(&s, stream.get());

    const auto &cs = std::as_const(enc).stream();
    EXPECT_EQ(&cs, stream.get());
}

// ── encrypted: release 转移所有权 ──

TEST(Encrypted, ReleaseOwnership)
{
    net::io_context ioc;
    ssl::context ssl_ctx(ssl::context::tls_client);

    auto mock = std::make_shared<MockTransport>();
    encrypted::connector_type conn(std::move(mock), {});

    auto stream = std::make_shared<encrypted::stream_type>(std::move(conn), ssl_ctx);
    encrypted enc(stream);

    auto &s = enc.stream();
    // stream() 返回引用，解引用 ssl_stream_ 后一定非空（否则 UB）
    // 验证引用有效：地址与 stream 相同
    EXPECT_EQ(&s, stream.get()) << "encrypted::stream() returns reference to internal stream";

    auto released = enc.release();
    EXPECT_EQ(released, stream);
}

// ── encrypted: close 和 cancel 传播（通过握手后的真实连接）──

TEST(Encrypted, CloseAndCancelPropagation)
{
    net::io_context ioc;

    net::ip::tcp::acceptor acceptor(ioc, {net::ip::tcp::v4(), 0});
    const auto port = acceptor.local_endpoint().port();

    std::atomic<bool> server_done{false};
    encrypted::shared_stream server_stream;
    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto socket = co_await acceptor.async_accept(net::use_awaitable);
            auto inbound = std::make_shared<reliable>(std::move(socket));

            ssl::context ctx(ssl::context::tls_server);
            load_self_signed_cert(ctx);

            auto [code, stream, recovered] = co_await encrypted::ssl_handshake(
                std::shared_ptr<transmission>(std::move(inbound)), ctx);
            if (psm::fault::succeeded(code))
            {
                server_stream = stream;
            }
            server_done = true;
        },
        net::detached);

    net::co_spawn(
        ioc,
        [&]() -> net::awaitable<void>
        {
            auto socket = net::ip::tcp::socket{ioc};
            co_await socket.async_connect(
                net::ip::tcp::endpoint{net::ip::make_address("127.0.0.1"), port},
                net::use_awaitable);

            ssl::context ctx(ssl::context::tls_client);
            ctx.set_verify_mode(ssl::context::verify_none);
            ssl::stream<net::ip::tcp::socket> tls_stream{std::move(socket), ctx};
            co_await tls_stream.async_handshake(ssl::stream_base::client, net::use_awaitable);
        },
        net::detached);

    ioc.run_for(std::chrono::milliseconds(3000));
    ASSERT_TRUE(server_done);
    ASSERT_TRUE(server_stream);

    auto enc = make_encrypted(server_stream);
    enc->cancel();
    enc->close();
}

// ── encrypted: executor 返回有效执行器 ──

TEST(Encrypted, ExecutorIsValid)
{
    net::io_context ioc;
    ssl::context ssl_ctx(ssl::context::tls_client);

    auto mock = std::make_shared<MockTransport>();
    encrypted::connector_type conn(std::move(mock), {});

    auto stream = std::make_shared<encrypted::stream_type>(std::move(conn), ssl_ctx);
    encrypted enc(stream);

    auto ex = enc.executor();
    EXPECT_TRUE(ex);
}

// ── make_encrypted 工厂函数 ──

TEST(Encrypted, MakeEncryptedFactory)
{
    net::io_context ioc;
    ssl::context ssl_ctx(ssl::context::tls_client);

    auto mock = std::make_shared<MockTransport>();
    encrypted::connector_type conn(std::move(mock), {});

    auto stream = std::make_shared<encrypted::stream_type>(std::move(conn), ssl_ctx);

    shared_transmission t = make_encrypted(stream);
    ASSERT_TRUE(t);
    EXPECT_EQ(t->transport_type(), transmission::type::tcp);
}

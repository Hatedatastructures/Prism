/**
 * @file EncryptedTest.cpp
 * @brief 加密传输层测试
 * @details 测试 encrypted 类的 TLS 握手、读写代理、关闭/取消传播。
 */

#include <prism/foundation/fault/handling.hpp>
#include <prism/foundation/foundation.hpp>
#include <prism/net/transport/adapter/connector.hpp>
#include <prism/net/transport/encrypted.hpp>
#include <prism/net/transport/reliable.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <span>

#include "TestSupport/Production/ProductionMockTransport.hpp"
#include <gtest/gtest.h>

// ── 加载自签名证书到 ssl::context 的辅助函数 ──

namespace
{
    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    namespace Transport = psm::transport;
    using Psm::Testing::ProductionMockTransport;

    auto LoadSelfSignedCert(Ssl::context &Context) -> void
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
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("Test"),
                                   -1, -1, 0);
        X509_set_subject_name(x509, name);
        X509_set_issuer_name(x509, name);
        X509_NAME_free(name);

        X509_set_pubkey(x509, pkey);
        X509_sign(x509, pkey, EVP_sha256());

        SSL_CTX_use_certificate(Context.native_handle(), x509);
        SSL_CTX_use_PrivateKey(Context.native_handle(), pkey);

        X509_free(x509);
        EVP_PKEY_free(pkey);
    }
} // namespace

// ── ssl_handshake: null 入站 ──

TEST(Encrypted, SslHandshakeNullInbound)
{
    Net::io_context ioc;
    std::atomic<bool> done{false};
    std::tuple<psm::fault::code, Transport::encrypted::shared_stream, Transport::shared_transmission> result;

    Net::co_spawn(
        ioc,
        [&]() -> Net::awaitable<void>
        {
            Ssl::context ctx(Ssl::context::tls_server);
            result = co_await Transport::encrypted::ssl_handshake(nullptr, ctx);
            done = true;
        },
        Net::detached);

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
    Net::io_context ioc;

    Net::ip::tcp::acceptor acceptor(ioc, {Net::ip::tcp::v4(), 0});
    const auto server_port = acceptor.local_endpoint().port();

    std::atomic<bool> done{false};
    std::tuple<psm::fault::code, Transport::encrypted::shared_stream, Transport::shared_transmission> result;

    // 服务端协程：接受连接 → ssl_handshake
    Net::co_spawn(
        ioc,
        [&]() -> Net::awaitable<void>
        {
            auto socket = co_await acceptor.async_accept(Net::use_awaitable);
            auto Inbound = std::make_shared<Transport::reliable>(std::move(socket));

            Ssl::context ctx(Ssl::context::tls_server);
            LoadSelfSignedCert(ctx);

            result =
                co_await Transport::encrypted::ssl_handshake(
                    std::shared_ptr<Transport::transmission>(std::move(Inbound)), ctx);
            done = true;
        },
        Net::detached);

    // 客户端协程：连接 → TLS 客户端握手
    Net::co_spawn(
        ioc,
        [&]() -> Net::awaitable<void>
        {
            auto socket = Net::ip::tcp::socket{ioc};
            auto ep = Net::ip::tcp::endpoint{Net::ip::make_address("127.0.0.1"), server_port};
            co_await socket.async_connect(ep, Net::use_awaitable);

            Ssl::context ctx(Ssl::context::tls_client);
            ctx.set_verify_mode(Ssl::context::verify_none);

            Ssl::stream<Net::ip::tcp::socket> TlsStream{std::move(socket), ctx};
            co_await TlsStream.async_handshake(Ssl::stream_base::client, Net::use_awaitable);
        },
        Net::detached);

    // 完成哨兵：done 或超时（2s）任一先到即停机
    Net::co_spawn(
        ioc,
        [&]() -> Net::awaitable<void>
        {
            Net::steady_timer Timer(ioc);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while (!done && std::chrono::steady_clock::now() < deadline)
            {
                Timer.expires_after(std::chrono::milliseconds(1));
                co_await Timer.async_wait(Net::use_awaitable);
            }
            ioc.stop();
        },
        Net::detached);

    ioc.run();
    EXPECT_TRUE(done);

    auto &[code, stream, recovered] = result;
    EXPECT_TRUE(psm::fault::succeeded(code));
    EXPECT_NE(stream, nullptr);
    EXPECT_EQ(recovered, nullptr);
}

// ── encrypted: transport_type 和 next_layer ──

TEST(Encrypted, TransportTypeAndNextLayer)
{
    Net::io_context ioc;
    Ssl::context SslCtx(Ssl::context::tls_client);

    auto mock = std::make_shared<ProductionMockTransport>();
    Transport::encrypted::connector_type Conn(std::move(mock), {});

    auto Stream = std::make_shared<Transport::encrypted::stream_type>(std::move(Conn), SslCtx);
    Transport::encrypted Encrypted(Stream);

    EXPECT_EQ(Encrypted.transport_type(), Transport::transmission::type::tcp);
    EXPECT_EQ(Encrypted.next_layer(), nullptr);

    auto &StreamReference = Encrypted.stream();
    EXPECT_EQ(&StreamReference, Stream.get());

    const auto &ConstStreamReference = std::as_const(Encrypted).stream();
    EXPECT_EQ(&ConstStreamReference, Stream.get());
}

// ── encrypted: release 转移所有权 ──

TEST(Encrypted, ReleaseOwnership)
{
    Net::io_context ioc;
    Ssl::context SslCtx(Ssl::context::tls_client);

    auto mock = std::make_shared<ProductionMockTransport>();
    Transport::encrypted::connector_type Conn(std::move(mock), {});

    auto Stream = std::make_shared<Transport::encrypted::stream_type>(std::move(Conn), SslCtx);
    Transport::encrypted Encrypted(Stream);

    auto &StreamReference = Encrypted.stream();
    // stream() 返回引用，解引用 ssl_stream_ 后一定非空（否则 UB）
    // 验证引用有效：地址与 stream 相同
    EXPECT_EQ(&StreamReference, Stream.get()) << "encrypted::stream() returns reference to internal stream";

    auto Released = Encrypted.release();
    EXPECT_EQ(Released, Stream);
}

// ── encrypted: close 和 cancel 传播（通过握手后的真实连接）──

TEST(Encrypted, CloseAndCancelPropagation)
{
    Net::io_context ioc;

    Net::ip::tcp::acceptor acceptor(ioc, {Net::ip::tcp::v4(), 0});
    const auto port = acceptor.local_endpoint().port();

    std::atomic<bool> server_done{false};
    Transport::encrypted::shared_stream ServerStream;
    Net::co_spawn(
        ioc,
        [&]() -> Net::awaitable<void>
        {
            auto socket = co_await acceptor.async_accept(Net::use_awaitable);
            auto Inbound = std::make_shared<Transport::reliable>(std::move(socket));

            Ssl::context ctx(Ssl::context::tls_server);
            LoadSelfSignedCert(ctx);

            auto [code, stream, recovered] =
                co_await Transport::encrypted::ssl_handshake(
                    std::shared_ptr<Transport::transmission>(std::move(Inbound)), ctx);
            if (psm::fault::succeeded(code))
            {
                ServerStream = stream;
            }
            server_done = true;
        },
        Net::detached);

    Net::co_spawn(
        ioc,
        [&]() -> Net::awaitable<void>
        {
            auto socket = Net::ip::tcp::socket{ioc};
            co_await socket.async_connect(Net::ip::tcp::endpoint{Net::ip::make_address("127.0.0.1"), port},
                                          Net::use_awaitable);

            Ssl::context ctx(Ssl::context::tls_client);
            ctx.set_verify_mode(Ssl::context::verify_none);
            Ssl::stream<Net::ip::tcp::socket> TlsStream{std::move(socket), ctx};
            co_await TlsStream.async_handshake(Ssl::stream_base::client, Net::use_awaitable);
        },
        Net::detached);

    // 完成哨兵：server_done 或超时（2s）任一先到即停机
    Net::co_spawn(
        ioc,
        [&]() -> Net::awaitable<void>
        {
            Net::steady_timer Timer(ioc);
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while (!server_done && std::chrono::steady_clock::now() < deadline)
            {
                Timer.expires_after(std::chrono::milliseconds(1));
                co_await Timer.async_wait(Net::use_awaitable);
            }
            ioc.stop();
        },
        Net::detached);

    ioc.run();
    ASSERT_TRUE(server_done);
    ASSERT_TRUE(ServerStream);

    auto Encrypted = Transport::make_encrypted(ServerStream);
    Encrypted->cancel();
    Encrypted->close();
}

// ── encrypted: executor 返回有效执行器 ──

TEST(Encrypted, ExecutorIsValid)
{
    Net::io_context ioc;
    Ssl::context SslCtx(Ssl::context::tls_client);

    auto mock = std::make_shared<ProductionMockTransport>();
    Transport::encrypted::connector_type Conn(std::move(mock), {});

    auto Stream = std::make_shared<Transport::encrypted::stream_type>(std::move(Conn), SslCtx);
    Transport::encrypted Encrypted(Stream);

    auto Executor = Encrypted.executor();
    EXPECT_TRUE(Executor);
}

// ── make_encrypted 工厂函数 ──

TEST(Encrypted, MakeEncryptedFactory)
{
    Net::io_context ioc;
    Ssl::context SslCtx(Ssl::context::tls_client);

    auto mock = std::make_shared<ProductionMockTransport>();
    Transport::encrypted::connector_type Conn(std::move(mock), {});

    auto Stream = std::make_shared<Transport::encrypted::stream_type>(std::move(Conn), SslCtx);

    Transport::shared_transmission Transmission = Transport::make_encrypted(Stream);
    ASSERT_TRUE(Transmission);
    EXPECT_EQ(Transmission->transport_type(), Transport::transmission::type::tcp);
}

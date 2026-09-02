/**
 * @file XhttpNgxE2E.cpp
 * @brief XHTTP Stream-one 端到端测试（T2-2，Preview 自包含实现）
 * @details 模拟 h2 客户端（Preview http2）：
 *          1. TLS 握手（自签证书）
 *          2. h2 SETTINGS + POST / 请求（Stream-one）
 *          3. 请求体发送数据 → 服务端响应 200 + echo
 *          4. 客户端验证回显
 * @note 使用自包含 http2 实现（非 nghttp2）
 */

#include <preview/Protocols/Http2/Impl.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <preview/Protocols/Xhttp/Xhttp.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <chrono>
#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;
    namespace h2 = Preview::Http2;
    using namespace Preview;

    void load_self_signed(ssl::context &ctx)
    {
        auto *PkeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        EVP_PKEY *pkey = nullptr;
        if (PkeyCtx && EVP_PKEY_keygen_init(PkeyCtx) > 0 &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(PkeyCtx, 2048) > 0)
        {
            EVP_PKEY_keygen(PkeyCtx, &pkey);
        }
        EVP_PKEY_CTX_free(PkeyCtx);
        ASSERT_NE(pkey, nullptr);

        auto *x509 = X509_new();
        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 3600 * 24);

        auto *Name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char *>("xhttp-test"), -1, -1, 0);
        X509_set_subject_name(x509, Name);
        X509_set_issuer_name(x509, Name);
        X509_NAME_free(Name);

        X509_set_pubkey(x509, pkey);
        X509_sign(x509, pkey, EVP_sha256());

        SSL_CTX_use_certificate(ctx.native_handle(), x509);
        SSL_CTX_use_PrivateKey(ctx.native_handle(), pkey);

        X509_free(x509);
        EVP_PKEY_free(pkey);
    }

    /// h2 客户端：TLS + SETTINGS + POST + 数据 + echo 验证
    net::awaitable<void> DoH2Client(SharedTransmission raw, ssl::context &client_ctx,
                                    const std::string &payload, std::shared_ptr<bool> Ok)
    {
        Preview::Transport::Connector Conn(raw);
        auto Stream = std::make_shared<ssl::stream<Preview::Transport::Connector>>(
            std::move(Conn), client_ctx);
        boost::system::error_code ec;
        co_await Stream->async_handshake(ssl::stream_base::client,
                                         net::redirect_error(net::use_awaitable, ec));
        if (ec)
        {
            *Ok = false;
            co_return;
        }

        auto Session = std::make_shared<h2::SessionImpl>(Stream->get_executor(), false);
        Session->SendSettings();

        // POST /
        h2::HeaderList headers = {
            {":Method", "POST"},
            {":Path", "/"},
            {":scheme", "https"},
            {":authority", "example.com"},
        };
        const auto sid = Session->OpenStream(headers, false);
        if (sid < 0)
        {
            *Ok = false;
            co_return;
        }
        Session->SubmitData(sid, std::span<const std::byte>(
                                     reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                             true);

        // 收集并发送
        std::vector<std::byte> wire;
        Session->Collect(wire);
        std::vector<std::byte> received;

        auto write_wire = [&]() -> net::awaitable<void>
        {
            if (wire.empty())
            {
                co_return;
            }
            auto out = std::move(wire);
            wire.clear();
            co_await Stream->async_write_some(net::buffer(out.data(), out.size()),
                                              net::redirect_error(net::use_awaitable, ec));
        };
        co_await write_wire();

        // 读响应循环
        Session->OnHeaders = [](std::int32_t, const h2::HeaderList &hdrs, bool)
        {
            for (const auto &h : hdrs)
            {
                if (h.Name == ":status")
                {
                    EXPECT_EQ(h.value, "200");
                }
            }
        };
        Session->OnData = [&](std::int32_t, std::span<const std::byte> Data)
        {
            received.insert(received.end(), Data.begin(), Data.end());
        };

        std::array<std::byte, 8192> buf{};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (received.size() < payload.size() && std::chrono::steady_clock::now() < deadline)
        {
            const auto n = co_await Stream->async_read_some(
                net::buffer(buf.data(), buf.size()), net::redirect_error(net::use_awaitable, ec));
            if (ec || n == 0)
            {
                break;
            }
            if (!Session->Feed(std::span<const std::byte>(buf.data(), n), ec))
            {
                break;
            }
            if (Session->Collect(wire))
            {
                co_await write_wire();
            }
        }

        *Ok = received.size() >= payload.size() &&
              std::string_view(reinterpret_cast<const char *>(received.data()), payload.size()) == payload;
        co_return;
    }

    /// xhttp 服务端：Accept + echo
    net::awaitable<void> DoXhttpServer(SharedTransmission raw, ssl::context &server_ctx,
                                       const std::string &payload, std::shared_ptr<bool> Ok)
    {
        Preview::Xhttp::Config cfg;
        auto trans = co_await Preview::Xhttp::Accept(std::move(raw), server_ctx, cfg);
        if (!trans)
        {
            *Ok = false;
            co_return;
        }
        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        std::size_t Total = 0;
        while (true)
        {
            const auto n = co_await trans->async_read_some(buf, ec);
            if (ec || n == 0)
            {
                break;
            }
            Total += n;
            std::error_code w_ec;
            co_await trans->async_write_some(std::span<const std::byte>(buf.data(), n), w_ec);
            if (w_ec)
            {
                *Ok = false;
                co_return;
            }
            if (Total >= payload.size())
            {
                break;
            }
        }
        *Ok = Total >= payload.size();
        co_return;
    }
} // namespace

TEST(XhttpNgxE2E, StreamOneEcho)
{
    net::io_context ioc;

    ssl::context server_ctx(ssl::context::tlsv13);
    load_self_signed(server_ctx);

    ssl::context client_ctx(ssl::context::tlsv13);
    client_ctx.set_verify_mode(ssl::verify_none);

    auto [a, b] = MakeMemoryPair(ioc.get_executor());
    auto sa = std::make_shared<Preview::MemoryStream>(std::move(a));
    auto sb = std::make_shared<Preview::MemoryStream>(std::move(b));

    const std::string payload = "xhttp-Stream-one-echo";
    auto client_ok = std::make_shared<bool>(false);
    auto server_ok = std::make_shared<bool>(false);

    std::exception_ptr ep;
    auto coro = [&]() -> net::awaitable<void>
    {
        net::co_spawn(ioc.get_executor(), DoH2Client(sa, client_ctx, payload, client_ok), net::detached);
        co_await DoXhttpServer(sb, server_ctx, payload, server_ok);
        net::steady_timer deadline(ioc);
        const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (!*client_ok && std::chrono::steady_clock::now() < end)
        {
            deadline.expires_after(std::chrono::milliseconds(10));
            co_await deadline.async_wait(net::use_awaitable);
        }
        ioc.stop();
    };
    net::co_spawn(ioc, coro(), [&](std::exception_ptr e) { ep = e; });
    ioc.run();
    if (ep)
    {
        std::rethrow_exception(ep);
    }
    EXPECT_TRUE(*server_ok);
    EXPECT_TRUE(*client_ok);
}

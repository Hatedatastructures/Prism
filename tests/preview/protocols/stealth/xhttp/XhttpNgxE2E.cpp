/**
 * @file XhttpNgxE2E.cpp
 * @brief XHTTP stream-one 端到端测试（T2-2，preview 自包含实现）
 * @details 模拟 h2 客户端（preview http2）：
 *          1. TLS 握手（自签证书）
 *          2. h2 SETTINGS + POST / 请求（stream-one）
 *          3. 请求体发送数据 → 服务端响应 200 + echo
 *          4. 客户端验证回显
 * @note 使用自包含 http2 实现（非 nghttp2）
 */

#include <common/protocols/http2/impl.hpp>
#include <common/core/transport/memory_stream.hpp>
#include <common/protocols/xhttp/xhttp.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <memory>

#include <gtest/gtest.h>

namespace
{
    namespace net = boost::asio;
    namespace ssl = net::ssl;
    namespace h2 = preview::http2;
    using namespace preview;

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
                                   reinterpret_cast<const unsigned char *>("xhttp-test"), -1, -1, 0);
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

    /// h2 客户端：TLS + SETTINGS + POST + 数据 + echo 验证
    net::awaitable<void> DoH2Client(shared_transmission raw, ssl::context &client_ctx,
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

        auto session = std::make_shared<h2::session_impl>(stream->get_executor(), false);
        session->send_settings();

        // POST /
        h2::header_list headers = {
            {":method", "POST"},
            {":path", "/"},
            {":scheme", "https"},
            {":authority", "example.com"},
        };
        const auto sid = session->open_stream(headers, false);
        if (sid < 0)
        {
            *ok = false;
            co_return;
        }
        session->submit_data(sid, std::span<const std::byte>(
                                     reinterpret_cast<const std::byte *>(payload.data()), payload.size()),
                             true);

        // 收集并发送
        std::vector<std::byte> wire;
        session->collect(wire);
        std::vector<std::byte> received;

        auto write_wire = [&]() -> net::awaitable<void>
        {
            if (wire.empty())
            {
                co_return;
            }
            auto out = std::move(wire);
            wire.clear();
            co_await stream->async_write_some(net::buffer(out.data(), out.size()),
                                              net::redirect_error(net::use_awaitable, ec));
        };
        co_await write_wire();

        // 读响应循环
        session->on_headers = [](std::int32_t, const h2::header_list &hdrs, bool)
        {
            for (const auto &h : hdrs)
            {
                if (h.name == ":status")
                {
                    EXPECT_EQ(h.value, "200");
                }
            }
        };
        session->on_data = [&](std::int32_t, std::span<const std::byte> data)
        {
            received.insert(received.end(), data.begin(), data.end());
        };

        std::array<std::byte, 8192> buf{};
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (received.size() < payload.size() && std::chrono::steady_clock::now() < deadline)
        {
            const auto n = co_await stream->async_read_some(
                net::buffer(buf.data(), buf.size()), net::redirect_error(net::use_awaitable, ec));
            if (ec || n == 0)
            {
                break;
            }
            if (!session->feed(std::span<const std::byte>(buf.data(), n), ec))
            {
                break;
            }
            if (session->collect(wire))
            {
                co_await write_wire();
            }
        }

        *ok = received.size() >= payload.size() &&
              std::string_view(reinterpret_cast<const char *>(received.data()), payload.size()) == payload;
        co_return;
    }

    /// xhttp 服务端：accept + echo
    net::awaitable<void> DoXhttpServer(shared_transmission raw, ssl::context &server_ctx,
                                       const std::string &payload, std::shared_ptr<bool> ok)
    {
        preview::xhttp::config cfg;
        auto trans = co_await preview::xhttp::accept(std::move(raw), server_ctx, cfg);
        if (!trans)
        {
            *ok = false;
            co_return;
        }
        std::array<std::byte, 4096> buf{};
        std::error_code ec;
        std::size_t total = 0;
        while (true)
        {
            const auto n = co_await trans->async_read_some(buf, ec);
            if (ec || n == 0)
            {
                break;
            }
            total += n;
            std::error_code w_ec;
            co_await trans->async_write_some(std::span<const std::byte>(buf.data(), n), w_ec);
            if (w_ec)
            {
                *ok = false;
                co_return;
            }
            if (total >= payload.size())
            {
                break;
            }
        }
        *ok = total >= payload.size();
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

    auto [a, b] = make_memory_pair(ioc.get_executor());
    auto sa = std::make_shared<preview::memory_stream>(std::move(a));
    auto sb = std::make_shared<preview::memory_stream>(std::move(b));

    const std::string payload = "xhttp-stream-one-echo";
    auto client_ok = std::make_shared<bool>(false);
    auto server_ok = std::make_shared<bool>(false);

    std::exception_ptr ep;
    auto coro = [&]() -> net::awaitable<void>
    {
        net::co_spawn(ioc.get_executor(), DoH2Client(sa, client_ctx, payload, client_ok), net::detached);
        co_await DoXhttpServer(sb, server_ctx, payload, server_ok);
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

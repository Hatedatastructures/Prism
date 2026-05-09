/**
 * @file MockTlsServer.hpp
 * @brief 可复用的 Mock TLS 后端服务器
 * @details 使用 BoringSSL 在内存中完成 TLS 握手，将原始 TLS 记录写入 TCP socket。
 * 这允许 ShadowTLS handshake 函数直接从 socket 读取 TLS 记录。
 *
 * 用法：
 *   tcp::acceptor acceptor(ioc, {address, 0});
 *   co_spawn(ioc, mock_tls_server::run(acceptor, 3), detached);
 */

#pragma once

#include <boost/asio.hpp>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <array>
#include <vector>
#include <cstring>

namespace psm::testing
{
    namespace net = boost::asio;

    struct mock_tls_server
    {
        /**
         * @brief 运行 TLS echo 服务器
         * @param acceptor TCP 接受器
         * @param max_connections 最大连接数，达到后退出
         * @details 使用 BoringSSL 在内存中完成 TLS 握手，
         * 将原始 TLS 记录通过 BIO 写入 TCP socket。
         */
        static auto run(net::ip::tcp::acceptor &acceptor, int max_connections = 1)
            -> net::awaitable<void>
        {
            // 创建 SSL_CTX
            auto *ssl_ctx = SSL_CTX_new(TLS_method());
            SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
            SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

            // 生成自签名 Ed25519 证书
            auto *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
            EVP_PKEY *pkey = nullptr;
            if (pkey_ctx && EVP_PKEY_keygen_init(pkey_ctx) > 0)
            {
                EVP_PKEY_keygen(pkey_ctx, &pkey);
            }
            EVP_PKEY_CTX_free(pkey_ctx);

            if (!pkey)
            {
                SSL_CTX_free(ssl_ctx);
                co_return;
            }

            auto *x509 = X509_new();
            X509_set_version(x509, 2);
            ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
            X509_gmtime_adj(X509_get_notBefore(x509), 0);
            X509_gmtime_adj(X509_get_notAfter(x509), 3600 * 24);

            auto *name = X509_NAME_new();
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char *>("MockTlsServer"), -1, -1, 0);
            X509_set_subject_name(x509, name);
            X509_set_issuer_name(x509, name);
            X509_NAME_free(name);

            X509_set_pubkey(x509, pkey);
            X509_sign(x509, pkey, nullptr);

            SSL_CTX_use_certificate(ssl_ctx, x509);
            SSL_CTX_use_PrivateKey(ssl_ctx, pkey);

            X509_free(x509);

            for (int i = 0; i < max_connections; ++i)
            {
                auto socket = co_await acceptor.async_accept(net::use_awaitable);

                // 创建 BIO 对：一个给 SSL 用，一个用于读取 SSL 写出的数据
                auto *read_bio = BIO_new(BIO_s_mem());
                auto *write_bio = BIO_new(BIO_s_mem());

                auto *ssl = SSL_new(ssl_ctx);
                SSL_set_accept_state(ssl);
                SSL_set_bio(ssl, read_bio, write_bio);

                // 协程：持续从 write_bio 读取 TLS 记录并写入 socket
                auto relay_out = [&socket, write_bio]() -> net::awaitable<void>
                {
                    std::array<std::byte, 16384> buf{};
                    while (true)
                    {
                        int n = BIO_read(write_bio, buf.data(), static_cast<int>(buf.size()));
                        if (n <= 0)
                        {
                            // 短暂 yield 让其他协程运行，然后重试
                            net::steady_timer timer(co_await net::this_coro::executor);
                            timer.expires_after(std::chrono::milliseconds(1));
                            co_await timer.async_wait(net::use_awaitable);

                            n = BIO_read(write_bio, buf.data(), static_cast<int>(buf.size()));
                            if (n <= 0)
                                break;
                        }

                        if (n > 0)
                        {
                            boost::system::error_code ec;
                            co_await net::async_write(socket, net::buffer(buf.data(), n),
                                                      net::redirect_error(net::use_awaitable, ec));
                            if (ec)
                                break;
                        }
                    }
                };
                net::co_spawn(co_await net::this_coro::executor, std::move(relay_out), net::detached);

                // 主循环：从 socket 读取数据，喂给 SSL，echo 回写
                std::array<std::byte, 16384> recv_buf{};
                std::array<std::byte, 16384> app_buf{};
                while (true)
                {
                    boost::system::error_code read_ec;
                    auto n = co_await socket.async_read_some(
                        net::buffer(recv_buf),
                        net::redirect_error(net::use_awaitable, read_ec));

                    if (read_ec || n == 0)
                        break;

                    // 将收到的数据写入 read_bio（SSL 会读取）
                    BIO_write(read_bio, recv_buf.data(), static_cast<int>(n));

                    // 如果 SSL 握手还没完成，尝试完成
                    if (!SSL_is_init_finished(ssl))
                    {
                        SSL_do_handshake(ssl);
                        continue;
                    }

                    // 握手完成后，尝试读取应用数据并 echo
                    int app_n = SSL_read(ssl, app_buf.data(), static_cast<int>(app_buf.size()));
                    if (app_n > 0)
                    {
                        SSL_write(ssl, app_buf.data(), app_n);
                    }
                }

                SSL_free(ssl); // 这也会释放 read_bio 和 write_bio
            }

            EVP_PKEY_free(pkey);
            SSL_CTX_free(ssl_ctx);
        }
    };

} // namespace psm::testing

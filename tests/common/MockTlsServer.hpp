/**
 * @file MockTlsServer.hpp
 * @brief 可复用的 Mock TLS 后端服务器
 * @details 使用 BoringSSL 在内存中完成 TLS 握手，将原始 TLS 记录写入 TCP socket。
 * 这允许 ShadowTLS handshake 函数直接从 socket 读取 TLS 记录。
 *
 * 用法：
 *   tcp::acceptor acceptor(ioc, {address, 0});
 *   co_spawn(ioc, MockTlsServer::run(acceptor, 3), detached);
 */

#pragma once

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <cstring>
#include <vector>

namespace Preview::Testing
{
    namespace net = boost::asio;

    struct MockTlsServer
    {
        /**
         * @brief 运行 TLS echo 服务器
         * @param acceptor TCP 接受器
         * @param MaxConnections 最大连接数，达到后退出
         * @details 使用 BoringSSL 在内存中完成 TLS 握手，
         * 将原始 TLS 记录通过 BIO 写入 TCP socket。
         */
        static auto Run(net::ip::tcp::acceptor &acceptor, int MaxConnections = 1) -> net::awaitable<void>
        {
            // 创建 SSL_CTX
            auto *SslCtx = SSL_CTX_new(TLS_method());
            SSL_CTX_set_min_proto_version(SslCtx, TLS1_3_VERSION);
            SSL_CTX_set_max_proto_version(SslCtx, TLS1_3_VERSION);

            // 生成自签名 Ed25519 证书
            auto *PkeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
            EVP_PKEY *pkey = nullptr;
            if (PkeyCtx && EVP_PKEY_keygen_init(PkeyCtx) > 0)
            {
                EVP_PKEY_keygen(PkeyCtx, &pkey);
            }
            EVP_PKEY_CTX_free(PkeyCtx);

            if (!pkey)
            {
                SSL_CTX_free(SslCtx);
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

            SSL_CTX_use_certificate(SslCtx, x509);
            SSL_CTX_use_PrivateKey(SslCtx, pkey);

            X509_free(x509);

            for (int I = 0; I < MaxConnections; ++I)
            {
                auto Socket = co_await acceptor.async_accept(net::use_awaitable);

                // 创建 BIO 对：一个给 SSL 用，一个用于读取 SSL 写出的数据
                auto *ReadBio = BIO_new(BIO_s_mem());
                auto *WriteBio = BIO_new(BIO_s_mem());

                auto *ssl = SSL_new(SslCtx);
                SSL_set_accept_state(ssl);
                SSL_set_bio(ssl, ReadBio, WriteBio);

                // 协程：持续从 WriteBio 读取 TLS 记录并写入 socket
                // 完成时经 RelayDone 通知主协程，确保 SSL_free（释放
                // WriteBio）前 detached 协程已退出，避免 use-after-free
                net::experimental::channel<void()> RelayDone(co_await net::this_coro::executor, 1);
                auto RelayOut = [&Socket, WriteBio, &RelayDone]() -> net::awaitable<void>
                {
                    std::array<std::byte, 16384> buf{};
                    while (true)
                    {
                        int N = BIO_read(WriteBio, buf.data(), static_cast<int>(buf.size()));
                        if (N <= 0)
                        {
                            // 短暂 yield 让其他协程运行，然后重试
                            net::steady_timer timer(co_await net::this_coro::executor);
                            timer.expires_after(std::chrono::milliseconds(1));
                            co_await timer.async_wait(net::use_awaitable);

                            N = BIO_read(WriteBio, buf.data(), static_cast<int>(buf.size()));
                            if (N <= 0)
                            {
                                break;
                            }
                        }

                        if (N > 0)
                        {
                            boost::system::error_code ec;
                            co_await net::async_write(Socket, net::buffer(buf.data(), N),
                                                      net::redirect_error(net::use_awaitable, ec));
                            if (ec)
                            {
                                break;
                            }
                        }
                    }
                    RelayDone.try_send();
                };
                net::co_spawn(co_await net::this_coro::executor, std::move(RelayOut), net::detached);

                // 主循环：从 socket 读取数据，喂给 SSL，echo 回写
                std::array<std::byte, 16384> RecvBuf{};
                std::array<std::byte, 16384> AppBuf{};
                while (true)
                {
                    boost::system::error_code ReadEc;
                    auto N = co_await Socket.async_read_some(
                        net::buffer(RecvBuf), net::redirect_error(net::use_awaitable, ReadEc));

                    if (ReadEc || N == 0)
                    {
                        break;
                    }

                    // 将收到的数据写入 ReadBio（SSL 会读取）
                    BIO_write(ReadBio, RecvBuf.data(), static_cast<int>(N));

                    // 如果 SSL 握手还没完成，尝试完成
                    if (!SSL_is_init_finished(ssl))
                    {
                        SSL_do_handshake(ssl);
                        continue;
                    }

                    // 握手完成后，尝试读取应用数据并 echo
                    int AppN = SSL_read(ssl, AppBuf.data(), static_cast<int>(AppBuf.size()));
                    if (AppN > 0)
                    {
                        SSL_write(ssl, AppBuf.data(), AppN);
                    }
                }

                // 等待 RelayOut 退出后再释放 SSL（连带释放 WriteBio），
                // 防止 detached 协程在 BIO 上执行 use-after-free
                co_await RelayDone.async_receive(net::use_awaitable);

                SSL_free(ssl); // 这也会释放 ReadBio 和 WriteBio
            }

            EVP_PKEY_free(pkey);
            SSL_CTX_free(SslCtx);
        }
    };

} // namespace Preview::Testing

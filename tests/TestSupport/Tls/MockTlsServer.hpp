/**
 * @file MockTlsServer.hpp
 * @brief 可复用的 Mock TLS 后端服务器（echo）
 * @details 使用 BoringSSL 在内存中完成 TLS 握手，将原始 TLS 记录写入 TCP socket。
 * 这允许 ShadowTLS handshake 函数直接从 socket 读取 TLS 记录，也用于 DoT/DoH
 * 等 TLS 承载协议的路径覆盖测试。
 *
 * 采用主协程内联 flush 模式：每个数据块到达后，推进握手 / 读取应用数据并
 * echo，随后将 WriteBio 中积累的全部 TLS 记录冲刷到 socket。TLS1.3 握手
 * 的多阶段输出（ServerHello → CCS/Finished）都能及时发出，无独立转发协程，
 * 避免了通道/信号等待的兼容性与竞态问题。
 *
 * 用法：
 *   tcp::acceptor acceptor(ioc, {address, 0});
 *   co_spawn(ioc, MockTlsServer::Run(acceptor, 3), detached);
 */

#pragma once

#include <boost/asio.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace Preview::Testing::Tls
{
    namespace net = boost::asio;

    struct MockTlsServer
    {
        /**
         * @brief 运行 TLS echo 服务器
         * @param acceptor TCP 接受器
         * @param MaxConnections 最大连接数，达到后退出
         * @param Responder 可选应答工厂：收到应用数据时调用，返回的构造应答
         *                  取代默认 echo 写回对端（用于 DoH 等需要结构化应答的
         *                  路径测试）。返回 nullopt 表示"本轮不应答、继续等待
         *                  后续数据"（请求分多条 TLS 记录到达时由工厂自行累积）；
         *                  为空表示使用默认 echo
         * @details 使用 BoringSSL 在内存中完成 TLS 握手，将原始 TLS 记录
         *          通过 BIO 写入 TCP socket；应用数据原样 echo
         */
        static auto Run(net::ip::tcp::acceptor &acceptor, int MaxConnections = 1,
                        std::function<std::optional<std::vector<std::byte>>(const std::byte *,
                                                                            std::size_t)>
                            Responder = {}) -> net::awaitable<void>
        {
            // 创建 SSL_CTX
            auto *SslCtx = SSL_CTX_new(TLS_method());
            SSL_CTX_set_min_proto_version(SslCtx, TLS1_3_VERSION);
            SSL_CTX_set_max_proto_version(SslCtx, TLS1_3_VERSION);

            // 生成自签名 ECDSA P-256 证书（TLS1.3 客户端必支持 ecdsa_secp256r1_sha256；
            // 此 BoringSSL 客户端默认签名算法不含 Ed25519，故不使用 Ed25519）
            auto *PkeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            EVP_PKEY *pkey = nullptr;
            if (PkeyCtx && EVP_PKEY_keygen_init(PkeyCtx) > 0 &&
                EVP_PKEY_CTX_set_ec_paramgen_curve_nid(PkeyCtx, NID_X9_62_prime256v1) > 0)
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
            X509_sign(x509, pkey, EVP_sha256()); // ECDSA 签名需显式摘要

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

                // 把 WriteBio 中积累的全部 TLS 记录冲刷到 socket；写失败返回 false
                auto FlushOut = [&Socket, WriteBio]() -> net::awaitable<bool>
                {
                    std::array<std::byte, 16384> buf{};
                    for (;;)
                    {
                        const int N = BIO_read(WriteBio, buf.data(), static_cast<int>(buf.size()));
                        if (N <= 0)
                        {
                            co_return true;
                        }
                        boost::system::error_code ec;
                        co_await net::async_write(Socket, net::buffer(buf.data(), N),
                                                  net::redirect_error(net::use_awaitable, ec));
                        if (ec)
                        {
                            co_return false;
                        }
                    }
                };

                // 主循环：读 socket → 喂 ReadBio → 推进握手 / 读取应用数据并 echo
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
                        const int Ret = SSL_do_handshake(ssl);
                        if (Ret <= 0)
                        {
                            const int Err = SSL_get_error(ssl, Ret);
                            if (Err != SSL_ERROR_WANT_READ && Err != SSL_ERROR_WANT_WRITE)
                            {
                                break; // 握手真正失败
                            }
                            // WANT_READ / WANT_WRITE：冲刷产出后回到读循环
                        }
                        if (!(co_await FlushOut()))
                        {
                            break;
                        }
                        // TLS1.3 客户端可能把 Finished 与应用数据同段送达：
                        // 握手仍未完成则继续等输入；已完成则下沉到 SSL_read，
                        // 消费已缓冲在 ReadBio 中的应用数据，避免双端互等
                        if (!SSL_is_init_finished(ssl))
                        {
                            continue;
                        }
                    }

                    // 握手完成后，循环读取已缓冲的应用数据并应答
                    // （TLS 记录可能分多条，必须消费完 ReadBio 中的全部内容，
                    //  否则客户端已发完所有记录、在等完整应答时双端互等）
                    for (;;)
                    {
                        int AppN = SSL_read(ssl, AppBuf.data(), static_cast<int>(AppBuf.size()));
                        if (AppN <= 0)
                        {
                            break; // WANT_READ / EOF / 错误：回到读循环
                        }
                        int Written = 0;
                        if (Responder)
                        {
                            auto Reply = Responder(AppBuf.data(), static_cast<std::size_t>(AppN));
                            if (!Reply)
                            {
                                continue; // 本轮不应答：继续等待后续数据（请求分块到达）
                            }
                            if (Reply->empty()
                                || SSL_write(ssl, Reply->data(),
                                             static_cast<int>(Reply->size()))
                                       <= 0)
                            {
                                break;
                            }
                        }
                        else
                        {
                            Written = SSL_write(ssl, AppBuf.data(), AppN);
                            if (Written <= 0)
                            {
                                break;
                            }
                        }
                        if (!(co_await FlushOut()))
                        {
                            break;
                        }
                    }
                }

                SSL_free(ssl); // 这也会释放 ReadBio 和 WriteBio
            }

            EVP_PKEY_free(pkey);
            SSL_CTX_free(SslCtx);
        }
    };

    /**
     * @brief 构造带状态累积的 DoH 应答工厂
     * @param statusLine HTTP 状态行（如 "HTTP/1.1 200 OK"）
     * @details HTTP 请求可能分多条 TLS 记录到达：工厂内部累积各分块，
     *          直到收满一个完整请求（头区结束 + 请求 Content-Length 声明的
     *          报文体）才以指定状态行 + DNS 报文体回包，随后重置累积状态
     *          以支持 keep-alive 连接上的后续请求。配合 MockTlsServer 的
     *          optional 语义：未收满前返回 nullopt 继续等待
     */
    inline auto MakeDohResponder(std::string_view statusLine)
        -> std::function<std::optional<std::vector<std::byte>>(const std::byte *, std::size_t)>
    {
        auto State = std::make_shared<std::string>();
        return [State, Line = std::string(statusLine)](const std::byte *data,
                                                       const std::size_t len)
                   -> std::optional<std::vector<std::byte>>
        {
            State->append(reinterpret_cast<const char *>(data), len);
            const auto HeaderEnd = State->find("\r\n\r\n");
            if (HeaderEnd == std::string::npos)
            {
                return std::nullopt;
            }
            // 请求头中的 Content-Length（决定何时收满报文体）
            std::size_t ContentLength = 0;
            if (const auto Pos = State->find("Content-Length:");
                Pos != std::string::npos && Pos < HeaderEnd)
            {
                const auto *p = State->c_str() + Pos + 15;
                while (*p == ' ' || *p == '\t')
                {
                    ++p; // 跳过冒号后的空白
                }
                for (; *p >= '0' && *p <= '9'; ++p)
                {
                    ContentLength = ContentLength * 10 + static_cast<std::size_t>(*p - '0');
                }
            }
            const auto BodyStart = HeaderEnd + 4;
            if (State->size() < BodyStart + ContentLength)
            {
                return std::nullopt;
            }

            const auto Body = State->substr(BodyStart, ContentLength);
            State->clear(); // keep-alive 多请求：重置累积状态

            std::string response(Line);
            response += "\r\nContent-Type: application/dns-message\r\nContent-Length: ";
            response += std::to_string(Body.size());
            response += "\r\n\r\n";
            std::vector<std::byte> out;
            out.reserve(response.size() + Body.size());
            for (const auto ch : response)
            {
                out.push_back(static_cast<std::byte>(ch));
            }
            for (const auto ch : Body)
            {
                out.push_back(static_cast<std::byte>(ch));
            }
            return out;
        };
    }

} // namespace Preview::Testing::Tls

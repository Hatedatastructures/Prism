/**
 * @file MockTlsServer.hpp
 * @brief 测试用内存 BIO TLS 服务端及 DoH 应答构造器。
 * @details 服务端身份、单连接 TLS 状态机和 DoH 请求累积器分别拥有自己的资源与状态。
 *          TLS 记录经 TCP socket 读写；应用数据默认原样回显，也可交给显式应答器。
 */

#pragma once

#include <boost/asio.hpp>
#include <boost/system/system_error.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace Prism::Testing::Tls
{
    namespace net = boost::asio;

    using TlsResponder =
        std::function<std::optional<std::vector<std::byte>>(const std::byte *, std::size_t)>;

    /**
     * @brief 拥有 TLS 测试身份及其 SSL_CTX。
     * @details 私钥和上下文存活至最后一个连接处理完毕；证书的引用由 SSL_CTX 持有。
     */
    class TlsServerIdentity final
    {
    public:
        [[nodiscard]] static auto Create() -> std::unique_ptr<TlsServerIdentity>
        {
            auto Identity = std::unique_ptr<TlsServerIdentity>{new TlsServerIdentity{}};
            Identity->Context_.reset(SSL_CTX_new(TLS_method()));
            if (!Identity->Context_)
            {
                return {};
            }
            if (SSL_CTX_set_min_proto_version(Identity->Context_.get(), TLS1_3_VERSION) != 1
                || SSL_CTX_set_max_proto_version(Identity->Context_.get(), TLS1_3_VERSION) != 1)
            {
                return {};
            }

            auto KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>{
                EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), &EVP_PKEY_CTX_free};
            if (!KeyContext || EVP_PKEY_keygen_init(KeyContext.get()) <= 0
                || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                       KeyContext.get(), NID_X9_62_prime256v1)
                       <= 0)
            {
                return {};
            }

            EVP_PKEY *GeneratedKey = nullptr;
            const int KeygenResult = EVP_PKEY_keygen(KeyContext.get(), &GeneratedKey);
            std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> KeyOwner{
                GeneratedKey, &EVP_PKEY_free};
            if (KeygenResult <= 0 || !KeyOwner)
            {
                return {};
            }
            Identity->PrivateKey_ = std::move(KeyOwner);

            auto Certificate = std::unique_ptr<X509, decltype(&X509_free)>{
                X509_new(), &X509_free};
            if (!Certificate || X509_set_version(Certificate.get(), 2) != 1
                || ASN1_INTEGER_set(X509_get_serialNumber(Certificate.get()), 1) != 1
                || !X509_gmtime_adj(X509_get_notBefore(Certificate.get()), 0)
                || !X509_gmtime_adj(X509_get_notAfter(Certificate.get()), 3600 * 24))
            {
                return {};
            }

            auto Name = std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)>{
                X509_NAME_new(), &X509_NAME_free};
            if (!Name
                || X509_NAME_add_entry_by_txt(
                       Name.get(), "CN", MBSTRING_ASC,
                       reinterpret_cast<const unsigned char *>("MockTlsServer"), -1, -1, 0)
                       != 1
                || X509_set_subject_name(Certificate.get(), Name.get()) != 1
                || X509_set_issuer_name(Certificate.get(), Name.get()) != 1
                || X509_set_pubkey(Certificate.get(), Identity->PrivateKey_.get()) != 1
                || X509_sign(Certificate.get(), Identity->PrivateKey_.get(), EVP_sha256()) <= 0)
            {
                return {};
            }
            if (SSL_CTX_use_certificate(Identity->Context_.get(), Certificate.get()) != 1
                || SSL_CTX_use_PrivateKey(Identity->Context_.get(), Identity->PrivateKey_.get()) != 1)
            {
                return {};
            }
            return Identity;
        }

        [[nodiscard]] auto Context() const noexcept -> SSL_CTX *
        {
            return Context_.get();
        }

    private:
        TlsServerIdentity()
            : PrivateKey_(nullptr, &EVP_PKEY_free), Context_(nullptr, &SSL_CTX_free)
        {
        }

        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> PrivateKey_;
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> Context_;
    };

    /**
     * @brief 拥有单条测试 TLS 连接的 socket、SSL 状态与内存 BIO。
     * @details SSL 独占两个 BIO；本对象只保留非拥有 BIO 指针用于读写。
     *          Responder 引用由外层 Run 协程持有，覆盖本连接的全部挂起周期。
     */
    class TlsServerConnection final
    {
    public:
        TlsServerConnection(net::ip::tcp::socket Socket, SSL_CTX *Context,
                            const TlsResponder &Responder)
            : Socket_(std::move(Socket)), Responder_(Responder), Ssl_(nullptr, &SSL_free)
        {
            using BioOwner = std::unique_ptr<BIO, decltype(&BIO_free)>;
            BioOwner ReadBio{BIO_new(BIO_s_mem()), &BIO_free};
            BioOwner WriteBio{BIO_new(BIO_s_mem()), &BIO_free};
            Ssl_.reset(SSL_new(Context));
            if (!ReadBio || !WriteBio || !Ssl_)
            {
                return;
            }

            SSL_set_accept_state(Ssl_.get());
            ReadBio_ = ReadBio.get();
            WriteBio_ = WriteBio.get();
            SSL_set_bio(Ssl_.get(), ReadBio.release(), WriteBio.release());
            Ready_ = true;
        }

        auto Run() -> net::awaitable<void>
        {
            if (!Ready_)
            {
                co_return;
            }

            std::array<std::byte, 16384> ReceiveBuffer{};
            std::array<std::byte, 16384> ApplicationBuffer{};
            while (true)
            {
                boost::system::error_code ErrorCode;
                const auto Bytes = co_await Socket_.async_read_some(
                    net::buffer(ReceiveBuffer),
                    net::redirect_error(net::use_awaitable, ErrorCode));
                if (ErrorCode || Bytes == 0)
                {
                    co_return;
                }
                const auto Input = std::span<const std::byte>(ReceiveBuffer.data(), Bytes);
                if (!(co_await ProcessInput(Input, ApplicationBuffer)))
                {
                    co_return;
                }
            }
        }

    private:
        auto ProcessInput(std::span<const std::byte> Input,
                          std::span<std::byte> ApplicationBuffer)
            -> net::awaitable<bool>
        {
            if (BIO_write(ReadBio_, Input.data(), static_cast<int>(Input.size())) <= 0)
            {
                co_return false;
            }
            if (!SSL_is_init_finished(Ssl_.get()))
            {
                const int Result = SSL_do_handshake(Ssl_.get());
                if (Result <= 0)
                {
                    const int Error = SSL_get_error(Ssl_.get(), Result);
                    if (Error != SSL_ERROR_WANT_READ && Error != SSL_ERROR_WANT_WRITE)
                    {
                        co_return false;
                    }
                }
                if (!(co_await FlushOutput()))
                {
                    co_return false;
                }
                if (!SSL_is_init_finished(Ssl_.get()))
                {
                    co_return true;
                }
            }

            while (true)
            {
                const int Bytes =
                    SSL_read(Ssl_.get(), ApplicationBuffer.data(),
                             static_cast<int>(ApplicationBuffer.size()));
                if (Bytes <= 0)
                {
                    break;
                }
                if (!WriteApplicationData(ApplicationBuffer.data(),
                                          static_cast<std::size_t>(Bytes)))
                {
                    break;
                }
                if (!(co_await FlushOutput()))
                {
                    break;
                }
            }
            co_return true;
        }

        auto WriteApplicationData(const std::byte *Data, std::size_t Length) -> bool
        {
            if (Responder_)
            {
                auto Reply = Responder_(Data, Length);
                if (!Reply)
                {
                    return true;
                }
                return !Reply->empty()
                       && SSL_write(Ssl_.get(), Reply->data(),
                                    static_cast<int>(Reply->size()))
                              > 0;
            }
            return SSL_write(Ssl_.get(), Data, static_cast<int>(Length)) > 0;
        }

        auto FlushOutput() -> net::awaitable<bool>
        {
            std::array<std::byte, 16384> Buffer{};
            while (true)
            {
                const int Bytes =
                    BIO_read(WriteBio_, Buffer.data(), static_cast<int>(Buffer.size()));
                if (Bytes <= 0)
                {
                    co_return true;
                }

                boost::system::error_code ErrorCode;
                co_await net::async_write(
                    Socket_, net::buffer(Buffer.data(), Bytes),
                    net::redirect_error(net::use_awaitable, ErrorCode));
                if (ErrorCode)
                {
                    co_return false;
                }
            }
        }

        net::ip::tcp::socket Socket_;
        const TlsResponder &Responder_;
        std::unique_ptr<SSL, decltype(&SSL_free)> Ssl_;
        BIO *ReadBio_{nullptr};
        BIO *WriteBio_{nullptr};
        bool Ready_{false};
    };

    struct MockTlsServer
    {
        /**
         * @brief 接受有限数量连接并逐条运行 TLS echo 或结构化应答。
         * @param Acceptor TCP 接受器；其生命周期由调用方覆盖整个协程。
         * @param MaxConnections 达到上限后退出。
         * @param Responder 可选应用数据应答器；空值使用原样 echo，nullopt 表示继续累积输入。
         * @details 服务端身份由本次 Run 独占；单连接状态由 TlsServerConnection 独占。
         *          调用方关闭 acceptor 时，等待中的 accept 以 operation_aborted 正常退栈；其他错误继续传播。
         */
        static auto Run(net::ip::tcp::acceptor &Acceptor, int MaxConnections = 1,
                        TlsResponder Responder = {}) -> net::awaitable<void>
        {
            auto Identity = TlsServerIdentity::Create();
            if (!Identity)
            {
                co_return;
            }

            for (int Index = 0; Index < MaxConnections; ++Index)
            {
                if (!Acceptor.is_open())
                {
                    co_return;
                }
                boost::system::error_code ErrorCode;
                auto Socket = co_await Acceptor.async_accept(
                    net::redirect_error(net::use_awaitable, ErrorCode));
                if (ErrorCode)
                {
                    if (!Acceptor.is_open() && ErrorCode == net::error::operation_aborted)
                    {
                        co_return;
                    }
                    throw boost::system::system_error(ErrorCode);
                }
                TlsServerConnection Connection{
                    std::move(Socket), Identity->Context(), Responder};
                co_await Connection.Run();
            }
        }
    };

    /**
     * @brief 构造带状态累积的 DoH 应答器。
     * @details 请求可能分多次 TLS 读取到达；收齐头与 Content-Length 正文后回送 DNS 正文，
     *          并清空本轮状态以支持同一 TLS 连接上的后续请求。
     */
    class DohResponder final
    {
    public:
        explicit DohResponder(std::string StatusLine)
            : State_(std::make_shared<std::string>()), StatusLine_(std::move(StatusLine))
        {
        }

        auto operator()(const std::byte *Data, std::size_t Length)
            -> std::optional<std::vector<std::byte>>
        {
            State_->append(reinterpret_cast<const char *>(Data), Length);
            const auto HeaderEnd = State_->find("\r\n\r\n");
            if (HeaderEnd == std::string::npos)
            {
                return std::nullopt;
            }

            std::size_t ContentLength = 0;
            if (const auto Position = State_->find("Content-Length:");
                Position != std::string::npos && Position < HeaderEnd)
            {
                const auto *Character = State_->c_str() + Position + 15;
                while (*Character == ' ' || *Character == '\t')
                {
                    ++Character;
                }
                for (; *Character >= '0' && *Character <= '9'; ++Character)
                {
                    ContentLength =
                        ContentLength * 10 + static_cast<std::size_t>(*Character - '0');
                }
            }

            const auto BodyStart = HeaderEnd + 4;
            if (State_->size() < BodyStart + ContentLength)
            {
                return std::nullopt;
            }
            const auto Body = State_->substr(BodyStart, ContentLength);
            State_->clear();

            std::string Response(StatusLine_);
            Response += "\r\nContent-Type: application/dns-message\r\nContent-Length: ";
            Response += std::to_string(Body.size());
            Response += "\r\n\r\n";
            std::vector<std::byte> Output;
            Output.reserve(Response.size() + Body.size());
            for (const auto Character : Response)
            {
                Output.push_back(static_cast<std::byte>(Character));
            }
            for (const auto Character : Body)
            {
                Output.push_back(static_cast<std::byte>(Character));
            }
            return Output;
        }

    private:
        std::shared_ptr<std::string> State_;
        std::string StatusLine_;
    };

    /**
     * @brief 创建可复制的 DoH 应答器；状态在各份 callable 间共享。
     * @param StatusLine 应答 HTTP 状态行。
     * @return 累积分块请求并保留 DNS 正文的应答器。
     */
    inline auto MakeDohResponder(std::string_view StatusLine) -> TlsResponder
    {
        return TlsResponder{DohResponder{std::string(StatusLine)}};
    }

} // namespace Prism::Testing::Tls

/**
 * @file Hysteria2Support.cpp
 * @brief Hysteria2 TCP/UDP 互操作 server 共用的 TLS、认证和 drain 支持。
 */

#include "Hysteria2Support.hpp"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cstdio>
#include <system_error>

#include <Prism/Account/Account.hpp>

namespace Prism::Testing::Integration::Hysteria2::Interop
{
    namespace Ssl = Net::ssl;

    namespace
    {
        [[nodiscard]] auto LoadSelfSigned(Ssl::context &Context) -> bool
        {
            auto *KeyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            EVP_PKEY *Key = nullptr;
            if (!KeyContext || EVP_PKEY_keygen_init(KeyContext) <= 0 ||
                EVP_PKEY_CTX_set_rsa_keygen_bits(KeyContext, 2048) <= 0 ||
                EVP_PKEY_keygen(KeyContext, &Key) <= 0)
            {
                EVP_PKEY_CTX_free(KeyContext);
                return false;
            }
            EVP_PKEY_CTX_free(KeyContext);
            auto *Certificate = X509_new();
            auto *Name = X509_NAME_new();
            const bool Ready = Certificate && Name && X509_set_version(Certificate, 2) > 0 &&
                               ASN1_INTEGER_set(X509_get_serialNumber(Certificate), 1) > 0 &&
                               X509_gmtime_adj(X509_get_notBefore(Certificate), 0) != nullptr &&
                               X509_gmtime_adj(X509_get_notAfter(Certificate), 3600) != nullptr &&
                               X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC,
                                                          reinterpret_cast<const unsigned char *>("localhost"), -1, -1,
                                                          0) > 0 &&
                               X509_set_subject_name(Certificate, Name) > 0 &&
                               X509_set_issuer_name(Certificate, Name) > 0 &&
                               X509_set_pubkey(Certificate, Key) > 0 &&
                               X509_sign(Certificate, Key, EVP_sha256()) > 0 &&
                               SSL_CTX_use_certificate(Context.native_handle(), Certificate) == 1 &&
                               SSL_CTX_use_PrivateKey(Context.native_handle(), Key) == 1;
            X509_NAME_free(Name);
            X509_free(Certificate);
            EVP_PKEY_free(Key);
            return Ready;
        }

        /** @brief 固定 HTTP/3 ALPN；签名遵循 BoringSSL 的选择回调 ABI。 */
        auto SelectH3(SSL *, const unsigned char **Out, unsigned char *OutLength,
                      const unsigned char *In, unsigned int InLength, void *) -> int
        {
            static constexpr unsigned char H3[] = {0x02, 'h', '3'};
            const auto Result = SSL_select_next_proto(
                const_cast<unsigned char **>(Out), OutLength, H3, sizeof(H3), In, InLength);
            return Result == OPENSSL_NPN_NEGOTIATED ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }

    auto CaptureDrainFailure(std::exception_ptr &FirstError, SessionRunResult Result) -> void
    {
        if (!Result && !FirstError)
        {
            FirstError = std::make_exception_ptr(
                std::system_error(Prism::Fault::ToNative(Result.error())));
        }
    }

    auto CaptureDrainFailure(Prism::Fault::Failure &FirstFailure,
                             SessionRunResult Result) -> void
    {
        if (!Result && FirstFailure.Succeeded())
        {
            FirstFailure = Result.error();
        }
    }

    auto ReportSessionRunFailure(const char *Context,
                                 const Prism::Fault::Failure &Failure) -> void
    {
        const auto Message = Prism::Fault::Describe(Failure.Code);
        std::fprintf(stderr, "FAIL: %s: %s native=%d category=%s\n",
                     Context, Message.data(), Failure.Native.value(), Failure.Native.category().name());
    }

    auto MakeServerTls() -> std::shared_ptr<Ssl::context>
    {
        auto Tls = std::make_shared<Ssl::context>(Ssl::context::tlsv13_server);
        if (!LoadSelfSigned(*Tls))
        {
            return {};
        }
        SSL_CTX_set_alpn_select_cb(Tls->native_handle(), SelectH3, nullptr);
        return Tls;
    }

    auto MakeAuthenticator(const std::string_view Password) -> AuthFixture
    {
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Token(Password));
        return AuthFixture{Directory, Directory->Authenticator};
    }

    auto DrainQuicServer(const std::shared_ptr<Prism::Quic::Server> &Server) -> Net::awaitable<void>
    {
        std::exception_ptr FirstError;
        Server->Close();
        try
        {
            CaptureDrainFailure(FirstError, co_await Server->Drain());
        }
        catch (...)
        {
            if (!FirstError)
            {
                FirstError = std::current_exception();
            }
        }
        if (FirstError)
        {
            std::rethrow_exception(FirstError);
        }
    }

    auto WaitQuicHandshakeOrDrain(
        const std::shared_ptr<Prism::Quic::Server> &Server) -> Net::awaitable<bool>
    {
        std::exception_ptr HandshakeError;
        bool HandshakeOk = false;
        try
        {
            HandshakeOk = co_await Server->WaitHandshake();
        }
        catch (...)
        {
            HandshakeError = std::current_exception();
        }
        if (HandshakeError)
        {
            try
            {
                co_await DrainQuicServer(Server);
            }
            catch (...)
            {
            }
            std::rethrow_exception(HandshakeError);
        }
        if (!HandshakeOk)
        {
            co_await DrainQuicServer(Server);
        }
        co_return HandshakeOk;
    }

    auto DrainHttp3SessionAndQuicServer(
        const std::shared_ptr<Prism::Http3::NativeServerSession> &Session,
        const std::shared_ptr<Prism::Quic::Server> &Server) -> Net::awaitable<void>
    {
        std::exception_ptr FirstError;
        try
        {
            CaptureDrainFailure(FirstError, co_await Session->Drain());
        }
        catch (...)
        {
            if (!FirstError)
            {
                FirstError = std::current_exception();
            }
        }
        try
        {
            CaptureDrainFailure(FirstError, co_await Server->Drain());
        }
        catch (...)
        {
            if (!FirstError)
            {
                FirstError = std::current_exception();
            }
        }
        if (FirstError)
        {
            std::rethrow_exception(FirstError);
        }
    }
}

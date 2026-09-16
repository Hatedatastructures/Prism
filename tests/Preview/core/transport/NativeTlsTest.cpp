/**
 * @file NativeTlsTest.cpp
 * @brief Native TLS admission 的预读所有权与回放测试。
 * @details 通过真实 PreviewTransport 读取 UpgradeNativeTls 转移的预读字节，
 *          覆盖读操作同时返回有效字节和终止错误时的非 TLS 分流语义。
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/steady_timer.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Transport/NativeTls.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{

    namespace Net = boost::asio;
    using Preview::SharedTransmission;

    template <typename Operation>
    auto RunCoro(Net::io_context &Ioc, Operation OperationValue) -> void
    {
        std::exception_ptr Failure;
        Ioc.restart();
        Net::co_spawn(
            Ioc,
            std::move(OperationValue),
            [&Failure, &Ioc](std::exception_ptr Error)
            {
                Failure = std::move(Error);
                Ioc.stop();
            });
        Ioc.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    auto ReadExactly(const SharedTransmission &Transport, std::span<std::byte> Buffer)
        -> Net::awaitable<bool>
    {
        std::size_t Offset = 0;
        while (Offset < Buffer.size())
        {
            std::error_code Error;
            const auto Count = co_await Transport->async_read_some(Buffer.subspan(Offset), Error);
            if (Error || Count == 0 || Count > Buffer.size() - Offset)
            {
                co_return false;
            }
            Offset += Count;
        }
        co_return true;
    }

    auto MakeTlsContext() -> std::shared_ptr<Net::ssl::context>
    {
        return std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
    }

    auto MakeTlsContextWithCertificate() -> std::shared_ptr<Net::ssl::context>
    {
        auto Context = MakeTlsContext();
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> Key(EVP_PKEY_new(), EVP_PKEY_free);
        std::unique_ptr<BIGNUM, decltype(&BN_free)> Exponent(BN_new(), BN_free);
        std::unique_ptr<RSA, decltype(&RSA_free)> RsaKey(RSA_new(), RSA_free);
        if (!Context || !Key || !Exponent || !RsaKey || BN_set_word(Exponent.get(), RSA_F4) != 1 ||
            RSA_generate_key_ex(RsaKey.get(), 2048, Exponent.get(), nullptr) != 1 ||
            EVP_PKEY_assign_RSA(Key.get(), RsaKey.get()) != 1)
        {
            return {};
        }
        (void)RsaKey.release();

        std::unique_ptr<X509, decltype(&X509_free)> Certificate(X509_new(), X509_free);
        if (!Certificate || X509_set_version(Certificate.get(), 2) != 1 ||
            ASN1_INTEGER_set(X509_get_serialNumber(Certificate.get()), 1) != 1 ||
            X509_gmtime_adj(X509_get_notBefore(Certificate.get()), 0) == nullptr ||
            X509_gmtime_adj(X509_get_notAfter(Certificate.get()), 24 * 60 * 60) == nullptr)
        {
            return {};
        }

        auto *Name = X509_get_subject_name(Certificate.get());
        constexpr unsigned char CommonName[] = "Preview Native TLS Test";
        if (!Name || X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC, CommonName, -1, -1, 0) != 1 ||
            X509_set_issuer_name(Certificate.get(), Name) != 1 ||
            X509_set_pubkey(Certificate.get(), Key.get()) != 1 ||
            X509_sign(Certificate.get(), Key.get(), EVP_sha256()) <= 0 ||
            SSL_CTX_use_certificate(Context->native_handle(), Certificate.get()) != 1 ||
            SSL_CTX_use_PrivateKey(Context->native_handle(), Key.get()) != 1 ||
            SSL_CTX_check_private_key(Context->native_handle()) != 1)
        {
            return {};
        }
        return Context;
    }

    auto MakeClientHello() -> std::optional<std::vector<std::uint8_t>>
    {
        Net::ssl::context Context(Net::ssl::context::tls_client);
        std::unique_ptr<SSL, decltype(&SSL_free)> Client(SSL_new(Context.native_handle()), SSL_free);
        if (!Client)
        {
            return std::nullopt;
        }

        auto *ReadBio = BIO_new(BIO_s_mem());
        auto *WriteBio = BIO_new(BIO_s_mem());
        if (!ReadBio || !WriteBio)
        {
            BIO_free(ReadBio);
            BIO_free(WriteBio);
            return std::nullopt;
        }
        SSL_set_bio(Client.get(), ReadBio, WriteBio);
        SSL_set_connect_state(Client.get());

        const auto HandshakeResult = SSL_do_handshake(Client.get());
        if (HandshakeResult == 1 || SSL_get_error(Client.get(), HandshakeResult) != SSL_ERROR_WANT_READ)
        {
            return std::nullopt;
        }

        auto *Outbound = SSL_get_wbio(Client.get());
        const auto Pending = BIO_ctrl_pending(Outbound);
        if (Pending == 0 || Pending > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
        {
            return std::nullopt;
        }
        std::vector<std::uint8_t> ClientHello(Pending);
        const auto ReadBytes = BIO_read(Outbound, ClientHello.data(), static_cast<int>(Pending));
        if (ReadBytes != static_cast<int>(Pending))
        {
            return std::nullopt;
        }
        return ClientHello;
    }

    class CloseCountingTransport final : public Preview::Transmission
    {
    public:
        explicit CloseCountingTransport(std::shared_ptr<Preview::PreviewMockTransport> Inner)
            : Inner_(std::move(Inner))
        {
        }

        [[nodiscard]] auto Executor() const -> ExecutorType override
        {
            return Inner_->Executor();
        }

        [[nodiscard]] auto IsOpen() const -> bool override
        {
            return Inner_->IsOpen();
        }

        [[nodiscard]] auto NextLayer() noexcept -> Preview::Transmission * override
        {
            return Inner_.get();
        }

        [[nodiscard]] auto async_read_some(std::span<std::byte> Buffer, std::error_code &ErrorCode)
            -> Net::awaitable<std::size_t> override
        {
            co_return co_await Inner_->async_read_some(Buffer, ErrorCode);
        }

        [[nodiscard]] auto async_write_some(
            std::span<const std::byte> Buffer,
            std::error_code &ErrorCode) -> Net::awaitable<std::size_t> override
        {
            co_return co_await Inner_->async_write_some(Buffer, ErrorCode);
        }

        void Close() override
        {
            ++CloseCalls;
            Inner_->Close();
        }

        void Cancel() override
        {
            Inner_->Cancel();
        }

        std::size_t CloseCalls{0};

    private:
        std::shared_ptr<Preview::PreviewMockTransport> Inner_;
    };

    TEST(NativeTls, UsesConfiguredDeadlineForStalledCompleteClientHello)
    {
        Net::io_context Ioc;
        auto ClientHello = MakeClientHello();
        ASSERT_TRUE(ClientHello.has_value());
        ASSERT_GE(ClientHello->size(), std::size_t{5});
        EXPECT_EQ((*ClientHello)[0], 0x16U);
        EXPECT_EQ((*ClientHello)[1], 0x03U);

        auto Context = MakeTlsContextWithCertificate();
        ASSERT_NE(Context, nullptr);

        auto Raw = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Raw->ToRead = std::move(*ClientHello);
        auto Counted = std::make_shared<CloseCountingTransport>(Raw);

        Preview::Transport::NativeTlsRequest Request;
        Request.Inbound = std::static_pointer_cast<Preview::Transmission>(Counted);
        Request.Context = std::move(Context);
        constexpr auto ConfiguredTimeout = std::chrono::milliseconds(100);
        Request.Timeout = ConfiguredTimeout;

        Preview::Transport::NativeTlsResult Result;
        bool Completed = false;
        bool WatchdogFired = false;
        std::exception_ptr Failure;
        std::chrono::steady_clock::time_point StartedAt{};
        Net::steady_timer Watchdog(Ioc);
        Watchdog.expires_after(std::chrono::seconds(2));
        Watchdog.async_wait(
            [&](boost::system::error_code Error)
            {
                if (!Error)
                {
                    WatchdogFired = true;
                    Counted->Cancel();
                }
            });

        Net::co_spawn(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                StartedAt = std::chrono::steady_clock::now();
                Result = co_await Preview::Transport::UpgradeNativeTls(std::move(Request));
                Completed = true;
            },
            [&](std::exception_ptr Error)
            {
                Watchdog.cancel();
                Failure = std::move(Error);
            });
        Ioc.run();
        const auto Elapsed = std::chrono::steady_clock::now() - StartedAt;
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }

        EXPECT_TRUE(Completed);
        EXPECT_FALSE(WatchdogFired);
        EXPECT_GE(Elapsed, ConfiguredTimeout / 2);
        EXPECT_LT(Elapsed, std::chrono::milliseconds(500));
        EXPECT_EQ(Result.Code, Preview::Fault::Code::Timeout);
        EXPECT_EQ(Result.Transport, nullptr);
        EXPECT_TRUE(Result.Attempted);
        EXPECT_TRUE(Raw->IsClosed());
        EXPECT_EQ(Counted->CloseCalls, 1U);
    }

    TEST(NativeTls, RejectsNonPositiveDeadlineBeforeReading)
    {
        Net::io_context Ioc;
        auto Context = MakeTlsContextWithCertificate();
        ASSERT_NE(Context, nullptr);

        auto Raw = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Raw->ToRead = {0x16U, 0x03U};
        auto Counted = std::make_shared<CloseCountingTransport>(Raw);

        Preview::Transport::NativeTlsRequest Request;
        Request.Inbound = std::static_pointer_cast<Preview::Transmission>(Counted);
        Request.Context = std::move(Context);
        Request.Timeout = std::chrono::steady_clock::duration::zero();

        Preview::Transport::NativeTlsResult Result;
        bool Completed = false;
        bool WatchdogFired = false;
        std::exception_ptr Failure;
        Net::steady_timer Watchdog(Ioc);
        Watchdog.expires_after(std::chrono::seconds(2));
        Watchdog.async_wait(
            [&](boost::system::error_code Error)
            {
                if (!Error)
                {
                    WatchdogFired = true;
                    Counted->Cancel();
                }
            });

        Net::co_spawn(
            Ioc,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Preview::Transport::UpgradeNativeTls(std::move(Request));
                Completed = true;
            },
            [&](std::exception_ptr Error)
            {
                Watchdog.cancel();
                Failure = std::move(Error);
            });
        Ioc.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }

        EXPECT_TRUE(Completed);
        EXPECT_FALSE(WatchdogFired);
        EXPECT_EQ(Result.Code, Preview::Fault::Code::Timeout);
        EXPECT_FALSE(Result.Attempted);
        EXPECT_EQ(Raw->ReadsDone, 0U);
        EXPECT_TRUE(Raw->IsClosed());
        EXPECT_EQ(Counted->CloseCalls, 1U);
    }

    TEST(NativeTls, ReplaysOneBytePlainPrefixWhenReadReturnsErrorWithBytes)
    {
        Net::io_context Ioc;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Raw->ToRead = {0x41U, 0x42U};
        Raw->ReadErrorBytes = 1;
        Raw->SetReadError(std::make_error_code(std::errc::connection_reset));

        Preview::Transport::NativeTlsResult Result;
        RunCoro(Ioc,
                [&]() -> Net::awaitable<void>
                {
                    Result = co_await Preview::Transport::UpgradeNativeTls(
                        std::static_pointer_cast<Preview::Transmission>(Raw), MakeTlsContext());
                });

        EXPECT_EQ(Result.Code, Preview::Fault::Code::Success);
        ASSERT_NE(Result.Transport, nullptr);

        std::array<std::byte, 2> Replayed{};
        bool ReadSucceeded = false;
        RunCoro(Ioc,
                [&]() -> Net::awaitable<void>
                {
                    ReadSucceeded = co_await ReadExactly(Result.Transport, Replayed);
                });

        ASSERT_TRUE(ReadSucceeded);
        EXPECT_EQ(Replayed[0], std::byte{0x41});
        EXPECT_EQ(Replayed[1], std::byte{0x42});
    }

    TEST(NativeTls, ReplaysTwoBytePlainPrefixWhenReadReturnsErrorWithBytes)
    {
        Net::io_context Ioc;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Raw->ToRead = {0x16U, 0x01U, 0x42U};
        Raw->ReadErrorBytes = 2;
        Raw->SetReadError(std::make_error_code(std::errc::connection_reset));

        Preview::Transport::NativeTlsResult Result;
        RunCoro(Ioc,
                [&]() -> Net::awaitable<void>
                {
                    Result = co_await Preview::Transport::UpgradeNativeTls(
                        std::static_pointer_cast<Preview::Transmission>(Raw), MakeTlsContext());
                });

        EXPECT_EQ(Result.Code, Preview::Fault::Code::Success);
        ASSERT_NE(Result.Transport, nullptr);

        std::array<std::byte, 3> Replayed{};
        bool ReadSucceeded = false;
        RunCoro(Ioc,
                [&]() -> Net::awaitable<void>
                {
                    ReadSucceeded = co_await ReadExactly(Result.Transport, Replayed);
                });

        ASSERT_TRUE(ReadSucceeded);
        EXPECT_EQ(Replayed[0], std::byte{0x16});
        EXPECT_EQ(Replayed[1], std::byte{0x01});
        EXPECT_EQ(Replayed[2], std::byte{0x42});
    }

    TEST(NativeTls, ReturnsTerminalCodeForIncompleteTlsPrefixAfterReadError)
    {
        Net::io_context Ioc;
        auto Raw = std::make_shared<Preview::PreviewMockTransport>(Ioc.get_executor());
        Raw->ToRead = {0x16U};
        Raw->ReadErrorBytes = 1;
        Raw->SetReadError(std::make_error_code(std::errc::connection_reset));

        Preview::Transport::NativeTlsResult Result;
        RunCoro(Ioc,
                [&]() -> Net::awaitable<void>
                {
                    Result = co_await Preview::Transport::UpgradeNativeTls(
                        std::static_pointer_cast<Preview::Transmission>(Raw), MakeTlsContext());
                });

        EXPECT_EQ(Result.Code, Preview::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.Transport, nullptr);
        EXPECT_FALSE(Result.Attempted);
        EXPECT_TRUE(Raw->IsClosed());
    }

} // namespace

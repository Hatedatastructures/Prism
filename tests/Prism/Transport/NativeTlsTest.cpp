/**
 * @file NativeTlsTest.cpp
 * @brief Native TLS admission 的预读所有权与回放测试。
 * @details 通过真实 PreviewTransport 读取 UpgradeNativeTls 转移的预读字节，
 *          覆盖读操作同时返回有效字节和终止错误时的非 TLS 分流语义。
 */

#include <gtest/gtest.h>
#include "TransportResources.hpp"

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

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Transport/NativeTls.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>

namespace
{

    namespace Net = boost::asio;
    using Prism::SharedTransmission;

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

            });
        Ioc.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

    /** @brief 读取本fixture一次性错误之后仍保留的全部输入，同时保留首个真实失败。 */
    auto ReadReplayBytes(const SharedTransmission &Transport, std::span<std::byte> Buffer)
        -> Net::awaitable<Prism::IoResult>
    {
        Prism::IoResult Result;
        while (Result.Bytes < Buffer.size())
        {
            const auto Part = co_await Transport->ReadSome(Buffer.subspan(Result.Bytes));
            if (Result.Failure.Succeeded()) Result.Failure = Part.Failure;
            if (Part.Bytes == 0 || Part.Bytes > Buffer.size() - Result.Bytes) co_return Result;
            Result.Bytes += Part.Bytes;
        }
        co_return Result;
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
        constexpr unsigned char CommonName[] = "Prism Native TLS Test";
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

    class CloseCountingTransport final : public Prism::Transmission
    {
    public:
        explicit CloseCountingTransport(std::shared_ptr<Prism::PrismMockTransport> Inner)
            : Prism::Transmission(Inner->Executor()), Inner_(std::move(Inner))
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

        [[nodiscard]] auto NextLayer() noexcept -> Prism::Transmission * override
        {
            return Inner_.get();
        }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Inner_->ReadSome(Buffer, std::move(Handler));
        }

        auto StartWrite(
            std::span<const std::byte> Buffer, Completion Handler) -> void override
        {
            Inner_->WriteSome(Buffer, std::move(Handler));
        }

        auto OnClose() -> ControlResult override
        {
            ++CloseCalls;
            return Inner_->Close();

            return {};
        }

        auto OnCancel() -> ControlResult override
        {
            return Inner_->Cancel();

            return {};
        }

        std::size_t CloseCalls{0};

    private:
        std::shared_ptr<Prism::PrismMockTransport> Inner_;

        /** @brief 测试替身显式兑现半关闭；装饰器沿实际inner转交。 */
        auto StartWriteShutdown(Completion Handler) -> void override
        {
            if (auto* Inner = NextLayer()) { Inner->WriteShutdown(std::move(Handler)); return; }
            Prism::Transport::Detail::PostResult(std::move(Handler), {});
        }
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

        auto Raw = std::make_shared<Prism::PrismMockTransport>(Ioc.get_executor());
        Raw->ToRead = std::move(*ClientHello);
        auto Counted = std::make_shared<CloseCountingTransport>(Raw);

        Prism::Transport::NativeTlsRequest Request;
        Request.Bytes = Prism::Testing::MakeTransportBytes();
        Request.Inbound = std::static_pointer_cast<Prism::Transmission>(Counted);
        Request.Context = std::move(Context);
        constexpr auto ConfiguredTimeout = std::chrono::milliseconds(100);
        Request.Timeout = ConfiguredTimeout;

        Prism::Transport::NativeTlsResult Result;
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
                Result = co_await Prism::Transport::UpgradeNativeTls(std::move(Request));
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
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Timeout);
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

        auto Raw = std::make_shared<Prism::PrismMockTransport>(Ioc.get_executor());
        Raw->ToRead = {0x16U, 0x03U};
        auto Counted = std::make_shared<CloseCountingTransport>(Raw);

        Prism::Transport::NativeTlsRequest Request;
        Request.Bytes = Prism::Testing::MakeTransportBytes();
        Request.Inbound = std::static_pointer_cast<Prism::Transmission>(Counted);
        Request.Context = std::move(Context);
        Request.Timeout = std::chrono::steady_clock::duration::zero();

        Prism::Transport::NativeTlsResult Result;
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
                Result = co_await Prism::Transport::UpgradeNativeTls(std::move(Request));
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
        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Timeout);
        EXPECT_FALSE(Result.Attempted);
        EXPECT_EQ(Raw->ReadsDone, 0U);
        EXPECT_TRUE(Raw->IsClosed());
        EXPECT_EQ(Counted->CloseCalls, 1U);
    }

    TEST(NativeTls, ReplaysOneBytePlainPrefixWhenReadReturnsErrorWithBytes)
    {
        Net::io_context Ioc;
        auto Raw = std::make_shared<Prism::PrismMockTransport>(Ioc.get_executor());
        Raw->ToRead = {0x41U, 0x42U};
        Raw->ReadErrorBytes = 1;
        Raw->SetReadError(std::make_error_code(std::errc::connection_reset));

        Prism::Transport::NativeTlsResult Result;
        RunCoro(Ioc,
                [&]() -> Net::awaitable<void>
                {
                    Result = co_await Prism::Transport::UpgradeNativeTls(
                        Prism::Transport::NativeTlsRequest{std::static_pointer_cast<Prism::Transmission>(Raw), MakeTlsContext(), Prism::Transport::Encrypted::DefaultHandshakeTimeout, Prism::Testing::MakeTransportBytes()});
                });

        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Success);
        ASSERT_NE(Result.Transport, nullptr);

        std::array<std::byte, 2> Replayed{};
        Prism::IoResult ReplayResult;
        RunCoro(Ioc,
                [&]() -> Net::awaitable<void>
                {
                    ReplayResult = co_await ReadReplayBytes(Result.Transport, Replayed);
                });

        ASSERT_TRUE(ReplayResult.Bytes == Replayed.size() && ReplayResult.Failure.Native == std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(Replayed[0], std::byte{0x41});
        EXPECT_EQ(Replayed[1], std::byte{0x42});
    }

    TEST(NativeTls, ReplaysTwoBytePlainPrefixWhenReadReturnsErrorWithBytes)
    {
        Net::io_context Ioc;
        auto Raw = std::make_shared<Prism::PrismMockTransport>(Ioc.get_executor());
        Raw->ToRead = {0x16U, 0x01U, 0x42U};
        Raw->ReadErrorBytes = 2;
        Raw->SetReadError(std::make_error_code(std::errc::connection_reset));

        Prism::Transport::NativeTlsResult Result;
        RunCoro(Ioc,
                [&]() -> Net::awaitable<void>
                {
                    Result = co_await Prism::Transport::UpgradeNativeTls(
                        Prism::Transport::NativeTlsRequest{std::static_pointer_cast<Prism::Transmission>(Raw), MakeTlsContext(), Prism::Transport::Encrypted::DefaultHandshakeTimeout, Prism::Testing::MakeTransportBytes()});
                });

        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::Success);
        ASSERT_NE(Result.Transport, nullptr);

        std::array<std::byte, 3> Replayed{};
        Prism::IoResult ReplayResult;
        RunCoro(Ioc,
                [&]() -> Net::awaitable<void>
                {
                    ReplayResult = co_await ReadReplayBytes(Result.Transport, Replayed);
                });

        ASSERT_TRUE(ReplayResult.Bytes == Replayed.size() && ReplayResult.Failure.Native == std::make_error_code(std::errc::connection_reset));
        EXPECT_EQ(Replayed[0], std::byte{0x16});
        EXPECT_EQ(Replayed[1], std::byte{0x01});
        EXPECT_EQ(Replayed[2], std::byte{0x42});
    }

    TEST(NativeTls, ReturnsTerminalCodeForIncompleteTlsPrefixAfterReadError)
    {
        Net::io_context Ioc;
        auto Raw = std::make_shared<Prism::PrismMockTransport>(Ioc.get_executor());
        Raw->ToRead = {0x16U};
        Raw->ReadErrorBytes = 1;
        Raw->SetReadError(std::make_error_code(std::errc::connection_reset));

        Prism::Transport::NativeTlsResult Result;
        RunCoro(Ioc,
                [&]() -> Net::awaitable<void>
                {
                    Result = co_await Prism::Transport::UpgradeNativeTls(
                        Prism::Transport::NativeTlsRequest{std::static_pointer_cast<Prism::Transmission>(Raw), MakeTlsContext(), Prism::Transport::Encrypted::DefaultHandshakeTimeout, Prism::Testing::MakeTransportBytes()});
                });

        EXPECT_EQ(Result.Failure.Code, Prism::Fault::Code::ConnectionReset);
        EXPECT_EQ(Result.Transport, nullptr);
        EXPECT_FALSE(Result.Attempted);
        EXPECT_TRUE(Raw->IsClosed());
    }

} // namespace

/**
 * @file ConnTest.cpp
 * @brief Native 伪装方案测试（T2-1）
 * @details 验证原生 TLS 兜底：
 *          1. 自签证书服务端握手 + 数据直通（echo）
 *          2. 证书校验失败（客户端拒绝自签）
 *          3. 握手超时（客户端不发 ClientHello）
 *          4. 半包握手（分片发送 ClientHello）
 */

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Protocols/Ech/Key.hpp>
#include <Prism/Protocols/Ech/ServerKeys.hpp>
#include <Prism/Protocols/Native/Native.hpp>
#include <Prism/Transport/Connector.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include "../../../Transport/Core/Resources.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;

    struct PkeyContextDeleter
    {
        auto operator()(EVP_PKEY_CTX *Value) const noexcept -> void
        {
            EVP_PKEY_CTX_free(Value);
        }
    };

    struct PkeyDeleter
    {
        auto operator()(EVP_PKEY *Value) const noexcept -> void
        {
            EVP_PKEY_free(Value);
        }
    };

    struct X509Deleter
    {
        auto operator()(X509 *Value) const noexcept -> void
        {
            X509_free(Value);
        }
    };

    struct X509NameDeleter
    {
        auto operator()(X509_NAME *Value) const noexcept -> void
        {
            X509_NAME_free(Value);
        }
    };

    using PkeyContextPtr = std::unique_ptr<EVP_PKEY_CTX, PkeyContextDeleter>;
    using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
    using X509Ptr = std::unique_ptr<X509, X509Deleter>;
    using X509NamePtr = std::unique_ptr<X509_NAME, X509NameDeleter>;

    struct ConnectionResult
    {
        bool Success{false};
        bool HalfClosed{false};
        bool TimedOut{false};
        std::string ServerName;
        bool EchAccepted{false};
    };

    struct PairOutcome
    {
        ConnectionResult Client;
        ConnectionResult Server;
        bool ClientCompleted{false};
        bool ServerCompleted{false};
        bool DeadlineExpired{false};
        std::exception_ptr ClientException;
        std::exception_ptr ServerException;
    };

    struct SingleOutcome
    {
        ConnectionResult Result;
        bool Completed{false};
        bool DeadlineExpired{false};
        std::exception_ptr Exception;
    };

    struct PairRunRequest final
    {
        Net::io_context &IoContext;
        Prism::SharedTransmission ClientRaw;
        Prism::SharedTransmission ServerRaw;
        Net::awaitable<ConnectionResult> ClientOperation;
        Net::awaitable<ConnectionResult> ServerOperation;
        std::chrono::milliseconds Timeout;
    };

    struct EchClientRequest final
    {
        Prism::SharedTransmission Raw;
        Ssl::context& Context;
        std::string Payload;
        std::vector<std::uint8_t> EchConfigList;
        bool SendGrease{false};
        std::string ServerName{"secret.example"};
    };

    /** @brief 为 Native TLS ECH 接受测试提供文件路径和临时文件清理。 */
    struct TemporaryNativeEchFiles final
    {
        /** @brief 创建隔离目录。 */
        TemporaryNativeEchFiles()
        {
            Directory = std::filesystem::temp_directory_path() /
                ("PrismNativeEch-" + std::to_string(
                    std::chrono::steady_clock::now().time_since_epoch().count()));
            std::error_code Error;
            Created = std::filesystem::create_directory(Directory, Error) && !Error;
        }

        /** @brief 清理本测试创建的文件。 */
        ~TemporaryNativeEchFiles()
        {
            std::error_code Error;
            if (Created) std::filesystem::remove_all(Directory, Error);
        }

        /** @brief 写出原始 X25519 私钥与序列化 ECHConfig。 */
        [[nodiscard]] auto Write(const Prism::Ech::Detail::EchKeypair& Keypair) const -> bool
        {
            std::ofstream Key(Directory / "server.key", std::ios::binary);
            std::ofstream Config(Directory / "server.ech", std::ios::binary);
            if (!Key || !Config) return false;
            Key.write(reinterpret_cast<const char*>(Keypair.PrivateKey.data()),
                      static_cast<std::streamsize>(Keypair.PrivateKey.size()));
            Config.write(reinterpret_cast<const char*>(Keypair.EchConfig.data()),
                         static_cast<std::streamsize>(Keypair.EchConfig.size()));
            return Key.good() && Config.good();
        }

        /** @brief 返回 ECH 公共工厂使用的两个原始文件路径。 */
        [[nodiscard]] auto Files() const -> Prism::Ech::ServerKeyFiles
        {
            return {Directory / "server.key", Directory / "server.ech"};
        }

        std::filesystem::path Directory;
        bool Created{false};
    };

    struct SingleRunRequest final
    {
        Net::io_context &IoContext;
        Prism::SharedTransmission Raw;
        Net::awaitable<ConnectionResult> Operation;
        std::chrono::milliseconds Timeout;
    };

    struct PairCompletionState final
    {
        explicit PairCompletionState(PairRunRequest &Request)
            : Deadline(Request.IoContext), ClientRaw(Request.ClientRaw),
              ServerRaw(Request.ServerRaw), Timeout(Request.Timeout)
        {
        }

        PairOutcome Outcome;
        Net::steady_timer Deadline;
        Prism::SharedTransmission ClientRaw;
        Prism::SharedTransmission ServerRaw;
        std::chrono::milliseconds Timeout;

        auto ClosePair() -> void
        {
            if (ClientRaw)
            {
                (void)ClientRaw->Cancel();
                (void)ClientRaw->Close();
            }
            if (ServerRaw)
            {
                (void)ServerRaw->Cancel();
                (void)ServerRaw->Close();
            }
        }

        auto StopWhenComplete() -> void
        {
            if (Outcome.ClientCompleted && Outcome.ServerCompleted)
            {
                Deadline.cancel();
            }
        }

        auto OnClientComplete(std::exception_ptr Error, ConnectionResult Result) -> void
        {
            Outcome.ClientCompleted = true;
            Outcome.Client = Result;
            Outcome.ClientException = std::move(Error);
            if (Outcome.ClientException)
            {
                ClosePair();
            }
            StopWhenComplete();
        }

        auto OnServerComplete(std::exception_ptr Error, ConnectionResult Result) -> void
        {
            Outcome.ServerCompleted = true;
            Outcome.Server = Result;
            Outcome.ServerException = std::move(Error);
            if (Outcome.ServerException)
            {
                ClosePair();
            }
            StopWhenComplete();
        }

        auto OnDeadline(const boost::system::error_code &Error) -> void
        {
            if (Error || (Outcome.ClientCompleted && Outcome.ServerCompleted))
            {
                return;
            }
            Outcome.DeadlineExpired = true;
            ClosePair();
        }
    };

    /// 生成自签证书并加载到服务端上下文。
    [[nodiscard]] auto LoadSelfSigned(Ssl::context &Context) -> bool
    {
        PkeyContextPtr PkeyContext(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
        if (!PkeyContext || EVP_PKEY_keygen_init(PkeyContext.get()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(PkeyContext.get(), 2048) <= 0)
        {
            return false;
        }

        EVP_PKEY *PkeyValue = nullptr;
        if (EVP_PKEY_keygen(PkeyContext.get(), &PkeyValue) <= 0 || PkeyValue == nullptr)
        {
            return false;
        }
        PkeyPtr Pkey(PkeyValue);

        X509Ptr Certificate(X509_new());
        if (!Certificate || X509_set_version(Certificate.get(), 2) != 1 ||
            ASN1_INTEGER_set(X509_get_serialNumber(Certificate.get()), 1) != 1 ||
            X509_gmtime_adj(X509_get_notBefore(Certificate.get()), 0) == nullptr ||
            X509_gmtime_adj(X509_get_notAfter(Certificate.get()), 3600 * 24) == nullptr)
        {
            return false;
        }

        X509NamePtr Name(X509_NAME_new());
        if (!Name ||
            X509_NAME_add_entry_by_txt(Name.get(), "CN", MBSTRING_ASC,
                                       reinterpret_cast<const unsigned char *>("Native-test"), -1, -1, 0) != 1 ||
            X509_set_subject_name(Certificate.get(), Name.get()) != 1 ||
            X509_set_issuer_name(Certificate.get(), Name.get()) != 1 ||
            X509_set_pubkey(Certificate.get(), Pkey.get()) != 1 ||
            X509_sign(Certificate.get(), Pkey.get(), EVP_sha256()) <= 0)
        {
            return false;
        }

        auto *NativeContext = Context.native_handle();
        if (SSL_CTX_use_certificate(NativeContext, Certificate.get()) != 1 ||
            SSL_CTX_use_PrivateKey(NativeContext, Pkey.get()) != 1 ||
            SSL_CTX_check_private_key(NativeContext) != 1)
        {
            return false;
        }
        return true;
    }

    /// 运行两条相互依赖的 TLS coroutine，并观察两条 completion。
    [[nodiscard]] auto RunPair(PairRunRequest Request) -> PairOutcome
    {
        PairCompletionState State(Request);
        State.Deadline.expires_after(State.Timeout);
        State.Deadline.async_wait([&State](const boost::system::error_code &Error)
        { State.OnDeadline(Error); });
        Net::co_spawn(Request.IoContext, std::move(Request.ClientOperation),
            [&State](std::exception_ptr Error, ConnectionResult Result)
            { State.OnClientComplete(std::move(Error), Result); });
        Net::co_spawn(Request.IoContext, std::move(Request.ServerOperation),
            [&State](std::exception_ptr Error, ConnectionResult Result)
            { State.OnServerComplete(std::move(Error), Result); });
        Request.IoContext.run();
        return std::move(State.Outcome);
    }

    /// 运行单条 TLS coroutine，并在 deadline 后关闭仍挂起的传输。
    [[nodiscard]] auto RunSingle(SingleRunRequest Request) -> SingleOutcome
    {
        SingleOutcome Outcome;
        Net::steady_timer Deadline(Request.IoContext);

        auto OnComplete = [&](std::exception_ptr Error, ConnectionResult Result) -> void
        {
            Outcome.Completed = true;
            Outcome.Result = Result;
            Outcome.Exception = std::move(Error);
            Deadline.cancel();
        };

        auto OnDeadline = [&](const boost::system::error_code &Error) -> void
        {
            if (Error || Outcome.Completed) { return; }
            Outcome.DeadlineExpired = true;
            if (Request.Raw) { Request.Raw->Cancel(); Request.Raw->Close(); }
        };

        Deadline.expires_after(Request.Timeout);
        Deadline.async_wait(OnDeadline);
        Net::co_spawn(Request.IoContext, std::move(Request.Operation), OnComplete);
        Request.IoContext.run();
        return Outcome;
    }

    /// 客户端：TLS 握手 + 数据 echo + 服务端半关观测。
    [[nodiscard]] auto DoTlsClient(Prism::SharedTransmission Raw, Ssl::context &ClientContext,
                                   const std::string &Payload) -> Net::awaitable<ConnectionResult>
    {
        Prism::Transport::Connector Connector(std::move(Raw));
        auto Stream = std::make_shared<Ssl::stream<Prism::Transport::Connector>>(
            std::move(Connector), ClientContext);
        boost::system::error_code Error;
        co_await Stream->async_handshake(Ssl::stream_base::client,
                                         Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            Stream->next_layer().Transmission().Close();
            co_return ConnectionResult{};
        }

        const auto Written = co_await Net::async_write(
            *Stream, Net::buffer(Payload.data(), Payload.size()),
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error || Written != Payload.size())
        {
            Stream->next_layer().Transmission().Close();
            co_return ConnectionResult{};
        }

        std::array<char, 256> Buffer{};
        if (Payload.size() > Buffer.size())
        {
            Stream->next_layer().Transmission().Close();
            co_return ConnectionResult{};
        }
        Error.clear();
        const auto Read = co_await Net::async_read(
            *Stream, Net::buffer(Buffer.data(), Payload.size()),
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error || Read != Payload.size() ||
            std::memcmp(Buffer.data(), Payload.data(), Payload.size()) != 0)
        {
            Stream->next_layer().Transmission().Close();
            co_return ConnectionResult{};
        }

        Stream->next_layer().Transmission().Close();
        co_return ConnectionResult{true, false, false};
    }

    /** @brief 客户端按 ECHConfigList 发送 inner SNI，并通过 TLS echo 验证完整数据路径。 */
    [[nodiscard]] auto DoEchTlsClient(EchClientRequest Request)
        -> Net::awaitable<ConnectionResult>
    {
        Prism::Transport::Connector Connector(std::move(Request.Raw));
        auto Stream = std::make_shared<Ssl::stream<Prism::Transport::Connector>>(
            std::move(Connector), Request.Context);
        if (SSL_set_tlsext_host_name(Stream->native_handle(), Request.ServerName.c_str()) != 1)
        {
            Stream->next_layer().Transmission().Close();
            co_return ConnectionResult{};
        }
        if (Request.SendGrease)
        {
            SSL_set_enable_ech_grease(Stream->native_handle(), 1);
        }
        else if (SSL_set1_ech_config_list(Stream->native_handle(), Request.EchConfigList.data(),
                                           Request.EchConfigList.size()) != 1)
        {
            Stream->next_layer().Transmission().Close();
            co_return ConnectionResult{};
        }
        boost::system::error_code Error;
        co_await Stream->async_handshake(Ssl::stream_base::client,
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error)
        {
            Stream->next_layer().Transmission().Close();
            co_return ConnectionResult{};
        }
        const auto Written = co_await Net::async_write(
            *Stream, Net::buffer(Request.Payload.data(), Request.Payload.size()),
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error || Written != Request.Payload.size())
        {
            Stream->next_layer().Transmission().Close();
            co_return ConnectionResult{};
        }
        std::array<char, 256> Buffer{};
        if (Request.Payload.size() > Buffer.size())
        {
            Stream->next_layer().Transmission().Close();
            co_return ConnectionResult{};
        }
        const auto Read = co_await Net::async_read(
            *Stream, Net::buffer(Buffer.data(), Request.Payload.size()),
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error || Read != Request.Payload.size() ||
            std::memcmp(Buffer.data(), Request.Payload.data(), Request.Payload.size()) != 0)
        {
            Stream->next_layer().Transmission().Close();
            co_return ConnectionResult{};
        }
        Stream->next_layer().Transmission().Close();
        co_return ConnectionResult{true, false, false};
    }

    /// 服务端：Native Accept + 完整数据 echo + 半关。
    [[nodiscard]] auto DoNativeServer(Prism::SharedTransmission Raw, Ssl::context &ServerContext,
                                      const std::string &Payload) -> Net::awaitable<ConnectionResult>
    {
        auto Pool = Prism::Testing::MakeTransportBytes();
        auto Accepted = co_await Prism::Native::Accept(Prism::Native::AcceptRequest{
            std::move(Raw), ServerContext, std::move(Pool)});
        if (!Accepted)
        {
            co_return ConnectionResult{};
        }
        auto Transport = std::move(Accepted->Transport);
        if (Payload.size() > 256)
        {
            Transport->Close();
            co_return ConnectionResult{};
        }

        std::array<std::byte, 256> Buffer{};
        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        const auto Read = co_await Transport->ReadExact(std::span<std::byte>(Buffer).first(Payload.size()));
        if (Read.Failure.Failed() || Read.Bytes != Payload.size() ||
            std::memcmp(Buffer.data(), Payload.data(), Payload.size()) != 0)
        {
            Transport->Close();
            co_return ConnectionResult{};
        }

        const auto Written = co_await Transport->WriteExact(PayloadBytes);
        if (Written.Failure.Failed() || Written.Bytes != Payload.size())
        {
            Transport->Close();
            co_return ConnectionResult{};
        }
        Transport->Close();
        ConnectionResult Result{true, false, false};
        Result.ServerName = std::move(Accepted->ServerName);
        Result.EchAccepted = Accepted->EchAccepted;
        co_return Result;
    }

    /// 客户端：Native Connect + 完整数据 echo + 服务端半关观测。
    [[nodiscard]] auto DoNativeClient(Prism::SharedTransmission Raw, Ssl::context &ClientContext,
                                      const std::string &Payload) -> Net::awaitable<ConnectionResult>
    {
        auto Pool = Prism::Testing::MakeTransportBytes();
        auto Connected = co_await Prism::Native::Connect(Prism::Native::ConnectRequest{
            std::move(Raw), ClientContext, "Native-test", std::move(Pool)});
        if (!Connected)
        {
            co_return ConnectionResult{};
        }
        auto Transport = std::move(*Connected);
        if (Payload.size() > 256)
        {
            Transport->Close();
            co_return ConnectionResult{};
        }

        const auto PayloadBytes = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Payload.data()), Payload.size());
        const auto Written = co_await Transport->WriteExact(PayloadBytes);
        if (Written.Failure.Failed() || Written.Bytes != Payload.size())
        {
            Transport->Close();
            co_return ConnectionResult{};
        }

        std::array<std::byte, 256> Buffer{};
        const auto Read = co_await Transport->ReadExact(std::span<std::byte>(Buffer).first(Payload.size()));
        if (Read.Failure.Failed() || Read.Bytes != Payload.size() ||
            std::memcmp(Buffer.data(), Payload.data(), Payload.size()) != 0)
        {
            Transport->Close();
            co_return ConnectionResult{};
        }

        Transport->Close();
        co_return ConnectionResult{true, false, false};
    }

    /// 客户端：只执行 TLS 握手，供证书校验失败用例使用。
    [[nodiscard]] auto DoVerifyClient(Prism::SharedTransmission Raw, Ssl::context &ClientContext)
        -> Net::awaitable<ConnectionResult>
    {
        Prism::Transport::Connector Connector(std::move(Raw));
        auto Stream = std::make_shared<Ssl::stream<Prism::Transport::Connector>>(
            std::move(Connector), ClientContext);
        boost::system::error_code Error;
        co_await Stream->async_handshake(Ssl::stream_base::client,
                                         Net::redirect_error(Net::use_awaitable, Error));
        Stream->next_layer().Transmission().Close();
        co_return ConnectionResult{!Error, false, false};
    }

    /// 服务端：只执行 Native TLS 握手，供证书校验失败用例使用。
    [[nodiscard]] auto DoVerifyServer(Prism::SharedTransmission Raw, Ssl::context &ServerContext)
        -> Net::awaitable<ConnectionResult>
    {
        auto Pool = Prism::Testing::MakeTransportBytes();
        auto Accepted = co_await Prism::Native::Accept(Prism::Native::AcceptRequest{
            std::move(Raw), ServerContext, std::move(Pool)});
        if (Accepted)
        {
            auto Transport = std::move(Accepted->Transport);
            Transport->Close();
            co_return ConnectionResult{true, false, false};
        }
        co_return ConnectionResult{};
    }

    /// 服务端：在无客户端 ClientHello 时用底层读超时结束握手。
    [[nodiscard]] auto DoNativeServerTimeout(Prism::SharedTransmission Raw,
                                             Ssl::context &ServerContext) -> Net::awaitable<ConnectionResult>
    {
        Raw->SetTimeout(std::chrono::milliseconds(50));
        auto Pool = Prism::Testing::MakeTransportBytes();
        auto Accepted = co_await Prism::Native::Accept(Prism::Native::AcceptRequest{
            std::move(Raw), ServerContext, std::move(Pool)});
        if (Accepted)
        {
            auto Transport = std::move(Accepted->Transport);
            Transport->Close();
            co_return ConnectionResult{true, false, false};
        }
        co_return ConnectionResult{false, false, true};
    }
} // namespace

TEST(NativeConn, TlsHandshakeAndPassthrough)
{
    Net::io_context IoContext;

    Ssl::context ServerContext(Ssl::context::tlsv13);
    ASSERT_TRUE(LoadSelfSigned(ServerContext));

    Ssl::context ClientContext(Ssl::context::tlsv13);
    ClientContext.set_verify_mode(Ssl::verify_none);

    auto [A, B] = Prism::MakeMemoryPair(IoContext.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(A));
    auto Server = std::make_shared<Prism::MemoryStream>(std::move(B));
    const std::string Payload = "Native-tls-passthrough";

    const auto Outcome = RunPair(PairRunRequest{
        IoContext, Client, Server, DoTlsClient(Client, ClientContext, Payload),
        DoNativeServer(Server, ServerContext, Payload), std::chrono::seconds(2)});
    ASSERT_TRUE(Outcome.ClientCompleted);
    ASSERT_TRUE(Outcome.ServerCompleted);
    ASSERT_FALSE(Outcome.ClientException);
    ASSERT_FALSE(Outcome.ServerException);
    EXPECT_FALSE(Outcome.DeadlineExpired);
    EXPECT_TRUE(Outcome.Server.Success);
    EXPECT_TRUE(Outcome.Client.Success);
    Client->Close();
    Server->Close();
}

TEST(NativeConn, ClientFactoryTlsHandshakeAndPassthrough)
{
    Net::io_context IoContext;

    Ssl::context ServerContext(Ssl::context::tlsv13);
    ASSERT_TRUE(LoadSelfSigned(ServerContext));

    Ssl::context ClientContext(Ssl::context::tlsv13);
    ClientContext.set_verify_mode(Ssl::verify_none);

    auto [A, B] = Prism::MakeMemoryPair(IoContext.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(A));
    auto Server = std::make_shared<Prism::MemoryStream>(std::move(B));
    const std::string Payload = "Native-client-factory";

    const auto Outcome = RunPair(PairRunRequest{
        IoContext, Client, Server, DoNativeClient(Client, ClientContext, Payload),
        DoNativeServer(Server, ServerContext, Payload), std::chrono::seconds(2)});
    ASSERT_TRUE(Outcome.ClientCompleted);
    ASSERT_TRUE(Outcome.ServerCompleted);
    ASSERT_FALSE(Outcome.ClientException);
    ASSERT_FALSE(Outcome.ServerException);
    EXPECT_FALSE(Outcome.DeadlineExpired);
    EXPECT_TRUE(Outcome.Server.Success);
    EXPECT_EQ(Outcome.Server.ServerName, "Native-test");
    EXPECT_FALSE(Outcome.Server.EchAccepted);
    EXPECT_TRUE(Outcome.Client.Success);
    Client->Close();
    Server->Close();
}

TEST(NativeConn, AcceptReportsInnerSniAfterEchHandshake)
{
    Net::io_context IoContext;
    Ssl::context ServerContext(Ssl::context::tlsv13);
    ASSERT_TRUE(LoadSelfSigned(ServerContext));
    Prism::Ech::Detail::EchKeypair Keypair;
    ASSERT_EQ(Prism::Ech::Detail::GenerateKeypair("public.example", 32, Keypair),
              Prism::Fault::Code::Success);
    TemporaryNativeEchFiles Files;
    ASSERT_TRUE(Files.Created);
    ASSERT_TRUE(Files.Write(Keypair));
    auto Prepared = Prism::Ech::PrepareServerKeys(Files.Files());
    ASSERT_TRUE(Prepared);
    ASSERT_TRUE(Prism::Ech::InstallServerKeys(
        ServerContext.native_handle(), std::move(*Prepared)));

    Ssl::context ClientContext(Ssl::context::tlsv13);
    ClientContext.set_verify_mode(Ssl::verify_none);
    auto [A, B] = Prism::MakeMemoryPair(IoContext.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(A));
    auto Server = std::make_shared<Prism::MemoryStream>(std::move(B));
    const std::string Payload = "Native-ech-inner-sni";
    const auto Outcome = RunPair(PairRunRequest{
        IoContext, Client, Server,
        DoEchTlsClient(EchClientRequest{Client, ClientContext, Payload, Keypair.EchConfigList}),
        DoNativeServer(Server, ServerContext, Payload), std::chrono::seconds(2)});

    ASSERT_TRUE(Outcome.ClientCompleted);
    ASSERT_TRUE(Outcome.ServerCompleted);
    ASSERT_FALSE(Outcome.ClientException);
    ASSERT_FALSE(Outcome.ServerException);
    EXPECT_FALSE(Outcome.DeadlineExpired);
    EXPECT_TRUE(Outcome.Client.Success);
    EXPECT_TRUE(Outcome.Server.Success);
    EXPECT_TRUE(Outcome.Server.EchAccepted);
    EXPECT_EQ(Outcome.Server.ServerName, "secret.example");
    Client->Close();
    Server->Close();
}

TEST(NativeConn, AcceptsGreaseAndKeepsOuterSni)
{
    Net::io_context IoContext;
    Ssl::context ServerContext(Ssl::context::tlsv13);
    ASSERT_TRUE(LoadSelfSigned(ServerContext));
    Ssl::context ClientContext(Ssl::context::tlsv13);
    ClientContext.set_verify_mode(Ssl::verify_none);
    auto [A, B] = Prism::MakeMemoryPair(IoContext.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(A));
    auto Server = std::make_shared<Prism::MemoryStream>(std::move(B));
    const std::string Payload = "Native-ech-grease";
    const auto Outcome = RunPair(PairRunRequest{
        IoContext, Client, Server,
        DoEchTlsClient(EchClientRequest{
            Client, ClientContext, Payload, {}, true, "outer.example"}),
        DoNativeServer(Server, ServerContext, Payload), std::chrono::seconds(2)});

    ASSERT_TRUE(Outcome.ClientCompleted);
    ASSERT_TRUE(Outcome.ServerCompleted);
    EXPECT_FALSE(Outcome.DeadlineExpired);
    EXPECT_TRUE(Outcome.Client.Success);
    EXPECT_TRUE(Outcome.Server.Success);
    EXPECT_FALSE(Outcome.Server.EchAccepted);
    EXPECT_EQ(Outcome.Server.ServerName, "outer.example");
    Client->Close();
    Server->Close();
}

// 客户端校验失败：verify_peer 且无受信 CA -> 握手失败。
TEST(NativeConn, ClientVerifyFailure)
{
    Net::io_context IoContext;

    Ssl::context ServerContext(Ssl::context::tlsv13);
    ASSERT_TRUE(LoadSelfSigned(ServerContext));

    Ssl::context ClientContext(Ssl::context::tlsv13);
    ClientContext.set_verify_mode(Ssl::verify_peer);

    auto [A, B] = Prism::MakeMemoryPair(IoContext.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(A));
    auto Server = std::make_shared<Prism::MemoryStream>(std::move(B));

    const auto Outcome = RunPair(PairRunRequest{
        IoContext, Client, Server, DoVerifyClient(Client, ClientContext),
        DoVerifyServer(Server, ServerContext), std::chrono::seconds(2)});
    ASSERT_TRUE(Outcome.ClientCompleted);
    ASSERT_TRUE(Outcome.ServerCompleted);
    ASSERT_FALSE(Outcome.ClientException);
    ASSERT_FALSE(Outcome.ServerException);
    EXPECT_FALSE(Outcome.DeadlineExpired);
    EXPECT_FALSE(Outcome.Client.Success);
    EXPECT_FALSE(Outcome.Server.Success);
    Client->Close();
    Server->Close();
}

// 服务端没有收到 ClientHello 时，底层读超时必须结束 Native 握手。
TEST(NativeConn, ServerHandshakeTimeout)
{
    Net::io_context IoContext;

    Ssl::context ServerContext(Ssl::context::tlsv13);
    ASSERT_TRUE(LoadSelfSigned(ServerContext));

    auto [A, B] = Prism::MakeMemoryPair(IoContext.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(A));
    auto Server = std::make_shared<Prism::MemoryStream>(std::move(B));

    const auto Outcome = RunSingle(SingleRunRequest{
        IoContext, Server, DoNativeServerTimeout(Server, ServerContext),
        std::chrono::seconds(2)});
    ASSERT_TRUE(Outcome.Completed);
    ASSERT_FALSE(Outcome.Exception);
    EXPECT_FALSE(Outcome.DeadlineExpired);
    EXPECT_FALSE(Outcome.Result.Success);
    EXPECT_TRUE(Outcome.Result.TimedOut);
    Client->Close();
    Server->Close();
}

// 半包握手：客户端分片发送 ClientHello -> 服务端仍完成握手。
TEST(NativeConn, FragmentedClientHello)
{
    Net::io_context IoContext;

    Ssl::context ServerContext(Ssl::context::tlsv13);
    ASSERT_TRUE(LoadSelfSigned(ServerContext));

    Ssl::context ClientContext(Ssl::context::tlsv13);
    ClientContext.set_verify_mode(Ssl::verify_none);

    auto [A, B] = Prism::MakeMemoryPair(IoContext.get_executor());
    auto Client = std::make_shared<Prism::MemoryStream>(std::move(A));
    auto Server = std::make_shared<Prism::MemoryStream>(std::move(B));
    const std::string Payload = "fragmented-hello";

    const auto Outcome = RunPair(PairRunRequest{
        IoContext, Client, Server, DoTlsClient(Client, ClientContext, Payload),
        DoNativeServer(Server, ServerContext, Payload), std::chrono::seconds(2)});
    ASSERT_TRUE(Outcome.ClientCompleted);
    ASSERT_TRUE(Outcome.ServerCompleted);
    ASSERT_FALSE(Outcome.ClientException);
    ASSERT_FALSE(Outcome.ServerException);
    EXPECT_FALSE(Outcome.DeadlineExpired);
    EXPECT_TRUE(Outcome.Server.Success);
    EXPECT_TRUE(Outcome.Client.Success);
    Client->Close();
    Server->Close();
}

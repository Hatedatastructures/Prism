/**
 * @file SessionRecognitionModeTest.cpp
 * @brief Session Profile/CandidateId winner 分发与 legacy 兼容测试
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <Preview/Composition/Recognition/CandidateFactory.hpp>
#include <Preview/Composition/Adapters/Vless.hpp>
#include <Preview/Composition/Recognition/ProfileBuilder.hpp>
#include <Preview/Account/Account.hpp>
#include <Preview/Foundation/Authenticator.hpp>
#include <Preview/Foundation/Utility/Crypto/Base64.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <Preview/Protocols/Vless/Vless.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include "../recognition/RecognitionWire.hpp"

namespace
{

    namespace Net = boost::asio;
    namespace Ssl = Net::ssl;
    namespace Core = Preview::Recognition;
    namespace Composition = Preview::Composition::Recognition;
    using CodeChannel = Net::experimental::channel<void(boost::system::error_code, Preview::Fault::Code)>;
    using ClientFlow = std::function<Net::awaitable<Preview::Error>(Preview::SharedTransmission)>;

    struct ProfileFlowResult
    {
        Preview::Fault::Code SessionCode{Preview::Fault::Code::Success};
        Preview::Error ClientError{Preview::Error::None};
        std::size_t ResolverCalls{0};
    };

    struct SessionWaitRequest
    {
        std::shared_ptr<CodeChannel> Done;
        std::shared_ptr<Preview::MemoryStream> Client;
        std::shared_ptr<Preview::MemoryStream> Inbound;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    struct SessionNativeTlsProbeResult final
    {
        bool CompletedBeforeWatchdog{false};
        bool SessionCompleted{false};
        Preview::Fault::Code Code{Preview::Fault::Code::GenericError};
    };

    struct SessionNativeTlsProbeRequest final
    {
        Net::any_io_executor Executor;
        std::shared_ptr<Preview::Runtime::Session> Session;
        std::shared_ptr<Preview::PreviewMockTransport> Raw;
        std::shared_ptr<CodeChannel> Done;
        std::shared_ptr<SessionNativeTlsProbeResult> Result;
    };

    auto MakeTls13ClientHello() -> std::vector<std::uint8_t>
    {
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ClientContext(
            SSL_CTX_new(TLS_client_method()), &SSL_CTX_free);
        if (!ClientContext || SSL_CTX_set_min_proto_version(ClientContext.get(), TLS1_3_VERSION) != 1 ||
            SSL_CTX_set_max_proto_version(ClientContext.get(), TLS1_3_VERSION) != 1)
        {
            return {};
        }

        std::unique_ptr<SSL, decltype(&SSL_free)> Client(SSL_new(ClientContext.get()), &SSL_free);
        auto *ReadBio = BIO_new(BIO_s_mem());
        auto *WriteBio = BIO_new(BIO_s_mem());
        if (!Client || !ReadBio || !WriteBio)
        {
            BIO_free(ReadBio);
            BIO_free(WriteBio);
            return {};
        }
        SSL_set_bio(Client.get(), ReadBio, WriteBio);
        if (SSL_set_tlsext_host_name(Client.get(), "example.com") != 1)
        {
            return {};
        }
        SSL_set_connect_state(Client.get());
        const auto HandshakeResult = SSL_do_handshake(Client.get());
        if (HandshakeResult == 1 || SSL_get_error(Client.get(), HandshakeResult) != SSL_ERROR_WANT_READ)
        {
            return {};
        }

        const auto Pending = BIO_ctrl_pending(WriteBio);
        if (Pending <= 0 || Pending > std::numeric_limits<int>::max())
        {
            return {};
        }
        std::vector<std::uint8_t> ClientHello(static_cast<std::size_t>(Pending));
        const auto Read = BIO_read(WriteBio, ClientHello.data(), static_cast<int>(ClientHello.size()));
        if (Read < 0 || static_cast<std::size_t>(Read) != ClientHello.size())
        {
            return {};
        }
        return ClientHello;
    }

    auto MakeSessionNativeTlsContext() -> std::shared_ptr<Ssl::context>
    {
        auto Context = std::make_shared<Ssl::context>(Ssl::context::tls_server);
        auto Repository = std::filesystem::absolute(__FILE__);
        for (std::size_t Depth = 0; Depth < 5; ++Depth)
        {
            Repository = Repository.parent_path();
        }
        Context->use_certificate_chain_file((Repository / "cert.pem").string());
        Context->use_private_key_file((Repository / "key.pem").string(), Ssl::context::pem);
        return Context;
    }

    auto RunSessionNativeTlsProbe(SessionNativeTlsProbeRequest Request) -> Net::awaitable<void>
    {
        Net::co_spawn(
            Request.Executor,
            Request.Session->Run(std::static_pointer_cast<Preview::Transmission>(Request.Raw)),
            [Done = Request.Done](std::exception_ptr Failure, Preview::Fault::Code Code)
            {
                (void)Done->try_send(
                    boost::system::error_code{},
                    Failure ? Preview::Fault::Code::IoError : Code);
            });

        Net::steady_timer Watchdog(Request.Executor);
        Watchdog.expires_after(std::chrono::milliseconds(250));
        boost::system::error_code Error;
        using Net::experimental::awaitable_operators::operator||;
        const auto Race = co_await (
            Request.Done->async_receive(Net::redirect_error(Net::use_awaitable, Error)) ||
            Watchdog.async_wait(Net::use_awaitable));
        if (Race.index() == 0U)
        {
            Request.Result->CompletedBeforeWatchdog = true;
            Request.Result->SessionCompleted = true;
            Request.Result->Code = std::get<0>(Race);
            co_return;
        }

        Request.Raw->SetReadError(std::make_error_code(std::errc::connection_reset));
        Net::steady_timer DrainWatchdog(Request.Executor);
        DrainWatchdog.expires_after(std::chrono::seconds(2));
        const auto DrainRace = co_await (
            Request.Done->async_receive(Net::redirect_error(Net::use_awaitable, Error)) ||
            DrainWatchdog.async_wait(Net::use_awaitable));
        if (DrainRace.index() == 0U)
        {
            Request.Result->SessionCompleted = true;
            Request.Result->Code = std::get<0>(DrainRace);
        }
    }

    auto CountSessionNativeTlsAccept(
        std::shared_ptr<std::size_t> Calls,
        Preview::SharedTransmission &Inbound,
        Preview::Middleware::Context &Context) -> Net::awaitable<Preview::Fault::Code>
    {
        (void)Inbound;
        (void)Context;
        ++*Calls;
        co_return Preview::Fault::Code::Success;
    }

    auto WaitForSession(SessionWaitRequest Request)
        -> Net::awaitable<std::pair<bool, Preview::Fault::Code>>
    {
        using Net::experimental::awaitable_operators::operator||;
        const auto Executor = co_await Net::this_coro::executor;
        Net::steady_timer Watchdog(Executor);
        Watchdog.expires_after(std::chrono::seconds(5));
        boost::system::error_code DoneError;
        auto Completion = co_await (
            Request.Done->async_receive(Net::redirect_error(Net::use_awaitable, DoneError)) ||
            Watchdog.async_wait(Net::use_awaitable));
        if (Completion.index() == 0U)
        {
            co_return std::pair{true, std::get<0>(Completion)};
        }

        Request.Client->Close();
        Request.Inbound->Close();
        Watchdog.expires_after(std::chrono::seconds(1));
        auto Grace = co_await (
            Request.Done->async_receive(Net::redirect_error(Net::use_awaitable, DoneError)) ||
            Watchdog.async_wait(Net::use_awaitable));
        if (Grace.index() == 0U)
        {
            co_return std::pair{true, std::get<0>(Grace)};
        }
        co_return std::pair{false, Preview::Fault::Code::Timeout};
    }

    auto RunProfileFlow(Preview::Runtime::SessionOptions Options, ClientFlow Flow)
        -> ProfileFlowResult
    {
        Net::io_context Io;
        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto Client = std::make_shared<Preview::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(Reader));
        auto Done = std::make_shared<CodeChannel>(Io.get_executor(), 1);
        auto ResolverCalls = std::make_shared<std::size_t>(0);
        auto ExistingResolver = Options.Resolver;
        if (Options.ResolveCandidate)
        {
            ExistingResolver = Options.ResolveCandidate;
        }
        Options.ResolveCandidate = [ExistingResolver, ResolverCalls](Core::CandidateId Id)
            -> Preview::Runtime::SessionOptions::ProtocolAcceptFn
        {
            ++*ResolverCalls;
            if (ExistingResolver)
            {
                return ExistingResolver(Id);
            }
            return Preview::Runtime::SessionOptions::ProtocolAcceptFn{};
        };
        const auto Executor = Io.get_executor();
        Options.Dial = [Executor](const Preview::Network::Target &)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            auto [Upstream, Peer] = Preview::MakeMemoryPair(Executor);
            Peer.Close();
            co_return std::pair{Preview::Fault::Code::Success,
                                std::make_shared<Preview::MemoryStream>(std::move(Upstream))};
        };

        ProfileFlowResult Result;
        Preview::Testing::RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                auto Failure = std::make_shared<std::exception_ptr>();
                auto SessionCode = std::make_shared<Preview::Fault::Code>(Preview::Fault::Code::IoError);
                auto SessionCoroutine = [Done, Inbound, Failure, SessionCode,
                                         Options = std::move(Options)]() mutable -> Net::awaitable<void>
                {
                    Preview::Runtime::Session Session(std::move(Options));
                    *SessionCode = co_await Session.Run(Inbound);
                };
                auto Completion = [Done, Failure, SessionCode](std::exception_ptr Error)
                {
                    *Failure = std::move(Error);
                    if (*Failure)
                    {
                        *SessionCode = Preview::Fault::Code::IoError;
                    }
                    (void)Done->try_send(boost::system::error_code{}, *SessionCode);
                };
                Net::co_spawn(Io.get_executor(), std::move(SessionCoroutine),
                              std::move(Completion));
                Result.ClientError = co_await Flow(Client);
                Client->Close();
                const auto SessionResult = co_await WaitForSession(
                    {Done, Client, Inbound, Failure});
                EXPECT_TRUE(SessionResult.first);
                EXPECT_FALSE(*Failure);
                Result.SessionCode = SessionResult.second;
                Inbound->Close();
            });
        Result.ResolverCalls = *ResolverCalls;
        return Result;
    }

    auto MakeConfiguredOptions(Composition::CandidateBinding Binding)
        -> Preview::Runtime::SessionOptions
    {
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Mode = Core::RecognitionMode::Configured;
        auto Built = Composition::ProfileBuilder::Build(std::move(Binding), std::move(BuilderOptions));
        EXPECT_TRUE(Built.has_value());
        Preview::Runtime::SessionOptions Options;
        if (Built)
        {
            Options.Profile = Built->Profile;
            Options.ResolveCandidate = Built->Resolver;
        }
        return Options;
    }

    auto MakeMixedOptions(std::vector<Composition::CandidateBinding> Bindings)
        -> Preview::Runtime::SessionOptions
    {
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Mode = Core::RecognitionMode::MixedTrial;
        BuilderOptions.Budget.MaxCandidates = 2;
        auto Built = Composition::ProfileBuilder::Build(std::move(Bindings), std::move(BuilderOptions));
        EXPECT_TRUE(Built.has_value());
        Preview::Runtime::SessionOptions Options;
        if (Built)
        {
            Options.Profile = Built->Profile;
            Options.ResolveCandidate = Built->Resolver;
        }
        return Options;
    }

    auto MakeDeterministicOptions(std::vector<Composition::CandidateBinding> Bindings)
        -> Preview::Runtime::SessionOptions
    {
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Mode = Core::RecognitionMode::Deterministic;
        BuilderOptions.Budget.MaxCandidates = 2;
        auto Built = Composition::ProfileBuilder::Build(std::move(Bindings), std::move(BuilderOptions));
        EXPECT_TRUE(Built.has_value());
        Preview::Runtime::SessionOptions Options;
        if (Built)
        {
            Options.Profile = Built->Profile;
            Options.ResolveCandidate = Built->Resolver;
        }
        return Options;
    }

    auto RunSocks5Client(Preview::SharedTransmission Client, Preview::Socks5::ClientConfig Config)
        -> Net::awaitable<Preview::Error>
    {
        const Preview::Socks5::Address Target{Preview::Socks5::AddressType::Domain, "example.com", 443};
        auto [Error, Conn] = co_await Preview::Socks5::Connect(std::move(Client), Config, Target);
        if (Conn)
        {
            Conn->Close();
        }
        co_return Error;
    }

    auto RunVlessClient(Preview::SharedTransmission Client, Preview::Vless::ClientConfig Config)
        -> Net::awaitable<Preview::Error>
    {
        const Preview::Vless::Address Target{Preview::Vless::AddressType::Domain, "example.com", 443};
        auto [Error, Conn] = co_await Preview::Vless::Connect(std::move(Client), Config, Target);
        if (Conn)
        {
            Conn->Close();
        }
        co_return Error;
    }

    auto RunTrojanClient(Preview::SharedTransmission Client, std::string Password)
        -> Net::awaitable<Preview::Error>
    {
        const Preview::Trojan::Address Target{Preview::Trojan::AddressType::Domain, "example.com", 443};
        Preview::Trojan::ClientConfig Config{std::move(Password)};
        auto [Error, Conn] = co_await Preview::Trojan::Connect(
            Preview::Trojan::ConnectParameters{std::move(Client), Config, Target});
        if (Conn)
        {
            Conn->Close();
        }
        co_return Error;
    }

    auto RunVmessClient(Preview::SharedTransmission Client, Preview::Vmess::ClientConfig Config)
        -> Net::awaitable<Preview::Error>
    {
        const Preview::Vmess::Address Target{Preview::Vmess::AddressType::Domain, "example.com", 443};
        auto [Error, Conn] = co_await Preview::Vmess::Connect(std::move(Client), Config, Target);
        if (Conn)
        {
            Conn->Close();
        }
        co_return Error;
    }

    auto RunSs2022Client(Preview::SharedTransmission Client,
                         std::array<std::uint8_t, 16> Psk)
        -> Net::awaitable<Preview::Error>
    {
        const Preview::Shadowsocks2022::Address Target{
            Preview::Shadowsocks2022::AddressType::Domain, "example.com", 443};
        auto Conn = std::make_shared<Preview::Shadowsocks2022::Conn<>>(Psk);
        const auto Error = co_await Conn->WriteHandshake(std::move(Client), Target);
        Conn->Close();
        co_return Error;
    }

    auto RunHttpSession(Preview::Runtime::SessionOptions Options, std::size_t &ResolverCalls,
                        std::size_t &LegacyCalls) -> Preview::Fault::Code
    {
        Net::io_context Io;
        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto Client = std::make_shared<Preview::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(Reader));
        auto Done = std::make_shared<CodeChannel>(Io.get_executor(), 1);
        // CONNECT 200 只能在 Dial 成功后发送；本测试的 Profile 路径
        // 同时注入 legacy acceptor 并让 Dial 失败，不能把旧的提前响应
        // 行为当作 candidate resolver 契约的一部分。
        const bool ExpectResponse = static_cast<bool>(Options.Profile) &&
                                     !static_cast<bool>(Options.AcceptProtocol);
        Preview::Fault::Code Result = Preview::Fault::Code::Success;
        Preview::Testing::RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                auto Failure = std::make_shared<std::exception_ptr>();
                auto SessionCode = std::make_shared<Preview::Fault::Code>(Preview::Fault::Code::IoError);
                auto SessionCoroutine = [Done, Inbound, Failure, SessionCode,
                                         Options = std::move(Options)]() mutable -> Net::awaitable<void>
                {
                    Preview::Runtime::Session Session(std::move(Options));
                    *SessionCode = co_await Session.Run(Inbound);
                };
                auto Completion = [Done, Failure, SessionCode](std::exception_ptr Error)
                {
                    *Failure = std::move(Error);
                    if (*Failure)
                    {
                        *SessionCode = Preview::Fault::Code::IoError;
                    }
                    (void)Done->try_send(boost::system::error_code{}, *SessionCode);
                };
                Net::co_spawn(Io.get_executor(), std::move(SessionCoroutine),
                              std::move(Completion));
                const auto Request = Preview::Testing::RecognitionWire::MakeHttp();
                std::error_code WriteError;
                co_await Client->async_write_some(Request, WriteError);
                if (ExpectResponse)
                {
                    std::array<std::byte, 128> Reply{};
                    std::error_code ReadError;
                    const auto Count = co_await Client->async_read_some(Reply, ReadError);
                    EXPECT_FALSE(ReadError);
                    EXPECT_NE(std::string_view(reinterpret_cast<const char *>(Reply.data()), Count).find("200"),
                              std::string_view::npos);
                }
                const auto SessionResult = co_await WaitForSession(
                    {Done, Client, Inbound, Failure});
                EXPECT_TRUE(SessionResult.first);
                EXPECT_FALSE(*Failure);
                Result = SessionResult.second;
                Client->Close();
                Inbound->Close();
            });
        return Result;
    }

    TEST(SessionRecognitionMode, DispatchesByCandidateIdAndSkipsLegacyAcceptor)
    {
        auto Binding = Composition::CandidateFactory::MakeHttp(5);
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Mode = Core::RecognitionMode::Configured;
        auto Built = Composition::ProfileBuilder::Build(std::move(Binding), std::move(BuilderOptions));
        ASSERT_TRUE(Built.has_value());

        std::size_t ResolverCalls = 0;
        std::size_t LegacyCalls = 0;
        Preview::Runtime::SessionOptions Options;
        Options.Profile = Built->Profile;
        Options.ResolveCandidate = [Resolver = Built->Resolver, &ResolverCalls](Core::CandidateId Id)
            -> Preview::Runtime::SessionOptions::ProtocolAcceptFn
        {
            ++ResolverCalls;
            return Resolver(Id);
        };
        Options.AcceptProtocol = [&LegacyCalls](Preview::SharedTransmission &, Preview::Middleware::Context &)
            -> Net::awaitable<Preview::Fault::Code>
        {
            ++LegacyCalls;
            co_return Preview::Fault::Code::ProtocolError;
        };
        Options.Dial = [](const Preview::Network::Target &)
            -> Net::awaitable<std::pair<Preview::Fault::Code, Preview::SharedTransmission>>
        {
            co_return std::pair{Preview::Fault::Code::NotSupported, Preview::SharedTransmission{}};
        };
        const auto Result = RunHttpSession(std::move(Options), ResolverCalls, LegacyCalls);
        EXPECT_EQ(Result, Preview::Fault::Code::NotSupported);
        EXPECT_EQ(ResolverCalls, 1U);
        EXPECT_EQ(LegacyCalls, 0U);
    }

    TEST(SessionRecognitionMode, LegacyAcceptorRemainsAvailableWithoutProfile)
    {
        std::size_t ResolverCalls = 0;
        std::size_t LegacyCalls = 0;
        Preview::Runtime::SessionOptions Options;
        Options.AcceptProtocol = [&LegacyCalls](Preview::SharedTransmission &Inbound,
                                                Preview::Middleware::Context &)
            -> Net::awaitable<Preview::Fault::Code>
        {
            ++LegacyCalls;
            if (Inbound)
            {
                Inbound->Close();
            }
            co_return Preview::Fault::Code::NotSupported;
        };
        const auto Result = RunHttpSession(std::move(Options), ResolverCalls, LegacyCalls);
        EXPECT_EQ(Result, Preview::Fault::Code::NotSupported);
        EXPECT_EQ(ResolverCalls, 0U);
        EXPECT_EQ(LegacyCalls, 1U);
    }

    TEST(SessionRecognitionMode, ConfiguredSocks5ProfileRunsAuthenticatedHandler)
    {
        Preview::Socks5::ServerConfig ServerConfig;
        ServerConfig.EnableAuth = true;
        ServerConfig.username = "alice";
        ServerConfig.password = "secret";
        auto Options = MakeConfiguredOptions(
            Composition::CandidateFactory::MakeSocks5(11, ServerConfig));
        const auto Flow = [ServerConfig](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            Preview::Socks5::ClientConfig Config;
            Config.EnableAuth = true;
            Config.username = ServerConfig.username;
            Config.password = ServerConfig.password;
            co_return co_await RunSocks5Client(std::move(Client), Config);
        };

        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

    TEST(SessionRecognitionMode, ConfiguredVlessProfileRunsHandlerAndRejectsWrongUuid)
    {
        const auto GoodUuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        const auto BadUuid = Preview::Testing::RecognitionWire::MakeUuid(9);
        auto Options = MakeConfiguredOptions(
            Composition::CandidateFactory::MakeVless(12, Preview::Vless::ServerConfig{GoodUuid}));
        const auto Flow = [GoodUuid](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunVlessClient(std::move(Client), Preview::Vless::ClientConfig{GoodUuid});
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(Result.ResolverCalls, 1U);

        auto BadOptions = MakeConfiguredOptions(
            Composition::CandidateFactory::MakeVless(13, Preview::Vless::ServerConfig{GoodUuid}));
        const auto BadFlow = [BadUuid](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunVlessClient(std::move(Client), Preview::Vless::ClientConfig{BadUuid});
        };
        const auto BadResult = RunProfileFlow(std::move(BadOptions), BadFlow);
        EXPECT_NE(BadResult.ClientError, Preview::Error::None);
        EXPECT_EQ(BadResult.ResolverCalls, 0U);
    }

    TEST(SessionRecognitionMode, ConfiguredTrojanProfileRunsHandler)
    {
        auto Options = MakeConfiguredOptions(
            Composition::CandidateFactory::MakeTrojan(14, Preview::Trojan::ServerConfig{"trojan-secret"}));
        const auto Flow = [](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunTrojanClient(std::move(Client), "trojan-secret");
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

    TEST(SessionRecognitionMode, ProtocolAuthenticationDoesNotRunGenericAuthAgain)
    {
        auto Options = MakeConfiguredOptions(
            Composition::CandidateFactory::MakeTrojan(22, Preview::Trojan::ServerConfig{"trojan-secret"}));
        Options.Auth = std::make_shared<Preview::RejectAuthenticator>();
        const auto Flow = [](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunTrojanClient(std::move(Client), "trojan-secret");
        };

        const auto Result = RunProfileFlow(std::move(Options), Flow);

        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_NE(Result.SessionCode, Preview::Fault::Code::AuthFailed);
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

    TEST(SessionRecognitionMode, ProtocolHandlerTransfersAccountLease)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(41);
        std::array<std::byte, 16> CredentialBytes{};
        for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
        {
            CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        const auto Record = std::make_shared<const Preview::Account::AccountRecord>(
            Preview::Account::AccountRecord::CreateRequest{
                .AccountId = Preview::AccountId{7201},
                .CredentialValue = Preview::Account::Credential::Uuid(CredentialBytes),
                .Quota = {.MaxConnections = 1}});
        Preview::Account::AccountDirectory Directory;
        ASSERT_TRUE(Directory.Upsert(Record));
        auto Authenticator = std::make_shared<Preview::DirectoryAuthenticator>(&Directory);

        Preview::Vless::ServerConfig Config;
        Config.uuid = Uuid;
        Config.AuthenticatorOwner = Authenticator;
        auto Handler = std::make_shared<Preview::Runtime::Handler::Vless>(Config);

        Net::io_context Io;
        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto Client = std::make_shared<Preview::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(Reader));
        Preview::Runtime::Handler::AcceptResult Result;

        Preview::Testing::RunCoro(
            Io,
            [Client, Inbound, Handler, Uuid, &Result]() -> Net::awaitable<void>
            {
                const auto Wire = Preview::Testing::RecognitionWire::MakeVless(Uuid);
                std::error_code Error;
                co_await Client->async_write_some(Wire, Error);
                Result = co_await Handler->Accept(Inbound);
            });

        EXPECT_EQ(Result.err, Preview::Error::None);
        EXPECT_TRUE(Result.ProtocolAuthenticated);
        EXPECT_EQ(Result.AccountId, Preview::AccountId{7201});
        EXPECT_TRUE(Result.AccountLease);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        Result.AccountLease.Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
    }

    TEST(SessionRecognitionMode, ConfiguredVmessProfileRunsHandler)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(21);
        auto Options = MakeConfiguredOptions(
            Composition::CandidateFactory::MakeVmess(15, Preview::Vmess::ServerConfig{Uuid}));
        const auto Flow = [Uuid](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunVmessClient(std::move(Client), Preview::Vmess::ClientConfig{Uuid});
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

    TEST(SessionRecognitionMode, ConfiguredSs2022ProfileUsesBase64Psk)
    {
        const auto Psk = Preview::Testing::RecognitionWire::MakePsk(0x51);
        Preview::Shadowsocks2022::ServerConfig Config;
        Config.password = Preview::Crypto::Base64Encode(std::span<const std::uint8_t>(Psk));
        auto Options = MakeConfiguredOptions(Composition::CandidateFactory::MakeSs2022(16, Config));
        const auto Flow = [Psk](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunSs2022Client(std::move(Client), Psk);
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

    TEST(SessionRecognitionMode, MixedTrialProfileResolvesAuthenticatedWinner)
    {
        const auto GoodUuid = Preview::Testing::RecognitionWire::MakeUuid(31);
        std::vector<Composition::CandidateBinding> Bindings;
        Bindings.push_back(Composition::CandidateFactory::MakeVless(
            18, Preview::Vless::ServerConfig{GoodUuid}));
        Bindings.push_back(Composition::CandidateFactory::MakeVmess(
            19, Preview::Vmess::ServerConfig{Preview::Testing::RecognitionWire::MakeUuid(32)}));
        auto Options = MakeMixedOptions(std::move(Bindings));
        const auto Flow = [GoodUuid](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunVlessClient(std::move(Client), Preview::Vless::ClientConfig{GoodUuid});
        };

        const auto Result = RunProfileFlow(std::move(Options), Flow);

        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

    TEST(SessionRecognitionMode, DeterministicProfileResolvesByStructuralSelector)
    {
        std::vector<Composition::CandidateBinding> Bindings;
        Bindings.push_back(Composition::CandidateFactory::MakeHttp(20));
        Bindings.push_back(Composition::CandidateFactory::MakeSocks5(21));
        auto Options = MakeDeterministicOptions(std::move(Bindings));
        const auto Flow = [](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunSocks5Client(std::move(Client), Preview::Socks5::ClientConfig{});
        };

        const auto Result = RunProfileFlow(std::move(Options), Flow);

        EXPECT_EQ(Result.ClientError, Preview::Error::None);
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

    TEST(SessionRecognitionMode, InvalidSs2022Base64DoesNotReachResolver)
    {
        const auto Psk = Preview::Testing::RecognitionWire::MakePsk(0x61);
        Preview::Shadowsocks2022::ServerConfig Config;
        Config.password = "not-base64-psk";
        auto Options = MakeConfiguredOptions(Composition::CandidateFactory::MakeSs2022(17, Config));
        const auto Flow = [Psk](Preview::SharedTransmission Client)
            -> Net::awaitable<Preview::Error>
        {
            co_return co_await RunSs2022Client(std::move(Client), Psk);
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_NE(Result.SessionCode, Preview::Fault::Code::Success);
        EXPECT_EQ(Result.ResolverCalls, 0U);
    }

    TEST(SessionRecognitionMode, SessionCancellationStopsRecognitionBeforeAccept)
    {
        Net::io_context Io;
        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto Client = std::make_shared<Preview::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(Reader));
        auto Control = std::make_shared<Preview::Runtime::SessionControl>(Io.get_executor());
        auto PrepareEntered = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
        auto ReleasePrepare = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
        auto PrepareCompleted = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(Io.get_executor(), 1);
        auto SessionDone = std::make_shared<CodeChannel>(Io.get_executor(), 1);
        auto AcceptCalls = std::make_shared<std::size_t>(0);

        Composition::CandidateBinding Binding;
        Binding.Spec.Id = 60;
        Binding.Spec.Name = "blocked-opaque";
        Binding.Spec.Protocol = Core::ProtocolType::Http;
        Binding.Spec.Kind = Core::CandidateKind::Opaque;
        Binding.Spec.FirstBytes = {0x42U};
        Binding.Spec.MinimumBytes = 1;
        Binding.Spec.RequiresAuthentication = true;
        Binding.Spec.Inspect = [](const Core::ProbeSnapshot &) { return Core::MatchState::Structural; };
        Binding.Spec.Prepare = [PrepareEntered, ReleasePrepare, PrepareCompleted](Core::PrepareContext Context)
            -> Net::awaitable<Core::PrepareResult>
        {
            (void)Context;
            (void)PrepareEntered->try_send(boost::system::error_code{});
            boost::system::error_code Error;
            co_await ReleasePrepare->async_receive(Net::redirect_error(Net::use_awaitable, Error));
            (void)PrepareCompleted->try_send(boost::system::error_code{});
            Core::PrepareResult Result;
            Result.Status = Core::RecognitionStatus::Accepted;
            co_return Result;
        };
        Binding.Spec.Commit = [](Core::CommitContext Context) -> Net::awaitable<Core::CommitResult>
        {
            Core::CommitResult Result;
            Result.Status = Core::RecognitionStatus::Accepted;
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        Binding.Accept = [AcceptCalls](Preview::SharedTransmission &, Preview::Middleware::Context &)
            -> Net::awaitable<Preview::Fault::Code>
        {
            ++*AcceptCalls;
            co_return Preview::Fault::Code::Success;
        };
        auto Built = Composition::ProfileBuilder::Build(std::move(Binding));
        ASSERT_TRUE(Built.has_value());

        Preview::Runtime::SessionOptions Options;
        Options.Control = Control;
        Options.Profile = Built->Profile;
        Options.ResolveCandidate = Built->Resolver;

        Preview::Fault::Code SessionCode = Preview::Fault::Code::IoError;
        bool TimedOut = false;
        Preview::Testing::RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Net::co_spawn(
                    Io,
                    [Inbound, SessionDone, Options = std::move(Options), &SessionCode]() mutable
                        -> Net::awaitable<void>
                    {
                        Preview::Runtime::Session Session(std::move(Options));
                        SessionCode = co_await Session.Run(Inbound);
                        (void)SessionDone->try_send(boost::system::error_code{}, SessionCode);
                    },
                    Net::detached);

                std::array<std::byte, 1> Prefix{std::byte{0x42}};
                std::error_code WriteError;
                co_await Client->async_write_some(Prefix, WriteError);

                boost::system::error_code EnteredError;
                co_await PrepareEntered->async_receive(
                    Net::redirect_error(Net::use_awaitable, EnteredError));
                Control->Cancel();
                (void)ReleasePrepare->try_send(boost::system::error_code{});

                Net::steady_timer Watchdog(Io);
                Watchdog.expires_after(std::chrono::seconds(2));
                boost::system::error_code DoneError;
                using Net::experimental::awaitable_operators::operator||;
                auto Race = co_await (
                    SessionDone->async_receive(Net::redirect_error(Net::use_awaitable, DoneError)) ||
                    Watchdog.async_wait(Net::use_awaitable));
                if (Race.index() == 1U)
                {
                    TimedOut = true;
                    Inbound->Close();
                }
                boost::system::error_code PrepareError;
                co_await PrepareCompleted->async_receive(
                    Net::redirect_error(Net::use_awaitable, PrepareError));
            });

        EXPECT_FALSE(TimedOut);
        EXPECT_EQ(SessionCode, Preview::Fault::Code::Canceled);
        EXPECT_EQ(*AcceptCalls, 0U);
    }

    TEST(SessionNativeTls, FallbackDeadlineCoversHandshakeAfterCompleteClientHello)
    {
        Net::io_context Io;
        auto ClientHello = MakeTls13ClientHello();
        ASSERT_FALSE(ClientHello.empty());

        auto Raw = std::make_shared<Preview::PreviewMockTransport>(Io.get_executor());
        Raw->ToRead = std::move(ClientHello);
        auto Services = std::make_shared<Preview::Runtime::SessionServices>();
        Services->NativeTls = MakeSessionNativeTlsContext();
        Services->HandshakeTimeout = std::chrono::milliseconds(20);

        auto AcceptCalls = std::make_shared<std::size_t>(0);
        const auto Accept = std::bind_front(CountSessionNativeTlsAccept, AcceptCalls);
        Services->AcceptProtocol = Accept;
        Preview::Runtime::SessionOptions Options;
        Options.Services = Services;
        Options.AcceptProtocol = Accept;
        auto Session = std::make_shared<Preview::Runtime::Session>(std::move(Options));
        auto Done = std::make_shared<CodeChannel>(Io.get_executor(), 1);
        auto Result = std::make_shared<SessionNativeTlsProbeResult>();

        Preview::Testing::RunCoro(
            Io,
            RunSessionNativeTlsProbe(SessionNativeTlsProbeRequest{
                Io.get_executor(), Session, Raw, Done, Result}));

        EXPECT_TRUE(Result->CompletedBeforeWatchdog);
        EXPECT_TRUE(Result->SessionCompleted);
        EXPECT_EQ(Result->Code, Preview::Fault::Code::Timeout);
        EXPECT_FALSE(Raw->IsOpen());
        EXPECT_FALSE(Raw->Written.empty());
        EXPECT_EQ(*AcceptCalls, 0U);
    }

} // namespace

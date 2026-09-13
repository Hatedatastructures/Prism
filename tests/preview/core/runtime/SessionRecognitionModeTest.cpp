/**
 * @file SessionRecognitionModeTest.cpp
 * @brief Session Profile/CandidateId winner 分发与 legacy 兼容测试
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <preview/Composition/Recognition/CandidateFactory.hpp>
#include <preview/Composition/Adapters/Vless.hpp>
#include <preview/Composition/Recognition/ProfileBuilder.hpp>
#include <preview/Foundation/Utility/Account/Authenticator.hpp>
#include <preview/Foundation/Utility/Account/Directory.hpp>
#include <preview/Foundation/Utility/Crypto/Base64.hpp>
#include <preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <preview/Protocols/Socks5/Socks5.hpp>
#include <preview/Protocols/Trojan/Trojan.hpp>
#include <preview/Protocols/Vless/Vless.hpp>
#include <preview/Protocols/Vmess/Vmess.hpp>
#include <preview/Runtime/Session.hpp>
#include <preview/Transport/MemoryStream.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include "../recognition/RecognitionWire.hpp"

namespace
{

    namespace Net = boost::asio;
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
                Net::co_spawn(
                    Io.get_executor(),
                    [Done, Inbound, Options = std::move(Options)]() mutable -> Net::awaitable<void>
                    {
                        Preview::Runtime::Session Session(std::move(Options));
                        const auto Code = co_await Session.Run(Inbound);
                        Done->try_send(boost::system::error_code{}, Code);
                    },
                    Net::detached);
                Result.ClientError = co_await Flow(Client);
                Client->Close();
                boost::system::error_code DoneError;
                Result.SessionCode = co_await Done->async_receive(
                    Net::redirect_error(Net::use_awaitable, DoneError));
                EXPECT_FALSE(DoneError);
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
        const bool ExpectResponse = static_cast<bool>(Options.Profile);
        Preview::Fault::Code Result = Preview::Fault::Code::Success;
        Preview::Testing::RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Net::co_spawn(
                    Io.get_executor(),
                    [&, Done, Inbound, Options = std::move(Options)]() mutable -> Net::awaitable<void>
                    {
                        Preview::Runtime::Session Session(std::move(Options));
                        const auto Code = co_await Session.Run(Inbound);
                        Done->try_send(boost::system::error_code{}, Code);
                    },
                    Net::detached);
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
                boost::system::error_code DoneError;
                Result = co_await Done->async_receive(
                    Net::redirect_error(Net::use_awaitable, DoneError));
                EXPECT_FALSE(DoneError);
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
        const std::string Credential(reinterpret_cast<const char *>(Uuid.data()), Uuid.size());
        Preview::Account::Directory Directory;
        Directory.Upsert(Credential, 1);
        auto Authenticator = std::make_shared<Preview::Account::DirectoryAuthenticator>(&Directory);

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
        ASSERT_TRUE(Result.AccountLease.has_value());
        EXPECT_TRUE(*Result.AccountLease);
        EXPECT_EQ(Directory.Find(Credential)->Active(), 1U);
        Result.AccountLease.reset();
        EXPECT_EQ(Directory.Find(Credential)->Active(), 0U);
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

} // namespace

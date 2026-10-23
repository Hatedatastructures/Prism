#include <TestSupport/Prism/ProtocolIngressBindings.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
/**
 * @file SessionAdmissionTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "SessionModeSupport.hpp"

#include <Prism/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Prism/Protocols/Http1/Binding.hpp>
#include <Prism/Runtime/Recognition/Profile.hpp>
#include <Prism/Runtime/Session/RecognitionAdmission.hpp>

#include <boost/asio/system_executor.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <utility>

namespace
{
    /** @brief 保留一次 VLESS 入站交换所需的客户端、handler、输入和凭据。 */
    struct VlessAccountLeaseExchange final
    {
        std::shared_ptr<Prism::MemoryStream> Client;
        std::shared_ptr<Prism::Vless::IngressFactory> Handler;
        Prism::Contract::StreamAcceptInput Input;
        std::array<std::uint8_t, 16> Uuid{};
    };

    /** @brief 写入原始 VLESS 请求后，将同一入站输入交给 handler 接受。 */
    [[nodiscard]] auto RunVlessAccountLeaseExchange(VlessAccountLeaseExchange Exchange)
        -> Net::awaitable<Prism::Contract::AcceptOutcome>
    {
        const auto Wire = Prism::Testing::RecognitionWire::MakeVless(Exchange.Uuid);
        const auto Written = co_await Exchange.Client->WriteExact(
            std::span<const std::byte>{Wire});
        if (Written.Failure.Failed())
        {
            co_return std::unexpected(Written.Failure);
        }
        co_return co_await Exchange.Handler->Accept(std::move(Exchange.Input));
    }

    auto RetireVlessAcceptedPlane(
        const std::shared_ptr<Prism::Vless::IngressFactory>& Handler,
        Prism::Contract::AcceptOutcome& Outcome,
        Prism::Fault::Failure& Retirement) -> Net::awaitable<void>
    {
        auto RootTransport = Outcome->Transport();
        const auto RootClose = RootTransport->Close();
        if (!RootClose) Retirement = RootClose.error();
        const auto RootRetirement = co_await RootTransport->Activity()->Drain();
        if (!RootRetirement && !Retirement.Failed())
            Retirement = RootRetirement.error();
        Outcome->Root = Prism::Contract::StreamDataPlane{};
        Handler->Close();
        const auto Drained = co_await Handler->Drain();
        if (!Drained && !Retirement.Failed()) Retirement = Drained.error();
    }

    /**
     * @brief 无 profile 时记录 direct acceptor 调用并返回原始 NotSupported。
     */
    struct DirectRejectFactory final
    {
        std::size_t &Calls;

        auto operator()(Prism::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            ++Calls;
            if (Input.Inbound)
            {
                std::array<std::byte, 1> Prefix{};
                const auto Read = co_await Input.Inbound->ReadSome(Prefix);
                if (Read.Failure.Failed())
                {
                    co_return std::unexpected(Read.Failure);
                }
                Input.Inbound->Close();
            }
            co_return std::unexpected(Prism::Contract::FailureFromProtocolError(Prism::Error::Unsupported));
        }
    };

    [[nodiscard]] auto MakeTlsRouteCandidate(
        const Prism::Recognition::CandidateId Id,
        std::string Name,
        std::string Scheme) -> Prism::Recognition::CandidateSpec
    {
        Prism::Composition::Recognition::TlsCandidateOptions Options;
        Options.Id = Id;
        Options.Name = std::move(Name);
        Options.Scheme = std::move(Scheme);
        Options.ServerNames = {"inner.example", "outer.example", "foreign.example"};
        Options.HasNativeTlsContext = true;
        auto Binding = Prism::Composition::Recognition::TlsCandidateFactory::Make(
            std::move(Options),
            [](Prism::Recognition::CarrierAcceptInput Input)
                -> boost::asio::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });
        return std::move(Binding.Spec);
    }
}

TEST(SessionRecognitionMode, EchAndGreaseRouteByNegotiatedSniWithinSameCarrier)
    {
        Prism::Recognition::ProfileSpec Spec;
        Spec.Mode = Prism::Recognition::RecognitionMode::MixedTrial;
        Spec.Candidates.push_back(MakeTlsRouteCandidate(1, "native-inner", "native"));
        Spec.Candidates.push_back(MakeTlsRouteCandidate(2, "native-outer", "native"));
        Spec.Candidates.push_back(MakeTlsRouteCandidate(3, "ws-foreign", "ws"));
        Spec.Routes.emplace_back("inner.example", 1);
        Spec.Routes.emplace_back("outer.example", 2);
        Spec.Routes.emplace_back("foreign.example", 3);
        const auto Compiled = Prism::Recognition::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());

        Prism::Recognition::CarrierMetadata Accepted;
        Accepted.Carrier = "native";
        Accepted.Sni = "inner.example";
        Accepted.EchAccepted = true;
        Accepted.NativeTlsEstablished = true;
        const auto InnerRoute = Prism::Runtime::Detail::ResolveNegotiatedTlsRoute(
            Compiled->get(), Accepted);
        ASSERT_TRUE(InnerRoute.has_value());
        ASSERT_TRUE(InnerRoute->has_value());
        EXPECT_EQ((**InnerRoute).Id(), 1U);

        auto Grease = Accepted;
        Grease.Sni = "outer.example";
        Grease.EchAccepted = false;
        const auto OuterRoute = Prism::Runtime::Detail::ResolveNegotiatedTlsRoute(
            Compiled->get(), Grease);
        ASSERT_TRUE(OuterRoute.has_value());
        ASSERT_TRUE(OuterRoute->has_value());
        EXPECT_EQ((**OuterRoute).Id(), 2U);

        auto CrossCarrier = Accepted;
        CrossCarrier.Sni = "foreign.example";
        const auto Rejected = Prism::Runtime::Detail::ResolveNegotiatedTlsRoute(
            Compiled->get(), CrossCarrier);
        ASSERT_FALSE(Rejected.has_value());
        EXPECT_EQ(Rejected.error().Code, Prism::Fault::Code::ProtocolError);

        Accepted.NativeTlsEstablished = false;
        const auto UnauthenticatedAcceptance =
            Prism::Runtime::Detail::ResolveNegotiatedTlsRoute(Compiled->get(), Accepted);
        ASSERT_FALSE(UnauthenticatedAcceptance.has_value());
        EXPECT_EQ(UnauthenticatedAcceptance.error().Code, Prism::Fault::Code::ProtocolError);
    }

TEST(SessionRecognitionMode, DispatchesByCandidateIdAndSkipsDirectFactory)
    {
        auto HttpFactory = std::make_shared<Prism::Http11::Binding>(
            Prism::Http11::PreparedBinding{
                .Instance = "session-recognition-http",
                .Executor = boost::asio::system_executor(),
                .RequireAuth = false});
        auto Binding = Composition::CandidateFactory::MakeHttp(
            Prism::Composition::Recognition::CandidateOptions{5}, std::move(HttpFactory));
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Mode = Core::RecognitionMode::Configured;
        auto Built = Composition::ProfileBuilder::Build(std::move(Binding), std::move(BuilderOptions));
        ASSERT_TRUE(Built.has_value());

        std::size_t ResolverCalls = 0;
        std::size_t DirectCalls = 0;
        Prism::Runtime::SessionOptions Options;
        Options.Services->Bytes = MakeSessionRecognitionBytePool();
        Options.Services->Profile = Built->Profile;
        Options.Services->ResolveCandidate = [Resolver = Built->Resolver, &ResolverCalls](Core::CandidateId Id)
            -> std::shared_ptr<Prism::Contract::StreamFactory>
        {
            ++ResolverCalls;
            return Resolver(Id);
        };
        Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>([&DirectCalls](Prism::Contract::StreamAcceptInput)
            -> Net::awaitable<Prism::Contract::AcceptOutcome>
        {
            ++DirectCalls;
            co_return std::unexpected(Prism::Contract::FailureFromProtocolError(Prism::Error::ProtocolError));
        });
        Options.Services->Dial = [](const Prism::Network::Target &)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        };
        const auto Result = RunHttpSession(std::move(Options));
        EXPECT_EQ(Result, Prism::Fault::Code::NotSupported);
        EXPECT_EQ(ResolverCalls, 1U);
        EXPECT_EQ(DirectCalls, 0U);
    }

TEST(SessionRecognitionMode, DirectAcceptorRemainsAvailableWithoutProfile)
    {
        std::size_t ResolverCalls = 0;
        std::size_t DirectCalls = 0;
        Prism::Runtime::SessionOptions Options;
        Options.Services->Bytes = MakeSessionRecognitionBytePool();
        Options.Services->AcceptProtocol = std::make_shared<Prism::Testing::StreamFactory>(
            DirectRejectFactory{DirectCalls});
        const auto Result = RunHttpSession(std::move(Options));
        EXPECT_EQ(Result, Prism::Fault::Code::NotSupported);
        EXPECT_EQ(ResolverCalls, 0U);
        EXPECT_EQ(DirectCalls, 1U);
    }

TEST(SessionRecognitionMode, ConfiguredSocks5ProfileRunsAuthenticatedHandler)
    {
        Prism::Socks5::ServerConfig ServerConfig;
        ServerConfig.EnableAuth = true;
        ServerConfig.Authenticator = Prism::Testing::ProviderAccount(Prism::Testing::ProviderAccountInput{Prism::AccountId{1U}, Prism::Account::Credential::Password("secret"), "alice", "alice", {}})->Authenticator;
        auto Options = MakeConfiguredOptions(
            Composition::CandidateFactory::MakeSocks5(Composition::CandidateOptions{11}, Prism::Testing::MakeSocks5Binding(ServerConfig)));
        const auto Flow = [ServerConfig](Prism::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            Prism::Socks5::ClientConfig Config;
            Config.EnableAuth = true;
            Config.Username = "alice";
            Config.Password = "secret";
            co_return co_await RunSocks5Client(std::move(Client), Config);
        };

        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_FALSE(Result.ClientFailure.Failed());
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

TEST(SessionRecognitionMode, ConfiguredVlessProfileRunsHandlerAndRejectsWrongUuid)
    {
        const auto GoodUuid = Prism::Testing::RecognitionWire::MakeUuid(1);
        const auto BadUuid = Prism::Testing::RecognitionWire::MakeUuid(9);
        auto Options = MakeConfiguredOptions(
            Prism::Testing::MakeVlessCandidate(Prism::Composition::Recognition::CandidateOptions{12}, Prism::Vless::ServerConfig{GoodUuid}));
        const auto Flow = [GoodUuid](Prism::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await RunVlessClient(std::move(Client), Prism::Vless::ClientConfig{GoodUuid});
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_FALSE(Result.ClientFailure.Failed());
        EXPECT_EQ(Result.ResolverCalls, 1U);

        auto BadOptions = MakeConfiguredOptions(
            Prism::Testing::MakeVlessCandidate(Prism::Composition::Recognition::CandidateOptions{13}, Prism::Vless::ServerConfig{GoodUuid}));
        const auto BadFlow = [BadUuid](Prism::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await RunVlessClient(std::move(Client), Prism::Vless::ClientConfig{BadUuid});
        };
        const auto BadResult = RunProfileFlow(std::move(BadOptions), BadFlow);
        EXPECT_TRUE(BadResult.ClientFailure.Failed());
        EXPECT_EQ(BadResult.ResolverCalls, 0U);
    }

TEST(SessionRecognitionMode, ConfiguredTrojanProfileRunsHandler)
    {
        auto Options = MakeConfiguredOptions(
            Prism::Testing::MakeTrojanCandidate(Prism::Composition::Recognition::CandidateOptions{14}, Prism::Trojan::ServerConfig{"trojan-secret"}));
        const auto Flow = [](Prism::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await RunTrojanClient(std::move(Client), "trojan-secret");
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_FALSE(Result.ClientFailure.Failed());
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

TEST(SessionRecognitionMode, ProtocolAuthenticationDoesNotRunGenericAuthAgain)
    {
        auto Options = MakeConfiguredOptions(
            Prism::Testing::MakeTrojanCandidate(Prism::Composition::Recognition::CandidateOptions{22}, Prism::Trojan::ServerConfig{"trojan-secret"}));
        const auto Flow = [](Prism::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await RunTrojanClient(std::move(Client), "trojan-secret");
        };

        const auto Result = RunProfileFlow(std::move(Options), Flow);

        EXPECT_FALSE(Result.ClientFailure.Failed());
        EXPECT_NE(Result.SessionCode, Prism::Fault::Code::AuthFailed);
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

TEST(SessionRecognitionMode, ProtocolHandlerTransfersAccountLease)
    {
        Net::io_context Io;
        const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(41);
        std::array<std::byte, 16> CredentialBytes{};
        for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
        {
            CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Uuid(CredentialBytes), Prism::AccountId{7201},
            {.MaxConnections = 1});
        const auto Record = Directory->Store->FindById(Prism::AccountId{7201});
        ASSERT_TRUE(Record);
        auto Authenticator = Directory->Authenticator;
        auto UseState = Prism::Testing::MakeProtocolIngressUseState();

        Prism::Vless::ServerConfig Config;
        Config.uuid = Uuid;
        Config.AuthenticatorOwner = Authenticator;
        auto Handler = Prism::Testing::MakeVlessIngress(Config,
            Prism::Testing::ProtocolIngressResources{{}, UseState, Io.get_executor()},
            Prism::Vless::IngressRoute{});

        auto [Writer, Reader] = Prism::MakeMemoryPair(Io.get_executor());
        auto Client = std::make_shared<Prism::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(Reader));
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U * 1024U, 64U});
        Prism::Contract::AcceptOutcome Result{std::unexpected(
            Prism::Contract::FailureFromProtocolError(Prism::Error::NotOpen))};

        Prism::Testing::RunCoro(
            Io,
            [Client, Inbound, Handler, Bytes, UseState, Uuid, &Result]() -> Net::awaitable<void>
            {
                Result = co_await RunVlessAccountLeaseExchange({
                    Client, Handler,
                    Prism::Contract::StreamAcceptInput{Inbound, {}, Bytes, UseState}, Uuid});
            });

        ASSERT_TRUE(Result);
        EXPECT_TRUE(Result->ProtocolAuthenticated);
        EXPECT_EQ(Result->AccountId, Prism::AccountId{7201});
        ASSERT_TRUE(Result->AccountLease);
        EXPECT_TRUE(Result->AccountLease);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        Result->AccountLease.Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        Prism::Fault::Failure Retirement;
        Io.restart();
        Prism::Testing::RunCoro(Io, RetireVlessAcceptedPlane(Handler, Result, Retirement));
        EXPECT_FALSE(Retirement.Failed());
        EXPECT_TRUE(Handler->IsRetired());
    }

TEST(SessionRecognitionMode, ConfiguredVmessProfileRunsHandler)
    {
        const auto Uuid = Prism::Testing::RecognitionWire::MakeUuid(21);
        auto Options = MakeConfiguredOptions(
            Prism::Testing::MakeVmessCandidate(Prism::Composition::Recognition::CandidateOptions{15}, Prism::Vmess::ServerConfig{Uuid}));
        const auto Flow = [Uuid](Prism::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await RunVmessClient(std::move(Client), Prism::Vmess::ClientConfig{Uuid});
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_FALSE(Result.ClientFailure.Failed());
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

TEST(SessionRecognitionMode, ConfiguredSs2022ProfileUsesTypedPsk)
    {
        const auto Psk = Prism::Testing::RecognitionWire::MakePsk(0x51);
        Prism::Shadowsocks2022::ServerConfig Config;
        Config.Psk = Psk;
        auto Options = MakeConfiguredOptions(Composition::CandidateFactory::MakeSs2022(Composition::CandidateOptions{16}, Prism::Testing::MakeSs2022Binding(Config)));
        const auto Flow = [Psk](Prism::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await RunSs2022Client(std::move(Client), Psk);
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_FALSE(Result.ClientFailure.Failed());
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

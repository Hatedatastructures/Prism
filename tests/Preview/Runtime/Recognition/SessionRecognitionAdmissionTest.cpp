#include <TestSupport/Preview/ProtocolIngressBindings.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
/**
 * @file SessionRecognitionAdmissionTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "SessionRecognitionModeTestSupport.hpp"

#include <Preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Preview/Protocols/Http1/Binding.hpp>
#include <Preview/Runtime/Recognition/Profile.hpp>
#include <Preview/Runtime/Session/Detail/NegotiatedTlsRoute.hpp>

#include <boost/asio/system_executor.hpp>

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <utility>

namespace
{
    /**
     * @brief 无 profile 时记录 direct acceptor 调用并返回原始 NotSupported。
     */
    struct DirectRejectFactory final
    {
        std::size_t &Calls;

        auto operator()(Preview::Contract::StreamAcceptInput Input) const
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            ++Calls;
            if (Input.Inbound)
            {
                Input.Inbound->Close();
            }
            co_return std::unexpected(Preview::Contract::FailureFromProtocolError(Preview::Error::NotSupported));
        }
    };

    [[nodiscard]] auto MakeTlsRouteCandidate(
        const Preview::Recognition::CandidateId Id,
        std::string Name,
        std::string Scheme) -> Preview::Recognition::CandidateSpec
    {
        Preview::Composition::Recognition::TlsCandidateOptions Options;
        Options.Id = Id;
        Options.Name = std::move(Name);
        Options.Scheme = std::move(Scheme);
        Options.ServerNames = {"inner.example", "outer.example", "foreign.example"};
        Options.HasNativeTlsContext = true;
        auto Binding = Preview::Composition::Recognition::TlsCandidateFactory::Make(
            std::move(Options),
            [](Preview::Recognition::CarrierAcceptInput Input)
                -> boost::asio::awaitable<Preview::Recognition::CarrierAcceptResult>
            {
                Preview::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });
        return std::move(Binding.Spec);
    }
}

TEST(SessionRecognitionMode, EchAndGreaseRouteByNegotiatedSniWithinSameCarrier)
    {
        Preview::Recognition::ProfileSpec Spec;
        Spec.Mode = Preview::Recognition::RecognitionMode::MixedTrial;
        Spec.Candidates.push_back(MakeTlsRouteCandidate(1, "native-inner", "native"));
        Spec.Candidates.push_back(MakeTlsRouteCandidate(2, "native-outer", "native"));
        Spec.Candidates.push_back(MakeTlsRouteCandidate(3, "ws-foreign", "ws"));
        Spec.Routes.emplace_back("inner.example", 1);
        Spec.Routes.emplace_back("outer.example", 2);
        Spec.Routes.emplace_back("foreign.example", 3);
        const auto Compiled = Preview::Recognition::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Compiled.has_value());

        Preview::Recognition::CarrierMetadata Accepted;
        Accepted.Carrier = "native";
        Accepted.Sni = "inner.example";
        Accepted.EchAccepted = true;
        Accepted.NativeTlsEstablished = true;
        const auto InnerRoute = Preview::Runtime::Detail::ResolveNegotiatedTlsRoute(
            Compiled->get(), Accepted);
        ASSERT_TRUE(InnerRoute.has_value());
        ASSERT_TRUE(InnerRoute->has_value());
        EXPECT_EQ((**InnerRoute).Id(), 1U);

        auto Grease = Accepted;
        Grease.Sni = "outer.example";
        Grease.EchAccepted = false;
        const auto OuterRoute = Preview::Runtime::Detail::ResolveNegotiatedTlsRoute(
            Compiled->get(), Grease);
        ASSERT_TRUE(OuterRoute.has_value());
        ASSERT_TRUE(OuterRoute->has_value());
        EXPECT_EQ((**OuterRoute).Id(), 2U);

        auto CrossCarrier = Accepted;
        CrossCarrier.Sni = "foreign.example";
        const auto Rejected = Preview::Runtime::Detail::ResolveNegotiatedTlsRoute(
            Compiled->get(), CrossCarrier);
        ASSERT_FALSE(Rejected.has_value());
        EXPECT_EQ(Rejected.error().Code, Preview::Fault::Code::ProtocolError);

        Accepted.NativeTlsEstablished = false;
        const auto UnauthenticatedAcceptance =
            Preview::Runtime::Detail::ResolveNegotiatedTlsRoute(Compiled->get(), Accepted);
        ASSERT_FALSE(UnauthenticatedAcceptance.has_value());
        EXPECT_EQ(UnauthenticatedAcceptance.error().Code, Preview::Fault::Code::ProtocolError);
    }

TEST(SessionRecognitionMode, DispatchesByCandidateIdAndSkipsDirectFactory)
    {
        auto HttpFactory = std::make_shared<Preview::Http11::Binding>(
            Preview::Http11::PreparedBinding{
                .Instance = "session-recognition-http",
                .Executor = boost::asio::system_executor(),
                .RequireAuth = false});
        auto Binding = Composition::CandidateFactory::MakeHttp(
            Preview::Composition::Recognition::CandidateOptions{5}, std::move(HttpFactory));
        Composition::ProfileBuilderOptions BuilderOptions;
        BuilderOptions.Mode = Core::RecognitionMode::Configured;
        auto Built = Composition::ProfileBuilder::Build(std::move(Binding), std::move(BuilderOptions));
        ASSERT_TRUE(Built.has_value());

        std::size_t ResolverCalls = 0;
        std::size_t DirectCalls = 0;
        Preview::Runtime::SessionOptions Options;
        Options.Services->Bytes = MakeSessionRecognitionBytePool();
        Options.Services->Profile = Built->Profile;
        Options.Services->ResolveCandidate = [Resolver = Built->Resolver, &ResolverCalls](Core::CandidateId Id)
            -> std::shared_ptr<Preview::Contract::StreamFactory>
        {
            ++ResolverCalls;
            return Resolver(Id);
        };
        Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>([&DirectCalls](Preview::Contract::StreamAcceptInput)
            -> Net::awaitable<Preview::Contract::AcceptOutcome>
        {
            ++DirectCalls;
            co_return std::unexpected(Preview::Contract::FailureFromProtocolError(Preview::Error::ProtocolError));
        });
        Options.Services->Dial = [](const Preview::Network::Target &)
            -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
        {
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::NotSupported});
        };
        const auto Result = RunHttpSession(std::move(Options));
        EXPECT_EQ(Result, Preview::Fault::Code::NotSupported);
        EXPECT_EQ(ResolverCalls, 1U);
        EXPECT_EQ(DirectCalls, 0U);
    }

TEST(SessionRecognitionMode, DirectAcceptorRemainsAvailableWithoutProfile)
    {
        std::size_t ResolverCalls = 0;
        std::size_t DirectCalls = 0;
        Preview::Runtime::SessionOptions Options;
        Options.Services->Bytes = MakeSessionRecognitionBytePool();
        Options.Services->AcceptProtocol = std::make_shared<Preview::Testing::StreamFactory>(
            DirectRejectFactory{DirectCalls});
        const auto Result = RunHttpSession(std::move(Options));
        EXPECT_EQ(Result, Preview::Fault::Code::NotSupported);
        EXPECT_EQ(ResolverCalls, 0U);
        EXPECT_EQ(DirectCalls, 1U);
    }

TEST(SessionRecognitionMode, ConfiguredSocks5ProfileRunsAuthenticatedHandler)
    {
        Preview::Socks5::ServerConfig ServerConfig;
        ServerConfig.EnableAuth = true;
        ServerConfig.Authenticator = Preview::Testing::ProviderAccount(Preview::Testing::ProviderAccountInput{Preview::AccountId{1U}, Preview::Account::Credential::Password("secret"), "alice", "alice", {}})->Authenticator;
        auto Options = MakeConfiguredOptions(
            Composition::CandidateFactory::MakeSocks5(Composition::CandidateOptions{11}, Preview::Testing::MakeSocks5Binding(ServerConfig)));
        const auto Flow = [ServerConfig](Preview::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            Preview::Socks5::ClientConfig Config;
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
        const auto GoodUuid = Preview::Testing::RecognitionWire::MakeUuid(1);
        const auto BadUuid = Preview::Testing::RecognitionWire::MakeUuid(9);
        auto Options = MakeConfiguredOptions(
            Preview::Testing::MakeVlessCandidate(Preview::Composition::Recognition::CandidateOptions{12}, Preview::Vless::ServerConfig{GoodUuid}));
        const auto Flow = [GoodUuid](Preview::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_return co_await RunVlessClient(std::move(Client), Preview::Vless::ClientConfig{GoodUuid});
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_FALSE(Result.ClientFailure.Failed());
        EXPECT_EQ(Result.ResolverCalls, 1U);

        auto BadOptions = MakeConfiguredOptions(
            Preview::Testing::MakeVlessCandidate(Preview::Composition::Recognition::CandidateOptions{13}, Preview::Vless::ServerConfig{GoodUuid}));
        const auto BadFlow = [BadUuid](Preview::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_return co_await RunVlessClient(std::move(Client), Preview::Vless::ClientConfig{BadUuid});
        };
        const auto BadResult = RunProfileFlow(std::move(BadOptions), BadFlow);
        EXPECT_TRUE(BadResult.ClientFailure.Failed());
        EXPECT_EQ(BadResult.ResolverCalls, 0U);
    }

TEST(SessionRecognitionMode, ConfiguredTrojanProfileRunsHandler)
    {
        auto Options = MakeConfiguredOptions(
            Preview::Testing::MakeTrojanCandidate(Preview::Composition::Recognition::CandidateOptions{14}, Preview::Trojan::ServerConfig{"trojan-secret"}));
        const auto Flow = [](Preview::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
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
            Preview::Testing::MakeTrojanCandidate(Preview::Composition::Recognition::CandidateOptions{22}, Preview::Trojan::ServerConfig{"trojan-secret"}));
        const auto Flow = [](Preview::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_return co_await RunTrojanClient(std::move(Client), "trojan-secret");
        };

        const auto Result = RunProfileFlow(std::move(Options), Flow);

        EXPECT_FALSE(Result.ClientFailure.Failed());
        EXPECT_NE(Result.SessionCode, Preview::Fault::Code::AuthFailed);
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

TEST(SessionRecognitionMode, ProtocolHandlerTransfersAccountLease)
    {
        Net::io_context Io;
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(41);
        std::array<std::byte, 16> CredentialBytes{};
        for (std::size_t Index = 0; Index < CredentialBytes.size(); ++Index)
        {
            CredentialBytes[Index] = static_cast<std::byte>(Uuid[Index]);
        }
        auto Directory = Preview::Testing::ProviderAccount(
            Preview::Account::Credential::Uuid(CredentialBytes), Preview::AccountId{7201},
            {.MaxConnections = 1});
        const auto Record = Directory->Store->FindById(Preview::AccountId{7201});
        ASSERT_TRUE(Record);
        auto Authenticator = Directory->Authenticator;
        auto UseState = Preview::Testing::MakeProtocolIngressUseState();

        Preview::Vless::ServerConfig Config;
        Config.uuid = Uuid;
        Config.AuthenticatorOwner = Authenticator;
        auto Handler = Preview::Testing::MakeVlessIngress(Config,
            Preview::Testing::ProtocolIngressResources{{}, UseState, Io.get_executor()},
            Preview::Vless::IngressRoute{});

        auto [Writer, Reader] = Preview::MakeMemoryPair(Io.get_executor());
        auto Client = std::make_shared<Preview::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Preview::MemoryStream>(std::move(Reader));
        auto Bytes = std::make_shared<Preview::Memory::BytePool>(
            Preview::Memory::BytePoolOptions{64U * 1024U, 64U});
        Preview::Contract::AcceptOutcome Result{std::unexpected(
            Preview::Contract::FailureFromProtocolError(Preview::Error::NotOpen))};

        Preview::Testing::RunCoro(
            Io,
            [Client, Inbound, Handler, Bytes, UseState, Uuid, &Result]() -> Net::awaitable<void>
            {
                const auto Wire = Preview::Testing::RecognitionWire::MakeVless(Uuid);
                const auto Written = co_await Client->WriteExact(
                    std::span<const std::byte>{Wire});
                if (Written.Failure.Failed())
                {
                    Result = std::unexpected(Written.Failure);
                    co_return;
                }
                Result = co_await Handler->Accept(
                    Preview::Contract::StreamAcceptInput{Inbound, {}, Bytes, UseState});
            });

        ASSERT_TRUE(Result);
        EXPECT_TRUE(Result->ProtocolAuthenticated);
        EXPECT_EQ(Result->AccountId, Preview::AccountId{7201});
        ASSERT_TRUE(Result->AccountLease);
        EXPECT_TRUE(Result->AccountLease);
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 1U);
        Result->AccountLease.Release();
        EXPECT_EQ(Record->Runtime()->ActiveConnections(), 0U);
        Preview::Fault::Failure Retirement;
        Preview::Testing::RunCoro(Io, [Handler, &Retirement]() -> Net::awaitable<void>
        {
            Handler->Close();
            auto Drained = co_await Handler->Drain();
            if (!Drained) Retirement = Drained.error();
        });
        EXPECT_FALSE(Retirement.Failed());
        EXPECT_TRUE(Handler->IsRetired());
    }

TEST(SessionRecognitionMode, ConfiguredVmessProfileRunsHandler)
    {
        const auto Uuid = Preview::Testing::RecognitionWire::MakeUuid(21);
        auto Options = MakeConfiguredOptions(
            Preview::Testing::MakeVmessCandidate(Preview::Composition::Recognition::CandidateOptions{15}, Preview::Vmess::ServerConfig{Uuid}));
        const auto Flow = [Uuid](Preview::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_return co_await RunVmessClient(std::move(Client), Preview::Vmess::ClientConfig{Uuid});
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_FALSE(Result.ClientFailure.Failed());
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

TEST(SessionRecognitionMode, ConfiguredSs2022ProfileUsesTypedPsk)
    {
        const auto Psk = Preview::Testing::RecognitionWire::MakePsk(0x51);
        Preview::Shadowsocks2022::ServerConfig Config;
        Config.Psk = Psk;
        auto Options = MakeConfiguredOptions(Composition::CandidateFactory::MakeSs2022(Composition::CandidateOptions{16}, Preview::Testing::MakeSs2022Binding(Config)));
        const auto Flow = [Psk](Preview::SharedTransmission Client)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_return co_await RunSs2022Client(std::move(Client), Psk);
        };
        const auto Result = RunProfileFlow(std::move(Options), Flow);
        EXPECT_FALSE(Result.ClientFailure.Failed());
        EXPECT_EQ(Result.ResolverCalls, 1U);
    }

/** @file MuxProviderFallbackTest.cpp @brief 显式 WebSocket fallback 的编译 TLS policy。 */
#include <TestSupport/Fixtures/RecognitionWire.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <TestSupport/Prism/GenerationPublication.hpp>

#include <Prism/Application/ProtocolAcceptors.hpp>
#include <Prism/Application/AccountCatalog.hpp>
#include <Prism/Application/Startup/GenerationPhase.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>
#include <gtest/gtest.h>

#include <exception>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace
{
    namespace Net = boost::asio;
    namespace Provider = Prism::Composition::Provider;
    namespace Application = Prism::Application;

    auto MakeUnavailableMuxServices() -> Prism::Contract::StreamServices
    {
        Prism::Contract::StreamServices Services;
        Services.Egress = Prism::Testing::UnavailableEgress();
        Services.Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        return Services;
    }

    struct FallbackOutcome final
    {
        bool CandidateCount{false};
        bool Fallback{false};
        bool CandidateValid{false};
        bool HasCommit{false};
        bool Structural{false};
        bool Drained{false};
        bool Retired{false};
        std::string Failure;
    };

    struct ConfiguredFallbackGeneration final
    {
        Prism::Application::Configuration::SharedConfigurationGeneration Generation;
        Application::AccountCatalog Accounts;
        std::shared_ptr<Prism::Runtime::GenerationPublication> Publication;
    };

    /** @brief 通过当前配置阶段构造具备正式账户准入 authority 的 generation。 */
    auto BuildFallbackGeneration() -> std::expected<ConfiguredFallbackGeneration, std::string>
    {
        const auto Root = std::filesystem::path{PRISM_TEST_REPO_ROOT};
        const auto Phase = Application::Startup::GenerationPhase::Build({
            Root / "Test/TestSupport/Prism/ConfiguredMux/socks5.json", {}});
        if (!Phase)
        {
            return std::unexpected(Phase.error().Path + ": " + Phase.error().Message);
        }

        auto Configuration = Phase->Generation->Configuration();
        Prism::Contract::CarrierConfiguration Carrier;
        Carrier.Id = "carrier-ws-fallback";
        Carrier.Name = "websocket-fallback";
        Carrier.Builtin = "ws";
        Carrier.Match.ServerNames = {"edge.example.com"};
        Carrier.Match.Fallback = true;
        Carrier.Options = Prism::Contract::WebSocketOptions{"/ws", "edge.example.com"};
        Configuration.Carriers.push_back(std::move(Carrier));
        if (Configuration.ProtocolBindings.empty())
        {
            return std::unexpected("configured protocol binding is missing");
        }
        Configuration.ProtocolBindings.front().CarrierId = "carrier-ws-fallback";
        Configuration.ProtocolBindings.front().Recognition.Pattern.clear();
        Configuration.ProtocolBindings.front().Recognition.Fallback = false;

        const auto Generation = Prism::Application::Configuration::GenerationBuilder::Build({
            .Configuration = std::move(Configuration),
            .Builtins = Phase->Generation->Builtins(),
            .AvailableCapabilities = Phase->Generation->Capabilities(),
            .Generation = Prism::GenerationId{Phase->Generation->Id().Value() + 1U}});
        if (!Generation)
        {
            return std::unexpected(Generation.error().Path + ": " + Generation.error().Message);
        }

        auto CarrierPhase = *Phase;
        CarrierPhase.Generation = *Generation;
        const auto Accounts = Application::Startup::GenerationPhase::BuildAccounts(CarrierPhase);
        if (!Accounts)
        {
            return std::unexpected(Accounts.error().Path + ": " + Accounts.error().Message);
        }
        auto PublishedAccounts = Prism::Testing::PublishConfiguredAccountCatalog(
            CarrierPhase.Accounts, *Generation);
        if (!PublishedAccounts)
        {
            return std::unexpected("configured account publication failed");
        }
        return ConfiguredFallbackGeneration{
            *Generation, std::move(CarrierPhase.Accounts), std::move(*PublishedAccounts)};
    }

    /** @brief 验证 fallback 位图、typed candidate commit 与 TLS ClientHello 结构检查。 */
    auto InspectFallbackCandidate(const ConfiguredFallbackGeneration& Setup,
        Provider::BoundCatalog& Bound) -> FallbackOutcome
    {
        FallbackOutcome Outcome;
        auto NativeTls = std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
        Application::ProtocolProfile::ProtocolFactoryContext Context{
            Setup.Generation->Configuration(), *Setup.Generation, Setup.Accounts,
            std::move(NativeTls), {}, &Bound, {},
            {.Egress = Prism::Testing::UnavailableEgress()}};
        const auto Profile = Application::ProtocolProfile::MakeTcpProfile(Context);
        if (!Profile)
        {
            Outcome.Failure = Profile.error().Path + ": " + Profile.error().Message;
            return Outcome;
        }
        Outcome.CandidateCount = Profile->Profile && Profile->Profile->CandidateCount() == 1U;
        if (!Profile->Profile || !Outcome.CandidateCount) return Outcome;

        const auto CandidateId = Profile->Profile->CandidateIdAt(0);
        Outcome.Fallback = Profile->Profile->FallbackCandidates().Test(CandidateId);
        const auto Candidate = Profile->Profile->FindCandidate(CandidateId);
        Outcome.CandidateValid = Candidate.IsValid();
        Outcome.HasCommit = Candidate.HasCommit();
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        Prism::Recognition::ProbeBuffer Buffer(4096, std::move(Bytes));
        const auto Hello = Prism::Testing::RecognitionWire::MakeTlsClientHello("wrong.example.com");
        const auto Seeded = Buffer.Seed(Hello);
        Outcome.Structural = Seeded && Candidate.IsValid() &&
            Candidate.Inspect(Buffer.Snapshot()) == Prism::Recognition::MatchState::Structural;
        return Outcome;
    }

    /** @brief 从真实冷配置构造 fallback Profile，并完整排空其 provider owner。 */
    auto RunExplicitWebsocketFallback() -> FallbackOutcome
    {
        FallbackOutcome Outcome;
        auto Setup = BuildFallbackGeneration();
        if (!Setup)
        {
            Outcome.Failure = Setup.error();
            return Outcome;
        }
        Net::io_context Io;
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        Provider::ConfigurationInput Input{
            Setup->Generation, UseState, Setup->Generation->Configuration().Protocols,
            Setup->Generation->Configuration().ProtocolBindings, {}};
        const auto& Protocols = Setup->Generation->Configuration().Protocols;
        if (Protocols.empty())
        {
            Outcome.Failure = "configured protocol list is empty";
            return Outcome;
        }
        const auto ProtocolId = Protocols.front().Id;
        const auto* Authentication = Setup->Accounts.Find(ProtocolId);
        if (!Authentication)
        {
            Outcome.Failure = "configured account services are missing";
            return Outcome;
        }
        Input.Authentication.emplace(ProtocolId, *Authentication);
        Provider::BindingServices Services{.Executor = Io.get_executor(),
            .Streams = MakeUnavailableMuxServices()};
        auto Prepared = Provider::Compile(std::move(Input), std::move(Services));
        if (!Prepared)
        {
            Outcome.Failure = Prepared.error().Instance + ": " + Prepared.error().Path;
            return Outcome;
        }
        auto Frozen = Prepared->Freeze();
        if (!Frozen)
        {
            Outcome.Failure = Frozen.error().Instance + ": " + Frozen.error().Path;
            return Outcome;
        }
        auto Bound = Frozen->Bind({});
        if (!Bound)
        {
            Outcome.Failure = Bound.error().Instance + ": " + Bound.error().Path;
            return Outcome;
        }

        Outcome = InspectFallbackCandidate(*Setup, *Bound);
        Bound->Close();
        using DrainResult = std::expected<void, Prism::Fault::Failure>;
        std::optional<DrainResult> Drain;
        std::exception_ptr DrainException;
        Net::co_spawn(Io, Bound->Drain(), [&Drain, &DrainException](
            std::exception_ptr Error, DrainResult Result)
        {
            DrainException = std::move(Error);
            if (!DrainException) Drain.emplace(std::move(Result));
        });
        Io.run();
        Outcome.Drained = !DrainException && Drain.has_value() && static_cast<bool>(*Drain);
        Outcome.Retired = Bound->PhysicalRetirement().Complete();
        return Outcome;
    }
}

TEST(ConfiguredMuxProvider, ExplicitWebsocketCarrierFallbackReachesCompiledTlsPolicy)
{
    const auto Outcome = RunExplicitWebsocketFallback();
    ASSERT_TRUE(Outcome.Failure.empty()) << Outcome.Failure;
    EXPECT_TRUE(Outcome.CandidateCount);
    EXPECT_TRUE(Outcome.Fallback);
    EXPECT_TRUE(Outcome.CandidateValid);
    EXPECT_TRUE(Outcome.HasCommit);
    EXPECT_TRUE(Outcome.Structural);
    EXPECT_TRUE(Outcome.Drained);
    EXPECT_TRUE(Outcome.Retired);
}

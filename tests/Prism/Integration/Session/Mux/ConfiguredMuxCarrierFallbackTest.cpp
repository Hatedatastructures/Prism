/** @file ConfiguredMuxCarrierFallbackTest.cpp @brief 配置化 WebSocket carrier 的显式 fallback policy。 */
#include <TestSupport/Fixtures/RecognitionWire.hpp>
#include <TestSupport/Fixtures/StreamFactory.hpp>
#include <TestSupport/Prism/GenerationPublication.hpp>

#include <Prism/Application/AccountCatalog.hpp>
#include <Prism/Application/ProtocolAcceptors.hpp>
#include <Prism/Application/Startup/GenerationPhase.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <Prism/Contract/Services/Datagram.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/this_coro.hpp>
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
        std::exception_ptr Exception;
    };

    struct ConfiguredFallbackGeneration final
    {
        Prism::Application::Configuration::SharedConfigurationGeneration Generation;
        Application::AccountCatalog Accounts;
        std::shared_ptr<Prism::Runtime::GenerationPublication> Publication;
    };

    auto SetFailure(FallbackOutcome& Outcome, std::string Message) -> void
    {
        if (Outcome.Failure.empty()) Outcome.Failure = std::move(Message);
    }

    auto ExceptionMessage(const std::exception_ptr& Exception) -> std::string
    {
        if (!Exception) return {};
        try
        {
            std::rethrow_exception(Exception);
        }
        catch (const std::exception& Error)
        {
            return Error.what();
        }
        catch (...)
        {
            return "unknown exception";
        }
    }

    /** @brief 验证显式 WebSocket carrier 的 fallback policy 与 TLS ClientHello 结构匹配。 */
    auto InspectFallbackCandidate(
        const Prism::Application::Configuration::SharedConfigurationGeneration& Generation,
        const Application::AccountCatalog& Accounts,
        Provider::BoundCatalog& Bound) -> FallbackOutcome
    {
        FallbackOutcome Outcome;
        auto NativeTls = std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
        Application::ProtocolProfile::ProtocolFactoryContext Context{
            Generation->Configuration(), *Generation, Accounts,
            std::move(NativeTls), {}, &Bound, {},
            {.Egress = Prism::Testing::UnavailableEgress()}};
        const auto Profile = Application::ProtocolProfile::MakeTcpProfile(Context);
        if (!Profile)
        {
            SetFailure(Outcome, Profile.error().Path + ": " + Profile.error().Message);
            return Outcome;
        }
        Outcome.CandidateCount = Profile->Profile &&
            Profile->Profile->CandidateCount() == 1U;
        if (!Profile->Profile || !Outcome.CandidateCount) return Outcome;

        const auto CandidateId = Profile->Profile->CandidateIdAt(0);
        Outcome.Fallback = Profile->Profile->FallbackCandidates().Test(CandidateId);
        const auto Candidate = Profile->Profile->FindCandidate(CandidateId);
        Outcome.CandidateValid = Candidate.IsValid();
        Outcome.HasCommit = Candidate.HasCommit();
        if (!Outcome.CandidateValid) return Outcome;

        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{.BlockCount = 8});
        Prism::Recognition::ProbeBuffer Buffer(4096, std::move(Bytes));
        const auto Hello = Prism::Testing::RecognitionWire::MakeTlsClientHello(
            "wrong.example.com");
        const auto Seeded = Buffer.Seed(Hello);
        Outcome.Structural = Seeded &&
            Candidate.Inspect(Buffer.Snapshot()) == Prism::Recognition::MatchState::Structural;
        return Outcome;
    }

    /** @brief 以显式 WebSocket carrier 构造正式配置代次及其账户准入 authority。 */
    auto BuildFallbackGeneration() -> std::expected<ConfiguredFallbackGeneration, std::string>
    {
        const auto Root = std::filesystem::path{PRISM_TEST_REPO_ROOT};
        const auto Phase = Application::Startup::GenerationPhase::Build({
            Root / "tests/TestSupport/Prism/ConfiguredMux/socks5.json", {}});
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

    /** @brief 构造显式 WebSocket fallback profile，并在所有已绑定出口排空 catalog。 */
    auto RunExplicitWebsocketFallback() -> Net::awaitable<FallbackOutcome>
    {
        FallbackOutcome Outcome;
        const auto Executor = co_await Net::this_coro::executor;
        const auto Setup = BuildFallbackGeneration();
        if (!Setup)
        {
            SetFailure(Outcome, Setup.error());
            co_return Outcome;
        }

        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        Provider::ConfigurationInput Input{
            Setup->Generation, UseState, Setup->Generation->Configuration().Protocols,
            Setup->Generation->Configuration().ProtocolBindings, {}};
        const auto& Protocols = Setup->Generation->Configuration().Protocols;
        if (Protocols.empty())
        {
            SetFailure(Outcome, "configured protocol list is empty");
            co_return Outcome;
        }
        const auto ProtocolId = Protocols.front().Id;
        const auto* Authentication = Setup->Accounts.Find(ProtocolId);
        if (!Authentication)
        {
            SetFailure(Outcome, "configured account services are missing");
            co_return Outcome;
        }
        Input.Authentication.emplace(ProtocolId, *Authentication);
        Provider::BindingServices Services{.Executor = Executor,
            .Streams = MakeUnavailableMuxServices()};
        auto Prepared = Provider::Compile(std::move(Input), std::move(Services));
        if (!Prepared)
        {
            SetFailure(Outcome, Prepared.error().Instance + ": " + Prepared.error().Path);
            co_return Outcome;
        }
        auto Frozen = Prepared->Freeze();
        if (!Frozen)
        {
            SetFailure(Outcome, Frozen.error().Instance + ": " + Frozen.error().Path);
            co_return Outcome;
        }
        auto Bound = Frozen->Bind({});
        if (!Bound)
        {
            SetFailure(Outcome, Bound.error().Instance + ": " + Bound.error().Path);
            co_return Outcome;
        }

        try
        {
            Outcome = InspectFallbackCandidate(Setup->Generation, Setup->Accounts, *Bound);
        }
        catch (...)
        {
            Outcome.Exception = std::current_exception();
        }

        Bound->Close();
        try
        {
            const auto Drained = co_await Bound->Drain();
            Outcome.Drained = static_cast<bool>(Drained);
            if (!Drained)
            {
                SetFailure(Outcome, "BoundCatalog drain failed: " +
                    Prism::Fault::ToNative(Drained.error()).message());
            }
        }
        catch (...)
        {
            if (!Outcome.Exception) Outcome.Exception = std::current_exception();
        }

        try
        {
            Outcome.Retired = Bound->PhysicalRetirement().Complete();
        }
        catch (...)
        {
            if (!Outcome.Exception) Outcome.Exception = std::current_exception();
        }
        if (!Outcome.Retired)
        {
            SetFailure(Outcome, "BoundCatalog did not physically retire");
        }
        co_return Outcome;
    }

    auto RunFallbackScenario() -> FallbackOutcome
    {
        Net::io_context Io;
        std::optional<FallbackOutcome> Outcome;
        std::exception_ptr Exception;
        Net::co_spawn(Io, RunExplicitWebsocketFallback(),
            [&Outcome, &Exception](std::exception_ptr Error, FallbackOutcome Result)
            {
                Exception = std::move(Error);
                if (!Exception) Outcome.emplace(std::move(Result));
            });
        Io.run();
        if (Exception)
        {
            FallbackOutcome Failed;
            Failed.Exception = std::move(Exception);
            return Failed;
        }
        if (!Outcome)
        {
            FallbackOutcome Failed;
            Failed.Failure = "fallback scenario did not complete";
            return Failed;
        }
        return std::move(*Outcome);
    }
}

TEST(ConfiguredMuxCarrierFallback, ExplicitWebsocketCarrierFallbackReachesCompiledTlsPolicy)
{
    const auto Outcome = RunFallbackScenario();
    ASSERT_TRUE(Outcome.Failure.empty()) << Outcome.Failure;
    ASSERT_FALSE(Outcome.Exception) << ExceptionMessage(Outcome.Exception);
    EXPECT_TRUE(Outcome.CandidateCount);
    EXPECT_TRUE(Outcome.Fallback);
    EXPECT_TRUE(Outcome.CandidateValid);
    EXPECT_TRUE(Outcome.HasCommit);
    EXPECT_TRUE(Outcome.Structural);
    EXPECT_TRUE(Outcome.Drained);
    EXPECT_TRUE(Outcome.Retired);
}

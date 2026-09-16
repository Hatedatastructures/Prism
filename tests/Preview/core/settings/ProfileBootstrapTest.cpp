/**
 * @file ProfileBootstrapTest.cpp
 * @brief Settings 到 Preview recognition Profile 的 Composition 接线测试
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>

#include <chrono>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <Preview/Composition/Recognition/SettingsBuilder.hpp>
#include <Preview/Composition/Recognition/TlsCandidateFactory.hpp>
#include <Preview/Composition/Settings/Loader.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Core = Preview::Recognition;
    namespace Composition = Preview::Composition::Recognition;

    auto MakeBinding(const Preview::Settings::RecognitionCandidate &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        Composition::CandidateBinding Binding;
        Binding.Spec.Id = Candidate.Id;
        Binding.Spec.Name = Candidate.Name;
        Binding.Spec.Protocol = Core::ProtocolType::Http;
        Binding.Spec.MinimumBytes = 1;
        Binding.Spec.FirstBytes = {'C'};
        Binding.Spec.Inspect = [](const Core::ProbeSnapshot &Snapshot)
        {
            if (Snapshot.Empty())
            {
                return Core::MatchState::NeedMore;
            }
            return Core::MatchState::Structural;
        };
        Binding.Spec.Commit = [](Core::CommitContext Context) -> Net::awaitable<Core::CommitResult>
        {
            Core::CommitResult Result;
            Result.Candidate = Context.Candidate;
            Result.Status = Core::RecognitionStatus::Accepted;
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        Binding.Accept = [](Preview::SharedTransmission &, Preview::Middleware::Context &)
            -> Net::awaitable<Preview::Fault::Code>
        {
            co_return Preview::Fault::Code::Success;
        };
        return Binding;
    }

} // namespace

TEST(ProfileBootstrap, BuildsConfiguredProfileAndResolverFromSettings)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 7;
    Config.Candidates.push_back(Preview::Settings::RecognitionCandidate{7, "http-entry", "http", 3, 1, false});

    const auto Result = Composition::BuildProfileFromSettings(Config, MakeBinding);

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->Profile);
    EXPECT_EQ(Result->Profile->Mode(), Core::RecognitionMode::Configured);
    EXPECT_EQ(Result->Profile->CandidateCount(), 1U);
    EXPECT_EQ(Result->Profile->CandidateIdAt(0), 7U);
    EXPECT_TRUE(static_cast<bool>(Result->Resolve(7)));

    Preview::Runtime::SessionOptions Options;
    EXPECT_TRUE(Composition::InstallProfile(Options, std::move(*Result)));
    EXPECT_EQ(Options.Profile->CandidateIdAt(0), 7U);
    EXPECT_TRUE(static_cast<bool>(Options.ResolveCandidate(7)));
    EXPECT_TRUE(static_cast<bool>(Options.Resolver(7)));
}

TEST(ProfileBootstrap, PreservesMixedTrialCandidatesAndRoutes)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::MixedTrial;
    Config.Budget.MaxCandidates = 2;
    Config.DefaultCandidate = 9;
    Config.Candidates.push_back(Preview::Settings::RecognitionCandidate{2, "first", "http", 2, 0, false});
    Config.Candidates.push_back(Preview::Settings::RecognitionCandidate{9, "second", "http", 1, 1, true});
    Config.Routes.emplace_back("*.example.com", 2);

    const auto Result = Composition::BuildProfileFromSettings(Config, MakeBinding);

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->Profile);
    EXPECT_EQ(Result->Profile->Mode(), Core::RecognitionMode::MixedTrial);
    ASSERT_EQ(Result->Profile->CandidateCount(), 2U);
    EXPECT_EQ(Result->Profile->CandidateIdAt(0), 2U);
    EXPECT_EQ(Result->Profile->CandidateIdAt(1), 9U);
    ASSERT_TRUE(Result->Profile->LookupRoute("api.example.com").has_value());
    EXPECT_EQ(Result->Profile->LookupRoute("api.example.com").value(), 2U);
    ASSERT_TRUE(Result->Profile->LookupRoute("unknown.example.net").has_value());
    EXPECT_EQ(Result->Profile->LookupRoute("unknown.example.net").value(), 9U);
}

TEST(ProfileBootstrap, DerivesTlsServerNamesFromRecognitionRoutes)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::MixedTrial;
    Preview::Settings::RecognitionCandidate Candidate{11, "edge-vless", "vless", 0, 0, false};
    Candidate.Scheme = "native";
    Config.Candidates.push_back(Candidate);
    Config.Routes.emplace_back("edge.example", Candidate.Id);

    std::vector<std::string> FactoryServerNames;
    const auto Result = Composition::BuildProfileFromSettings(
        Config,
        [&FactoryServerNames](const auto &FactoryCandidate)
            -> std::optional<Composition::CandidateBinding>
        {
            FactoryServerNames = FactoryCandidate.ServerNames;
            Composition::TlsCandidateOptions Options;
            Options.Id = FactoryCandidate.Id;
            Options.Name = FactoryCandidate.Name;
            Options.Scheme = FactoryCandidate.Scheme;
            Options.ServerNames = FactoryCandidate.ServerNames;
            Options.Alpn = FactoryCandidate.Alpn;
            Options.Fallback = FactoryCandidate.Fallback;
            auto Tls = Composition::TlsCandidateFactory::Make(
                std::move(Options),
                [](Preview::SharedTransmission Inbound)
                    -> Net::awaitable<Preview::Recognition::CarrierAcceptResult>
                {
                    Preview::Recognition::CarrierAcceptResult Result;
                    Result.Transport = std::move(Inbound);
                    co_return Result;
                });
            Composition::CandidateBinding Binding;
            Binding.Spec = std::move(Tls.Spec);
            Binding.Accept = [](Preview::SharedTransmission &, Preview::Middleware::Context &)
                -> Net::awaitable<Preview::Fault::Code>
            {
                co_return Preview::Fault::Code::Success;
            };
            return Binding;
        });

    ASSERT_TRUE(Result.has_value());
    ASSERT_EQ(FactoryServerNames.size(), 1U);
    EXPECT_EQ(FactoryServerNames.front(), "edge.example");
}

TEST(ProfileBootstrap, DoesNotInferConfiguredCandidateForDeterministicMode)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::DeterministicRoute;
    Config.Candidates.push_back(Preview::Settings::RecognitionCandidate{7, "deterministic", "http", 0, 0, false});

    const auto Result = Composition::BuildProfileFromSettings(Config, MakeBinding);

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->Profile);
    EXPECT_EQ(Result->Profile->Mode(), Core::RecognitionMode::DeterministicRoute);
    EXPECT_EQ(Result->Profile->ConfiguredCandidate(), Core::InvalidCandidate);
}

TEST(ProfileBootstrap, RejectsMissingCandidateFactoryResult)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 3;
    Config.Candidates.push_back(Preview::Settings::RecognitionCandidate{3, "missing", "http", 0, 0, false});

    const auto Result = Composition::BuildProfileFromSettings(
        Config, [](const auto &) -> std::optional<Composition::CandidateBinding> { return std::nullopt; });

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::MissingResolver);
}

TEST(ProfileBootstrap, BuildsProfileThroughCandidateRegistry)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 14;
    Config.Candidates.push_back(Preview::Settings::RecognitionCandidate{14, "registry-http", "HTTP", 0, 0, false});

    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register("http", MakeBinding));

    const auto Result = Composition::BuildProfileFromSettings(Config, Registry);

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->Profile);
    EXPECT_EQ(Result->Profile->ConfiguredCandidate(), 14U);
    EXPECT_TRUE(static_cast<bool>(Result->Resolve(14)));
}

TEST(ProfileBootstrap, RejectsQuicCandidateInTcpProfile)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 15;
    Config.Candidates.push_back(Preview::Settings::RecognitionCandidate{15, "hysteria2", "hysteria2", 0, 0, false});

    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register(
        "hysteria2",
        [](const auto &Candidate) -> std::optional<Composition::CandidateBinding>
        {
            auto Binding = MakeBinding(Candidate);
            if (!Binding)
            {
                return std::nullopt;
            }
            Binding->Spec.Protocol = Core::ProtocolType::Hysteria2;
            Binding->Spec.Kind = Core::CandidateKind::QuicCarrier;
            return Binding;
        }));

    const auto Result = Composition::BuildProfileFromSettings(Config, Registry);

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::QuicCandidateRequiresGateway);
}

TEST(ProfileBootstrap, RejectsQuicCandidateBeforeCallingFactory)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::MixedTrial;
    Config.Candidates.push_back(
        Preview::Settings::RecognitionCandidate{16, "hysteria", "hysteria2", 0, 0, false});

    bool FactoryCalled = false;
    const auto Result = Composition::BuildProfileFromSettings(
        Config,
        [&FactoryCalled](const auto &) -> std::optional<Composition::CandidateBinding>
        {
            FactoryCalled = true;
            return std::nullopt;
        });

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::QuicCandidateRequiresGateway);
    EXPECT_FALSE(FactoryCalled);
}

TEST(ProfileBootstrap, PreservesConfiguredOuterSchemeMetadata)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 16;
    Preview::Settings::RecognitionCandidate Candidate{16, "secured", "http", 0, 0, false};
    Candidate.Scheme = "native";
    Config.Candidates.push_back(std::move(Candidate));

    Composition::CandidateRegistry Registry;
    ASSERT_TRUE(Registry.Register("http", MakeBinding));
    ASSERT_TRUE(Registry.RegisterCarrier(
        "native",
        [](Preview::SharedTransmission Inbound)
            -> Net::awaitable<Preview::Recognition::CarrierAcceptResult>
        {
            Preview::Recognition::CarrierAcceptResult Result;
            Result.Transport = std::move(Inbound);
            co_return Result;
        }));

    const auto Result = Composition::BuildProfileFromSettings(Config, Registry);

    ASSERT_TRUE(Result.has_value());
    const auto Handle = Result->Profile->FindCandidate(16);
    EXPECT_EQ(Handle.Scheme(), "native");
}

TEST(ProfileBootstrap, RejectsSchemeWithoutCarrierBinding)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 19;
    Preview::Settings::RecognitionCandidate Candidate{19, "raw", "http", 0, 0, false};
    Candidate.Scheme = "native";
    Config.Candidates.push_back(std::move(Candidate));

    const auto Result = Composition::BuildProfileFromSettings(Config, MakeBinding);

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::MissingResolver);
}

TEST(ProfileBootstrap, RejectsMismatchedCarrierScheme)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Explicit = true;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 21;
    Preview::Settings::RecognitionCandidate Candidate{21, "mismatch", "http", 0, 0, false};
    Candidate.Scheme = "native";
    Config.Candidates.push_back(std::move(Candidate));

    const auto Result = Composition::BuildProfileFromSettings(
        Config,
        [](const auto &Candidate) -> std::optional<Composition::CandidateBinding>
        {
            auto Binding = MakeBinding(Candidate);
            if (!Binding)
            {
                return std::nullopt;
            }
            Binding->Spec.Kind = Core::CandidateKind::TlsCarrier;
            Binding->Spec.Scheme = "reality";
            return Binding;
        });

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::MissingResolver);
}

TEST(ProfileBootstrap, BuildsCompleteSessionOptionsFromProxyConfig)
{
    Preview::Settings::ProxyConfig Config;
    const auto LoadError = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"IdleTimeoutMs":1234,"Recognition":{"Mode":"Configured","Candidates":[{"Id":4,"Protocol":"http"}]}})",
        Config);
    ASSERT_TRUE(LoadError.Message.empty()) << LoadError.Message;

    const auto Result = Composition::BuildSessionOptionsFromSettings(Config, MakeBinding);

    ASSERT_TRUE(Result.has_value());
    ASSERT_TRUE(Result->Profile);
    EXPECT_EQ(Result->Profile->Mode(), Core::RecognitionMode::Configured);
    EXPECT_EQ(Result->Profile->CandidateIdAt(0), 4U);
    EXPECT_TRUE(static_cast<bool>(Result->ResolveCandidate(4)));
    EXPECT_EQ(Result->RelayIdleTimeout, std::chrono::milliseconds(1234));
}

TEST(ProfileBootstrap, RejectsIdleTimeoutThatCannotFitSessionDuration)
{
    Preview::Settings::ProxyConfig Config;
    const auto LoadError = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"Configured","Candidates":[{"Id":4,"Protocol":"http"}]}})",
        Config);
    ASSERT_TRUE(LoadError.Message.empty()) << LoadError.Message;
    Config.IdleTimeoutMs = std::numeric_limits<std::uint64_t>::max();

    const auto Result = Composition::BuildSessionOptionsFromSettings(Config, MakeBinding);

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::InvalidTimeout);
}

TEST(ProfileBootstrap, RejectsRequiredAuthWithoutSessionAuthenticator)
{
    Preview::Settings::ProxyConfig Config;
    const auto LoadError = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"AuthRequired":true,"Recognition":{"Mode":"Configured","Candidates":[{"Id":4,"Protocol":"http"}]}})",
        Config);
    ASSERT_TRUE(LoadError.Message.empty()) << LoadError.Message;

    const auto Result = Composition::BuildSessionOptionsFromSettings(Config, MakeBinding);

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::MissingAuthenticator);
}

TEST(ProfileBootstrap, RejectsUnsupportedProtocolBeforeFactoryInvocation)
{
    Preview::Settings::RecognitionConfig Config;
    Config.Mode = Core::RecognitionMode::Configured;
    Config.ConfiguredCandidate = 5;
    Config.Candidates.push_back(Preview::Settings::RecognitionCandidate{5, "unknown", "future-proto", 0, 0, false});

    bool Invoked = false;
    const auto Result = Composition::BuildProfileFromSettings(
        Config,
        [&Invoked](const auto &) -> std::optional<Composition::CandidateBinding>
        {
            Invoked = true;
            return std::nullopt;
        });

    ASSERT_FALSE(Result.has_value());
    EXPECT_EQ(Result.error(), Core::ProfileError::MissingResolver);
    EXPECT_FALSE(Invoked);
}

TEST(ProfileBootstrap, CreatesListenerSessionFactoryWithOwnedRecognitionBundle)
{
    Preview::Settings::ProxyConfig Config;
    const auto LoadError = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"Configured","Candidates":[{"Id":6,"Protocol":"http"}]}})",
        Config);
    ASSERT_TRUE(LoadError.Message.empty()) << LoadError.Message;

    auto Factory = Composition::BuildSessionFactoryFromSettings(Config, MakeBinding);

    ASSERT_TRUE(Factory.has_value());
    const auto SessionFactory = std::move(*Factory);
    auto Session = SessionFactory(Preview::SharedTransmission{}, 0);
    ASSERT_NE(Session, nullptr);
}

TEST(ProfileBootstrap, CarriesMaxConnectionsIntoListener)
{
    Preview::Settings::ProxyConfig Config;
    const auto LoadError = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"MaxConnections":7,"Recognition":{"Mode":"Configured","Candidates":[{"Id":6,"Protocol":"http"}]}})",
        Config);
    ASSERT_TRUE(LoadError.Message.empty()) << LoadError.Message;

    auto Factory = Composition::BuildSessionFactoryFromSettings(Config, MakeBinding);
    ASSERT_TRUE(Factory.has_value());

    boost::asio::io_context Io;
    auto Listener = Composition::MakeTcpListenerFromSettings(
        Config, Io.get_executor(), std::move(*Factory), 2);

    EXPECT_EQ(Listener.MaxConnections(), 7U);
}

TEST(ProfileBootstrap, StartsListenerFromNumericSettingsEndpoint)
{
    Preview::Settings::ProxyConfig Config;
    const auto LoadError = Preview::Settings::LoadConfig(
        R"({"ListenAddr":"127.0.0.1","ListenPort":1080,"Recognition":{"Mode":"Configured","Candidates":[{"Id":6,"Protocol":"http"}]}})",
        Config);
    ASSERT_TRUE(LoadError.Message.empty()) << LoadError.Message;
    Config.ListenPort = 0;
    auto Factory = Composition::BuildSessionFactoryFromSettings(Config, MakeBinding);
    ASSERT_TRUE(Factory.has_value());

    boost::asio::io_context Io;
    auto Listener = Composition::MakeTcpListenerFromSettings(
        Config, Io.get_executor(), std::move(*Factory));
    Preview::Fault::Code Result = Preview::Fault::Code::GenericError;
    std::uint16_t BoundPort = 0;
    Preview::Testing::RunCoro(Io,
                              [&]() -> Net::awaitable<void>
                              {
                                  Result = co_await Composition::StartTcpListenerFromSettings(Config, Listener);
                                  if (Result == Preview::Fault::Code::Success)
                                  {
                                      BoundPort = Listener.LocalEndpoint().port();
                                  }
                                  Listener.Stop();
                              });

    EXPECT_EQ(Result, Preview::Fault::Code::Success);
    EXPECT_NE(BoundPort, 0U);
}

TEST(ProfileBootstrap, RejectsNonNumericListenAddress)
{
    Preview::Settings::ProxyConfig Config;
    const auto LoadError = Preview::Settings::LoadConfig(
        R"({"ListenPort":1080,"Recognition":{"Mode":"Configured","Candidates":[{"Id":6,"Protocol":"http"}]}})",
        Config);
    ASSERT_TRUE(LoadError.Message.empty()) << LoadError.Message;
    Config.ListenAddr = "localhost";
    Config.ListenPort = 0;
    auto Factory = Composition::BuildSessionFactoryFromSettings(Config, MakeBinding);
    ASSERT_TRUE(Factory.has_value());
    boost::asio::io_context Io;
    auto Listener = Composition::MakeTcpListenerFromSettings(
        Config, Io.get_executor(), std::move(*Factory));
    Preview::Fault::Code Result = Preview::Fault::Code::GenericError;

    Preview::Testing::RunCoro(Io,
                              [&]() -> Net::awaitable<void>
                              {
                                  Result = co_await Composition::StartTcpListenerFromSettings(Config, Listener);
                              });

    EXPECT_EQ(Result, Preview::Fault::Code::InvalidArgument);
}

/**
 * @file CarrierSelectionTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "CarrierTestSupport.hpp"

#include <boost/asio/co_spawn.hpp>

#include <Prism/Composition/Provider/TlsCarrierProvider.hpp>
#include <Prism/Composition/Provider/ProviderCatalog.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

#include <exception>

namespace
{
    namespace Provider = Prism::Composition::Provider;

    auto MakeHttpInnerBinding(const Composition::CandidateDefinition &Candidate)
        -> std::optional<Composition::CandidateBinding>
    {
        Composition::CandidateBinding Binding;
        Binding.Spec.Id = Candidate.Id;
        Binding.Spec.Name = Candidate.Name;
        Binding.Spec.Scheme = "http";
        Binding.Spec.Protocol = Prism::Contract::ProtocolType::Http;
        Binding.Spec.Kind = Core::CandidateKind::Cleartext;
        Binding.Spec.Inspect = [](const Core::ProbeSnapshot &)
        {
            return Core::MatchState::Structural;
        };
        Binding.Accept = std::make_shared<Prism::Testing::StreamFactory>(
            [](Prism::Contract::StreamAcceptInput)
                -> Net::awaitable<Prism::Contract::AcceptOutcome>
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
            });
        return Binding;
    }

    auto MakeClientHelloWithEch(
        const std::string_view ServerName,
        const std::string_view Alpn) -> std::vector<std::uint8_t>
    {
        auto Message = MakeClientHello(ServerName, Alpn);
        constexpr std::array<std::uint8_t, 5> EchExtension{0xfe, 0x0d, 0x00, 0x01, 0x00};
        const auto ExtensionsSize =
            (static_cast<std::size_t>(Message[45]) << 8) | Message[46];
        Message[45] = static_cast<std::uint8_t>((ExtensionsSize + EchExtension.size()) >> 8);
        Message[46] = static_cast<std::uint8_t>(ExtensionsSize + EchExtension.size());
        Message.insert(Message.end(), EchExtension.begin(), EchExtension.end());
        const auto HandshakeSize = Message.size() - 4U;
        Message[1] = static_cast<std::uint8_t>(HandshakeSize >> 16);
        Message[2] = static_cast<std::uint8_t>(HandshakeSize >> 8);
        Message[3] = static_cast<std::uint8_t>(HandshakeSize);
        return Message;
    }

    struct RecognitionCarrierScenarioRequest final
    {
        std::shared_ptr<Prism::MemoryStream> Source;
        std::shared_ptr<Prism::MemoryStream> Inbound;
        Core::SharedProfile Profile;
        std::vector<std::byte> Record;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        Core::RecognizeResult &Result;
    };

    auto RunRecognitionCarrierScenario(RecognitionCarrierScenarioRequest Request)
        -> Net::awaitable<void>
    {
        const auto Write = co_await Request.Source->WriteSome(
            std::span<const std::byte>(Request.Record));
        const auto WriteError = Prism::Fault::ToNative(Write.Failure);
        EXPECT_FALSE(WriteError);
        EXPECT_EQ(Write.Bytes, Request.Record.size());
        const auto ShutdownResult = co_await Request.Source->WriteShutdown();
        EXPECT_TRUE(ShutdownResult);
        Core::Pipeline Pipeline(Request.Profile, Request.Bytes);
        Request.Result = co_await Pipeline.Recognize(Request.Inbound);
        if (Request.Result.transport)
        {
            const auto CloseResult = Request.Result.transport->Close();
            EXPECT_TRUE(CloseResult);
            const auto DrainResult = co_await Request.Result.transport->Activity()->Drain();
            EXPECT_TRUE(DrainResult);
        }
        const auto CloseResult = Request.Source->Close();
        EXPECT_TRUE(CloseResult);
        const auto DrainResult = co_await Request.Source->Activity()->Drain();
        EXPECT_TRUE(DrainResult);
    }

    auto RunNaturalCoro(Net::io_context &Io, Net::awaitable<void> Operation) -> void
    {
        std::exception_ptr Failure;
        Net::co_spawn(Io, std::move(Operation),
                      [&Failure](std::exception_ptr Error) { Failure = Error; });
        Io.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }

} // namespace

TEST(RecognitionCarrier, AnytlsCandidateFactoryAndRegistryConstructTypedBinding)
    {
        auto Generation = Prism::Testing::ProviderPin();
        auto Accounts = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Password("candidate-secret"));
        auto UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        Prism::Composition::Provider::ConfiguredInstance Instance;
        Instance.Protocol = {"anytls", "anytls", "anytls", {}};
        Instance.Authentication = {
            Generation, Accounts->Credentials, Accounts->Authenticator};
        Prism::Composition::Provider::Preparation Preparation{
            Generation, UseState, {std::move(Instance)}, {}};
        Net::io_context Io;
        Prism::Composition::Provider::BindingServices Services;
        Services.Executor = Io.get_executor();
        Services.Streams.Egress = Prism::Testing::UnavailableEgress();
        auto Prepared = Prism::Composition::Provider::ProviderCatalog::Prepare(
            std::move(Preparation), std::move(Services));
        ASSERT_TRUE(Prepared);
        auto Frozen = Prepared->Freeze();
        ASSERT_TRUE(Frozen);
        auto Bound = Frozen->Bind({});
        ASSERT_TRUE(Bound);
        const auto *ProviderBinding = Bound->Find("anytls");
        ASSERT_NE(ProviderBinding, nullptr);

        Composition::CandidateRegistry Registry;
        ASSERT_TRUE(Registry.RegisterConfiguredProvider(
            "anytls", Composition::ProviderCandidateInputs{*ProviderBinding, {}}));

        Composition::CandidateDefinition Candidate;
        Candidate.Id = 102;
        Candidate.Name = "anytls";
        Candidate.Protocol = "anytls";
        Candidate.ProtocolId = "anytls";
        const auto Binding = Registry.Build(Candidate);
        ASSERT_TRUE(Binding.has_value());
        EXPECT_EQ(Binding->Spec.Protocol, Prism::Contract::ProtocolType::AnyTls);
        EXPECT_EQ(Binding->Spec.Kind, Core::CandidateKind::Opaque);
        EXPECT_TRUE(Binding->Spec.RequiresAuthentication);
    }

TEST(RecognitionCarrier, AnytlsCandidateAuthenticatesIntoMuxDataPlane)
    {
        auto Binding = Composition::CandidateFactory::MakeAnytls(Composition::CandidateOptions{103, "anytls", 0, 0, false}, Prism::Anytls::IngressOptions{.Configuration = Prism::Anytls::ServerConfig{"candidate-secret"}, .Streams = {.Egress = Prism::Testing::UnavailableEgress()}});
        const auto Result = RunAnytlsCandidateAccept(
            std::move(Binding), MakeAnytlsAuthFrame("candidate-secret", 3));

        EXPECT_EQ(Result.Exception, nullptr);
        EXPECT_EQ(Result.Code, Prism::Fault::Code::Success);
        EXPECT_TRUE(Result.IsMux);
        EXPECT_TRUE(Result.ProtocolAuthenticated);
        EXPECT_TRUE(Result.HasTransport);
        EXPECT_TRUE(Result.HasOwner);
    }

TEST(RecognitionCarrier, AnytlsCandidateRejectsWrongPasswordBeforeCommit)
    {
        auto Binding = Composition::CandidateFactory::MakeAnytls(Composition::CandidateOptions{104, "anytls", 0, 0, false}, Prism::Anytls::IngressOptions{.Configuration = Prism::Anytls::ServerConfig{"candidate-secret"}, .Streams = {.Egress = Prism::Testing::UnavailableEgress()}});
        const auto Frame = MakeAnytlsAuthFrame("wrong-secret");
        const auto Snapshot = SnapshotOf(Frame);
        EXPECT_EQ(Binding.Spec.Inspect(Snapshot), Core::MatchState::Rejected);

        Core::PrepareContext Context;
        Context.Candidate = Binding.Spec.Id;
        Context.Snapshot = Snapshot;
        const auto Prepared = RunPrepare(Binding.Spec.Prepare, std::move(Context));
        EXPECT_EQ(Prepared.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_FALSE(Prepared.NeedMore);
    }

TEST(RecognitionCarrier, AnytlsCandidateAcceptsKnownHashBeforePaddingCompletes)
    {
        auto Binding = Composition::CandidateFactory::MakeAnytls(Composition::CandidateOptions{105, "anytls", 0, 0, false}, Prism::Anytls::IngressOptions{.Configuration = Prism::Anytls::ServerConfig{"candidate-secret"}, .Streams = {.Egress = Prism::Testing::UnavailableEgress()}});
        auto Frame = MakeAnytlsAuthFrame("candidate-secret", 5);
        Frame.resize(Prism::Anytls::AuthFrameHdrlen + 4);
        const auto Snapshot = SnapshotOf(Frame);
        EXPECT_EQ(Binding.Spec.Inspect(Snapshot), Core::MatchState::Authenticated);

        Core::PrepareContext Context;
        Context.Candidate = Binding.Spec.Id;
        Context.Snapshot = Snapshot;
        const auto Prepared = RunPrepare(Binding.Spec.Prepare, std::move(Context));
        EXPECT_EQ(Prepared.Status, Core::RecognitionStatus::Accepted);
        EXPECT_FALSE(Prepared.NeedMore);
    }

TEST(RecognitionCarrier, FiltersBySniAndAlpnWithoutExecutingScheme)
    {
        std::size_t Executes = 0;
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{7, "native", "native", {"edge.example"}, {"h2"}},
            [&Executes](Core::CarrierAcceptInput Input)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                ++Executes;
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });
        const auto Features = MakeFeatures("edge.example", {"h2", "http/1.1"});

        EXPECT_EQ(Binding.Inspect(Features), Core::MatchState::Structural);
        EXPECT_EQ(Executes, 0U);
    }

TEST(RecognitionCarrier, CommitsSchemeOnlyAfterWinnerSelection)
    {
        Net::io_context Io;
        auto [WriterEndpoint, Reader] = Prism::MakeMemoryPair(Io.get_executor());
        auto Writer = std::make_shared<Prism::MemoryStream>(
            std::move(WriterEndpoint));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(Reader));
        const auto WriterCloseResult = Writer->Close();
        EXPECT_TRUE(WriterCloseResult);
        std::size_t Executes = 0;
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{8, "ws", "ws", {"edge.example"}, {"http/1.1"}},
            [&Executes](Core::CarrierAcceptInput Input)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                ++Executes;
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });
        Core::CommitContext Context;
        Context.Candidate = Binding.Spec.Id;
        Context.Inbound = Inbound;
        Core::CommitResult Result;
        Net::co_spawn(Io, Binding.Spec.Commit(std::move(Context)),
                      [&Result](std::exception_ptr Error, Core::CommitResult Value)
                      {
                          if (!Error)
                          {
                              Result = std::move(Value);
                          }
                      });
        Io.run();

        EXPECT_EQ(Executes, 1U);
        EXPECT_EQ(Result.Status, Core::RecognitionStatus::Accepted);
        if (Result.Transport)
        {
            Io.restart();
            const auto CloseResult = Result.Transport->Close();
            EXPECT_TRUE(CloseResult);
            Io.run();
        }
    }

TEST(RecognitionCarrier, RejectsMissingSniUnlessExplicitFallback)
    {
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{9, "native", "native", {"edge.example"}, {"h2"}},
            [](Core::CarrierAcceptInput Input)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });
        EXPECT_EQ(Binding.Inspect(MakeFeatures("", {"h2"})), Core::MatchState::Rejected);

        auto Fallback = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{10, "native-fallback", "native", {}, {}, true},
            [](Core::CarrierAcceptInput Input)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });
        EXPECT_EQ(Fallback.Inspect(MakeFeatures("", {})), Core::MatchState::Structural);
    }

TEST(RecognitionCarrier, AllowsEchOnNativeTlsFallback)
    {
        auto Features = MakeFeatures("outer.example", {"h2"});
        Features.HasEch = true;

        auto RoutedOptions = Composition::TlsCandidateOptions{
            30, "native", "native", {"outer.example"}, {"h2"}};
        RoutedOptions.HasNativeTlsContext = true;
        auto Routed = Composition::TlsCandidateFactory::Make(
            std::move(RoutedOptions),
            [](Core::CarrierAcceptInput Input)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });
        auto FallbackOptions = Composition::TlsCandidateOptions{
            31, "native-fallback", "native", {}, {}, true};
        FallbackOptions.HasNativeTlsContext = true;
        auto Fallback = Composition::TlsCandidateFactory::Make(
            std::move(FallbackOptions),
            [](Core::CarrierAcceptInput Input)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });

        EXPECT_EQ(Routed.Inspect(Features), Core::MatchState::Structural);
        EXPECT_EQ(Fallback.Inspect(Features), Core::MatchState::Structural);
    }

TEST(RecognitionCarrier, PassesEchSyntaxToXhttpWithNativeTlsContext)
    {
        Composition::TlsCandidateOptions Options;
        Options.Id = 32;
        Options.Name = "xhttp-context";
        Options.Scheme = "xhttp";
        Options.Carrier = Composition::TlsCarrier::Xhttp;
        Options.ServerNames = {"inner.example"};
        Options.Alpn = {"h2"};
        Options.HasNativeTlsContext = true;
        const auto Binding = Composition::TlsCandidateFactory::Make(
            std::move(Options),
            [](Core::CarrierAcceptInput Input)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });
        auto Features = MakeFeatures("outer.example", {"http/1.1"});
        Features.HasEch = true;
        EXPECT_EQ(Binding.Inspect(Features), Core::MatchState::Structural);
    }

TEST(RecognitionCarrier, NativeTlsContextFromTypedCatalogDefersEchOuterFiltering)
    {
        Net::io_context Io;
        auto TlsContext = std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
        Provider::TlsCarrierPreparationServices Services;
        Services.NativeTls = TlsContext;
        Services.UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        auto Prepared = Provider::TlsCarrierProviderCatalog::Prepare({}, std::move(Services));
        ASSERT_TRUE(Prepared);
        auto Frozen = Prepared->Freeze();
        ASSERT_TRUE(Frozen);
        auto Bound = Frozen->Bind({});
        ASSERT_TRUE(Bound);

        Composition::CandidateRegistry Registry;
        ASSERT_TRUE((*Bound)->Register(Registry));
        ASSERT_TRUE(Registry.Register("http", MakeHttpInnerBinding));
        Composition::CandidateDefinition Definition;
        Definition.Id = 45;
        Definition.Name = "native-inner";
        Definition.Protocol = "http";
        Definition.Scheme = "native";
        Definition.ServerNames = {"inner.example"};
        Definition.Alpn = {"h2"};
        const auto Binding = Registry.Build(Definition);
        ASSERT_TRUE(Binding.has_value());

        const auto Hello = MakeClientHelloWithEch("outer.example", "http/1.1");
        const auto Record = MakeTlsRecord(Hello);
        const std::string Raw(
            reinterpret_cast<const char *>(Record.data()), Record.size());
        EXPECT_EQ(Binding->Spec.Inspect(SnapshotOf(Raw)), Core::MatchState::Structural);

        std::exception_ptr Exception;
        bool Drained = false;
        Net::co_spawn(Io, (*Bound)->Drain(),
            [&Exception, &Drained](std::exception_ptr Error,
                std::expected<void, Prism::Fault::Failure> Result)
            {
                Exception = std::move(Error);
                Drained = Result.has_value();
            });
        Io.run();
        EXPECT_FALSE(Exception);
        EXPECT_TRUE(Drained);
    }

TEST(RecognitionCarrier, ExplicitWebsocketFallbackStillRejectsEchAndKeepsCarrierCommit)
    {
        Composition::TlsCandidateOptions Options;
        Options.Id = 33;
        Options.Scheme = "ws";
        Options.Carrier = Composition::TlsCarrier::WebSocket;
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"http/1.1"};
        Options.Fallback = true;
        const auto Binding = Composition::TlsCandidateFactory::Make(
            std::move(Options), MakeWsAccept(std::make_shared<WsAcceptState>()));
        auto Features = MakeFeatures("wrong.example", {"h2"});
        EXPECT_TRUE(Binding.Spec.Fallback);
        EXPECT_EQ(Binding.Inspect(Features), Core::MatchState::Structural);
        Features.HasEch = true;
        EXPECT_EQ(Binding.Inspect(Features), Core::MatchState::Rejected);
        EXPECT_EQ(Binding.Spec.Scheme, "ws");
        EXPECT_TRUE(static_cast<bool>(Binding.Spec.Commit));
    }

TEST(RecognitionCarrier, ParsesClientHelloBeforeProfileCommit)
    {
        const auto Record = MakeTlsRecord(MakeClientHello("edge.example", "h2"));
        const auto Parsed = Core::ParseClientHello(
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(Record.data()), Record.size()));
        ASSERT_EQ(Parsed.first, Prism::Error::None);
        ASSERT_EQ(Parsed.second.ServerName, "edge.example");
        ASSERT_EQ(Parsed.second.AlpnProtocols.front(), "h2");

        Net::io_context Io;
        std::size_t Executes = 0;
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{11, "native", "", {"edge.example"}, {"h2"}},
            [&Executes](Core::CarrierAcceptInput Input)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                ++Executes;
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });
        Core::ProfileSpec Spec;
        Spec.ConfiguredCandidate = Binding.Spec.Id;
        Spec.Candidates.push_back(Binding.Spec);
        auto Profile = Core::Profile::Compile(std::move(Spec));
        ASSERT_TRUE(Profile.has_value());

        auto [Writer, Reader] = Prism::MakeMemoryPair(Io.get_executor());
        auto Source = std::make_shared<Prism::MemoryStream>(std::move(Writer));
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(Reader));
        Core::RecognizeResult Result;
        RunNaturalCoro(Io, RunRecognitionCarrierScenario(RecognitionCarrierScenarioRequest{
            Source, Inbound, *Profile, std::move(Record),
            Prism::Tests::WsFactorySupport::WebSocketTestBytes(), Result}));

        EXPECT_TRUE(Result.success);
        EXPECT_EQ(Result.Candidate, 11U);
        EXPECT_EQ(Result.CandidateName, "native");
        EXPECT_EQ(Executes, 1U);
    }

TEST(RecognitionCarrier, ExposesAllCarrierSchemeNames)
    {
        const std::vector<std::pair<Composition::TlsCarrier, std::string>> Cases = {
            {Composition::TlsCarrier::Native, "native"},
            {Composition::TlsCarrier::Reality, "reality"},
            {Composition::TlsCarrier::Shadowtls, "shadowtls"},
            {Composition::TlsCarrier::Restls, "restls"},
            {Composition::TlsCarrier::WebSocket, "ws"},
            {Composition::TlsCarrier::Xhttp, "xhttp"},
            {Composition::TlsCarrier::Gun, "gun"},
        };
        EXPECT_EQ(Cases.size(), 7U);
        for (const auto &[Carrier, Scheme] : Cases)
        {
            auto Options = Composition::TlsCandidateOptions{21, {}, {}, {"edge.example"}, {"h2"}};
            Options.Carrier = Carrier;
            const auto Binding = Composition::TlsCandidateFactory::Make(
                Options,
                [](Core::CarrierAcceptInput Input)
                    -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
                {
                    Prism::Recognition::CarrierAcceptResult Result;
                    Result.Transport = std::move(Input.Inbound);
                    co_return Result;
                });
            EXPECT_EQ(Binding.Scheme, Scheme);
            EXPECT_EQ(Binding.Spec.Name, Scheme);
            EXPECT_EQ(Binding.Spec.Scheme, Scheme);
        }
    }

TEST(RecognitionCarrier, NormalizesDirectFactorySchemeAndFallback)
    {
        const auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{26, "native", "NATIVE", {}, {}, true},
            [](Core::CarrierAcceptInput Input)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });

        EXPECT_EQ(Binding.Spec.Scheme, "native");
        EXPECT_TRUE(Binding.Spec.Fallback);
    }

TEST(RecognitionCarrier, MarksDirectFactoryAsTlsCarrier)
    {
        const auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{27, "native", {}, {"edge.example"}, {"h2"}},
            [](Core::CarrierAcceptInput Input)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                Prism::Recognition::CarrierAcceptResult Result;
                Result.Transport = std::move(Input.Inbound);
                co_return Result;
            });

        EXPECT_EQ(Binding.Spec.Kind, Core::CandidateKind::TlsCarrier);
    }


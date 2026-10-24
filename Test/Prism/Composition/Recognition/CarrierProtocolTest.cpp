/**
 * @file CarrierProtocolTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "CarrierTestSupport.hpp"

#include <boost/asio/post.hpp>

#include <Prism/Composition/Recognition/CandidateRegistry.hpp>
#include <Prism/Composition/Provider/BoundCatalog.hpp>
#include <Prism/Composition/Provider/TlsCarrierProvider.hpp>
#include <Prism/Composition/Recognition/TlsCarrierFailure.hpp>
#include <Prism/Composition/Recognition/RestlsCarrier.hpp>
#include <Prism/Contract/Ingress/CarrierConfiguration.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Protocols/Common/ExactIo.hpp>
#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Transport/MemoryStream.hpp>

#include <array>
#include <exception>
#include <memory>
#include <optional>
#include <system_error>
#include <string_view>
#include <tuple>

namespace
{
    namespace Provider = Prism::Composition::Provider;
    namespace Contract = Prism::Contract;

    inline constexpr std::array<std::byte, 4> ReplayPrefix{
        std::byte{0x16}, std::byte{0x03}, std::byte{0x03}, std::byte{0x2a}};

    struct ReplayOwner final
    {
        Prism::SharedTransmission Inbound;
        Prism::SharedTransmission Peer;
        std::shared_ptr<Prism::Memory::BytePool> Bytes;
        bool Seeded{false};
    };

    auto MakeReplayOwner(Net::io_context &Io) -> ReplayOwner
    {
        auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U, 2U});
        Prism::Recognition::ProbeBuffer Buffer(ReplayPrefix.size(), Bytes);
        const auto Seeded = Buffer.Seed(ReplayPrefix);
        auto [Writer, Reader] = Prism::MakeMemoryPair(Io.get_executor());
        auto Raw = std::make_shared<Prism::MemoryStream>(std::move(Reader));
        return {Buffer.Replay(Raw),
                std::make_shared<Prism::MemoryStream>(std::move(Writer)),
                std::move(Bytes), Seeded};
    }

    struct CommitObservation final
    {
        Core::CommitResult Result;
        Prism::IoResult Read;
        Prism::IoResult SchemeWrite;
        std::array<std::byte, ReplayPrefix.size()> Bytes{};
        std::exception_ptr Exception;
        bool CallbackEntered{false};
        bool CallbackResumed{false};
        bool OwnersDrained{false};
        bool OriginalClosedAfterCommit{false};
        bool OriginalDrained{false};
    };

    struct CommitRequest final
    {
        Composition::TlsCandidateBinding Binding;
        ReplayOwner Owner;
        std::shared_ptr<CommitObservation> Observation;
    };

    struct YieldingAcceptRequest final
    {
        std::shared_ptr<CommitObservation> Observation;
        bool ReturnTransport{false};
        Core::CarrierAcceptInput Input;
    };

    struct YieldingAccept final
    {
        std::shared_ptr<CommitObservation> Observation;
        bool ReturnTransport{false};

        auto operator()(Core::CarrierAcceptInput Input) const
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            return Run(YieldingAcceptRequest{Observation, ReturnTransport, std::move(Input)});
        }

        static auto Run(YieldingAcceptRequest Request)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            Request.Observation->CallbackEntered = true;
            co_await Net::post(Net::use_awaitable);
            Request.Observation->CallbackResumed = true;
            Core::CarrierAcceptResult Result;
            if (Request.ReturnTransport) Result.Transport = std::move(Request.Input.Inbound);
            co_return Result;
        }
    };

    struct ImmediateAccept final
    {
        auto operator()(Core::CarrierAcceptInput Input) const
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            Core::CarrierAcceptResult Result;
            Result.Transport = std::move(Input.Inbound);
            co_return Result;
        }
    };

    auto MakeYieldingAccept(const std::shared_ptr<CommitObservation> &Observation,
                            const bool ReturnTransport) -> Composition::CarrierAcceptFn
    {
        return Composition::CarrierAcceptFn(YieldingAccept{Observation, ReturnTransport});
    }

    auto RunCarrierCommit(CommitRequest Request) -> Net::awaitable<void>
    {
        Core::CommitContext Context;
        Context.Candidate = Request.Binding.Spec.Id;
        Context.Inbound = Request.Owner.Inbound;
        Context.Bytes = Request.Owner.Bytes;
        Request.Observation->Result = co_await Request.Binding.Spec.Commit(std::move(Context));
        if (Request.Observation->Result.Transport)
        {
            Request.Observation->Read = co_await Request.Observation->Result.Transport->ReadSome(
                Request.Observation->Bytes);
            co_await CloseAndDrain(Request.Observation->Result.Transport);
        }
        const auto PeerClose = Request.Owner.Peer->Close();
        EXPECT_TRUE(PeerClose);
        const auto PeerDrain = co_await Request.Owner.Peer->Activity()->Drain();
        Request.Observation->OwnersDrained = PeerDrain.has_value();
    }

    auto RunSchemeExceptionCommit(CommitRequest Request) -> Net::awaitable<void>
    {
        Core::CommitContext Context;
        Context.Candidate = Request.Binding.Spec.Id;
        Context.Inbound = Request.Owner.Inbound;
        Context.Bytes = Request.Owner.Bytes;
        Request.Observation->Result = co_await Request.Binding.Spec.Commit(std::move(Context));
        co_await Net::post(Request.Owner.Inbound->Executor(), Net::use_awaitable);
        Request.Observation->OriginalClosedAfterCommit = !Request.Owner.Inbound->IsOpen();
        if (Request.Owner.Inbound->IsOpen())
        {
            const auto CleanupClose = Request.Owner.Inbound->Close();
            EXPECT_TRUE(CleanupClose);
        }
        const auto OriginalDrain = co_await Request.Owner.Inbound->Activity()->Drain();
        Request.Observation->OriginalDrained = OriginalDrain.has_value();
        const auto PeerClose = Request.Owner.Peer->Close();
        EXPECT_TRUE(PeerClose);
        const auto PeerDrain = co_await Request.Owner.Peer->Activity()->Drain();
        Request.Observation->OwnersDrained = PeerDrain.has_value();
    }

    auto RunUnavailablePrepare(Contract::CarrierConfiguration Configuration)
        -> std::tuple<Contract::ProviderError, std::string, Prism::IoResult,
                      std::array<std::byte, ReplayPrefix.size()>, bool, bool>
    {
        Net::io_context Io;
        auto Owner = MakeReplayOwner(Io);
        Provider::TlsCarrierPreparationServices Services;
        Services.UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
        Services.ResolveSecret = [](std::string_view) -> std::optional<std::string>
        {
            return std::nullopt;
        };
        const auto Prepared = Provider::TlsCarrierProviderCatalog::Prepare(
            {std::move(Configuration)}, std::move(Services));

        Contract::ProviderError Failure = Contract::ProviderError::UnsupportedInstance;
        std::string FailurePath;
        if (!Prepared)
        {
            Failure = Prepared.error().Code;
            FailurePath = Prepared.error().Path;
        }
        Prism::IoResult Read;
        std::array<std::byte, ReplayPrefix.size()> Bytes{};
        bool Drained = false;
        Net::co_spawn(Io,
            [&Owner, &Read, &Bytes, &Drained]() -> Net::awaitable<void>
            {
                Read = co_await Owner.Inbound->ReadSome(Bytes);
                co_await CloseAndDrain(Owner.Inbound);
                const auto PeerClose = Owner.Peer->Close();
                EXPECT_TRUE(PeerClose);
                const auto PeerDrain = co_await Owner.Peer->Activity()->Drain();
                Drained = PeerDrain.has_value();
            },
            [](std::exception_ptr Error)
            {
                EXPECT_FALSE(Error);
            });
        Io.run();
        return {Failure, std::move(FailurePath), Read, Bytes, Owner.Seeded, Drained};
    }

    /** @brief 写入 ShadowTLS 拒绝样本并执行原有写半关闭。 */
    auto RunShadowtlsMalformedRecord(Prism::SharedTransmission Inbound)
        -> Net::awaitable<Prism::Error>
    {
        const std::array<std::uint8_t, 2> Malformed{0x16, 0x03};
        std::error_code Ec;
        const auto Write = co_await Inbound->WriteSome(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Malformed.data()),
                Malformed.size()));
        Ec = Prism::Fault::ToNative(Write.Failure);
        const auto ShutdownResult = co_await Inbound->WriteShutdown();
        EXPECT_TRUE(ShutdownResult);
        co_return Prism::Error::None;
    }

    /** @brief 向 carrier 写入无效 TLS 前缀并交付原有最终关闭。 */
    auto RunInvalidCarrierStream(Prism::SharedTransmission Inbound)
        -> Net::awaitable<Prism::Error>
    {
        const std::array<std::byte, 2> Invalid{
            std::byte{0x16}, std::byte{0x03}};
        std::error_code ErrorCode;
        const auto Write = co_await Inbound->WriteSome(Invalid);
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        const auto CloseResult = Inbound->Close();
        EXPECT_TRUE(CloseResult);
        co_return Prism::Error::None;
    }
}

TEST(RecognitionCarrier, MapsProtocolAndNativeErrorsToTypedFailures)
{
    const auto Auth = Composition::Detail::FailureFromProtocolError(
        Prism::Error::BadAuth);
    EXPECT_EQ(Auth.Code, Prism::Fault::Code::AuthFailed);
    EXPECT_EQ(Auth.Native, static_cast<std::error_code>(
        Prism::make_error_code(Prism::Error::BadAuth)));

    const auto CancelledNative = std::make_error_code(std::errc::operation_canceled);
    const auto CancelledIo = Prism::IoResult{
        0, Prism::Fault::FromNative(CancelledNative)};
    const auto Cancelled = Prism::Protocol::Common::FailureFromIo(CancelledIo);
    EXPECT_EQ(Cancelled.Code, Prism::Fault::Code::Canceled);
    EXPECT_EQ(Cancelled.Native, CancelledNative);

    const auto TimeoutNative = std::make_error_code(std::errc::timed_out);
    const auto TimeoutIo = Prism::IoResult{
        0, Prism::Fault::FromNative(TimeoutNative)};
    const auto Timeout = Prism::Protocol::Common::FailureFromIo(TimeoutIo);
    EXPECT_EQ(Timeout.Code, Prism::Fault::Code::Timeout);
    EXPECT_EQ(Timeout.Native, TimeoutNative);
}

TEST(RecognitionCarrier, CommitPreservesReplayOwnerAcrossSuspendedAccept)
{
    Net::io_context Io;
    auto Owner = MakeReplayOwner(Io);
    auto Observation = std::make_shared<CommitObservation>();
    auto Options = Composition::TlsCandidateOptions{};
    Options.Id = 40;
    Options.Name = "replay-owner";
    Options.Scheme = "replay-owner";
    auto Binding = Composition::TlsCandidateFactory::Make(
        std::move(Options), MakeYieldingAccept(Observation, true));
    Net::co_spawn(Io, RunCarrierCommit(CommitRequest{
        std::move(Binding), Owner, Observation}),
        [Observation](std::exception_ptr Error) { Observation->Exception = std::move(Error); });
    Io.run();

    EXPECT_FALSE(Observation->Exception);
    EXPECT_TRUE(Observation->CallbackEntered);
    EXPECT_TRUE(Observation->CallbackResumed);
    ASSERT_EQ(Observation->Result.Status, Core::RecognitionStatus::Accepted);
    EXPECT_EQ(Observation->Result.Transport, Owner.Inbound);
    EXPECT_EQ(Observation->Read.Bytes, ReplayPrefix.size());
    EXPECT_FALSE(Observation->Read.Failure.Failed());
    EXPECT_EQ(Observation->Bytes, ReplayPrefix);
    EXPECT_TRUE(Observation->OwnersDrained);
}

TEST(RecognitionCarrier, AcceptedTransportConsumesItsOwnedReplayPrefix)
{
    Net::io_context Io;
    auto Owner = MakeReplayOwner(Io);
    auto Observation = std::make_shared<CommitObservation>();
    auto Options = Composition::TlsCandidateOptions{};
    Options.Id = 42;
    Options.Name = "owned-replay-prefix";
    Options.Scheme = "owned-replay-prefix";
    auto Binding = Composition::TlsCandidateFactory::Make(
        std::move(Options), Composition::CarrierAcceptFn(ImmediateAccept{}));
    Net::co_spawn(Io, RunCarrierCommit(CommitRequest{
        std::move(Binding), Owner, Observation}),
        [Observation](std::exception_ptr Error) { Observation->Exception = std::move(Error); });
    Io.run();

    EXPECT_FALSE(Observation->Exception);
    ASSERT_EQ(Observation->Result.Status, Core::RecognitionStatus::Accepted);
    EXPECT_EQ(Observation->Result.Transport, Owner.Inbound);
    EXPECT_EQ(Observation->Read.Bytes, ReplayPrefix.size());
    EXPECT_FALSE(Observation->Read.Failure.Failed());
    EXPECT_EQ(Observation->Bytes, ReplayPrefix);
    EXPECT_TRUE(Observation->OwnersDrained);
}

TEST(RecognitionCarrier, SuccessWithoutTransportFailsAndRetainsReplayOwner)
{
    Net::io_context Io;
    auto Owner = MakeReplayOwner(Io);
    auto Observation = std::make_shared<CommitObservation>();
    auto Options = Composition::TlsCandidateOptions{};
    Options.Id = 41;
    Options.Name = "malformed-success";
    Options.Scheme = "malformed-success";
    auto Binding = Composition::TlsCandidateFactory::Make(
        std::move(Options), MakeYieldingAccept(Observation, false));
    Net::co_spawn(Io, RunCarrierCommit(CommitRequest{
        std::move(Binding), Owner, Observation}),
        [Observation](std::exception_ptr Error) { Observation->Exception = std::move(Error); });
    Io.run();

    EXPECT_FALSE(Observation->Exception);
    EXPECT_TRUE(Observation->CallbackEntered);
    EXPECT_TRUE(Observation->CallbackResumed);
    ASSERT_EQ(Observation->Result.Status, Core::RecognitionStatus::NoMatch);
    EXPECT_EQ(Observation->Result.FaultCode, Prism::Fault::Code::ProtocolError);
    ASSERT_TRUE(Observation->Result.Transport);
    EXPECT_EQ(Observation->Result.Transport, Owner.Inbound);
    EXPECT_EQ(Observation->Result.Error, std::make_error_code(std::errc::protocol_error));
    EXPECT_FALSE(Observation->Result.NativeError);
    EXPECT_EQ(Observation->Read.Bytes, ReplayPrefix.size());
    EXPECT_FALSE(Observation->Read.Failure.Failed());
    EXPECT_EQ(Observation->Bytes, ReplayPrefix);
    EXPECT_TRUE(Observation->OwnersDrained);
}

TEST(RecognitionCarrier, UnavailableProtocolPrepareRetainsReplayInput)
{
    std::array<Contract::CarrierConfiguration, 3> Cases{};
    Cases[0].Id = "reality-no-key";
    Cases[0].Builtin = "reality";
    Cases[0].Options = Contract::RealityOptions{
        "target.example:443", {"example.com"}, "private-key", {"0102030405060708"}};
    Cases[1].Id = "shadowtls-no-dial";
    Cases[1].Builtin = "shadowtls";
    Cases[1].Options = Contract::ShadowTlsOptions{
        3U, "password", "target.example:443", {"example.com"}, true, 5000U};
    Cases[2].Id = "restls-no-dial";
    Cases[2].Builtin = "restls";
    Cases[2].Options = Contract::RestlsOptions{
        {"example.com"}, "target.example:443", "password", "", "", 5000U};

    const std::array<Contract::ProviderError, 3> Expected{
        Contract::ProviderError::MissingAuthentication,
        Contract::ProviderError::MissingResolver,
        Contract::ProviderError::MissingResolver};
    const std::array<std::string_view, 3> ExpectedPaths{
        "Carriers.Reality.PrivateKeyRef",
        "Carriers.ShadowTLS.Services",
        "Carriers.Restls.Services"};
    for (std::size_t Index = 0; Index < Cases.size(); ++Index)
    {
        const auto [Failure, Path, Read, Bytes, Seeded, Drained] =
            RunUnavailablePrepare(std::move(Cases[Index]));
        EXPECT_EQ(Failure, Expected[Index]);
        EXPECT_EQ(std::string_view(Path), ExpectedPaths[Index]);
        EXPECT_TRUE(Seeded);
        EXPECT_EQ(Read.Bytes, ReplayPrefix.size());
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_EQ(Bytes, ReplayPrefix);
        EXPECT_TRUE(Drained);
    }
}

TEST(RecognitionCarrier, MissingCallbackCannotReportSuccess)
{
    namespace Protocol = Prism::Composition::Protocol;
    Prism::Composition::Recognition::CandidateRegistry Registry;
    const Protocol::ProviderKey Key{
        Protocol::ProviderCategory::TlsCarrier, Protocol::CarrierKind::Restls};

    EXPECT_FALSE(Registry.RegisterTlsCarrier(Key, "restls-missing-callback", {}));
}

TEST(RecognitionCarrier, SchemeExceptionBecomesNoMatch)
    {
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{28, "throwing", "throwing", {}, {}},
            [](Prism::Recognition::CarrierAcceptInput)
                -> Net::awaitable<Prism::Recognition::CarrierAcceptResult>
            {
                throw std::runtime_error("carrier failure");
                co_return Prism::Recognition::CarrierAcceptResult{};
            });
        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Prism::SharedTransmission) -> Net::awaitable<Prism::Error>
            {
                co_return Prism::Error::None;
            });

        EXPECT_EQ(Result.Exception, nullptr);
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
    }

TEST(RecognitionCarrier, SchemeExceptionAfterWriteClosesAndDiscardsTransport)
{
    Net::io_context Io;
    auto Owner = MakeReplayOwner(Io);
    ASSERT_TRUE(Owner.Seeded);
    auto Observation = std::make_shared<CommitObservation>();
    auto Binding = Composition::TlsCandidateFactory::Make(
        Composition::TlsCandidateOptions{42, "write-throw", "write-throw", {}, {}},
        [Observation](Core::CarrierAcceptInput Input)
            -> Net::awaitable<Core::CarrierAcceptResult>
        {
            const std::array<std::byte, 1> Payload{std::byte{0xA5}};
            Observation->SchemeWrite = co_await Input.Inbound->WriteSome(Payload);
            throw std::runtime_error("scheme write failure");
            co_return Core::CarrierAcceptResult{};
        });
    Net::co_spawn(
        Io,
        RunSchemeExceptionCommit(CommitRequest{std::move(Binding), Owner, Observation}),
        [Observation](std::exception_ptr Error)
        { Observation->Exception = std::move(Error); });
    Io.run();

    EXPECT_EQ(Observation->Exception, nullptr);
    EXPECT_EQ(Observation->SchemeWrite.Bytes, 1U);
    EXPECT_FALSE(Observation->SchemeWrite.Failure.Failed());
    EXPECT_EQ(Observation->Result.Status, Core::RecognitionStatus::NoMatch);
    EXPECT_EQ(Observation->Result.FaultCode, Prism::Fault::Code::TlsHsfail);
    EXPECT_EQ(Observation->Result.Transport, nullptr);
    EXPECT_TRUE(Observation->OriginalClosedAfterCommit);
    EXPECT_TRUE(Observation->OriginalDrained);
    EXPECT_TRUE(Observation->OwnersDrained);
}

TEST(RecognitionCarrier, ShadowtlsServerAdapterPreservesMissingTargetFault)
    {
        const auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{29, "shadowtls", "shadowtls", {}, {}},
            Composition::MakeShadowtlsServerAccept(Prism::Shadowtls::ServerOptions{},
                                                    Prism::Shadowtls::ServerConfig{"carrier-password"}));
        const auto Result = RunConcreteHandshake(
            std::move(Binding), RunShadowtlsMalformedRecord);
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Commit.FaultCode, Prism::Fault::Code::NotSupported);
        EXPECT_EQ(Result.Commit.Metadata.Carrier, "shadowtls");
    }

TEST(RecognitionCarrier, ShadowtlsConfiguredCarrierRequiresDialContextAndDestination)
    {
        Composition::ShadowtlsCarrierOptions Options;
        Options.HandshakeDest = "target.example:443";
        Options.Password = "shadowtls-test-password";

        EXPECT_FALSE(Composition::MakeConfiguredShadowtlsServerAccept(Options).has_value());

        Options.Dial = [](const Prism::Network::Target &)
            -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
        {
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::NotSupported});
        };
        const auto Accept = Composition::MakeConfiguredShadowtlsServerAccept(std::move(Options));
        ASSERT_TRUE(Accept.has_value());

        Composition::TlsCandidateOptions Candidate;
        Candidate.Id = 32;
        Candidate.Name = "shadowtls-configured";
        Candidate.Scheme = "shadowtls";
        const auto Binding = Composition::TlsCandidateFactory::Make(
            std::move(Candidate), std::move(*Accept));
        EXPECT_EQ(Binding.Spec.Scheme, "shadowtls");
        EXPECT_TRUE(static_cast<bool>(Binding.Spec.Commit));
    }

TEST(RecognitionCarrier, RestlsConfiguredCarrierRequiresTargetDial)
{
    Composition::RestlsCarrierOptions Options;
    Options.Host = "target.example:443";
    Options.Password = "restls-test-password";

    const auto Accept = Composition::MakeConfiguredRestlsServerAccept(std::move(Options));
    ASSERT_FALSE(Accept);
    EXPECT_EQ(Accept.error(), Composition::RestlsCarrierBuildError::MissingDial);
}

TEST(RecognitionCarrier, TlsCallbackOwnerRequiresDrainForPhysicalRetirement)
{
    namespace Provider = Prism::Composition::Provider;
    using Failure = Prism::Fault::Failure;

    Net::io_context Io;
    Provider::TlsCarrierPreparationServices Services;
    Services.UseState = std::make_shared<Prism::Foundation::GenerationUseState>();
    Services.ResolveSecret = [](std::string_view) -> std::optional<std::string>
    {
        return "test-password";
    };
    Services.Dial = [](const Prism::Network::Target &)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Failure>>
    {
        co_return std::unexpected(Failure{Prism::Fault::Code::NotSupported});
    };

    Prism::Contract::CarrierConfiguration Configuration;
    Configuration.Id = "shadowtls-owner";
    Configuration.Builtin = "shadowtls";
    Prism::Contract::ShadowTlsOptions Options;
    Options.HandshakeDest = "target.example:443";
    Options.PasswordSecretRef = "test-password";
    Configuration.Options = std::move(Options);

    auto Prepared = Provider::TlsCarrierProviderCatalog::Prepare(
        {std::move(Configuration)}, std::move(Services));
    ASSERT_TRUE(Prepared);
    auto Frozen = Prepared->Freeze();
    ASSERT_TRUE(Frozen);
    auto CarrierOwner = Frozen->Bind({});
    ASSERT_TRUE(CarrierOwner);

    Provider::BoundCatalog Catalog;
    ASSERT_TRUE(Catalog.AdoptCarrierOwner("shadowtls-owner", *CarrierOwner));
    EXPECT_FALSE(Catalog.PhysicalRetirement().Complete());
    Catalog.Close();
    const auto Closed = Catalog.PhysicalRetirement();
    ASSERT_EQ(Closed.Owners.size(), 1U);
    EXPECT_EQ(Closed.Owners.front().State, Provider::PhysicalRetirementState::Active);
    EXPECT_FALSE((*CarrierOwner)->IsRetired());

    std::exception_ptr Exception;
    std::expected<void, Failure> DrainResult = std::unexpected(
        Failure{Prism::Fault::Code::ResourceUnavailable});
    bool Completed = false;
    Net::co_spawn(Io, Catalog.Drain(),
        [&Exception, &DrainResult, &Completed](
            std::exception_ptr Error, std::expected<void, Failure> Result)
        {
            Exception = std::move(Error);
            DrainResult = std::move(Result);
            Completed = true;
        });
    Io.run();

    EXPECT_FALSE(Exception);
    ASSERT_TRUE(Completed);
    ASSERT_TRUE(DrainResult);
    EXPECT_TRUE((*CarrierOwner)->IsRetired());
    EXPECT_TRUE(Catalog.PhysicalRetirement().Complete());
}

TEST(RecognitionCarrier, WebsocketServerAcceptFactoryRunsRealHandshake)
    {
        Composition::TlsCandidateOptions Options;
        Options.Id = 31;
        Options.Name = "ws-real";
        Options.Scheme = "ws";
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"http/1.1"};
        const auto Binding = Composition::TlsCandidateFactory::Make(
            std::move(Options),
            Composition::MakeWebsocketServerAccept(
                {},
                Prism::Ws::ServerOptions{"/", "edge.example"}));

        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Prism::SharedTransmission Inbound)
            {
                return RunWsClient(std::move(Inbound), "edge.example");
            });

        EXPECT_EQ(Result.ClientError, Prism::Error::None);
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::Accepted);
        EXPECT_EQ(Result.Commit.Metadata.Carrier, "ws");
    }

TEST(RecognitionCarrier, WebsocketServerAcceptFactoryAcceptsNativeTlsContext)
    {
        auto TlsContext = std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
        const auto Accept = Composition::MakeWebsocketServerAccept(
            TlsContext, Prism::Ws::ServerOptions{"/", "edge.example"});
        EXPECT_TRUE(static_cast<bool>(Accept));
    }

TEST(RecognitionCarrier, WebsocketConcreteAcceptRunsOnlyAtCommit)
    {
        auto State = std::make_shared<WsAcceptState>();
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{22, "ws", "ws", {"edge.example"}, {"http/1.1"}},
            MakeWsAccept(State));
        EXPECT_EQ(Binding.Inspect(MakeFeatures("edge.example", {"http/1.1"})),
                  Core::MatchState::Structural);
        EXPECT_EQ(State->Calls, 0U);
        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Prism::SharedTransmission Inbound)
            {
                return RunWsClient(std::move(Inbound), "edge.example");
            });
        EXPECT_EQ(Result.ClientError, Prism::Error::None);
        EXPECT_TRUE(State->Failure.Succeeded());
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::Accepted);
        EXPECT_EQ(State->Calls, 1U);
    }

TEST(RecognitionCarrier, WebsocketConcreteFailureDoesNotFallbackNative)
    {
        auto State = std::make_shared<WsAcceptState>();
        auto Binding = Composition::TlsCandidateFactory::Make(
            Composition::TlsCandidateOptions{23, "ws", "ws", {"edge.example"}, {"http/1.1"}},
            MakeWsAccept(State));
        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Prism::SharedTransmission Inbound)
            {
                return RunBadWsClient(std::move(Inbound), "edge.example");
            });
        EXPECT_EQ(State->Failure.Code, Prism::Fault::Code::BadMessage);
        EXPECT_FALSE(State->Failure.Native);
        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(State->Calls, 1U);
    }

TEST(RecognitionCarrier, XhttpServerAcceptFactoryRunsRealHandshake)
    {
        auto TlsContext = std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
        Prism::Xhttp::Config Config;
        Config.Path = "/xhttp";
        Config.Host = "edge.example";
        Config.Mode = "StreamOne";
        Composition::TlsCandidateOptions Options;
        Options.Id = 33;
        Options.Name = "xhttp-real";
        Options.Scheme = "xhttp";
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"h2"};
        const auto Binding = Composition::TlsCandidateFactory::Make(
            std::move(Options),
            Composition::MakeXhttpServerAccept(TlsContext, std::move(Config)));

        const auto Result = RunConcreteHandshake(
            std::move(Binding), RunInvalidCarrierStream);

        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Commit.Metadata.Carrier, "xhttp");
        EXPECT_TRUE(Prism::Fault::Failed(Result.Commit.FaultCode));
    }

TEST(RecognitionCarrier, GunServerAcceptFactoryRunsRealHandshake)
    {
        auto TlsContext = std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
        Composition::TlsCandidateOptions Options;
        Options.Id = 34;
        Options.Name = "gun-real";
        Options.Scheme = "gun";
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"h2"};
        const auto Binding = Composition::TlsCandidateFactory::Make(
            std::move(Options),
            Composition::MakeGunServerAccept(
                Composition::GunServerAcceptOptions{
                    TlsContext,
                    Prism::Gun::Config{"/GunService/Tun", "GunService"},
                    Composition::GunServerMode::GunLite}));

        const auto Result = RunConcreteHandshake(
            std::move(Binding), RunInvalidCarrierStream);

        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Commit.Metadata.Carrier, "gun");
        EXPECT_TRUE(Prism::Fault::Failed(Result.Commit.FaultCode));
    }

TEST(RecognitionCarrier, RealityPreparedFactoryRejectsMissingPreparedHello)
    {
        std::array<std::uint8_t, Prism::Reality::KeyLen> PrivateKey{};
        std::vector<std::array<std::uint8_t, Prism::Reality::MaxShortIdLen>> ShortIds(1);
        Composition::TlsCandidateOptions Options;
        Options.Id = 35;
        Options.Name = "reality-prepared";
        Options.Scheme = "reality";
        Options.ServerNames = {"edge.example"};
        Options.Alpn = {"h2"};
        Prism::Reality::PreparedConfig Config{PrivateKey, std::move(ShortIds),
            {"edge.example"}};
        const auto Binding = Composition::TlsCandidateFactory::MakePrepared(
            std::move(Options),
            Composition::MakeRealityServerAccept(std::move(Config)));
        const auto Result = RunConcreteHandshake(
            std::move(Binding), [](Prism::SharedTransmission Inbound)
            -> Net::awaitable<Prism::Error>
            {
                const auto CloseResult = Inbound->Close();
                EXPECT_TRUE(CloseResult);
                co_return Prism::Error::None;
            });

        EXPECT_EQ(Result.Commit.Status, Core::RecognitionStatus::NoMatch);
        EXPECT_EQ(Result.Commit.Metadata.Carrier, "reality");
        EXPECT_TRUE(Prism::Fault::Failed(Result.Commit.FaultCode));
    }

TEST(RecognitionCarrier, AnytlsProtocolAuthenticatesAndPreservesWirePayload)
    {
        const auto Result = RunAnytlsProtocolPair(
            AnytlsProtocolOptions{"carrier-secret", "carrier-secret", true});

        EXPECT_FALSE(Result.TimedOut);
        EXPECT_TRUE(Result.ClientError.Succeeded());
        EXPECT_TRUE(Result.ServerError.Succeeded());
        EXPECT_TRUE(Result.ClientConnected);
        EXPECT_TRUE(Result.ServerConnected);
        EXPECT_FALSE(Result.ReadError);
        EXPECT_FALSE(Result.WriteError);
        EXPECT_EQ(Result.ReadBytes, AnytlsPayload.size());
        EXPECT_EQ(Result.WrittenBytes, AnytlsPayload.size());
        EXPECT_EQ(Result.Received, AnytlsPayload);
        EXPECT_EQ(Result.Exception, nullptr);
    }

TEST(RecognitionCarrier, AnytlsProtocolRejectsWrongPassword)
    {
        const auto Result = RunAnytlsProtocolPair(
            AnytlsProtocolOptions{"wrong-secret", "carrier-secret", false});

        EXPECT_FALSE(Result.TimedOut);
        EXPECT_EQ(Result.ServerError.Code, Prism::Fault::Code::AuthFailed);
        EXPECT_FALSE(Result.ServerConnected);
        EXPECT_EQ(Result.Exception, nullptr);
    }


/** @brief 原wire-vector中的三种不可用入口改由真实配置prepare边界拒绝，不发布虚假wire owner。 */
TEST(RecognitionCarrier, UnavailableConfiguredCarriersCannotPublishWireOwner)
{
    std::array<Contract::CarrierConfiguration, 3> Cases{};
    Cases[0].Id = "reality-no-key";
    Cases[0].Builtin = "reality";
    Cases[0].Options = Contract::RealityOptions{
        "target.example:443", {"example.com"}, "private-key", {"0102030405060708"}};
    Cases[1].Id = "shadowtls-no-dial";
    Cases[1].Builtin = "shadowtls";
    Cases[1].Options = Contract::ShadowTlsOptions{
        3U, "password", "target.example:443", {"example.com"}, true, 5000U};
    Cases[2].Id = "restls-no-dial";
    Cases[2].Builtin = "restls";
    Cases[2].Options = Contract::RestlsOptions{
        {"example.com"}, "target.example:443", "password", "", "", 5000U};

    const std::array<Contract::ProviderError, 3> Expected{
        Contract::ProviderError::MissingAuthentication,
        Contract::ProviderError::MissingResolver,
        Contract::ProviderError::MissingResolver};
    const std::array<std::string_view, 3> ExpectedPaths{
        "Carriers.Reality.PrivateKeyRef",
        "Carriers.ShadowTLS.Services",
        "Carriers.Restls.Services"};
    for (std::size_t Index = 0; Index < Cases.size(); ++Index)
    {
        const auto [Failure, Path, Read, Bytes, Seeded, Drained] =
            RunUnavailablePrepare(std::move(Cases[Index]));
        EXPECT_EQ(Failure, Expected[Index]);
        EXPECT_EQ(std::string_view(Path), ExpectedPaths[Index]);
        EXPECT_TRUE(Seeded);
        EXPECT_EQ(Read.Bytes, ReplayPrefix.size());
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_EQ(Bytes, ReplayPrefix);
        EXPECT_TRUE(Drained);
    }
}


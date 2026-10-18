/** @file AnytlsHandshakeFailureTest.cpp @brief 保留握手首因与根创建失败退休回归。 */
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Anytls/IngressFactory.hpp>
#include <Prism/Protocols/Anytls/Detail/Session/Retirement.hpp>
#include <Prism/Protocols/Mux/RootBinding.hpp>
#include <Prism/Transport/Detail/IoCompletion.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Transport/Transmission.hpp>
#include <TestSupport/Prism/ProviderBindings.hpp>

#include <cstddef>
#include <expected>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <utility>

namespace
{
    namespace Net = boost::asio;

    class PartialHandshakeCarrier final : public Prism::Transmission
    {
    public:
        PartialHandshakeCarrier(Net::any_io_executor Executor, const bool FailWrite,
            Prism::Fault::Failure Failure)
            : Prism::Transmission(Executor), Executor_(std::move(Executor)),
              FailWrite_(FailWrite), Failure_(Failure) {}

        auto Executor() const -> ExecutorType override { return Executor_; }

        auto StartRead(std::span<std::byte> Buffer, Completion Handler) -> void override
        {
            Prism::IoResult Result{0U, Failure_};
            const auto Partial = !FailWrite_ && Reads_++ == 0;
            if (Partial)
            {
                Buffer.front() = std::byte{0};
                Result = Prism::IoResult{1U, {}};
            }
            Prism::Transport::Detail::PostResult(Executor_, std::move(Handler), Result);
        }

        auto StartWrite(std::span<const std::byte>, Completion Handler) -> void override
        {
            Prism::IoResult Result{0U, Failure_};
            const auto Partial = FailWrite_ && Writes_++ == 0;
            if (Partial) Result = Prism::IoResult{1U, {}};
            Prism::Transport::Detail::PostResult(Executor_, std::move(Handler), Result);
        }

        auto StartWriteShutdown(Completion Handler) -> void override
        {
            Prism::Transport::Detail::PostResult(
                Executor_, std::move(Handler), Prism::IoResult{});
        }

        auto OnClose() -> ControlResult override { Closed_ = true; return {}; }
        auto OnCancel() -> ControlResult override { Canceled_ = true; return {}; }

        std::size_t Reads_{0}, Writes_{0};
        bool Closed_{false}, Canceled_{false};

    private:
        Net::any_io_executor Executor_;
        bool FailWrite_{false};
        Prism::Fault::Failure Failure_;
    };

    struct ParentLeaseFailureResult final
    {
        std::shared_ptr<const Prism::Account::AccountBinding> Record;
        std::weak_ptr<Prism::Anytls::Detail::TransportRetirement> WeakRetirement;
        std::shared_ptr<Prism::Foundation::GenerationUseState> UseState{
            std::make_shared<Prism::Foundation::GenerationUseState>()};
        bool SetupFailed{false};
        bool CreateRejected{false};
        bool PhysicalRetirementSucceeded{false};
        bool OwnerRetired{false};
        std::uint32_t ActiveStreamsBefore{0};
        std::uint32_t ActiveStreamsAfter{0};
        std::uint32_t ActiveConnectionsBefore{0};
        std::uint32_t ActiveConnectionsAfter{0};
        std::size_t GenerationUsesBefore{0};
        std::size_t GenerationUsesAfter{0};
        std::string SetupStage{"NotStarted"};
    };

    auto RetainParentLeaseOnCreateFailure(ParentLeaseFailureResult &State)
        -> Net::awaitable<void>
    {
        State.SetupStage = "AccountRecord";
        auto Directory = Prism::Testing::ProviderAccount(
            Prism::Account::Credential::Token("mux-create-parent"),
            Prism::AccountId{4601}, {.MaxConnections = 1, .MaxStreams = 1});
        State.Record = Directory->Store->FindById(Prism::AccountId{4601});
        if (!State.Record) { State.SetupFailed = true; co_return; }
        State.SetupStage = "Credential";
        auto Auth = Directory->Credentials.TryAcquire(
            {.Credential = Prism::Account::CredentialView::Token("mux-create-parent")});
        if (!Auth) { State.SetupFailed = true; co_return; }
        State.SetupStage = "MemoryPair";
        auto [InboundRaw, PeerRaw] = Prism::MakeMemoryPair(co_await Net::this_coro::executor);
        auto Inbound = std::make_shared<Prism::MemoryStream>(std::move(InboundRaw));
        auto Peer = std::make_shared<Prism::MemoryStream>(std::move(PeerRaw));
        Prism::Contract::ProtocolDataPlane Plane;
        Plane.Protocol = Prism::Contract::ProtocolType::AnyTls;
        Plane.ProtocolAuthenticated = true;
        Plane.AccountLease = std::move(*Auth);
        Plane.Root = Prism::Contract::MuxRootDataPlane{Inbound, {}};
        State.SetupStage = "ParentLease";
        auto ParentLease = Plane.AccountLease.Streams().Acquire();
        if (!ParentLease) { State.SetupFailed = true; co_return; }
        State.SetupStage = "RetirementPrepare";
        auto Prepared = Prism::Anytls::Detail::TransportRetirement::Prepare();
        if (!Prepared) { State.SetupFailed = true; co_return; }
        auto Retirement = std::move(*Prepared);
        State.WeakRetirement = Retirement;
        State.SetupStage = "RootParentLease";
        if (!Retirement->AttachMuxRootParentStreamLease(std::move(*ParentLease)))
        {
            State.SetupFailed = true;
            co_return;
        }
        State.SetupStage = "RequestPrepare";
        auto Request = Prism::Contract::MuxRootCreateRequest::Prepare(
            Retirement, State.UseState, std::move(Plane));
        if (!Request) { State.SetupFailed = true; co_return; }
        Prism::Mux::RootOptions WrongGeneration;
        WrongGeneration.GenerationUseState =
            std::make_shared<Prism::Foundation::GenerationUseState>();
        State.SetupStage = "NestedCreate";
        Prism::Mux::NestedRootFactory NestedFactory(WrongGeneration);
        const auto Created = NestedFactory.Create(*Request);
        State.CreateRejected = !Created &&
            Created.error().Code == Prism::Fault::Code::InvalidArgument;
        State.ActiveStreamsBefore = State.Record->Runtime()->ActiveStreams();
        State.ActiveConnectionsBefore = State.Record->Runtime()->ActiveConnections();
        State.GenerationUsesBefore = State.UseState->Outstanding();
        const auto Physical = co_await Retirement->RetireAndDrain();
        State.PhysicalRetirementSucceeded = static_cast<bool>(Physical);
        State.OwnerRetired = Retirement->IsRetired();
        State.ActiveStreamsAfter = State.Record->Runtime()->ActiveStreams();
        State.ActiveConnectionsAfter = State.Record->Runtime()->ActiveConnections();
        State.GenerationUsesAfter = State.UseState->Outstanding();
        (void)Peer->Close();
    }
}

TEST(AnytlsSessionOwner, HandshakeExpectedPreservesPartialNativeFailureAndRetiresCarrier)
{
    Net::io_context Io;
    const auto Native = std::make_error_code(std::errc::connection_reset);
    const auto Failure = Prism::Fault::FromNative(Native);
    auto Client = std::make_shared<PartialHandshakeCarrier>(Io.get_executor(), true, Failure);
    auto Server = std::make_shared<PartialHandshakeCarrier>(Io.get_executor(), false, Failure);
    using ConnectionResult = std::expected<Prism::Anytls::SharedConn,
        Prism::Fault::Failure>;
    std::optional<ConnectionResult> ClientResult;
    std::optional<ConnectionResult> ServerResult;
    std::exception_ptr Exception;
    auto Run = [&]() -> Net::awaitable<void>
    {
        ClientResult = co_await Prism::Anytls::Connect(
            Client, Prism::Anytls::ClientConfig{"partial-write"});
        ServerResult = co_await Prism::Anytls::Accept(
            Server, Prism::Anytls::ServerConfig{"partial-read"});
    };
    Net::co_spawn(Io, Run(), [&](std::exception_ptr Error)
    {
        Exception = Error;
        Io.stop();
    });
    Io.run();

    ASSERT_FALSE(Exception);
    ASSERT_TRUE(ClientResult.has_value());
    ASSERT_TRUE(ServerResult.has_value());
    ASSERT_FALSE(*ClientResult);
    ASSERT_FALSE(*ServerResult);
    EXPECT_EQ(ClientResult->error().Code, Prism::Fault::Code::ConnectionReset);
    EXPECT_EQ(ClientResult->error().Native, Native);
    EXPECT_EQ(ServerResult->error().Code, Prism::Fault::Code::ConnectionReset);
    EXPECT_EQ(ServerResult->error().Native, Native);
    EXPECT_EQ(Client->Writes_, 2U);
    EXPECT_EQ(Server->Reads_, 2U);
    EXPECT_TRUE(Client->Canceled_);
    EXPECT_TRUE(Client->Closed_);
    EXPECT_TRUE(Server->Canceled_);
    EXPECT_TRUE(Server->Closed_);
}

TEST(AnytlsSessionOwner, NestedCreateFailureKeepsParentLeaseUntilPhysicalRetirement)
{
    Net::io_context Io;
    ParentLeaseFailureResult Actual;
    std::exception_ptr Failure;
    Net::co_spawn(Io, RetainParentLeaseOnCreateFailure(Actual),
        [&Failure](std::exception_ptr Error) { Failure = Error; });
    Io.run();
    ASSERT_FALSE(Failure);
    ASSERT_FALSE(Actual.SetupFailed) << "stage=" << Actual.SetupStage;
    EXPECT_TRUE(Actual.CreateRejected);
    EXPECT_EQ(Actual.ActiveStreamsBefore, 1U);
    EXPECT_EQ(Actual.GenerationUsesBefore, 1U);
    EXPECT_TRUE(Actual.PhysicalRetirementSucceeded);
    EXPECT_TRUE(Actual.OwnerRetired);
    EXPECT_EQ(Actual.ActiveStreamsAfter, 0U);
    EXPECT_EQ(Actual.ActiveConnectionsBefore, 1U);
    EXPECT_EQ(Actual.ActiveConnectionsAfter, 0U);
    EXPECT_EQ(Actual.GenerationUsesAfter, 0U);
    EXPECT_TRUE(Actual.WeakRetirement.expired());
}

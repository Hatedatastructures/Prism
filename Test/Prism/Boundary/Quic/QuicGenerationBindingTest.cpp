/** @file QuicGenerationBindingTest.cpp @brief 验证 QUIC 新 CID 按发布代次选择 factory。 */
#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>

#include <Prism/Boundary/Quic/QuicConnectionRegistry.hpp>
#include <Prism/Boundary/Contract/BoundaryDispatcher.hpp>
#include <TestSupport/Prism/QuicFactory.hpp>

#include <array>
#include <functional>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace
{
    namespace Net = boost::asio;
    using Udp = Net::ip::udp;

    class GenerationOwner final : public Prism::Contract::QuicConnectionOwner
    {
    public:
        GenerationOwner(Prism::Contract::QuicConnectionGenerationLease GenerationUse,
            std::function<void()> OnClosed)
            : GenerationUse_(std::move(GenerationUse)), OnClosed_(std::move(OnClosed))
        {
        }

        auto Start() -> void override { HandshakeReady_ = true; }

        [[nodiscard]] auto ReceivePacket(std::span<const std::byte>, const Udp::endpoint&) -> bool override
        {
            if (Closed_) return false;
            ++ReceivedPackets_;
            return true;
        }

        [[nodiscard]] auto State() const noexcept
            -> Prism::Contract::QuicConnectionState override
        {
            return {HandshakeReady_, Closed_};
        }

        auto RequestClose() noexcept -> std::expected<void, Prism::Fault::Failure> override
        {
            ++CloseRequests_;
            return {};
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            Closed_ = true;
            auto OnClosed = std::move(OnClosed_);
            if (OnClosed) OnClosed();
            GenerationUse_ = {};
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        [[nodiscard]] auto ReceivedPackets() const noexcept -> std::size_t { return ReceivedPackets_; }
        [[nodiscard]] auto CloseRequests() const noexcept -> std::size_t { return CloseRequests_; }

    private:
        Prism::Contract::QuicConnectionGenerationLease GenerationUse_;
        std::function<void()> OnClosed_;
        std::size_t ReceivedPackets_{0};
        std::size_t CloseRequests_{0};
        bool HandshakeReady_{false};
        bool Closed_{false};
    };

    class GenerationFactory final : public Prism::Contract::QuicConnectionFactory
    {
    public:
        GenerationFactory(Prism::GenerationId Generation, std::string BindingId)
            : Generation_(Generation), BindingId_(std::move(BindingId))
        {
        }

        [[nodiscard]] auto Create(Prism::Contract::QuicAcceptRequest Request)
            -> std::expected<Prism::Contract::QuicConnectionLease,
                Prism::Contract::ProviderFailure> override
        {
            if (!Request.GenerationUse || Request.GenerationUse.Generation() != Generation_ ||
                Request.GenerationUse.BindingId() != BindingId_ ||
                Request.Metadata.TaskIdentity.Generation != Generation_)
            {
                return std::unexpected(Prism::Contract::ProviderFailure{
                    Prism::Contract::ProviderError::GenerationMismatch, BindingId_, "Quic.Generation"});
            }
            ++Calls_;
            Owner_ = std::make_shared<GenerationOwner>(
                std::move(Request.GenerationUse), std::move(Request.OnClosed));
            return Prism::Contract::QuicConnectionLease{Owner_};
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return false; }
        [[nodiscard]] auto Calls() const noexcept -> std::size_t { return Calls_; }
        [[nodiscard]] auto Owner() const noexcept -> std::shared_ptr<GenerationOwner> { return Owner_; }
        auto ReleaseOwner() noexcept -> void { Owner_.reset(); }

    private:
        Prism::GenerationId Generation_;
        std::string BindingId_;
        std::shared_ptr<GenerationOwner> Owner_;
        std::size_t Calls_{0};
    };

    [[nodiscard]] auto MakePacket(const std::array<std::byte, 4>& Cid, const Udp::endpoint& Peer)
        -> Prism::Boundary::BoundaryPacket
    {
        Prism::Boundary::BoundaryPacket Packet;
        Packet.Peer = Peer;
        // 代次准入场景使用 Initial 前缀，长头与固定比特均必须置位。
        Packet.Payload = {std::byte{0xC0}};
        Packet.Classification.Kind = Prism::Boundary::DatagramKind::Quic;
        Packet.Classification.Route = Prism::Boundary::DatagramRoute::UnknownCid;
        Packet.Classification.ConnectionIdBytes.assign(Cid.begin(), Cid.end());
        return Packet;
    }
}

TEST(QuicGenerationBinding, NewCidUsesCurrentFactoryAndExistingCidKeepsOldOwner)
{
    Net::io_context Io;
    auto Budget = std::make_shared<Prism::Boundary::QuicAdmissionBudget>(
        Prism::Boundary::QuicAdmissionBudgetLimits{8U, 32U});
    auto Registry = std::make_shared<Prism::Boundary::QuicConnectionRegistry>(
        Prism::Boundary::QuicConnectionRegistry::Options{.AdmissionBudget = Budget});
    const auto PeerA = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const auto PeerB = Udp::endpoint(Net::ip::address_v4::loopback(), 4434);
    const std::array<std::byte, 4> CidA{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 4> CidAliasA{
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    const std::array<std::byte, 4> CidB{
        std::byte{9}, std::byte{10}, std::byte{11}, std::byte{12}};
    auto FactoryA = std::make_shared<GenerationFactory>(Prism::GenerationId{31}, "quic-a");
    auto FactoryB = std::make_shared<GenerationFactory>(Prism::GenerationId{32}, "quic-b");
    const auto SnapshotA = Prism::Testing::Quic::MakeIngress(
        FactoryA, Prism::GenerationId{31}, "quic-a");
    const auto SnapshotB = Prism::Testing::Quic::MakeIngress(
        FactoryB, Prism::GenerationId{32}, "quic-b");
    const auto SelectionA = Prism::Testing::Quic::MakeSelection(SnapshotA);
    ASSERT_TRUE(SelectionA->Matches(SnapshotA->GenerationOwner(), SnapshotA->UseState()));
    EXPECT_FALSE(SelectionA->Matches(SnapshotB->GenerationOwner(), SnapshotB->UseState()));

    EXPECT_EQ(Registry->Handle(MakePacket(CidA, PeerA), SnapshotA),
        Prism::Boundary::QuicAdmissionDisposition::Accepted);
    ASSERT_TRUE(FactoryA->Owner());
    auto OwnerA = FactoryA->Owner();
    EXPECT_EQ(FactoryA->Calls(), 1U);
    EXPECT_EQ(FactoryB->Calls(), 0U);
    EXPECT_EQ(SnapshotA->UseState()->Outstanding(), 1U);

    EXPECT_EQ(Registry->Handle(MakePacket(CidAliasA, PeerA), SnapshotB),
        Prism::Boundary::QuicAdmissionDisposition::Rejected);
    EXPECT_EQ(FactoryA->Calls(), 1U);
    EXPECT_EQ(FactoryB->Calls(), 0U);
    EXPECT_EQ(OwnerA->CloseRequests(), 0U);
    EXPECT_FALSE(OwnerA->State().Closed);

    EXPECT_EQ(Registry->Handle(MakePacket(CidA, PeerA), SnapshotB),
        Prism::Boundary::QuicAdmissionDisposition::Accepted);
    EXPECT_EQ(OwnerA->ReceivedPackets(), 2U);
    EXPECT_EQ(FactoryB->Calls(), 0U);
    EXPECT_EQ(SnapshotA->UseState()->Outstanding(), 1U);
    EXPECT_EQ(SnapshotB->UseState()->Outstanding(), 0U);

    auto AliasLease = std::make_shared<Prism::Contract::QuicConnectionLease>(OwnerA);
    ASSERT_TRUE(Registry->Register({
        Prism::Boundary::QuicConnectionRegistry::Cid(CidAliasA.begin(), CidAliasA.end()),
        AliasLease, PeerA}));
    EXPECT_EQ(Registry->ActiveConnectionCount(), 1U);
    EXPECT_EQ(Registry->Handle(MakePacket(CidAliasA, PeerA), SnapshotB),
        Prism::Boundary::QuicAdmissionDisposition::Accepted);
    EXPECT_EQ(FactoryA->Calls(), 1U);
    EXPECT_EQ(SnapshotA->UseState()->Outstanding(), 1U);

    EXPECT_EQ(Registry->Handle(MakePacket(CidB, PeerB), SnapshotB),
        Prism::Boundary::QuicAdmissionDisposition::Accepted);
    ASSERT_TRUE(FactoryB->Owner());
    auto OwnerB = FactoryB->Owner();
    EXPECT_EQ(FactoryB->Calls(), 1U);
    EXPECT_EQ(SnapshotB->UseState()->Outstanding(), 1U);
    EXPECT_EQ(Registry->ActiveConnectionCount(), 2U);

    ASSERT_TRUE(Registry->Close());
    EXPECT_FALSE(Registry->IsRetired());
    bool DrainA = false;
    bool DrainB = false;
    Net::co_spawn(Io, OwnerA->Drain(), [&DrainA](std::exception_ptr Error,
        std::expected<void, Prism::Fault::Failure> Result)
    { DrainA = !Error && static_cast<bool>(Result); });
    Net::co_spawn(Io, OwnerB->Drain(), [&DrainB](std::exception_ptr Error,
        std::expected<void, Prism::Fault::Failure> Result)
    { DrainB = !Error && static_cast<bool>(Result); });
    Io.run();

    EXPECT_TRUE(DrainA);
    EXPECT_TRUE(DrainB);
    EXPECT_TRUE(Registry->IsRetired());
    EXPECT_EQ(Budget->ActiveConnections(), 0U);
    EXPECT_EQ(SnapshotA->UseState()->Outstanding(), 0U);
    EXPECT_EQ(SnapshotB->UseState()->Outstanding(), 0U);
    AliasLease.reset();
    OwnerA.reset();
    OwnerB.reset();
    FactoryA->ReleaseOwner();
    FactoryB->ReleaseOwner();
    EXPECT_EQ(SnapshotA->UseState()->Outstanding(), 0U);
    EXPECT_EQ(SnapshotB->UseState()->Outstanding(), 0U);
}

TEST(QuicGenerationBinding, DispatcherRejectsRawAndQuicSnapshotsFromDifferentGenerations)
{
    auto FactoryA = std::make_shared<GenerationFactory>(Prism::GenerationId{41}, "quic-a");
    auto FactoryB = std::make_shared<GenerationFactory>(Prism::GenerationId{42}, "quic-b");
    const auto SnapshotA = Prism::Testing::Quic::MakeIngress(
        FactoryA, Prism::GenerationId{41}, "quic-a");
    const auto SnapshotB = Prism::Testing::Quic::MakeIngress(
        FactoryB, Prism::GenerationId{42}, "quic-b");
    const auto RawB = std::make_shared<const Prism::Contract::RawDatagramIngressSnapshot>(
        Prism::Contract::RawDatagramIngressSnapshot::Options{
            SnapshotA->Generation(), SnapshotB->UseState(), {}, {}});
    const auto Mismatched =
        std::make_shared<const Prism::Contract::DatagramIngressSelection>(
            Prism::Contract::DatagramIngressSelection::Options{
                SnapshotA->GenerationOwner(), SnapshotA->UseState(), RawB, SnapshotA});
    std::size_t AdmissionCalls = 0;
    Prism::Boundary::BoundaryDispatcher Dispatcher({
        nullptr,
        {},
        [&AdmissionCalls](Prism::Boundary::BoundaryPacket,
            std::shared_ptr<const Prism::Contract::QuicIngressBindingSnapshot>)
        {
            ++AdmissionCalls;
            return Prism::Boundary::QuicAdmissionDisposition::Accepted;
        }});

    Dispatcher.Dispatch(MakePacket(
        {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}},
        Udp::endpoint(Net::ip::address_v4::loopback(), 4433)), Mismatched);

    EXPECT_EQ(AdmissionCalls, 0U);
    EXPECT_EQ(Dispatcher.Snapshot().RejectedPackets, 1U);
    EXPECT_EQ(SnapshotB->UseState()->Outstanding(), 0U);
}

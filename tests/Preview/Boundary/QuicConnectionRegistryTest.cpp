/**
 * @file QuicConnectionRegistryTest.cpp
 * @brief QUIC CID 到已绑定 Native server owner 的注册与生命周期合同。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl/context.hpp>

#include <array>
#include <cstddef>
#include <exception>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <Preview/Boundary/Contract/BoundaryDispatcher.hpp>
#include <Preview/Boundary/Datagram/DatagramClassifier.hpp>
#include <Preview/Boundary/Quic/QuicConnectionRegistry.hpp>
#include <TestSupport/Preview/QuicFactory.hpp>
using Preview::Testing::Quic::MakeLease;
using Preview::Testing::Quic::MakeFactory;
using Preview::Testing::Quic::MakeSender;

namespace
{
    namespace Net = boost::asio;
    using BoundaryPacket = Preview::Boundary::BoundaryPacket;
    using Registry = Preview::Boundary::QuicConnectionRegistry;
    using Udp = Net::ip::udp;

    [[nodiscard]] auto MakeBudget(
        const std::size_t MaxConnections = 4096U,
        const std::size_t MaxPacketsPerConnection = 65536U)
        -> std::shared_ptr<Preview::Boundary::QuicAdmissionBudget>
    {
        return std::make_shared<Preview::Boundary::QuicAdmissionBudget>(
            Preview::Boundary::QuicAdmissionBudgetLimits{
                MaxConnections, MaxPacketsPerConnection});
    }

    [[nodiscard]] auto MakeRegistryOptions() -> Registry::Options
    {
        Registry::Options Value;
        Value.AdmissionBudget = MakeBudget();
        return Value;
    }

    /** @brief 关闭通知落到 registry owner 后移除同一主 CID。 */
    auto RemoveClosedOwner(const std::shared_ptr<std::weak_ptr<Registry>>& OwnerSlot,
        const std::array<std::byte, 4>& PrimaryCid) -> void
    {
        if (const auto RegistryOwner = OwnerSlot->lock())
        {
            (void)RegistryOwner->OnOwnerClosed(PrimaryCid);
        }
    }

    [[nodiscard]] auto MakeServer(
        Net::io_context &Io,
        std::shared_ptr<Net::ssl::context> Tls = {},
        std::size_t *ClosedCalls = nullptr) -> std::shared_ptr<Preview::Quic::Server>
    {
        Preview::Quic::ServerOptions Options;
        Options.Executor = Io.get_executor();
        Options.Socket = std::make_shared<Udp::socket>(Io, Udp::v4());
        Options.Sender = MakeSender(Options.Socket);
        Options.TlsContext = std::move(Tls);
        Options.ExternalReceive = true;
        if (ClosedCalls)
        {
            Options.OnClosed = [ClosedCalls] { ++*ClosedCalls; };
        }
        return std::make_shared<Preview::Quic::Server>(std::move(Options));
    }

    [[nodiscard]] auto MakePacket(
        const std::array<std::byte, 4> &ConnectionId,
        const Udp::endpoint &Peer) -> Preview::Boundary::BoundaryPacket
    {
        Preview::Boundary::BoundaryPacket Packet;
        Packet.Peer = Peer;
        Packet.Payload = {std::byte{0x01}};
        Packet.Classification.ConnectionIdBytes.assign(ConnectionId.begin(), ConnectionId.end());
        return Packet;
    }

    [[nodiscard]] auto MakeUnknownQuicPacket(
        const std::array<std::byte, 4>& ConnectionId,
        const Udp::endpoint& Peer) -> Preview::Boundary::BoundaryPacket
    {
        auto Packet = MakePacket(ConnectionId, Peer);
        Packet.Classification.Kind = Preview::Boundary::DatagramKind::Quic;
        Packet.Classification.Route = Preview::Boundary::DatagramRoute::UnknownCid;
        return Packet;
    }

    class RetryCloseOwner final : public Preview::Contract::QuicConnectionOwner
    {
    public:
        explicit RetryCloseOwner(std::vector<Preview::Fault::Failure> Rejections,
            const bool HandshakeReady = false, const bool Closed = false)
            : Rejections_(std::move(Rejections)), Closed_(Closed), HandshakeReady_(HandshakeReady)
        {
        }

        auto Start() -> void override {}

        [[nodiscard]] auto ReceivePacket(
            std::span<const std::byte>, const Udp::endpoint&) -> bool override
        {
            return false;
        }

        [[nodiscard]] auto State() const noexcept
            -> Preview::Contract::QuicConnectionState override
        {
            return {HandshakeReady_, Closed_};
        }

        [[nodiscard]] auto RequestClose() noexcept
            -> std::expected<void, Preview::Fault::Failure> override
        {
            ++Attempts_;
            if (Attempts_ <= Rejections_.size())
            {
                return std::unexpected(Rejections_[Attempts_ - 1U]);
            }
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] auto Attempts() const noexcept -> std::size_t
        {
            return Attempts_;
        }

    private:
        std::vector<Preview::Fault::Failure> Rejections_;
        std::size_t Attempts_{0};
        bool Closed_{false};
        bool HandshakeReady_{false};
    };

    class BudgetAdmissionOwner final : public Preview::Contract::QuicConnectionOwner
    {
    public:
        BudgetAdmissionOwner(std::vector<Preview::Fault::Failure> Rejections,
            std::function<void()> OnClosed,
            Preview::Contract::QuicConnectionGenerationLease GenerationUse)
            : Rejections_(std::move(Rejections)), OnClosed_(std::move(OnClosed)),
              GenerationUse_(std::move(GenerationUse))
        {
        }

        auto Start() -> void override {}

        [[nodiscard]] auto ReceivePacket(
            std::span<const std::byte>, const Udp::endpoint&) -> bool override
        {
            return true;
        }

        [[nodiscard]] auto State() const noexcept
            -> Preview::Contract::QuicConnectionState override
        {
            return {false, Closed_};
        }

        [[nodiscard]] auto RequestClose() noexcept
            -> std::expected<void, Preview::Fault::Failure> override
        {
            ++Attempts_;
            if (Attempts_ <= Rejections_.size())
            {
                return std::unexpected(Rejections_[Attempts_ - 1U]);
            }
            Closed_ = true;
            return {};
        }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>> override
        {
            if (!Closed_)
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            auto Observer = std::move(OnClosed_);
            if (Observer)
            {
                Observer();
            }
            GenerationUse_ = {};
            co_return std::expected<void, Preview::Fault::Failure>{};
        }

        [[nodiscard]] auto Attempts() const noexcept -> std::size_t
        {
            return Attempts_;
        }

    private:
        std::vector<Preview::Fault::Failure> Rejections_;
        std::function<void()> OnClosed_;
        Preview::Contract::QuicConnectionGenerationLease GenerationUse_;
        std::size_t Attempts_{0};
        bool Closed_{false};
    };

    class BudgetAdmissionFactory final : public Preview::Contract::QuicConnectionFactory
    {
    public:
        explicit BudgetAdmissionFactory(std::vector<Preview::Fault::Failure> Rejections)
            : Rejections_(std::move(Rejections))
        {
        }

        [[nodiscard]] auto Create(Preview::Contract::QuicAcceptRequest Request)
            -> std::expected<Preview::Contract::QuicConnectionLease,
                Preview::Contract::ProviderFailure> override
        {
            ++Calls_;
            Owner_ = std::make_shared<BudgetAdmissionOwner>(
                Rejections_, std::move(Request.OnClosed), std::move(Request.GenerationUse));
            return std::expected<Preview::Contract::QuicConnectionLease,
                Preview::Contract::ProviderFailure>{std::in_place, Owner_};
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return false; }

        [[nodiscard]] auto Calls() const noexcept -> std::size_t
        {
            return Calls_;
        }

        [[nodiscard]] auto Owner() const noexcept
            -> std::shared_ptr<BudgetAdmissionOwner>
        {
            return Owner_;
        }

        auto ReleaseOwner() noexcept -> void { Owner_.reset(); }

    private:
        std::vector<Preview::Fault::Failure> Rejections_;
        std::shared_ptr<BudgetAdmissionOwner> Owner_;
        std::size_t Calls_{0};
    };
} // namespace

TEST(QuicConnectionRegistry, RejectsDuplicateCidAndPeerConflicts)
{
    Net::io_context Io;
    Registry Owners(MakeRegistryOptions());
    const auto Peer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const auto OtherPeer = Udp::endpoint(Net::ip::address_v4::loopback(), 4434);
    const std::array<std::byte, 4> Cid{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};

    ASSERT_TRUE(Owners.Register({Registry::Cid(Cid.begin(), Cid.end()), MakeLease(MakeServer(Io)), Peer}));
    EXPECT_FALSE(Owners.Register({Registry::Cid(Cid.begin(), Cid.end()), MakeLease(MakeServer(Io)), OtherPeer}));
    const std::array<std::byte, 4> OtherCid{
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    EXPECT_FALSE(Owners.Register({
        Registry::Cid(OtherCid.begin(), OtherCid.end()), MakeLease(MakeServer(Io)), Peer}));
    EXPECT_EQ(Owners.Size(), 1U);
    ASSERT_TRUE(Owners.Close());
    EXPECT_EQ(Owners.Size(), 0U);
}

TEST(QuicConnectionRegistry, RequiresBoundFactoryForUnknownCid)
{
    Net::io_context Io;
    const auto Peer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const std::array<std::byte, 4> Cid{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const auto Packet = MakePacket(Cid, Peer);

    Registry MissingFactory(MakeRegistryOptions());
    EXPECT_EQ(MissingFactory.Handle(Packet, Preview::Testing::Quic::MakeIngress()),
        Preview::Boundary::QuicAdmissionDisposition::NotHandled);
    EXPECT_EQ(MissingFactory.Size(), 0U);

    std::size_t FactoryCalls = 0;
    Registry NullFactory(MakeRegistryOptions());
    const auto Ingress = Preview::Testing::Quic::MakeIngress(
        MakeFactory([&FactoryCalls](Preview::Contract::QuicAcceptRequest)
            -> std::shared_ptr<Preview::Quic::Server>
        {
            ++FactoryCalls;
            return {};
        }));
    EXPECT_EQ(NullFactory.Handle(Packet, Ingress),
        Preview::Boundary::QuicAdmissionDisposition::Rejected);
    EXPECT_EQ(FactoryCalls, 1U);
    EXPECT_EQ(NullFactory.Size(), 0U);
}

TEST(QuicConnectionRegistry, RejectsEmptyCidFromNewPeerBeforeFactoryAndPreservesFallback)
{
    Net::io_context Io;
    const auto ExistingPeer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const auto NewPeer = Udp::endpoint(Net::ip::address_v4::loopback(), 4434);
    const std::array<std::byte, 4> ExistingCid{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    std::size_t ExistingCloseCalls = 0;
    const auto ExistingServer = MakeServer(Io, {}, &ExistingCloseCalls);
    std::size_t FactoryCalls = 0;
    auto Owners = std::make_shared<Registry>(MakeRegistryOptions());
    const auto Ingress = Preview::Testing::Quic::MakeIngress(MakeFactory(
        [&FactoryCalls](Preview::Contract::QuicAcceptRequest)
            -> std::shared_ptr<Preview::Quic::Server>
        {
            ++FactoryCalls;
            return {};
        }));
    const auto Selection = Preview::Testing::Quic::MakeSelection(Ingress);
    ASSERT_TRUE(Owners->Register({
        Registry::Cid(ExistingCid.begin(), ExistingCid.end()), MakeLease(ExistingServer), ExistingPeer}));

    const std::vector<std::byte> ExpectedPayload{
        std::byte{0x40}, std::byte{0xA1}, std::byte{0x02}, std::byte{0x03}};
    Preview::Boundary::DatagramClassifier Classifier;
    BoundaryPacket Packet;
    Packet.Payload = ExpectedPayload;
    Packet.Peer = NewPeer;
    Packet.Classification = Classifier.Classify(Packet.Payload);
    Packet.Sequence = 0x1020304050607080ULL;
    ASSERT_EQ(Packet.Classification.Kind, Preview::Boundary::DatagramKind::Quic);
    ASSERT_EQ(Packet.Classification.Route, Preview::Boundary::DatagramRoute::UnknownCid);
    ASSERT_TRUE(Packet.Classification.ConnectionIdBytes.empty());

    std::optional<BoundaryPacket> Fallback;
    Preview::Boundary::BoundaryDispatcher Dispatcher({
        nullptr,
        [&Fallback](BoundaryPacket Received) { Fallback = std::move(Received); },
        [Owners](BoundaryPacket Candidate,
            std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot> Ingress)
        { return Owners->Handle(Candidate, Ingress); }});

    Dispatcher.Dispatch(Packet, Selection);

    EXPECT_EQ(FactoryCalls, 0U);
    EXPECT_EQ(Owners->Size(), 1U);
    EXPECT_FALSE(ExistingServer->Health().Closed);
    EXPECT_EQ(ExistingCloseCalls, 0U);
    ASSERT_TRUE(Fallback.has_value());
    EXPECT_EQ(Fallback->Payload, ExpectedPayload);
    EXPECT_EQ(Fallback->Peer, NewPeer);
    EXPECT_EQ(Fallback->Sequence, Packet.Sequence);
    EXPECT_EQ(Fallback->Classification.Kind, Preview::Boundary::DatagramKind::Quic);
    EXPECT_EQ(Fallback->Classification.Route, Preview::Boundary::DatagramRoute::UnknownCid);
    EXPECT_TRUE(Fallback->Classification.ConnectionIdBytes.empty());
    EXPECT_EQ(Dispatcher.Snapshot().DatagramPackets, 1U);
    EXPECT_EQ(Dispatcher.Snapshot().QuicPackets, 0U);
    EXPECT_EQ(Dispatcher.Snapshot().RejectedPackets, 0U);

    ASSERT_TRUE(Owners->Close());
    Io.run();
    EXPECT_EQ(ExistingCloseCalls, 1U);
}

TEST(QuicConnectionRegistry, PreboundFactoryReceivesCidPeerAndRollsBackRejectedPacket)
{
    Net::io_context Io;
    auto Tls=std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
    const auto Peer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const std::array<std::byte, 4> Cid{
        std::byte{9}, std::byte{10}, std::byte{11}, std::byte{12}};
    std::size_t FactoryCalls = 0;
    std::size_t ClosedCalls = 0;
    std::vector<std::byte> FactoryCid;
    Udp::endpoint FactoryPeer;
    std::shared_ptr<Preview::Quic::Server> CreatedServer;
    Registry Owners(MakeRegistryOptions());
    const auto Ingress = Preview::Testing::Quic::MakeIngress(MakeFactory(
        [&Io, &Tls, &FactoryCalls, &FactoryCid, &FactoryPeer, &ClosedCalls, &CreatedServer](
            Preview::Contract::QuicAcceptRequest Request) -> std::shared_ptr<Preview::Quic::Server>
        {
            ++FactoryCalls;
            FactoryCid = Request.ConnectionId;
            FactoryPeer = Request.Peer;
            CreatedServer = MakeServer(Io, Tls, &ClosedCalls);
            return CreatedServer;
        }));

    auto Packet = MakePacket(Cid, Peer);
    Packet.Payload.clear();
    EXPECT_EQ(Owners.Handle(std::move(Packet), Ingress),
        Preview::Boundary::QuicAdmissionDisposition::Rejected);
    EXPECT_EQ(FactoryCalls, 1U);
    EXPECT_EQ(FactoryCid, (std::vector<std::byte>(Cid.begin(), Cid.end())));
    EXPECT_EQ(FactoryPeer, Peer);
    EXPECT_EQ(Owners.Size(), 0U);
    ASSERT_TRUE(CreatedServer);
    Io.run();
    EXPECT_TRUE(CreatedServer->Health().Closed);
    EXPECT_EQ(ClosedCalls, 1U);
}

TEST(QuicConnectionRegistry, RemovesServerWhenFirstPacketIsRejected)
{
    Net::io_context Io;
    auto Tls=std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
    const auto Peer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const std::array<std::byte, 4> Cid{
        std::byte{9}, std::byte{10}, std::byte{11}, std::byte{12}};
    std::size_t ClosedCalls = 0;
    std::shared_ptr<Preview::Quic::Server> CreatedServer;
    Registry Owners(MakeRegistryOptions());
    const auto Ingress = Preview::Testing::Quic::MakeIngress(MakeFactory(
        [&Io, &Tls, &ClosedCalls, &CreatedServer](
            Preview::Contract::QuicAcceptRequest)
            -> std::shared_ptr<Preview::Quic::Server>
        {
            CreatedServer = MakeServer(Io, Tls, &ClosedCalls);
            return CreatedServer;
        }));

    EXPECT_EQ(Owners.Handle(MakePacket(Cid, Peer), Ingress),
        Preview::Boundary::QuicAdmissionDisposition::Rejected);
    EXPECT_EQ(Owners.Size(), 0U);
    ASSERT_TRUE(CreatedServer);
    Io.run();
    EXPECT_TRUE(CreatedServer->Health().Closed);
    EXPECT_EQ(ClosedCalls, 1U);
}

TEST(QuicConnectionRegistry, KeepsRegisteredCidOwnersIndependent)
{
    Net::io_context Io;
    Registry Owners(MakeRegistryOptions());
    const auto FirstPeer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const auto SecondPeer = Udp::endpoint(Net::ip::address_v4::loopback(), 4434);
    const std::array<std::byte, 4> FirstCid{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 4> SecondCid{
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};

    ASSERT_TRUE(Owners.Register({
        Registry::Cid(FirstCid.begin(), FirstCid.end()), MakeLease(MakeServer(Io)), FirstPeer}));
    ASSERT_TRUE(Owners.Register({
        Registry::Cid(SecondCid.begin(), SecondCid.end()), MakeLease(MakeServer(Io)), SecondPeer}));
    ASSERT_EQ(Owners.Size(), 2U);
    EXPECT_TRUE(Owners.Remove(FirstCid));
    EXPECT_EQ(Owners.Size(), 1U);
    EXPECT_TRUE(Owners.Remove(SecondCid));
    EXPECT_EQ(Owners.Size(), 0U);
    ASSERT_TRUE(Owners.Close());
}

TEST(QuicConnectionRegistry, RemoveKeepsBudgetUntilPhysicalOwnerReceipt)
{
    auto Budget = MakeBudget(2U, 8U);
    Registry::Options Options;
    Options.AdmissionBudget = Budget;
    Registry Owners(std::move(Options));
    const auto Peer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const std::array<std::byte, 4> ConnectionId{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    auto Owner = std::make_shared<RetryCloseOwner>(
        std::vector<Preview::Fault::Failure>{});
    auto Lease = std::make_shared<Preview::Contract::QuicConnectionLease>(Owner);

    ASSERT_TRUE(Owners.Register({
        Registry::Cid(ConnectionId.begin(), ConnectionId.end()), Lease, Peer}));
    ASSERT_TRUE(Owner->RequestClose());
    ASSERT_TRUE(Owners.Remove(ConnectionId));
    EXPECT_EQ(Owners.Size(), 0U);
    EXPECT_EQ(Budget->ActiveConnections(), 1U);

    ASSERT_TRUE(Owners.Close());
    EXPECT_FALSE(Owners.IsRetired());
    EXPECT_EQ(Budget->ActiveConnections(), 1U);
    ASSERT_TRUE(Owners.OnOwnerClosed(ConnectionId));
    EXPECT_TRUE(Owners.IsRetired());
    EXPECT_EQ(Budget->ActiveConnections(), 0U);
}

TEST(QuicConnectionRegistry, RegisteredAliasesShareOwnerUntilFinalCidIsRemoved)
{
    Net::io_context Io;
    auto Tls=std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
    Registry Owners(MakeRegistryOptions());
    const auto Peer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const auto OtherPeer = Udp::endpoint(Net::ip::address_v4::loopback(), 4434);
    const std::array<std::byte, 4> FirstCid{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 4> AliasCid{
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    const std::array<std::byte, 4> SecondAliasCid{
        std::byte{9}, std::byte{10}, std::byte{11}, std::byte{12}};
    const std::array<std::byte, 4> ConflictingPeerCid{
        std::byte{13}, std::byte{14}, std::byte{15}, std::byte{16}};
    std::size_t ClosedCalls = 0;
    const auto Server = MakeServer(Io, Tls, &ClosedCalls);
    ASSERT_TRUE(Owners.Register({
        Registry::Cid(FirstCid.begin(), FirstCid.end()), MakeLease(Server), Peer}));
    ASSERT_TRUE(Owners.Register({
        Registry::Cid(AliasCid.begin(), AliasCid.end()), MakeLease(Server), Peer}));
    EXPECT_EQ(Owners.ActiveConnectionCount(), 1U);
    EXPECT_EQ(Owners.Size(), 2U);
    EXPECT_FALSE(Owners.Register({
        Registry::Cid(ConflictingPeerCid.begin(), ConflictingPeerCid.end()), MakeLease(Server), OtherPeer}));
    EXPECT_EQ(Owners.Size(), 2U);
    EXPECT_EQ(Owners.ActiveConnectionCount(), 1U);
    EXPECT_TRUE(Owners.Remove(AliasCid));
    EXPECT_EQ(Owners.ActiveConnectionCount(), 1U);
    EXPECT_EQ(Owners.Size(), 1U);
    EXPECT_FALSE(Server->Health().Closed);
    EXPECT_EQ(ClosedCalls, 0U);

    EXPECT_TRUE(Owners.Register({
        Registry::Cid(SecondAliasCid.begin(), SecondAliasCid.end()), MakeLease(Server), Peer}));
    EXPECT_EQ(Owners.Size(), 2U);

    ASSERT_TRUE(Owners.Close());
    Io.run();
    EXPECT_TRUE(Server->Health().Closed);
    EXPECT_EQ(ClosedCalls, 1U);
    EXPECT_EQ(Owners.Size(), 0U);
}

TEST(QuicConnectionRegistry, SharedBudgetUses4096ProductionOwnerLimit)
{
    const Preview::Boundary::QuicAdmissionBudget Budget;
    const auto Limits = Budget.Limits();
    EXPECT_EQ(Limits.MaxConnections, 4096U);
    EXPECT_EQ(Limits.MaxPacketsPerConnection, 65536U);
}

TEST(QuicConnectionRegistry, RejectedPeerAliasDoesNotCloseExistingOwner)
{
    Registry Owners(MakeRegistryOptions());
    const auto Peer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const std::array<std::byte, 4> PrimaryCid{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 4> AliasCid{
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    const auto Owner = std::make_shared<RetryCloseOwner>(
        std::vector<Preview::Fault::Failure>{}, true);
    auto Lease = std::make_shared<Preview::Contract::QuicConnectionLease>(Owner);
    ASSERT_TRUE(Owners.Register({
        Registry::Cid(PrimaryCid.begin(), PrimaryCid.end()), Lease, Peer}));

    auto Conflict = MakePacket(AliasCid, Peer);
    Conflict.Payload.front() = std::byte{0x80};
    EXPECT_EQ(Owners.Handle(Conflict, Preview::Testing::Quic::MakeIngress()),
        Preview::Boundary::QuicAdmissionDisposition::NotHandled);
    EXPECT_EQ(Owners.Size(), 1U);
    EXPECT_EQ(Owner->Attempts(), 0U);
    EXPECT_FALSE(Owner->State().Closed);
    ASSERT_TRUE(Owners.Close());
    EXPECT_FALSE(Owners.IsRetired());
    EXPECT_TRUE(Owners.OnOwnerClosed(PrimaryCid));
    EXPECT_TRUE(Owners.IsRetired());
}

TEST(QuicConnectionRegistry, ServerCloseCallbackRemovesOwnerAndAliasesWithoutAnotherPacket)
{
    Net::io_context Io;
    auto Tls=std::make_shared<Net::ssl::context>(Net::ssl::context::tls_server);
    auto Owners = std::make_shared<Registry>(MakeRegistryOptions());
    auto OwnerSlot = std::make_shared<std::weak_ptr<Registry>>(Owners);
    const auto Peer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const std::array<std::byte, 4> PrimaryCid{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 4> AliasCid{
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    std::size_t OwnerCloseCalls = 0;

    Preview::Quic::ServerOptions Options;
    Options.Executor = Io.get_executor();
    Options.Socket = std::make_shared<Udp::socket>(Io, Udp::v4());
    Options.Sender = MakeSender(Options.Socket);
    Options.TlsContext = Tls;
    Options.ExternalReceive = true;
    Options.OnClosed = [OwnerSlot, PrimaryCid, &Io, &OwnerCloseCalls]
    {
        ++OwnerCloseCalls;
        Net::post(Io, [OwnerSlot, PrimaryCid]
        {
            RemoveClosedOwner(OwnerSlot, PrimaryCid);
        });
    };
    const auto Server = std::make_shared<Preview::Quic::Server>(std::move(Options));
    ASSERT_TRUE(Owners->Register({
        Registry::Cid(PrimaryCid.begin(), PrimaryCid.end()), MakeLease(Server), Peer}));
    ASSERT_TRUE(Owners->Register({
        Registry::Cid(AliasCid.begin(), AliasCid.end()), MakeLease(Server), Peer}));
    ASSERT_EQ(Owners->Size(), 2U);

    Server->Close();
    Io.run();

    EXPECT_TRUE(Server->Health().Closed);
    EXPECT_EQ(OwnerCloseCalls, 1U);
    EXPECT_EQ(Owners->Size(), 0U);
}

TEST(QuicConnectionRegistry, RetainsExactRejectedReceiptAndRetriesWithoutBlockingOtherOwners)
{
    Registry Owners(MakeRegistryOptions());
    const auto FirstPeer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const auto SecondPeer = Udp::endpoint(Net::ip::address_v4::loopback(), 4434);
    const std::array<std::byte, 4> FirstCid{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 4> SecondCid{
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};
    const Preview::Fault::Failure OriginalFailure{
        Preview::Fault::Code::Blocked,
        std::make_error_code(std::errc::operation_not_permitted)};
    const Preview::Fault::Failure LaterFailure{
        Preview::Fault::Code::IoError,
        std::make_error_code(std::errc::io_error)};
    auto RejectedOwner = std::make_shared<RetryCloseOwner>(
        std::vector<Preview::Fault::Failure>{OriginalFailure, LaterFailure});
    auto RejectedLease = std::make_shared<Preview::Contract::QuicConnectionLease>(
        RejectedOwner);
    auto IndependentOwner = std::make_shared<RetryCloseOwner>(
        std::vector<Preview::Fault::Failure>{});
    auto IndependentLease = std::make_shared<Preview::Contract::QuicConnectionLease>(
        IndependentOwner);
    ASSERT_TRUE(Owners.Register({
        Registry::Cid(FirstCid.begin(), FirstCid.end()), RejectedLease, FirstPeer}));
    ASSERT_TRUE(Owners.Register({
        Registry::Cid(SecondCid.begin(), SecondCid.end()), IndependentLease, SecondPeer}));

    const auto FirstDrain = Owners.Drain();
    ASSERT_FALSE(FirstDrain);
    EXPECT_EQ(FirstDrain.error().Code, OriginalFailure.Code);
    EXPECT_EQ(FirstDrain.error().Native, OriginalFailure.Native);
    EXPECT_TRUE(Owners.HasPendingClose());
    EXPECT_EQ(Owners.Size(), 1U);
    EXPECT_EQ(RejectedOwner->Attempts(), 1U);
    EXPECT_EQ(IndependentOwner->Attempts(), 1U);

    const auto RetryDrain = Owners.Close();
    ASSERT_FALSE(RetryDrain);
    EXPECT_EQ(RetryDrain.error().Code, OriginalFailure.Code);
    EXPECT_EQ(RetryDrain.error().Native, OriginalFailure.Native);
    EXPECT_TRUE(Owners.HasPendingClose());
    EXPECT_EQ(Owners.Size(), 1U);
    EXPECT_EQ(RejectedOwner->Attempts(), 2U);

    ASSERT_TRUE(Owners.Close());
    EXPECT_FALSE(Owners.HasPendingClose());
    EXPECT_EQ(Owners.Size(), 0U);
    EXPECT_EQ(RejectedOwner->Attempts(), 3U);
}

TEST(QuicConnectionRegistry, SharedBudgetRejectsBeforeFactoryAndReturnsAfterRetryDrain)
{
    Net::io_context Io;
    const auto Budget = MakeBudget(1U, 2U);
    auto Gateway = std::make_shared<Preview::Boundary::QuicPacketGateway>(
        Preview::Boundary::QuicPacketGatewayOptions{Budget});
    const auto FirstFailure = Preview::Fault::Failure{
        Preview::Fault::Code::Blocked,
        std::make_error_code(std::errc::operation_not_permitted)};
    const auto SecondFailure = Preview::Fault::Failure{
        Preview::Fault::Code::IoError,
        std::make_error_code(std::errc::io_error)};
    const auto Factory = std::make_shared<BudgetAdmissionFactory>(
        std::vector<Preview::Fault::Failure>{FirstFailure, SecondFailure});
    Registry::Options Options;
    Options.AdmissionBudget = Budget;
    auto Owners = std::make_shared<Registry>(std::move(Options));
    const auto Ingress = Preview::Testing::Quic::MakeIngress(Factory);
    const auto Selection = Preview::Testing::Quic::MakeSelection(Ingress);
    std::size_t FallbackCalls = 0;
    Preview::Boundary::BoundaryDispatcher Dispatcher({
        Gateway,
        [&FallbackCalls](BoundaryPacket) { ++FallbackCalls; },
        [Owners](BoundaryPacket Packet,
            std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot> Snapshot)
        { return Owners->Handle(Packet, Snapshot); }});
    const auto FirstPeer = Udp::endpoint(Net::ip::address_v4::loopback(), 4433);
    const auto SecondPeer = Udp::endpoint(Net::ip::address_v4::loopback(), 4434);
    const std::array<std::byte, 4> FirstCid{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 4> SecondCid{
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8}};

    Dispatcher.Dispatch(MakeUnknownQuicPacket(FirstCid, FirstPeer), Selection);
    Dispatcher.Dispatch(MakeUnknownQuicPacket(FirstCid, FirstPeer), Selection);
    Dispatcher.Dispatch(MakeUnknownQuicPacket(FirstCid, FirstPeer), Selection);
    EXPECT_EQ(Factory->Calls(), 1U);
    EXPECT_EQ(Owners->Size(), 1U);
    EXPECT_EQ(Owners->ActiveConnectionCount(), 1U);
    EXPECT_EQ(Ingress->UseState()->Outstanding(), 1U);
    EXPECT_EQ(Budget->AcceptedPackets(), 2U);
    EXPECT_EQ(Gateway->Health().Connections, 1U);
    EXPECT_EQ(Gateway->Health().Packets, 2U);
    EXPECT_EQ(FallbackCalls, 1U);

    Dispatcher.Dispatch(MakeUnknownQuicPacket(SecondCid, SecondPeer), Selection);
    EXPECT_EQ(Factory->Calls(), 1U);
    EXPECT_EQ(Budget->ActiveConnections(), 1U);
    EXPECT_EQ(Ingress->UseState()->Outstanding(), 1U);
    EXPECT_EQ(FallbackCalls, 1U);

    const auto InitialClose = Owners->Drain();
    ASSERT_FALSE(InitialClose);
    EXPECT_EQ(InitialClose.error().Native, FirstFailure.Native);
    EXPECT_EQ(Budget->ActiveConnections(), 1U);
    EXPECT_EQ(Factory->Owner()->Attempts(), 1U);

    const auto FirstRetry = Owners->Close();
    ASSERT_FALSE(FirstRetry);
    EXPECT_EQ(FirstRetry.error().Native, FirstFailure.Native);
    EXPECT_EQ(Budget->ActiveConnections(), 1U);
    EXPECT_EQ(Factory->Owner()->Attempts(), 2U);

    ASSERT_TRUE(Owners->Close());
    EXPECT_EQ(Owners->Size(), 0U);
    EXPECT_FALSE(Owners->IsRetired());
    EXPECT_EQ(Budget->ActiveConnections(), 1U);
    EXPECT_EQ(Factory->Owner()->Attempts(), 3U);

    std::optional<std::expected<void, Preview::Fault::Failure>> DrainResult;
    std::exception_ptr DrainException;
    Net::co_spawn(Io, Factory->Owner()->Drain(),
        [&DrainResult, &DrainException](std::exception_ptr Error,
            std::expected<void, Preview::Fault::Failure> Result)
        {
            DrainException = std::move(Error);
            DrainResult = std::move(Result);
        });
    Io.run();

    ASSERT_FALSE(DrainException);
    ASSERT_TRUE(DrainResult);
    ASSERT_TRUE(*DrainResult);
    EXPECT_EQ(Budget->ActiveConnections(), 0U);
    EXPECT_EQ(Gateway->Health().Connections, 0U);
    EXPECT_TRUE(Owners->IsRetired());
    EXPECT_EQ(Ingress->UseState()->Outstanding(), 0U);
    Factory->ReleaseOwner();
    EXPECT_EQ(Ingress->UseState()->Outstanding(), 0U);

    std::size_t GatewayCalls = 0;
    ASSERT_TRUE(Gateway->RegisterConnection(SecondCid,
        [&GatewayCalls](const BoundaryPacket &) { ++GatewayCalls; return true; }));
    const auto ReplacementFactory = std::make_shared<BudgetAdmissionFactory>(
        std::vector<Preview::Fault::Failure>{});
    auto ReplacementOptions = MakeRegistryOptions();
    ReplacementOptions.AdmissionBudget = Budget;
    Registry Replacement(std::move(ReplacementOptions));
    const auto ReplacementIngress = Preview::Testing::Quic::MakeIngress(ReplacementFactory);
    const auto ReplacementSelection = Preview::Testing::Quic::MakeSelection(ReplacementIngress);
    Preview::Boundary::BoundaryDispatcher QuotaDispatcher({
        Gateway,
        [&FallbackCalls](BoundaryPacket) { ++FallbackCalls; },
        [&Replacement](BoundaryPacket Packet,
            std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot> Snapshot)
        { return Replacement.Handle(Packet, Snapshot); }});
    QuotaDispatcher.Dispatch(MakeUnknownQuicPacket(SecondCid, SecondPeer), ReplacementSelection);
    EXPECT_EQ(GatewayCalls, 0U);
    EXPECT_EQ(FallbackCalls, 1U);
    EXPECT_EQ(QuotaDispatcher.Snapshot().RejectedPackets, 1U);
    EXPECT_TRUE(Gateway->OnConnectionClosed(SecondCid));
    EXPECT_EQ(Budget->ActiveConnections(), 0U);

    EXPECT_EQ(Replacement.Handle(MakePacket(SecondCid, SecondPeer), ReplacementIngress),
        Preview::Boundary::QuicAdmissionDisposition::Accepted);
    EXPECT_EQ(ReplacementFactory->Calls(), 1U);
    EXPECT_EQ(Budget->ActiveConnections(), 1U);
}

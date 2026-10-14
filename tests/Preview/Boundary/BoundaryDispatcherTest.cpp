/**
 * @file BoundaryDispatcherTest.cpp
 * @brief UDP 入口分发契约测试
 * @details 生产证据：SS2022 UDP 的 separate header 是 AES-ECB 密文，
 *          首字节随机；约一半概率命中 QUIC short header 的 fixed bit
 *          （0x40），被 demux 分类为 Quic/UnknownCid。
 *          当部署未配置 QUIC gateway 时，这类包必须回落到普通
 *          datagram handler（SS2022 gateway），否则会被静默丢弃，
 *          表现为 SS2022 UDP 请求随机失败。
 */

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <Preview/Boundary/Contract/BoundaryDispatcher.hpp>
#include <Preview/Boundary/Datagram/DatagramClassifier.hpp>

namespace
{

    using Preview::Boundary::DatagramKind;
    using Preview::Boundary::DatagramRoute;
    using Preview::Boundary::BoundaryDispatcher;
    using Preview::Boundary::BoundaryPacket;

    [[nodiscard]] auto MakeGatewayOptions(
        const std::size_t MaxConnections = 4096U,
        const std::size_t MaxPacketsPerConnection = 65536U)
        -> Preview::Boundary::QuicPacketGatewayOptions
    {
        auto Budget = std::make_shared<Preview::Boundary::QuicAdmissionBudget>(
            Preview::Boundary::QuicAdmissionBudgetLimits{
                MaxConnections, MaxPacketsPerConnection});
        return {std::move(Budget), {}, {}};
    }

    auto MakeOwnershipPacket() -> BoundaryPacket
    {
        BoundaryPacket Packet;
        Packet.Payload = {std::byte{0x41}, std::byte{0x00}, std::byte{0xA5}, std::byte{0xFF}};
        Packet.Peer = {boost::asio::ip::make_address("2001:db8::27"), 45123};
        Packet.Classification = {
            DatagramKind::Quic, 0x123456789ABCDEF0ULL, DatagramRoute::RegisteredCid,
            Preview::Boundary::QuicHeaderError::None, 1,
            {std::byte{0x00}, std::byte{0x17}, std::byte{0xFF}, std::byte{0x42}}};
        Packet.Sequence = 0x1020304050607080ULL;
        return Packet;
    }

    auto ExpectOwnershipPacket(const BoundaryPacket &Packet) -> void
    {
        EXPECT_EQ(Packet.Payload, (std::vector<std::byte>{
            std::byte{0x41}, std::byte{0x00}, std::byte{0xA5}, std::byte{0xFF}}));
        EXPECT_EQ(Packet.Peer.address(), boost::asio::ip::make_address("2001:db8::27"));
        EXPECT_EQ(Packet.Peer.port(), 45123);
        EXPECT_EQ(Packet.Classification.Kind, DatagramKind::Quic);
        EXPECT_EQ(Packet.Classification.ConnectionId, 0x123456789ABCDEF0ULL);
        EXPECT_EQ(Packet.Classification.Route, DatagramRoute::RegisteredCid);
        EXPECT_EQ(Packet.Classification.Error, Preview::Boundary::QuicHeaderError::None);
        EXPECT_EQ(Packet.Classification.Version, 1U);
        EXPECT_EQ(Packet.Classification.ConnectionIdBytes, (std::vector<std::byte>{
            std::byte{0x00}, std::byte{0x17}, std::byte{0xFF}, std::byte{0x42}}));
        EXPECT_EQ(Packet.Sequence, 0x1020304050607080ULL);
    }

    class BoundaryPacketOwnership : public testing::Test
    {
    protected:
        auto SetUp() -> void override
        {
            Gateway = std::make_shared<Preview::Boundary::QuicPacketGateway>(
                MakeGatewayOptions(4U, 1U));
            Dispatcher = std::make_unique<BoundaryDispatcher>(BoundaryDispatcher::Options{
                Gateway,
                [this](BoundaryPacket Packet) { Fallback.push_back(std::move(Packet)); },
                {},
                [this](Preview::Boundary::BoundaryDispatchEvent Event) { Events.push_back(Event); }});
        }

        auto RegisterHandler() -> void
        {
            const std::vector<std::byte> Cid{
                std::byte{0x00}, std::byte{0x17}, std::byte{0xFF}, std::byte{0x42}};
            ASSERT_TRUE(Gateway->RegisterConnection(
                Cid, [this](const BoundaryPacket &Packet) { return HandlePacket(Packet); }));
        }

        auto HandlePacket(const BoundaryPacket &Packet) -> bool
        {
            Quic.push_back(Packet);
            return Accept;
        }

        auto ExpectFallback() -> void
        {
            ASSERT_EQ(Fallback.size(), 1U);
            ExpectOwnershipPacket(Fallback.front());
            const auto Snapshot = Dispatcher->Snapshot();
            EXPECT_EQ(Snapshot.DatagramPackets, 1U);
            EXPECT_EQ(Snapshot.RejectedPackets, 0U);
            ASSERT_FALSE(Events.empty());
            EXPECT_EQ(Events.back().Stage, Preview::Boundary::BoundaryDispatchStage::DatagramFallback);
            EXPECT_EQ(Events.back().Kind, DatagramKind::Quic);
            EXPECT_EQ(Events.back().Route, DatagramRoute::RegisteredCid);
            EXPECT_EQ(Events.back().PayloadBytes, 4U);
        }

        Preview::Boundary::SharedQuicPacketGateway Gateway;
        std::unique_ptr<BoundaryDispatcher> Dispatcher;
        std::vector<BoundaryPacket> Fallback;
        std::vector<BoundaryPacket> Quic;
        std::vector<Preview::Boundary::BoundaryDispatchEvent> Events;
        bool Accept{true};
    };

    TEST_F(BoundaryPacketOwnership, UnknownCidPreservesFallbackPacket)
    {
        Dispatcher->Dispatch(MakeOwnershipPacket(), {});
        ExpectFallback();
        EXPECT_TRUE(Quic.empty());
        EXPECT_EQ(Dispatcher->Snapshot().QuicPackets, 0U);
        EXPECT_FALSE(Gateway->Health().BoundedFailure);
    }

    TEST_F(BoundaryPacketOwnership, ClosedGatewayPreservesFallbackPacket)
    {
        RegisterHandler();
        Gateway->Close();
        Dispatcher->Dispatch(MakeOwnershipPacket(), {});
        ExpectFallback();
        EXPECT_TRUE(Quic.empty());
        EXPECT_EQ(Dispatcher->Snapshot().QuicPackets, 0U);
    }

    TEST_F(BoundaryPacketOwnership, DrainingGatewayPreservesFallbackPacket)
    {
        RegisterHandler();
        Gateway->Drain();
        Dispatcher->Dispatch(MakeOwnershipPacket(), {});
        ExpectFallback();
        EXPECT_TRUE(Quic.empty());
        EXPECT_EQ(Dispatcher->Snapshot().QuicPackets, 0U);
    }

    TEST_F(BoundaryPacketOwnership, PacketBudgetPreservesRejectedFallbackPacket)
    {
        RegisterHandler();
        Dispatcher->Dispatch(MakeOwnershipPacket(), {});
        ASSERT_EQ(Quic.size(), 1U);
        ExpectOwnershipPacket(Quic.front());
        ASSERT_TRUE(Fallback.empty());
        Dispatcher->Dispatch(MakeOwnershipPacket(), {});
        ExpectFallback();
        EXPECT_EQ(Quic.size(), 1U);
        EXPECT_EQ(Dispatcher->Snapshot().QuicPackets, 1U);
        EXPECT_TRUE(Gateway->Health().BoundedFailure);
    }

    TEST_F(BoundaryPacketOwnership, HandlerRejectionPreservesFallbackPacket)
    {
        RegisterHandler();
        Accept = false;
        Dispatcher->Dispatch(MakeOwnershipPacket(), {});
        ExpectFallback();
        ASSERT_EQ(Quic.size(), 1U);
        ExpectOwnershipPacket(Quic.front());
        EXPECT_EQ(Dispatcher->Snapshot().QuicPackets, 0U);
        EXPECT_TRUE(Gateway->Health().BoundedFailure);
    }

    TEST_F(BoundaryPacketOwnership, AcceptedPacketOnlyReachesQuicHandler)
    {
        RegisterHandler();
        Dispatcher->Dispatch(MakeOwnershipPacket(), {});
        ASSERT_EQ(Quic.size(), 1U);
        ExpectOwnershipPacket(Quic.front());
        EXPECT_TRUE(Fallback.empty());
        EXPECT_EQ(Dispatcher->Snapshot().QuicPackets, 1U);
        EXPECT_EQ(Dispatcher->Snapshot().DatagramPackets, 0U);
        EXPECT_EQ(Dispatcher->Snapshot().RejectedPackets, 0U);
        ASSERT_EQ(Events.size(), 2U);
        EXPECT_EQ(Events.back().Stage, Preview::Boundary::BoundaryDispatchStage::QuicGatewayAccepted);
        EXPECT_EQ(Events.back().PayloadBytes, 4U);
    }

    auto MakeQuicClassifiedPacket() -> BoundaryPacket
    {
        BoundaryPacket Packet;
        Packet.Payload = {std::byte{0x7F}, std::byte{0x00}, std::byte{0x01}};
        Packet.Classification.Kind = DatagramKind::Quic;
        Packet.Classification.Route = DatagramRoute::UnknownCid;
        return Packet;
    }

    TEST(BoundaryDispatcher, FallsBackToDatagramWhenNoQuicPacketGatewayConfigured)
    {
        std::size_t DatagramCalls = 0;
        BoundaryDispatcher Dispatcher(BoundaryDispatcher::Options{
            nullptr,
            [&DatagramCalls](BoundaryPacket) { ++DatagramCalls; },
            {}});

        Dispatcher.Dispatch(MakeQuicClassifiedPacket(), {});

        EXPECT_EQ(DatagramCalls, 1U);
        EXPECT_EQ(Dispatcher.Snapshot().DatagramPackets, 1U);
        EXPECT_EQ(Dispatcher.Snapshot().RejectedPackets, 0U);
    }

    TEST(BoundaryDispatcher, FallsBackToDatagramWhenQuicPacketGatewayRejectsUnknownCid)
    {
        auto Gateway = std::make_shared<Preview::Boundary::QuicPacketGateway>(
            MakeGatewayOptions());
        std::size_t DatagramCalls = 0;
        BoundaryDispatcher Dispatcher(BoundaryDispatcher::Options{
            Gateway,
            [&DatagramCalls](BoundaryPacket) { ++DatagramCalls; },
            {}});

        Dispatcher.Dispatch(MakeQuicClassifiedPacket(), {});

        EXPECT_EQ(DatagramCalls, 1U);
    }

    TEST(BoundaryDispatcher, CapacityExceededDoesNotReachGatewayOrFallback)
    {
        auto Budget = std::make_shared<Preview::Boundary::QuicAdmissionBudget>(
            Preview::Boundary::QuicAdmissionBudgetLimits{1U, 4U});
        auto Gateway = std::make_shared<Preview::Boundary::QuicPacketGateway>(
            Preview::Boundary::QuicPacketGatewayOptions{Budget});
        const auto Cid = std::vector<std::byte>{
            std::byte{0x00}, std::byte{0x17}, std::byte{0xFF}, std::byte{0x42}};
        std::size_t GatewayCalls = 0;
        std::size_t DatagramCalls = 0;
        ASSERT_TRUE(Gateway->RegisterConnection(Cid,
            [&GatewayCalls](const BoundaryPacket &) { ++GatewayCalls; return true; }));
        BoundaryDispatcher Dispatcher(BoundaryDispatcher::Options{
            Gateway,
            [&DatagramCalls](BoundaryPacket) { ++DatagramCalls; },
            [](BoundaryPacket,
                std::shared_ptr<const Preview::Contract::QuicIngressBindingSnapshot>)
            { return Preview::Boundary::QuicAdmissionDisposition::CapacityExceeded; }});

        Dispatcher.Dispatch(MakeOwnershipPacket(), {});

        EXPECT_EQ(GatewayCalls, 0U);
        EXPECT_EQ(DatagramCalls, 0U);
        EXPECT_EQ(Dispatcher.Snapshot().RejectedPackets, 1U);
    }

    TEST(BoundaryDispatcher, RetiredCredentialAssociationAndCurrentCredentialBothDispatch)
    {
        auto PreviousUse = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto CurrentUse = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Previous = std::make_shared<CredentialAssociationIngress>(
            "old-key", "session-17", true);
        auto Current = std::make_shared<CredentialAssociationIngress>(
            "new-key", "session-42", false);
        auto Ingress = std::make_shared<const Preview::Contract::RawDatagramIngressSnapshot>(
            Preview::Contract::RawDatagramIngressSnapshot::Options{
                Preview::GenerationId{2U}, CurrentUse,
                {{Current, CurrentUse}}, {{Previous, PreviousUse}}});
        std::size_t FallbackCalls = 0U;
        BoundaryDispatcher Dispatcher(BoundaryDispatcher::Options{
            nullptr,
            [&FallbackCalls](BoundaryPacket) { ++FallbackCalls; },
            {}, {}});

        Dispatcher.Dispatch(MakeCredentialPacket("old-key|session-17|old-payload"), Ingress);
        Dispatcher.Dispatch(MakeCredentialPacket("new-key|session-42|new-payload"), Ingress);

        EXPECT_EQ(Previous->ExistingAssociations, 1U);
        EXPECT_EQ(Previous->NewAssociations, 0U);
        EXPECT_EQ(Current->ExistingAssociations, 0U);
        EXPECT_EQ(Current->NewAssociations, 1U);
        EXPECT_EQ(PreviousUse->Outstanding(), 0U);
        EXPECT_EQ(CurrentUse->Outstanding(), 0U);
        EXPECT_EQ(FallbackCalls, 0U);
    }

    TEST(BoundaryDispatcher, GenerationUseLeaseMoveTransfersSingleReservationAndPinsState)
    {
        auto Owner = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto OtherOwner = std::make_shared<Preview::Foundation::GenerationUseState>();
        const std::weak_ptr<Preview::Foundation::GenerationUseState> WeakOwner = Owner;
        auto First = Owner->Acquire();
        auto Other = OtherOwner->Acquire();
        ASSERT_TRUE(First);
        ASSERT_TRUE(Other);
        auto Lease = std::move(*First);
        EXPECT_FALSE(static_cast<bool>(*First));
        EXPECT_EQ(Owner->Outstanding(), 1U);

        *Other = std::move(Lease);
        EXPECT_FALSE(static_cast<bool>(Lease));
        EXPECT_EQ(OtherOwner->Outstanding(), 0U);
        EXPECT_EQ(Owner->Outstanding(), 1U);
        EXPECT_FALSE(Owner->CloseAdmissionIfUnused());

        Owner.reset();
        EXPECT_FALSE(WeakOwner.expired());
        *Other = Preview::Foundation::GenerationUseLease{};
        EXPECT_TRUE(WeakOwner.expired());
        EXPECT_TRUE(OtherOwner->CloseAdmissionIfUnused());
        EXPECT_EQ(OtherOwner->Outstanding(), 0U);
    }

    TEST(BoundaryDispatcher, UnownedGenerationUseStateRejectsWithoutBurningReservation)
    {
        Preview::Foundation::GenerationUseState Unowned;
        const auto Acquired = Unowned.Acquire();
        ASSERT_FALSE(Acquired);
        EXPECT_EQ(Acquired.error().Code, Preview::Fault::Code::ResourceUnavailable);
        EXPECT_EQ(Unowned.Outstanding(), 0U);
        EXPECT_TRUE(Unowned.AdmissionOpen());
        EXPECT_TRUE(Unowned.CloseAdmissionIfUnused());
        EXPECT_FALSE(Unowned.AdmissionOpen());
    }

    TEST(BoundaryDispatcher, GenerationUseAdmissionClosesOnlyAfterLastLease)
    {
        auto UseState = std::make_shared<Preview::Foundation::GenerationUseState>();
        auto Acquired = UseState->Acquire();
        ASSERT_TRUE(Acquired);
        auto Lease = std::move(*Acquired);

        EXPECT_FALSE(UseState->CloseAdmissionIfUnused());
        EXPECT_TRUE(UseState->AdmissionOpen());
        EXPECT_EQ(UseState->Outstanding(), 1U);

        Lease = Preview::Foundation::GenerationUseLease{};
        EXPECT_TRUE(UseState->CloseAdmissionIfUnused());
        EXPECT_FALSE(UseState->AdmissionOpen());
        EXPECT_EQ(UseState->Outstanding(), 0U);
        EXPECT_FALSE(UseState->Acquire());
    }

} // namespace

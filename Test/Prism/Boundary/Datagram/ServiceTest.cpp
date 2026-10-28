/**
 * @file ServiceTest.cpp
 * @brief 按功能拆分的 GoogleTest 行为契约。
 */

#include "ServiceTestSupport.hpp"

#include <boost/asio/this_coro.hpp>

#include <cstddef>
#include <memory>
#include <utility>

namespace
{
    [[nodiscard]] auto MakeGatewayOptions(
        const std::size_t MaxConnections = 4096U,
        const std::size_t MaxPacketsPerConnection = 65536U)
        -> Prism::Boundary::QuicPacketGatewayOptions
    {
        auto Budget = std::make_shared<Prism::Boundary::QuicAdmissionBudget>(
            Prism::Boundary::QuicAdmissionBudgetLimits{
                MaxConnections, MaxPacketsPerConnection});
        return {std::move(Budget), {}, {}};
    }

    struct DatagramStopResult final
    {
        Prism::Boundary::DatagramStartResult Start;
        bool DrainCompleted{false};
        bool WatchdogWon{false};
    };

    /**
     * @brief 保有 listener 和结果，验证仅停止接收时完整 drain 胜过原 watchdog。
     * @details 参数按值保活；timer 归协程帧，RunCoro 完整等待当前 executor。
     *          Stop(false) 保持原关闭合同，UDP 不涉及半关闭。
     */
    auto StopAndDrain(
        std::shared_ptr<Prism::Boundary::DatagramListener> Listener,
        std::shared_ptr<DatagramStopResult> Result) -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        auto Demux = std::make_shared<Prism::Boundary::DatagramClassifier>();
        Result->Start = co_await Listener->Start(
            Prism::Boundary::DatagramListener::StartRequest{
                Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0),
                Demux,
                [](Prism::Boundary::BoundaryPacket) {},
                {}});
        if (!Result->Start.Succeeded())
        {
            co_return;
        }

        Listener->Stop(Prism::Boundary::DatagramListener::StopRequest{false});
        Net::steady_timer Watchdog(Executor);
        Watchdog.expires_after(std::chrono::milliseconds(20));
        const auto Race = co_await Net::experimental::awaitable_operators::operator||(
            Listener->Drain(), Watchdog.async_wait(Net::use_awaitable));
        if (Race.index() == 0U)
        {
            Result->DrainCompleted = std::get<0>(Race).Completed;
        }
        else
        {
            Result->WatchdogWon = true;
        }
    }

    /**
     * @brief 关闭关联表并等待关联 owner 的最终关闭通知。
     * @details Table 借用完整等待 RunCoro 的测试作用域；Association 和结果按值保活。
     *          association 在自身 executor 完成取消与关闭，UDP 不涉及半关闭。
     */
    auto CloseAndWait(
        Prism::Boundary::DatagramAssociationTable &Table,
        std::shared_ptr<Prism::Boundary::DatagramAssociation> Association,
        std::shared_ptr<bool> WaitClosed) -> Net::awaitable<void>
    {
        Table.Close();
        *WaitClosed = co_await Association->WaitClosed();
    }
}

TEST(DatagramClassifier, KeepsRegisteredDestinationCidAffinityAcrossHeaderForms)
    {
        Prism::Boundary::DatagramClassifier Demux;
        const std::array<std::byte, 13> LongHeader{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x04}, std::byte{0x01}, std::byte{0x02},
            std::byte{0x03}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}};
        const auto LongClassification = Demux.Classify(LongHeader);
        ASSERT_EQ(LongClassification.ConnectionIdBytes.size(), 4U);
        ASSERT_TRUE(Demux.RegisterQuicCid(LongClassification.ConnectionIdBytes));

        const std::array<std::byte, 6> ShortHeader{
            std::byte{0x41}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
            std::byte{0x04}, std::byte{0xaa}};
        const auto ShortClassification = Demux.Classify(ShortHeader);

        EXPECT_EQ(ShortClassification.Kind, Prism::Boundary::DatagramKind::Quic);
        EXPECT_EQ(ShortClassification.ConnectionId, LongClassification.ConnectionId);
    }

TEST(DatagramClassifier, ExposesUnknownRegisteredAndMalformedQuicBoundaries)
    {
        Prism::Boundary::DatagramClassifier Demux;
        const auto Empty = Demux.Classify(std::span<const std::byte>{});
        EXPECT_EQ(Empty.Kind, Prism::Boundary::DatagramKind::Invalid);
        EXPECT_EQ(Empty.Route, Prism::Boundary::DatagramRoute::Malformed);
        EXPECT_EQ(Empty.Error, Prism::Boundary::QuicHeaderError::Empty);

        const std::array<std::byte, 13> ValidLong{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x04}, std::byte{0x01}, std::byte{0x02},
            std::byte{0x03}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}};

        const auto Unknown = Demux.Classify(ValidLong);
        EXPECT_EQ(Unknown.Kind, Prism::Boundary::DatagramKind::Quic);
        EXPECT_EQ(Unknown.Route, Prism::Boundary::DatagramRoute::UnknownCid);
        EXPECT_EQ(Unknown.Error, Prism::Boundary::QuicHeaderError::None);
        ASSERT_EQ(Unknown.ConnectionIdBytes.size(), 4U);

        ASSERT_TRUE(Demux.RegisterQuicCid(Unknown.ConnectionIdBytes));
        const auto Registered = Demux.Classify(ValidLong);
        EXPECT_EQ(Registered.Route, Prism::Boundary::DatagramRoute::RegisteredCid);
        EXPECT_EQ(Registered.ConnectionIdBytes, Unknown.ConnectionIdBytes);

        auto MissingFixedBit = ValidLong;
        MissingFixedBit[0] = std::byte{0x80};
        const auto FixedBit = Demux.Classify(MissingFixedBit);
        EXPECT_EQ(FixedBit.Kind, Prism::Boundary::DatagramKind::Ordinary);
        EXPECT_EQ(FixedBit.Route, Prism::Boundary::DatagramRoute::Malformed);
        EXPECT_EQ(FixedBit.Error, Prism::Boundary::QuicHeaderError::FixedBit);

        auto UnsupportedVersion = ValidLong;
        UnsupportedVersion[4] = std::byte{0x02};
        const auto Version = Demux.Classify(UnsupportedVersion);
        EXPECT_EQ(Version.Route, Prism::Boundary::DatagramRoute::Malformed);
        EXPECT_EQ(Version.Error, Prism::Boundary::QuicHeaderError::UnsupportedVersion);

        auto ReservedBits = ValidLong;
        ReservedBits[0] = std::byte{0xcc};
        const auto Reserved = Demux.Classify(ReservedBits);
        EXPECT_EQ(Reserved.Route, Prism::Boundary::DatagramRoute::RegisteredCid);
        EXPECT_EQ(Reserved.Error, Prism::Boundary::QuicHeaderError::None);

        auto InvalidPacketType = ValidLong;
        InvalidPacketType[0] = std::byte{0xf1};
        const auto PacketType = Demux.Classify(InvalidPacketType);
        EXPECT_EQ(PacketType.Route, Prism::Boundary::DatagramRoute::RegisteredCid);
        EXPECT_EQ(PacketType.Error, Prism::Boundary::QuicHeaderError::None);

        const std::array<std::byte, 4> UnknownShort{
            std::byte{0x41}, std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}};
        const auto Short = Demux.Classify(UnknownShort);
        EXPECT_EQ(Short.Kind, Prism::Boundary::DatagramKind::Quic);
        EXPECT_EQ(Short.Route, Prism::Boundary::DatagramRoute::UnknownCid);
    }

TEST(QuicPacketGateway, RoutesOnlyTheRegisteredExactConnectionId)
    {
        Prism::Boundary::QuicPacketGateway Gateway(MakeGatewayOptions(1U, 4U));
        const std::array<std::byte, 4> RegisteredCid{
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::size_t Handled = 0;
        ASSERT_TRUE(Gateway.RegisterConnection(
            std::span<const std::byte>(RegisteredCid),
            [&Handled](const Prism::Boundary::BoundaryPacket &) {
                ++Handled;
                return true;
            }));

        Prism::Boundary::BoundaryPacket RegisteredPacket;
        RegisteredPacket.Classification.Kind = Prism::Boundary::DatagramKind::Quic;
        RegisteredPacket.Classification.Route = Prism::Boundary::DatagramRoute::RegisteredCid;
        RegisteredPacket.Classification.ConnectionIdBytes.assign(
            RegisteredCid.begin(), RegisteredCid.end());
        EXPECT_TRUE(Gateway.Handle(RegisteredPacket));

        Prism::Boundary::BoundaryPacket DifferentPacket;
        DifferentPacket.Classification.Kind = Prism::Boundary::DatagramKind::Quic;
        DifferentPacket.Classification.Route = Prism::Boundary::DatagramRoute::UnknownCid;
        DifferentPacket.Classification.ConnectionIdBytes = {
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x05}};
        EXPECT_FALSE(Gateway.Handle(DifferentPacket));
        EXPECT_EQ(Handled, 1U);
    }

TEST(QuicPacketGateway, ReadinessIsMonotonicAndDrainIsTerminal)
    {
        Prism::Boundary::QuicPacketGateway Gateway(MakeGatewayOptions());

        Gateway.MarkProtocolReady();
        EXPECT_EQ(Gateway.Readiness(), Prism::Boundary::QuicReadiness::Offline);

        Gateway.MarkSocketReady();
        Gateway.MarkReceiveLoopReady();
        Gateway.MarkHandshakeReady();
        Gateway.MarkProtocolReady();
        EXPECT_EQ(Gateway.Readiness(), Prism::Boundary::QuicReadiness::Protocol);
        EXPECT_TRUE(Gateway.Health().Healthy());

        Gateway.MarkSocketReady();
        EXPECT_EQ(Gateway.Readiness(), Prism::Boundary::QuicReadiness::Protocol);

        Gateway.Drain();
        EXPECT_EQ(Gateway.Readiness(), Prism::Boundary::QuicReadiness::Draining);
        Gateway.MarkSocketReady();
        Gateway.MarkReceiveLoopReady();
        Gateway.MarkHandshakeReady();
        Gateway.MarkProtocolReady();
        EXPECT_EQ(Gateway.Readiness(), Prism::Boundary::QuicReadiness::Draining);
        EXPECT_FALSE(Gateway.Health().Healthy());

        Gateway.Close();
        EXPECT_EQ(Gateway.Readiness(), Prism::Boundary::QuicReadiness::Closed);
    }

TEST(BoundaryDispatcher, FallsBackToOrdinaryHandlerWhenQuicCidUnclaimed)
    {
        auto Gateway = std::make_shared<Prism::Boundary::QuicPacketGateway>(MakeGatewayOptions());
        std::size_t OrdinaryPackets = 0;
        Prism::Boundary::BoundaryDispatcher Dispatcher(
            Prism::Boundary::BoundaryDispatcher::Options{
                Gateway,
                [&OrdinaryPackets](Prism::Boundary::BoundaryPacket) { ++OrdinaryPackets; }});
        Prism::Boundary::DatagramClassifier Demux;

        const std::array<std::byte, 6> Malformed{
            std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x04}};
        Prism::Boundary::BoundaryPacket Ordinary;
        Ordinary.Classification = Demux.Classify(Malformed);
        Dispatcher.Dispatch(std::move(Ordinary), {});

        const std::array<std::byte, 13> UnknownPayload{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x04}, std::byte{0x01}, std::byte{0x02},
            std::byte{0x03}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}};
        Prism::Boundary::BoundaryPacket Unknown;
        Unknown.Classification = Demux.Classify(UnknownPayload);
        Dispatcher.Dispatch(std::move(Unknown), {});

        const auto Snapshot = Dispatcher.Snapshot();
        EXPECT_EQ(OrdinaryPackets, 2U);
        EXPECT_EQ(Snapshot.DatagramPackets, 2U);
        EXPECT_EQ(Snapshot.QuicPackets, 0U);
        EXPECT_EQ(Snapshot.RejectedPackets, 0U);
    }

TEST(DatagramListener, StopWithoutCloseStillCompletesOwnerHeldReceiveLoop)
    {
        Net::io_context Io;
        auto Listener = std::make_shared<Prism::Boundary::DatagramListener>(Io.get_executor());
        auto Result = std::make_shared<DatagramStopResult>();

        RunCoro(Io, StopAndDrain(Listener, Result));

        EXPECT_TRUE(Result->Start.Succeeded());
        EXPECT_TRUE(Result->DrainCompleted);
        EXPECT_FALSE(Result->WatchdogWon);
    }

TEST(NativeQuicReadiness, HandshakeDoesNotImplyProtocolReady)
    {
        Prism::Quic::NativeConnectionHealth Health;
        Health.SocketReady = true;
        Health.ReceiveLoopReady = true;
        Health.HandshakeReady = true;

        EXPECT_FALSE(Health.ProtocolReady);
        EXPECT_FALSE(Health.Healthy());

        Health.ProtocolReady = true;
        EXPECT_TRUE(Health.Healthy());
    }

TEST(DatagramAssociationTable, KeysAssociationsByEndpointAndWorker)
    {
        Net::io_context Io;
        const auto Peer = Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 41001);
        const Prism::Boundary::DatagramAssociationKey WorkerOneKey{Peer, 7, 1};
        const Prism::Boundary::DatagramAssociationKey WorkerTwoKey{Peer, 7, 2};
        std::size_t Canceled = 0;
        auto Owner = std::make_shared<Prism::Boundary::DatagramAssociation>(
            WorkerOneKey,
            Prism::Boundary::DatagramAssociationOptions{
                Io.get_executor(),
                [&Canceled]() noexcept { ++Canceled; }});
        Prism::Boundary::DatagramAssociationTable Table;

        ASSERT_TRUE(Table.Register(WorkerOneKey, Owner));
        EXPECT_FALSE(Table.Register(WorkerOneKey, Owner));
        EXPECT_TRUE(Table.Register(
            WorkerTwoKey,
            std::make_shared<Prism::Boundary::DatagramAssociation>(
                WorkerTwoKey,
                Prism::Boundary::DatagramAssociationOptions{Io.get_executor(), {}})));
        EXPECT_EQ(Table.Size(), 2U);
        EXPECT_EQ(Table.Find(WorkerOneKey), Owner);
        EXPECT_EQ(Table.Find(Prism::Boundary::DatagramAssociationKey{Peer, 8, 1}), nullptr);
    }

TEST(DatagramAssociationTable, DrainRejectsNewKeysAndCloseCancelsOwners)
    {
        Net::io_context Io;
        const auto Peer = Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 41002);
        const Prism::Boundary::DatagramAssociationKey Key{Peer, 9, 3};
        std::size_t Canceled = 0;
        auto Association = std::make_shared<Prism::Boundary::DatagramAssociation>(
            Key,
            Prism::Boundary::DatagramAssociationOptions{
                Io.get_executor(),
                [&Canceled]() noexcept { ++Canceled; }});
        Prism::Boundary::DatagramAssociationTable Table;
        ASSERT_TRUE(Table.Register(Key, Association));

        Table.Drain();
        EXPECT_TRUE(Table.IsDraining());
        EXPECT_FALSE(Table.Register(Key, Association));

        auto WaitClosed = std::make_shared<bool>(false);
        RunCoro(Io, CloseAndWait(Table, Association, WaitClosed));

        EXPECT_TRUE(*WaitClosed);
        EXPECT_EQ(Canceled, 1U);
        EXPECT_EQ(Table.Size(), 0U);
        EXPECT_TRUE(Association->IsClosed());
    }

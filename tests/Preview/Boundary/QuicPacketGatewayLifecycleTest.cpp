/**
 * @file QuicPacketGatewayLifecycleTest.cpp
 * @brief QUIC 网关分阶段就绪与有界数据包接纳测试。
 */

#include <Preview/Boundary/Quic/QuicPacketGateway.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <utility>

namespace
{

    using Cid = std::array<std::byte, 4>;

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

    [[nodiscard]] auto MakeCid(const std::uint8_t Last) -> Cid
    {
        return {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{Last}};
    }

    auto SetCid(Preview::Boundary::BoundaryPacket &Packet, const Cid &Value,
                const Preview::Boundary::DatagramRoute Route) -> void
    {
        Packet.Classification.Kind = Preview::Boundary::DatagramKind::Quic;
        Packet.Classification.Route = Route;
        Packet.Classification.ConnectionIdBytes.assign(Value.begin(), Value.end());
    }

    TEST(QuicPacketGatewayLifecycle, SocketAndReceiveReadyDoNotImplyProtocolHealth)
    {
        Preview::Boundary::QuicPacketGateway Gateway(MakeGatewayOptions());

        Gateway.MarkSocketReady();
        Gateway.MarkReceiveLoopReady();

        const auto Health = Gateway.Health();
        EXPECT_TRUE(Health.SocketReady);
        EXPECT_TRUE(Health.ReceiveLoopReady);
        EXPECT_FALSE(Health.Healthy());
    }

    TEST(QuicPacketGatewayLifecycle, PacketCounterDoesNotImplyProtocolHealth)
    {
        std::size_t CallbackCount = 0;
        auto Options = MakeGatewayOptions(4U, 4U);
        Options.OnPacket = [&CallbackCount](const Preview::Boundary::BoundaryPacket &) { ++CallbackCount; };
        Preview::Boundary::QuicPacketGateway Gateway(std::move(Options));
        Gateway.MarkSocketReady();
        Gateway.MarkReceiveLoopReady();
        const auto RegisteredCid = MakeCid(7);
        ASSERT_TRUE(Gateway.RegisterConnection(
            std::span<const std::byte>(RegisteredCid),
            [&RegisteredCid](const Preview::Boundary::BoundaryPacket &Packet)
            {
                return Packet.Payload.size() == 8U &&
                       Packet.Classification.ConnectionIdBytes.size() == RegisteredCid.size() &&
                       std::equal(RegisteredCid.begin(), RegisteredCid.end(),
                                  Packet.Classification.ConnectionIdBytes.begin());
            }));

        Preview::Boundary::BoundaryPacket Packet;
        Packet.Payload.resize(8);
        SetCid(Packet, RegisteredCid, Preview::Boundary::DatagramRoute::RegisteredCid);

        ASSERT_TRUE(Gateway.Handle(Packet));
        EXPECT_EQ(CallbackCount, 1U);
        EXPECT_EQ(Gateway.Health().Packets, 1U);
        EXPECT_FALSE(Gateway.Health().Healthy());
    }

    TEST(QuicPacketGatewayLifecycle, UnknownCidDoesNotCreateConnectionOrConsumeCapacity)
    {
        Preview::Boundary::QuicPacketGateway Gateway(MakeGatewayOptions(1U, 4U));
        const auto UnknownCid = MakeCid(9);

        Preview::Boundary::BoundaryPacket UnknownPacket;
        UnknownPacket.Payload = {std::byte{0xee}};
        SetCid(UnknownPacket, UnknownCid, Preview::Boundary::DatagramRoute::UnknownCid);

        EXPECT_FALSE(Gateway.Handle(UnknownPacket));
        EXPECT_EQ(Gateway.ConnectionCount(), 0U);
        EXPECT_FALSE(Gateway.Health().BoundedFailure);
        EXPECT_EQ(std::to_integer<std::uint8_t>(UnknownPacket.Payload.front()), 0xeeU);
        EXPECT_EQ(UnknownPacket.Classification.Route, Preview::Boundary::DatagramRoute::UnknownCid);
        EXPECT_EQ(UnknownPacket.Classification.ConnectionIdBytes.size(), UnknownCid.size());
        EXPECT_TRUE(std::equal(UnknownCid.begin(), UnknownCid.end(),
                               UnknownPacket.Classification.ConnectionIdBytes.begin()));

        ASSERT_TRUE(Gateway.RegisterConnection(
            std::span<const std::byte>(UnknownCid),
            [&UnknownCid](const Preview::Boundary::BoundaryPacket &Packet)
            {
                return Packet.Classification.ConnectionIdBytes.size() == UnknownCid.size() &&
                       std::equal(UnknownCid.begin(), UnknownCid.end(),
                                  Packet.Classification.ConnectionIdBytes.begin());
            }));
        EXPECT_EQ(Gateway.ConnectionCount(), 1U);

        Preview::Boundary::BoundaryPacket RegisteredPacket;
        SetCid(RegisteredPacket, UnknownCid, Preview::Boundary::DatagramRoute::RegisteredCid);
        EXPECT_TRUE(Gateway.Handle(RegisteredPacket));
    }

    TEST(QuicPacketGatewayLifecycle, ProtocolReadyRequiresHandshakeReady)
    {
        Preview::Boundary::QuicPacketGateway Gateway(MakeGatewayOptions());
        Gateway.MarkSocketReady();
        Gateway.MarkReceiveLoopReady();

        Gateway.MarkProtocolReady();
        EXPECT_FALSE(Gateway.Health().ProtocolReady);
        EXPECT_FALSE(Gateway.Health().Healthy());

        Gateway.MarkHandshakeReady();
        EXPECT_TRUE(Gateway.Health().HandshakeReady);
        EXPECT_FALSE(Gateway.Health().ProtocolReady);
        EXPECT_FALSE(Gateway.Health().Healthy());

        Gateway.MarkProtocolReady();
        EXPECT_TRUE(Gateway.Health().ProtocolReady);
        EXPECT_TRUE(Gateway.Health().Healthy());
    }

    TEST(QuicPacketGatewayLifecycle, RegisteredCidRoutesToItsConnectionHandler)
    {
        Preview::Boundary::QuicPacketGateway Gateway(MakeGatewayOptions());
        std::size_t Handled = 0;
        const auto RegisteredCid = MakeCid(41);
        ASSERT_TRUE(Gateway.RegisterConnection(
            std::span<const std::byte>(RegisteredCid),
            [&Handled](const Preview::Boundary::BoundaryPacket &Packet)
            {
                ++Handled;
                return !Packet.Classification.ConnectionIdBytes.empty();
            }));

        Preview::Boundary::BoundaryPacket Packet;
        SetCid(Packet, RegisteredCid, Preview::Boundary::DatagramRoute::RegisteredCid);
        EXPECT_TRUE(Gateway.Handle(Packet));
        EXPECT_EQ(Handled, 1U);

        EXPECT_TRUE(Gateway.OnConnectionClosed(std::span<const std::byte>(RegisteredCid)));
        EXPECT_FALSE(Gateway.OnConnectionClosed(std::span<const std::byte>(RegisteredCid)));
    }

} // namespace

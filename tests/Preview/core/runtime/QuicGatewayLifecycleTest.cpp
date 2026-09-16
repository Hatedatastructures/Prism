/**
 * @file QuicGatewayLifecycleTest.cpp
 * @brief QUIC 网关分阶段就绪与有界数据包接纳测试。
 */

#include <Preview/Ingress/QuicGateway.hpp>

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <utility>

namespace
{

    TEST(QuicGatewayLifecycle, SocketAndReceiveReadyDoNotImplyProtocolHealth)
    {
        Preview::Ingress::QuicGateway Gateway;

        Gateway.MarkSocketReady();
        Gateway.MarkReceiveLoopReady();

        const auto Health = Gateway.Health();
        EXPECT_TRUE(Health.SocketReady);
        EXPECT_TRUE(Health.ReceiveLoopReady);
        EXPECT_FALSE(Health.Healthy());
    }

    TEST(QuicGatewayLifecycle, PacketCounterDoesNotImplyProtocolHealth)
    {
        std::size_t CallbackCount = 0;
        Preview::Ingress::QuicGateway Gateway(
            Preview::Ingress::QuicGatewayOptions{
                4,
                4,
                [&CallbackCount](const Preview::Ingress::UdpPacket &) { ++CallbackCount; }});
        Gateway.MarkSocketReady();
        Gateway.MarkReceiveLoopReady();
        ASSERT_TRUE(Gateway.RegisterConnection(
            7, [](const Preview::Ingress::UdpPacket &) { return true; }));

        Preview::Ingress::UdpPacket Packet;
        Packet.Payload.resize(8);
        Packet.Classification = {
            Preview::Ingress::DatagramKind::Quic,
            static_cast<std::uint64_t>(7)};

        ASSERT_TRUE(Gateway.Handle(std::move(Packet)));
        EXPECT_EQ(CallbackCount, 1U);
        EXPECT_EQ(Gateway.Health().Packets, 1U);
        EXPECT_FALSE(Gateway.Health().Healthy());
    }

    TEST(QuicGatewayLifecycle, UnknownCidDoesNotCreateConnectionOrConsumeCapacity)
    {
        Preview::Ingress::QuicGateway Gateway(
            Preview::Ingress::QuicGatewayOptions{1, 4, {}, {}});

        Preview::Ingress::UdpPacket UnknownPacket;
        UnknownPacket.Classification = {
            Preview::Ingress::DatagramKind::Quic,
            static_cast<std::uint64_t>(9)};

        EXPECT_FALSE(Gateway.Handle(std::move(UnknownPacket)));
        EXPECT_EQ(Gateway.ConnectionCount(), 0U);
        EXPECT_FALSE(Gateway.Health().BoundedFailure);

        ASSERT_TRUE(Gateway.RegisterConnection(
            9, [](const Preview::Ingress::UdpPacket &Packet)
            { return Packet.Classification.ConnectionId == 9U; }));
        EXPECT_EQ(Gateway.ConnectionCount(), 1U);

        Preview::Ingress::UdpPacket RegisteredPacket;
        RegisteredPacket.Classification = {
            Preview::Ingress::DatagramKind::Quic,
            static_cast<std::uint64_t>(9)};
        EXPECT_TRUE(Gateway.Handle(std::move(RegisteredPacket)));
    }

    TEST(QuicGatewayLifecycle, ProtocolReadyRequiresHandshakeReady)
    {
        Preview::Ingress::QuicGateway Gateway;
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

    TEST(QuicGatewayLifecycle, RegisteredCidRoutesToItsConnectionHandler)
    {
        Preview::Ingress::QuicGateway Gateway;
        std::size_t Handled = 0;
        ASSERT_TRUE(Gateway.RegisterConnection(
            41,
            [&Handled](const Preview::Ingress::UdpPacket &Packet)
            {
                ++Handled;
                return Packet.Classification.ConnectionId == 41U;
            }));

        Preview::Ingress::UdpPacket Packet;
        Packet.Classification = {
            Preview::Ingress::DatagramKind::Quic,
            static_cast<std::uint64_t>(41)};
        EXPECT_TRUE(Gateway.Handle(std::move(Packet)));
        EXPECT_EQ(Handled, 1U);

        EXPECT_TRUE(Gateway.RemoveConnection(41));
        EXPECT_FALSE(Gateway.RemoveConnection(41));
    }

} // namespace

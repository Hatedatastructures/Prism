/**
 * @file IngressDispatcherTest.cpp
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
#include <vector>

#include <Preview/Ingress/IngressDispatcher.hpp>
#include <Preview/Ingress/UdpDemux.hpp>

namespace
{

    using Preview::Ingress::DatagramKind;
    using Preview::Ingress::DatagramRoute;
    using Preview::Ingress::IngressDispatcher;
    using Preview::Ingress::UdpPacket;

    auto MakeQuicClassifiedPacket() -> UdpPacket
    {
        UdpPacket Packet;
        Packet.Payload = {std::byte{0x7F}, std::byte{0x00}, std::byte{0x01}};
        Packet.Classification.Kind = DatagramKind::Quic;
        Packet.Classification.Route = DatagramRoute::UnknownCid;
        return Packet;
    }

    TEST(IngressDispatcher, FallsBackToDatagramWhenNoQuicGatewayConfigured)
    {
        std::size_t DatagramCalls = 0;
        IngressDispatcher Dispatcher(IngressDispatcher::Options{
            nullptr,
            [&DatagramCalls](UdpPacket) { ++DatagramCalls; },
            {}});

        Dispatcher.Dispatch(MakeQuicClassifiedPacket());

        EXPECT_EQ(DatagramCalls, 1U);
        EXPECT_EQ(Dispatcher.Snapshot().DatagramPackets, 1U);
        EXPECT_EQ(Dispatcher.Snapshot().RejectedPackets, 0U);
    }

    TEST(IngressDispatcher, FallsBackToDatagramWhenQuicGatewayRejectsUnknownCid)
    {
        auto Gateway = std::make_shared<Preview::Ingress::QuicGateway>(
            Preview::Ingress::QuicGatewayOptions{});
        std::size_t DatagramCalls = 0;
        IngressDispatcher Dispatcher(IngressDispatcher::Options{
            Gateway,
            [&DatagramCalls](UdpPacket) { ++DatagramCalls; },
            {}});

        Dispatcher.Dispatch(MakeQuicClassifiedPacket());

        EXPECT_EQ(DatagramCalls, 1U);
    }

} // namespace

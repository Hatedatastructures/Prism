/**
 * @file UdpIngressTest.cpp
 * @brief Preview 独立 UDP socket、demux 和 shutdown contract 测试。
 */
#include <gtest/gtest.h>

#include <Preview/Ingress/UdpListener.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace
{

    namespace Net = boost::asio;

    TEST(PreviewUdpDemux, SeparatesQuicLongHeaderAndOrdinaryDatagram)
    {
        Preview::Ingress::UdpDemux Demux;
        const std::array<std::byte, 18> Quic{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x04}, std::byte{0x01}, std::byte{0x02},
            std::byte{0x03}, std::byte{0x04}, std::byte{0x04}, std::byte{0x05},
            std::byte{0x06}, std::byte{0x07}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x00}};
        const std::array<std::byte, 4> Ordinary{
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

        const auto QuicResult = Demux.Classify(Quic);
        const auto OrdinaryResult = Demux.Classify(Ordinary);
        EXPECT_EQ(QuicResult.Kind, Preview::Ingress::DatagramKind::Quic);
        EXPECT_NE(QuicResult.ConnectionId, 0U);
        EXPECT_EQ(OrdinaryResult.Kind, Preview::Ingress::DatagramKind::Ordinary);
        EXPECT_EQ(OrdinaryResult.ConnectionId, 0U);
    }

    TEST(PreviewUdpDemux, RejectsMalformedLongHeaderAsOrdinaryDatagram)
    {
        Preview::Ingress::UdpDemux Demux;
        const std::array<std::byte, 6> MissingFixedBit{
            std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x00}};
        const std::array<std::byte, 12> ZeroVersion{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x04}, std::byte{0x01}, std::byte{0x02},
            std::byte{0x03}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00}};
        const std::array<std::byte, 6> MissingConnectionId{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x04}};

        for (const auto Payload : {std::span<const std::byte>(MissingFixedBit),
                                   std::span<const std::byte>(ZeroVersion),
                                   std::span<const std::byte>(MissingConnectionId)})
        {
            const auto Result = Demux.Classify(Payload);
            EXPECT_EQ(Result.Kind, Preview::Ingress::DatagramKind::Ordinary);
            EXPECT_EQ(Result.ConnectionId, 0U);
        }
    }

    TEST(PreviewUdpListener, BindsReceivesAndDrainsOneSocket)
    {
        Net::io_context Io;
        auto Listener = std::make_shared<Preview::Ingress::UdpListener>(Io.get_executor());
        auto Demux = std::make_shared<Preview::Ingress::UdpDemux>();
        std::atomic<std::size_t> Received{0};
        Preview::Ingress::UdpStartResult StartResult;
        Preview::Ingress::UdpDrainResult DrainResult;

        Net::co_spawn(Io, [&]() -> Net::awaitable<void>
        {
            StartResult = co_await Listener->Start(
                Preview::Ingress::UdpListener::StartRequest{
                    Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0),
                    Demux,
                    [&Received](Preview::Ingress::UdpPacket) noexcept
                    {
                        Received.fetch_add(1, std::memory_order_relaxed);
                    },
                    {}});
            if (!StartResult.Succeeded())
            {
                Io.stop();
                co_return;
            }
            const auto Endpoint = Listener->LocalEndpoint();
            Net::ip::udp::socket Client(Io);
            Client.open(Net::ip::udp::v4());
            const std::array<std::byte, 3> Payload{
                std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};
            boost::system::error_code Error;
            Client.send_to(Net::buffer(Payload), Endpoint, 0, Error);
            if (Error)
            {
                Io.stop();
                co_return;
            }

            Net::steady_timer Timer(Io);
            Timer.expires_after(std::chrono::milliseconds(10));
            co_await Timer.async_wait(Net::use_awaitable);
            Listener->Stop(Preview::Ingress::UdpListener::StopRequest{});
            DrainResult = co_await Listener->Drain();
            Io.stop();
            co_return;
        }(), Net::detached);
        Io.run();

        EXPECT_TRUE(StartResult.Succeeded());
        EXPECT_TRUE(DrainResult.Completed);
        EXPECT_GE(Received.load(std::memory_order_relaxed), 1U);
        EXPECT_FALSE(Listener->Health().Ready);
    }

} // namespace

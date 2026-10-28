/**
 * @file BoundaryTest.cpp
 * @brief Prism 独立 UDP socket、demux 和 shutdown contract 测试。
 */
#include <gtest/gtest.h>

#include <Prism/Boundary/Datagram/Listener.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>

namespace
{

    namespace Net = boost::asio;

    struct DatagramReceiveResult final
    {
        Prism::Boundary::DatagramStartResult Start;
        Prism::Boundary::DatagramDrainResult Drain;
        std::atomic<std::size_t> Received{0};
    };

    /**
     * @brief 保有 UDP listener 和接收结果，发送原报文后等待接收循环完整排空。
     * @details 参数按值保活；报文、socket 和 timer 归协程帧。RunCoro 完整等待，
     *          listener 在当前 executor 停止与 drain；UDP 不涉及半关闭。
     */
    auto ReceiveAndDrain(
        std::shared_ptr<Prism::Boundary::DatagramListener> Listener,
        std::shared_ptr<DatagramReceiveResult> Result) -> Net::awaitable<void>
    {
        const auto Executor = co_await Net::this_coro::executor;
        auto Demux = std::make_shared<Prism::Boundary::DatagramClassifier>();
        Result->Start = co_await Listener->Start(
            Prism::Boundary::DatagramListener::StartRequest{
                Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0),
                Demux,
                [Result](Prism::Boundary::BoundaryPacket) noexcept
                { Result->Received.fetch_add(1, std::memory_order_relaxed); },
                {}});
        if (!Result->Start.Succeeded())
        {
            co_return;
        }

        Net::ip::udp::socket Client(Executor);
        Client.open(Net::ip::udp::v4());
        const std::array<std::byte, 3> Payload{
            std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};
        boost::system::error_code Error;
        co_await Client.async_send_to(
            Net::buffer(Payload), Listener->LocalEndpoint(),
            Net::redirect_error(Net::use_awaitable, Error));
        if (!Error)
        {
            Net::steady_timer Timer(Executor);
            Timer.expires_after(std::chrono::milliseconds(10));
            co_await Timer.async_wait(Net::use_awaitable);
        }
        Listener->Stop(Prism::Boundary::DatagramListener::StopRequest{});
        Result->Drain = co_await Listener->Drain();
    }

    TEST(PrismDatagramClassifier, SeparatesQuicLongHeaderAndOrdinaryDatagram)
    {
        Prism::Boundary::DatagramClassifier Demux;
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
        EXPECT_EQ(QuicResult.Kind, Prism::Boundary::DatagramKind::Quic);
        EXPECT_NE(QuicResult.ConnectionId, 0U);
        EXPECT_EQ(OrdinaryResult.Kind, Prism::Boundary::DatagramKind::Ordinary);
        EXPECT_EQ(OrdinaryResult.ConnectionId, 0U);
    }

    TEST(PrismDatagramClassifier, RejectsMalformedLongHeaderAsOrdinaryDatagram)
    {
        Prism::Boundary::DatagramClassifier Demux;
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
            EXPECT_EQ(Result.Kind, Prism::Boundary::DatagramKind::Ordinary);
            EXPECT_EQ(Result.ConnectionId, 0U);
        }
    }

    TEST(PrismDatagramClassifier, AcceptsHeaderProtectedLongHeaderReservedBits)
    {
        Prism::Boundary::DatagramClassifier Demux;
        const std::array<std::byte, 32> Initial{
            std::byte{0xc4}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x01},
            std::byte{0x08}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}, std::byte{0x00}};

        const auto Result = Demux.Classify(Initial);
        EXPECT_EQ(Result.Kind, Prism::Boundary::DatagramKind::Quic);
        EXPECT_EQ(Result.Route, Prism::Boundary::DatagramRoute::UnknownCid);
        EXPECT_EQ(Result.Version, 1U);
        EXPECT_EQ(Result.ConnectionIdBytes.size(), 8U);
    }

    TEST(PrismDatagramClassifier, AcceptsHeaderProtectedShortHeaderReservedBits)
    {
        Prism::Boundary::DatagramClassifier Demux;
        const std::array<std::byte, 12> ShortHeader{
            std::byte{0x51}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
            std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07},
            std::byte{0x08}, std::byte{0x09}, std::byte{0x0A}, std::byte{0x0B}};

        const auto Result = Demux.Classify(ShortHeader);
        EXPECT_EQ(Result.Kind, Prism::Boundary::DatagramKind::Quic);
        EXPECT_EQ(Result.Route, Prism::Boundary::DatagramRoute::UnknownCid);
        EXPECT_NE(Result.ConnectionId, 0U);
    }

    TEST(PrismDatagramListener, BindsReceivesAndDrainsOneSocket)
    {
        Net::io_context Io;
        auto Listener = std::make_shared<Prism::Boundary::DatagramListener>(Io.get_executor());
        auto Result = std::make_shared<DatagramReceiveResult>();

        Prism::Testing::RunCoro(Io, ReceiveAndDrain(Listener, Result));

        EXPECT_TRUE(Result->Start.Succeeded());
        EXPECT_TRUE(Result->Drain.Completed);
        EXPECT_GE(Result->Received.load(std::memory_order_relaxed), 1U);
        EXPECT_FALSE(Listener->Health().Ready);
    }

    TEST(PrismDatagramListener, RecoversUdpPeerPortUnreachableWithoutStoppingSharedIngress)
    {
        EXPECT_TRUE(Prism::Boundary::IsRecoverableReceiveError(boost::asio::error::connection_reset));
        EXPECT_FALSE(Prism::Boundary::IsRecoverableReceiveError(boost::asio::error::operation_aborted));
        EXPECT_FALSE(Prism::Boundary::IsRecoverableReceiveError(boost::asio::error::bad_descriptor));
    }
    TEST(PrismDatagramListener, ClassifiesTransientConnectionRefusedAsRecoverable)
    {
        EXPECT_TRUE(Prism::Boundary::IsRecoverableReceiveError(
            boost::asio::error::connection_refused));
        EXPECT_FALSE(Prism::Boundary::IsRecoverableReceiveError(
            boost::asio::error::operation_aborted));
    }

} // namespace

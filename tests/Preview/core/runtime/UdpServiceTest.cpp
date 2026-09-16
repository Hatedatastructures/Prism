/**
 * @file UdpServiceTest.cpp
 * @brief Preview UDP service factory 的类型边界与生命周期测试。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <array>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <Preview/Composition/UdpService.hpp>
#include <Preview/Foundation/Fault/Code.hpp>
#include <Preview/Ingress/IngressDispatcher.hpp>
#include <Preview/Ingress/QuicGateway.hpp>
#include <Preview/Ingress/UdpAssociation.hpp>
#include <Preview/Ingress/UdpDemux.hpp>
#include <Preview/Ingress/UdpListener.hpp>
#include <Preview/Protocols/Quic/Native.hpp>
#include <Preview/Runtime/Middleware/Context.hpp>
#include <Preview/Protocols/Socks5/Codec.hpp>
#include <Preview/Protocols/Socks5/Conn.hpp>
#include <Preview/Protocols/Trojan/Dgram.hpp>
#include <Preview/Protocols/Trojan/Types.hpp>
#include <Preview/Protocols/Vless/Codec.hpp>
#include <Preview/Protocols/Vless/Conn.hpp>
#include <Preview/Protocols/Vmess/Vmess.hpp>
#include <Preview/Composition/Adapters/ProtocolAdapter.hpp>
#include <Preview/Net/Dialer/Dialer.hpp>
#include <Preview/Runtime/Listener.hpp>
#include <Preview/Runtime/Session.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <TestSupport/Fixtures/RuntimeTestHelpers.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace Composition = Preview::Composition;
    namespace Fault = Preview::Fault;
    namespace Middleware = Preview::Middleware;
    namespace Network = Preview::Network;
    namespace Runtime = Preview::Runtime;
    namespace Socks5 = Preview::Socks5;
    namespace Trojan = Preview::Trojan;
    namespace Vless = Preview::Vless;
    namespace Vmess = Preview::Vmess;
    using Udp = Net::ip::udp;
    using Tcp = Net::ip::tcp;
    using Preview::Error;
    using Preview::PreviewMockTransport;
    using Preview::SharedTransmission;
    using Preview::Testing::RunCoro;
    using Preview::Testing::TrafficRecorder;
    using Preview::Testing::MakeUuid;
    using Preview::Testing::UdpEchoServer;
    using Preview::Runtime::MakeAcceptVmess;

    auto MakeContext(SharedTransmission Inbound) -> Middleware::Context
    {
        Middleware::Context ContextValue;
        ContextValue.Inbound = std::move(Inbound);
        return ContextValue;
    }

    auto UdpEchoOnce(const std::shared_ptr<Udp::socket> &Socket) -> Net::awaitable<void>
    {
        std::array<std::byte, 65535> Payload{};
        Udp::endpoint Peer;
        boost::system::error_code ErrorCode;
        const auto Size = co_await Socket->async_receive_from(
            Net::buffer(Payload), Peer,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        if (ErrorCode)
        {
            co_return;
        }
        co_await Socket->async_send_to(
            Net::buffer(Payload.data(), Size), Peer,
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        co_return;
    }

    TEST(UdpDemux, KeepsRegisteredDestinationCidAffinityAcrossHeaderForms)
    {
        Preview::Ingress::UdpDemux Demux;
        const std::array<std::byte, 13> LongHeader{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x04}, std::byte{0x01}, std::byte{0x02},
            std::byte{0x03}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}};
        const auto LongClassification = Demux.Classify(LongHeader);
        ASSERT_NE(LongClassification.ConnectionId, 0U);
        ASSERT_TRUE(Demux.RegisterQuicCid(LongClassification.ConnectionId));

        const std::array<std::byte, 6> ShortHeader{
            std::byte{0x41}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03},
            std::byte{0x04}, std::byte{0xaa}};
        const auto ShortClassification = Demux.Classify(ShortHeader);

        EXPECT_EQ(ShortClassification.Kind, Preview::Ingress::DatagramKind::Quic);
        EXPECT_EQ(ShortClassification.ConnectionId, LongClassification.ConnectionId);
    }

    TEST(UdpDemux, ExposesUnknownRegisteredAndMalformedQuicBoundaries)
    {
        Preview::Ingress::UdpDemux Demux;
        const auto Empty = Demux.Classify(std::span<const std::byte>{});
        EXPECT_EQ(Empty.Kind, Preview::Ingress::DatagramKind::Invalid);
        EXPECT_EQ(Empty.Route, Preview::Ingress::DatagramRoute::Malformed);
        EXPECT_EQ(Empty.Error, Preview::Ingress::QuicHeaderError::Empty);

        const std::array<std::byte, 13> ValidLong{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x04}, std::byte{0x01}, std::byte{0x02},
            std::byte{0x03}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}};

        const auto Unknown = Demux.Classify(ValidLong);
        EXPECT_EQ(Unknown.Kind, Preview::Ingress::DatagramKind::Quic);
        EXPECT_EQ(Unknown.Route, Preview::Ingress::DatagramRoute::UnknownCid);
        EXPECT_EQ(Unknown.Error, Preview::Ingress::QuicHeaderError::None);
        ASSERT_EQ(Unknown.ConnectionIdBytes.size(), 4U);

        ASSERT_TRUE(Demux.RegisterQuicCid(Unknown.ConnectionIdBytes));
        const auto Registered = Demux.Classify(ValidLong);
        EXPECT_EQ(Registered.Route, Preview::Ingress::DatagramRoute::RegisteredCid);
        EXPECT_EQ(Registered.ConnectionIdBytes, Unknown.ConnectionIdBytes);

        auto MissingFixedBit = ValidLong;
        MissingFixedBit[0] = std::byte{0x80};
        const auto FixedBit = Demux.Classify(MissingFixedBit);
        EXPECT_EQ(FixedBit.Kind, Preview::Ingress::DatagramKind::Ordinary);
        EXPECT_EQ(FixedBit.Route, Preview::Ingress::DatagramRoute::Malformed);
        EXPECT_EQ(FixedBit.Error, Preview::Ingress::QuicHeaderError::FixedBit);

        auto UnsupportedVersion = ValidLong;
        UnsupportedVersion[4] = std::byte{0x02};
        const auto Version = Demux.Classify(UnsupportedVersion);
        EXPECT_EQ(Version.Route, Preview::Ingress::DatagramRoute::Malformed);
        EXPECT_EQ(Version.Error, Preview::Ingress::QuicHeaderError::UnsupportedVersion);

        auto ReservedBits = ValidLong;
        ReservedBits[0] = std::byte{0xcc};
        const auto Reserved = Demux.Classify(ReservedBits);
        EXPECT_EQ(Reserved.Route, Preview::Ingress::DatagramRoute::Malformed);
        EXPECT_EQ(Reserved.Error, Preview::Ingress::QuicHeaderError::ReservedBits);

        auto InvalidPacketType = ValidLong;
        InvalidPacketType[0] = std::byte{0xf1};
        const auto PacketType = Demux.Classify(InvalidPacketType);
        EXPECT_EQ(PacketType.Route, Preview::Ingress::DatagramRoute::Malformed);
        EXPECT_EQ(PacketType.Error, Preview::Ingress::QuicHeaderError::PacketType);

        const std::array<std::byte, 4> UnknownShort{
            std::byte{0x41}, std::byte{0xaa}, std::byte{0xbb}, std::byte{0xcc}};
        const auto Short = Demux.Classify(UnknownShort);
        EXPECT_EQ(Short.Kind, Preview::Ingress::DatagramKind::Quic);
        EXPECT_EQ(Short.Route, Preview::Ingress::DatagramRoute::UnknownCid);
    }

    TEST(QuicGateway, RoutesOnlyTheRegisteredExactConnectionId)
    {
        Preview::Ingress::QuicGateway Gateway(
            Preview::Ingress::QuicGatewayOptions{1, 4, {}, {}});
        const std::array<std::byte, 4> RegisteredCid{
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
        std::size_t Handled = 0;
        ASSERT_TRUE(Gateway.RegisterConnection(
            std::span<const std::byte>(RegisteredCid),
            [&Handled](const Preview::Ingress::UdpPacket &) {
                ++Handled;
                return true;
            }));

        Preview::Ingress::UdpPacket RegisteredPacket;
        RegisteredPacket.Classification.Kind = Preview::Ingress::DatagramKind::Quic;
        RegisteredPacket.Classification.Route = Preview::Ingress::DatagramRoute::RegisteredCid;
        RegisteredPacket.Classification.ConnectionIdBytes.assign(
            RegisteredCid.begin(), RegisteredCid.end());
        EXPECT_TRUE(Gateway.Handle(std::move(RegisteredPacket)));

        Preview::Ingress::UdpPacket DifferentPacket;
        DifferentPacket.Classification.Kind = Preview::Ingress::DatagramKind::Quic;
        DifferentPacket.Classification.Route = Preview::Ingress::DatagramRoute::UnknownCid;
        DifferentPacket.Classification.ConnectionIdBytes = {
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x05}};
        EXPECT_FALSE(Gateway.Handle(std::move(DifferentPacket)));
        EXPECT_EQ(Handled, 1U);
    }

    TEST(QuicGateway, ReadinessIsMonotonicAndDrainIsTerminal)
    {
        Preview::Ingress::QuicGateway Gateway;

        Gateway.MarkProtocolReady();
        EXPECT_EQ(Gateway.Readiness(), Preview::Ingress::QuicReadiness::Offline);

        Gateway.MarkSocketReady();
        Gateway.MarkReceiveLoopReady();
        Gateway.MarkHandshakeReady();
        Gateway.MarkProtocolReady();
        EXPECT_EQ(Gateway.Readiness(), Preview::Ingress::QuicReadiness::Protocol);
        EXPECT_TRUE(Gateway.Health().Healthy());

        Gateway.MarkSocketReady();
        EXPECT_EQ(Gateway.Readiness(), Preview::Ingress::QuicReadiness::Protocol);

        Gateway.Drain();
        EXPECT_EQ(Gateway.Readiness(), Preview::Ingress::QuicReadiness::Draining);
        Gateway.MarkSocketReady();
        Gateway.MarkReceiveLoopReady();
        Gateway.MarkHandshakeReady();
        Gateway.MarkProtocolReady();
        EXPECT_EQ(Gateway.Readiness(), Preview::Ingress::QuicReadiness::Draining);
        EXPECT_FALSE(Gateway.Health().Healthy());

        Gateway.Close();
        EXPECT_EQ(Gateway.Readiness(), Preview::Ingress::QuicReadiness::Closed);
    }

    TEST(IngressDispatcher, KeepsMalformedOrdinaryAndUnknownCidOnSeparateRoutes)
    {
        auto Gateway = std::make_shared<Preview::Ingress::QuicGateway>();
        std::size_t OrdinaryPackets = 0;
        Preview::Ingress::IngressDispatcher Dispatcher(
            Preview::Ingress::IngressDispatcher::Options{
                Gateway,
                [&OrdinaryPackets](Preview::Ingress::UdpPacket) { ++OrdinaryPackets; }});
        Preview::Ingress::UdpDemux Demux;

        const std::array<std::byte, 6> Malformed{
            std::byte{0x80}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x04}};
        Preview::Ingress::UdpPacket Ordinary;
        Ordinary.Classification = Demux.Classify(Malformed);
        Dispatcher.Dispatch(std::move(Ordinary));

        const std::array<std::byte, 13> UnknownPayload{
            std::byte{0xc0}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x01}, std::byte{0x04}, std::byte{0x01}, std::byte{0x02},
            std::byte{0x03}, std::byte{0x04}, std::byte{0x00}, std::byte{0x00},
            std::byte{0x00}};
        Preview::Ingress::UdpPacket Unknown;
        Unknown.Classification = Demux.Classify(UnknownPayload);
        Dispatcher.Dispatch(std::move(Unknown));

        const auto Snapshot = Dispatcher.Snapshot();
        EXPECT_EQ(OrdinaryPackets, 1U);
        EXPECT_EQ(Snapshot.DatagramPackets, 1U);
        EXPECT_EQ(Snapshot.QuicPackets, 0U);
        EXPECT_EQ(Snapshot.RejectedPackets, 1U);
    }

    TEST(UdpListener, StopWithoutCloseStillCompletesOwnerHeldReceiveLoop)
    {
        Net::io_context Io;
        auto Listener = std::make_shared<Preview::Ingress::UdpListener>(Io.get_executor());
        auto Demux = std::make_shared<Preview::Ingress::UdpDemux>();
        Preview::Ingress::UdpStartResult StartResult;
        bool DrainCompleted = false;
        bool WatchdogWon = false;

        Net::co_spawn(
            Io,
            [&]() -> Net::awaitable<void>
            {
                StartResult = co_await Listener->Start(
                    Preview::Ingress::UdpListener::StartRequest{
                        Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0),
                        Demux,
                        [](Preview::Ingress::UdpPacket) {},
                        {}});
                if (!StartResult.Succeeded())
                {
                    Io.stop();
                    co_return;
                }

                Listener->Stop(Preview::Ingress::UdpListener::StopRequest{false});
                Net::steady_timer Watchdog(Io);
                Watchdog.expires_after(std::chrono::milliseconds(20));
                const auto Race = co_await Net::experimental::awaitable_operators::operator||(
                    Listener->Drain(), Watchdog.async_wait(Net::use_awaitable));
                if (Race.index() == 0U)
                {
                    DrainCompleted = std::get<0>(Race).Completed;
                }
                else
                {
                    WatchdogWon = true;
                }
                Io.stop();
                co_return;
            }(),
            Net::detached);
        Io.run();

        EXPECT_TRUE(StartResult.Succeeded());
        EXPECT_TRUE(DrainCompleted);
        EXPECT_FALSE(WatchdogWon);
    }

    TEST(NativeQuicReadiness, HandshakeDoesNotImplyProtocolReady)
    {
        Preview::Quic::NativeConnectionHealth Health;
        Health.SocketReady = true;
        Health.ReceiveLoopReady = true;
        Health.HandshakeReady = true;

        EXPECT_FALSE(Health.ProtocolReady);
        EXPECT_FALSE(Health.Healthy());

        Health.ProtocolReady = true;
        EXPECT_TRUE(Health.Healthy());
    }

    TEST(UdpAssociationTable, KeysAssociationsByEndpointAndWorker)
    {
        Net::io_context Io;
        const auto Peer = Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 41001);
        const Preview::Ingress::UdpAssociationKey WorkerOneKey{Peer, 7, 1};
        const Preview::Ingress::UdpAssociationKey WorkerTwoKey{Peer, 7, 2};
        std::size_t Canceled = 0;
        auto Owner = std::make_shared<Preview::Ingress::UdpAssociation>(
            WorkerOneKey,
            Preview::Ingress::UdpAssociationOptions{
                Io.get_executor(),
                [&Canceled]() noexcept { ++Canceled; }});
        Preview::Ingress::UdpAssociationTable Table;

        ASSERT_TRUE(Table.Register(WorkerOneKey, Owner));
        EXPECT_FALSE(Table.Register(WorkerOneKey, Owner));
        EXPECT_TRUE(Table.Register(
            WorkerTwoKey,
            std::make_shared<Preview::Ingress::UdpAssociation>(
                WorkerTwoKey,
                Preview::Ingress::UdpAssociationOptions{Io.get_executor(), {}})));
        EXPECT_EQ(Table.Size(), 2U);
        EXPECT_EQ(Table.Find(WorkerOneKey), Owner);
        EXPECT_EQ(Table.Find(Preview::Ingress::UdpAssociationKey{Peer, 8, 1}), nullptr);
    }

    TEST(UdpAssociationTable, DrainRejectsNewKeysAndCloseCancelsOwners)
    {
        Net::io_context Io;
        const auto Peer = Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 41002);
        const Preview::Ingress::UdpAssociationKey Key{Peer, 9, 3};
        std::size_t Canceled = 0;
        auto Association = std::make_shared<Preview::Ingress::UdpAssociation>(
            Key,
            Preview::Ingress::UdpAssociationOptions{
                Io.get_executor(),
                [&Canceled]() noexcept { ++Canceled; }});
        Preview::Ingress::UdpAssociationTable Table;
        ASSERT_TRUE(Table.Register(Key, Association));

        Table.Drain();
        EXPECT_TRUE(Table.IsDraining());
        EXPECT_FALSE(Table.Register(Key, Association));

        bool WaitClosed = false;
        Net::co_spawn(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Table.Close();
                WaitClosed = co_await Association->WaitClosed();
                Io.stop();
                co_return;
            }(),
            Net::detached);
        Io.run();

        EXPECT_TRUE(WaitClosed);
        EXPECT_EQ(Canceled, 1U);
        EXPECT_EQ(Table.Size(), 0U);
        EXPECT_TRUE(Association->IsClosed());
    }

    auto SendSocks5FrameAfterBind(
        const std::shared_ptr<PreviewMockTransport> &Carrier,
        std::shared_ptr<bool> Sent,
        std::uint16_t Port,
        std::chrono::milliseconds PollInterval)
        -> Net::awaitable<void>
    {
        Net::steady_timer Wait(Carrier->Executor());
        while (Carrier->Written.size() < 10)
        {
            Wait.expires_after(PollInterval);
            co_await Wait.async_wait(Net::use_awaitable);
        }

        Socks5::Reply ReplyValue;
        std::size_t Consumed = 0;
        const auto Parsed = Socks5::ParseReply(
            std::span<const std::uint8_t>(Carrier->Written.data(), Carrier->Written.size()),
            ReplyValue,
            Consumed);
        if (Parsed != Error::None || ReplyValue.Code != Socks5::ReplyCode::Success)
        {
            co_return;
        }

        Net::ip::udp::socket Client(Carrier->Executor());
        boost::system::error_code ErrorCode;
        Client.open(Net::ip::udp::v4(), ErrorCode);
        if (ErrorCode)
        {
            co_return;
        }
        Client.bind(Net::ip::udp::endpoint(Net::ip::make_address("127.0.0.1"), 0), ErrorCode);
        if (ErrorCode)
        {
            co_return;
        }

        const auto Frame = Socks5::BuildUdpDatagram(
            Socks5::Address{Socks5::AddressType::Domain, "resolve-failure.test", Port},
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>("x"), 1));
        co_await Client.async_send_to(
            Net::buffer(Frame),
            Net::ip::udp::endpoint(Net::ip::make_address(ReplyValue.Bind.Host), ReplyValue.Bind.Port),
            Net::redirect_error(Net::use_awaitable, ErrorCode));
        *Sent = !ErrorCode;
        co_return;
    }

    TEST(UdpServiceFactory, RejectsUnsupportedSocks5Carrier)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        auto ContextValue = MakeContext(Carrier);
        auto Service = Composition::UdpServiceFactory::MakeSocks5({});
        Fault::Code Result = Fault::Code::GenericError;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service(ContextValue);
                co_return;
            });

        EXPECT_EQ(Result, Fault::Code::ProtocolError);
        EXPECT_TRUE(Carrier->IsClosed());
    }

    TEST(UdpServiceFactory, RejectsUnsupportedVlessCarrier)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        auto ContextValue = MakeContext(Carrier);
        auto Service = Composition::UdpServiceFactory::MakeVless({});
        Fault::Code Result = Fault::Code::GenericError;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service(ContextValue);
                co_return;
            });

        EXPECT_EQ(Result, Fault::Code::ProtocolError);
        EXPECT_TRUE(Carrier->IsClosed());
    }

    TEST(UdpServiceFactory, ClosesSocks5OwnerWhenControlCarrierEnds)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        Carrier->EofOnDrain = true;
        auto Owner = std::make_shared<Socks5::Conn<>>(Carrier);
        auto ContextValue = MakeContext(Owner);
        auto Service = Composition::UdpServiceFactory::MakeSocks5({});
        Fault::Code Result = Fault::Code::GenericError;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service(ContextValue);
                co_return;
            });

        EXPECT_EQ(Result, Fault::Code::Success);
        EXPECT_TRUE(Carrier->IsClosed());
    }

    TEST(UdpServiceFactory, ClosesVlessOwnerOnIdle)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        Carrier->TransportKind = Preview::Transmission::Type::Udp;
        auto Owner = std::make_shared<Vless::Conn<>>(Carrier, Preview::Testing::MakeUuid());
        auto ContextValue = MakeContext(Owner);
        Composition::UdpServiceOptions Options;
        Options.IdleTimeout = std::chrono::milliseconds(20);
        auto Service = Composition::UdpServiceFactory::MakeVless(std::move(Options));
        Fault::Code Result = Fault::Code::GenericError;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service(ContextValue);
                co_return;
            });

        EXPECT_EQ(Result, Fault::Code::Success);
        EXPECT_TRUE(Carrier->IsClosed());
    }

    TEST(UdpServiceFactory, ClosesSocks5OwnerAfterResolveFailure)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        auto Owner = std::make_shared<Socks5::Conn<>>(Carrier);
        auto ContextValue = MakeContext(Owner);
        auto ResolveCalls = std::make_shared<std::size_t>(0);
        Composition::UdpServiceOptions Options;
        Options.IdleTimeout = std::chrono::milliseconds(20);
        Options.Resolver = [ResolveCalls](Composition::UdpResolveRequest)
            -> Net::awaitable<std::pair<Error, Net::ip::udp::endpoint>>
        {
            ++*ResolveCalls;
            co_return std::pair{Error::BadAddress, Net::ip::udp::endpoint{}};
        };
        auto Service = Composition::UdpServiceFactory::MakeSocks5(std::move(Options));
        Fault::Code Result = Fault::Code::GenericError;
        auto Sent = std::make_shared<bool>(false);

        Net::co_spawn(
            Io,
            SendSocks5FrameAfterBind(Carrier, Sent, 53, std::chrono::milliseconds(1)),
            Net::detached);
        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service(ContextValue);
                co_return;
            });

        EXPECT_EQ(Result, Fault::Code::Success);
        EXPECT_EQ(*ResolveCalls, 1u);
        EXPECT_TRUE(*Sent);
        EXPECT_TRUE(Carrier->IsClosed());
    }

    TEST(UdpServiceFactory, ClosesVlessOwnerAfterResolveFailure)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        Carrier->TransportKind = Preview::Transmission::Type::Udp;
        Carrier->ToRead = Vless::BuildUdpPkt(
            Vless::Address{Vless::AddressType::Domain, "resolve-failure.test", 53},
            std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>("x"), 1));
        auto Owner = std::make_shared<Vless::Conn<>>(Carrier, Preview::Testing::MakeUuid());
        auto ContextValue = MakeContext(Owner);
        auto ResolveCalls = std::make_shared<std::size_t>(0);
        Composition::UdpServiceOptions Options;
        Options.IdleTimeout = std::chrono::milliseconds(20);
        Options.Resolver = [ResolveCalls](Composition::UdpResolveRequest)
            -> Net::awaitable<std::pair<Error, Net::ip::udp::endpoint>>
        {
            ++*ResolveCalls;
            co_return std::pair{Error::BadAddress, Net::ip::udp::endpoint{}};
        };
        auto Service = Composition::UdpServiceFactory::MakeVless(std::move(Options));
        Fault::Code Result = Fault::Code::GenericError;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service(ContextValue);
                co_return;
            });

        EXPECT_EQ(Result, Fault::Code::Success);
        EXPECT_EQ(*ResolveCalls, 1u);
        EXPECT_TRUE(Carrier->IsClosed());
    }

    TEST(UdpServiceFactory, TrojanRelaysOneDatagramAndReportsPayloadTraffic)
    {
        Net::io_context Io;
        auto Echo = std::make_shared<Udp::socket>(
            Io.get_executor(), Udp::endpoint(Udp::v4(), 0));
        const auto EchoPort = Echo->local_endpoint().port();
        Net::co_spawn(Io, UdpEchoOnce(Echo), Net::detached);

        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        const std::string Payload = "trojan packet";
        const std::string TargetHost = "udp-echo.test";
        Carrier->ToRead = {
            static_cast<std::uint8_t>(Trojan::AddressType::Domain),
            static_cast<std::uint8_t>(TargetHost.size())};
        Carrier->ToRead.insert(Carrier->ToRead.end(), TargetHost.begin(), TargetHost.end());
        Carrier->ToRead.insert(
            Carrier->ToRead.end(),
            {static_cast<std::uint8_t>(EchoPort >> 8),
             static_cast<std::uint8_t>(EchoPort),
             0, static_cast<std::uint8_t>(Payload.size()), '\r', '\n'});
        Carrier->ToRead.insert(Carrier->ToRead.end(), Payload.begin(), Payload.end());
        auto Owner = std::make_shared<Trojan::Dgram<>>(Carrier);
        auto ContextValue = MakeContext(Owner);
        TrafficRecorder Traffic;
        ContextValue.traffic = &Traffic;
        ContextValue.identity = "trojan-udp-user";
        Composition::UdpServiceOptions Options;
        Options.IdleTimeout = std::chrono::milliseconds(20);
        std::size_t ResolveCalls = 0;
        std::string ResolvedHost;
        std::uint16_t ResolvedPort = 0;
        Options.Resolver = [&ResolveCalls, &ResolvedHost, &ResolvedPort, EchoPort](
                               Composition::UdpResolveRequest Request)
            -> Net::awaitable<std::pair<Error, Udp::endpoint>>
        {
            ++ResolveCalls;
            ResolvedHost = std::move(Request.Host);
            ResolvedPort = Request.Port;
            co_return std::pair{
                Error::None,
                Udp::endpoint(Net::ip::address_v4::loopback(), EchoPort)};
        };
        auto Service = Composition::UdpServiceFactory::MakeTrojan(std::move(Options));
        auto Result = Fault::Code::GenericError;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service(ContextValue);
                co_return;
            });

        EXPECT_EQ(Result, Fault::Code::Success);
        EXPECT_TRUE(Carrier->IsClosed());
        EXPECT_EQ(ResolveCalls, 1U);
        EXPECT_EQ(ResolvedHost, TargetHost);
        EXPECT_EQ(ResolvedPort, EchoPort);
        ASSERT_EQ(Carrier->Written.size(), Payload.size() + 11U);
        EXPECT_EQ(Carrier->Written[0], static_cast<std::uint8_t>(Trojan::AddressType::Ipv4));
        EXPECT_EQ(Carrier->Written[1], 127);
        EXPECT_EQ(Carrier->Written[2], 0);
        EXPECT_EQ(Carrier->Written[3], 0);
        EXPECT_EQ(Carrier->Written[4], 1);
        EXPECT_EQ(Carrier->Written[5], static_cast<std::uint8_t>(EchoPort >> 8));
        EXPECT_EQ(Carrier->Written[6], static_cast<std::uint8_t>(EchoPort));
        EXPECT_EQ(std::string(Carrier->Written.begin() + 11, Carrier->Written.end()), Payload);
        EXPECT_EQ(Traffic.Calls, 1);
        EXPECT_EQ(Traffic.Identity, "trojan-udp-user");
        EXPECT_EQ(Traffic.Up, Payload.size());
        EXPECT_EQ(Traffic.Down, Payload.size());
    }

    TEST(UdpServiceFactory, RejectsNonDatagramVmessCarrierAndClosesOwner)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        auto ContextValue = MakeContext(Carrier);
        auto Service = Composition::UdpServiceFactory::MakeVmess({});
        auto Result = Fault::Code::GenericError;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service(ContextValue);
                co_return;
            });

        EXPECT_EQ(Result, Fault::Code::ProtocolError);
        EXPECT_TRUE(Carrier->IsClosed());
    }

    TEST(UdpServiceFactory, RejectsVmessTargetPortZero)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        auto Datagram = std::make_shared<Vmess::Dgram<>>(Carrier);
        auto ContextValue = MakeContext(Datagram);
        ContextValue.Target.Host = "127.0.0.1";
        ContextValue.Target.Port = "0";
        auto Service = Composition::UdpServiceFactory::MakeVmess({});
        auto Result = Fault::Code::GenericError;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service(ContextValue);
                co_return;
            });

        EXPECT_EQ(Result, Fault::Code::InvalidArgument);
        EXPECT_TRUE(Carrier->IsClosed());
    }

    TEST(UdpServiceFactory, VmessUsesAcceptedTargetForUdpDatagrams)
    {
        Net::io_context Io;
        Udp::socket EchoSocket(Io.get_executor(), Udp::endpoint(Udp::v4(), 0));
        const auto EchoPort = EchoSocket.local_endpoint().port();
        auto EchoFailure = std::make_shared<std::exception_ptr>();
        auto EchoFailureOwner = EchoFailure;
        Net::co_spawn(
            Io.get_executor(), UdpEchoServer(std::move(EchoSocket)),
            [EchoFailureOwner](const std::exception_ptr &Exception)
            {
                if (Exception)
                {
                    *EchoFailureOwner = Exception;
                }
            });

        const auto Uuid = MakeUuid();
        Runtime::TcpListener Listener(
            Io.get_executor(),
            [Uuid](SharedTransmission, std::size_t)
                -> std::shared_ptr<Runtime::Session>
            {
                Runtime::SessionOptions Options;
                Options.AcceptProtocol = MakeAcceptVmess(Vmess::ServerConfig{Uuid});
                Composition::UdpServiceOptions UdpOptions;
                UdpOptions.IdleTimeout = std::chrono::seconds(3);
                Options.udp_service = Composition::UdpServiceFactory::MakeVmess(
                    std::move(UdpOptions));
                return std::make_shared<Runtime::Session>(std::move(Options));
            });

        bool Echoed = false;
        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                const auto StartResult = co_await Listener.Start(
                    Tcp::endpoint(Tcp::v4(), 0));
                if (StartResult != Fault::Code::Success)
                {
                    co_return;
                }
                Network::Dialer::Dialer Dialer(Io.get_executor());
                std::error_code ErrorCode;
                auto Raw = co_await Dialer.Connect(
                    "127.0.0.1", Listener.LocalEndpoint().port(), ErrorCode);
                if (ErrorCode || !Raw)
                {
                    co_return;
                }
                auto [ConnectError, Datagram] = co_await Vmess::ConnectPacket(
                    std::move(Raw), Vmess::ClientConfig{Uuid},
                    Vmess::Address{Vmess::AddressType::Ipv4, "127.0.0.1", EchoPort});
                if (ConnectError != Error::None || !Datagram)
                {
                    co_return;
                }
                const std::string Payload = "vmess packet";
                const auto SendError = co_await Datagram->AsyncSendTo(
                    std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t *>(Payload.data()),
                        Payload.size()));
                if (SendError == Error::None)
                {
                    std::vector<std::uint8_t> Received;
                    Net::steady_timer Watchdog(Datagram->Executor());
                    Watchdog.expires_after(std::chrono::seconds(2));
                    using Net::experimental::awaitable_operators::operator||;
                    auto Race = co_await (
                        Datagram->AsyncReceiveFrom(Received) ||
                        Watchdog.async_wait(Net::use_awaitable));
                    if (Race.index() == 0 && std::get<0>(Race) == Error::None)
                    {
                        Echoed = std::string(Received.begin(), Received.end()) == Payload;
                    }
                }
                Datagram->Close();
                Listener.Stop();
                co_return;
            });

        EXPECT_TRUE(Echoed);
        EXPECT_FALSE(*EchoFailure);
    }

    TEST(UdpServiceFactory, RejectsSs2022StreamDatagramAsTypedUnsupported)
    {
        Net::io_context Io;
        auto Carrier = std::make_shared<PreviewMockTransport>(Io.get_executor());
        auto ContextValue = MakeContext(Carrier);
        auto Service = Composition::UdpServiceFactory::MakeSs2022();
        auto Result = Fault::Code::GenericError;

        RunCoro(
            Io,
            [&]() -> Net::awaitable<void>
            {
                Result = co_await Service(ContextValue);
                co_return;
            });

        EXPECT_EQ(Result, Fault::Code::NotSupported);
        EXPECT_TRUE(Carrier->IsClosed());
    }

} // namespace

/**
 * @file Session.cpp
 * @brief Hysteria2 数据报会话生命周期测试。
 */
#include "DgramSupport.hpp"

namespace
{
    struct StreamDatagramRejectRequest final
    {
        std::shared_ptr<Dgram> Datagram;
        std::shared_ptr<MemoryStream> Peer;
    };

    /**
     * @brief 验证 stream-backed 数据报的收发均被拒绝。
     * @param Request 数据报 owner 与对端流。
     */
    auto RunStreamDatagramReject(StreamDatagramRejectRequest Request) -> Net::awaitable<void>
    {
        Address Source;
        std::vector<std::uint8_t> Payload;
        EXPECT_EQ(co_await Request.Datagram->AsyncReceiveFrom(Source, Payload), Error::Unsupported);
        EXPECT_EQ(co_await Request.Datagram->AsyncSendTo(
            MakeAddress(AddressType::Ipv4, "127.0.0.1", 53),
            AsU8Span(std::string_view{"payload"})), Error::Unsupported);
        Request.Datagram->Close();
        Request.Peer->Close();
    }

    /**
     * @brief 验证 stream-backed 数据报发送被拒绝。
     * @param Request 数据报 owner 与对端流。
     */
    auto RunStreamDatagramSendReject(StreamDatagramRejectRequest Request) -> Net::awaitable<void>
    {
        EXPECT_EQ(co_await Request.Datagram->AsyncSendTo(
            MakeAddress(AddressType::Ipv4, "93.184.216.34", 443),
            AsU8Span(std::string_view{"payload"})), Error::Unsupported);
        Request.Datagram->Close();
        Request.Peer->Close();
    }

    struct RawDatagramRequest final
    {
        std::shared_ptr<Dgram> Client;
        std::shared_ptr<Dgram> Server;
        std::string Payload;
    };

    /**
     * @brief 发送并接收一个真实 UDP 数据报，核对地址和完整 payload。
     * @param Request UDP 两端与拥有型 payload。
     */
    auto RunRawDatagram(RawDatagramRequest Request) -> Net::awaitable<void>
    {
        const auto SendError = co_await Request.Client->AsyncSendTo(
            MakeAddress(AddressType::Domain, "example.com", 443),
            AsU8Span(std::string_view(Request.Payload)));
        EXPECT_EQ(SendError, Error::None);
        Address Target;
        std::vector<std::uint8_t> Received;
        const auto ReceiveError = co_await Request.Server->AsyncReceiveFrom(Target, Received);
        EXPECT_EQ(ReceiveError, Error::None);
        EXPECT_EQ(Target.Host, "example.com");
        EXPECT_EQ(std::string(Received.begin(), Received.end()), Request.Payload);
        Request.Server->Close();
        Request.Client->Close();
    }

    struct InvalidWireRequest final
    {
        std::shared_ptr<MemoryDatagramProvider> ClientProvider;
        std::shared_ptr<MemoryDatagramProvider> ServerProvider;
        std::vector<std::uint8_t> Wire;
        Error Expected{Error::BadMessage};
    };

    struct InvalidWireServerRequest final
    {
        std::shared_ptr<Dgram> Datagram;
        Error Expected;
    };

    auto RunInvalidWireServer(InvalidWireServerRequest Request) -> Net::awaitable<void>
    {
        Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue = co_await Request.Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ErrorValue, Request.Expected);
        Request.Datagram->Close();
    }

    /**
     * @brief 通过真实数据报 provider 注入非法 wire 并等待解析结果。
     * @param Request 数据报提供者、完整 wire 和预期错误。
     */
    auto RunInvalidWire(InvalidWireRequest Request) -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Dgram>(
            std::make_shared<DatagramAdapter>(Request.ServerProvider));
        const auto ServerDone = SpawnServer(
            Datagram->Executor(),
            RunInvalidWireServer(InvalidWireServerRequest{Datagram, Request.Expected}));
        std::error_code ErrorCode;
        const auto Data = AsBytes(std::span<const std::uint8_t>(Request.Wire));
        const auto Sent = co_await Request.ClientProvider->Send(Data, ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(Sent, Data.size());
        const auto ServerCompleted = co_await ServerDone->async_receive(Net::use_awaitable);
        EXPECT_TRUE(ServerCompleted);
        Request.ClientProvider->Close();
    }

    struct PeerClosedRequest final
    {
        std::shared_ptr<Dgram> Datagram;
        std::shared_ptr<MemoryStream> Peer;
    };

    /**
     * @brief 验证对端 EOF 后数据报 owner 的错误收口。
     * @param Request 数据报 owner 与对端流。
     */
    auto RunPeerClosed(PeerClosedRequest Request) -> Net::awaitable<void>
    {
        Request.Peer->Close();
        Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue = co_await Request.Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ErrorValue, Error::Unsupported);
        Request.Datagram->Close();
    }
}

TEST(Hysteria2DgramSession, StreamBackedDatagramIsRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto Datagram = std::make_shared<Dgram>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)));
        RunCoroutine(IoContext, RunStreamDatagramReject(
            StreamDatagramRejectRequest{Datagram, Peer}));
    }

    TEST(Hysteria2DgramSession, StreamBackedSendIsRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto Datagram = std::make_shared<Dgram>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)));
        RunCoroutine(IoContext, RunStreamDatagramSendReject(
            StreamDatagramRejectRequest{Datagram, Peer}));
    }

    TEST(Hysteria2DgramSession, RawUdpDatagramKeepsFrameBoundary)
    {
        Net::io_context IoContext;
        auto RawServer = std::make_shared<Unreliable>(
            IoContext.get_executor());
        auto RawClient = std::make_shared<Unreliable>(
            IoContext.get_executor());
        boost::system::error_code OpenError;
        RawServer->NativeSocket().open(
            Net::ip::udp::v4(),
            OpenError);
        RawServer->NativeSocket().bind(
            {Net::ip::address_v4::loopback(), 0},
            OpenError);
        EXPECT_FALSE(OpenError);
        const auto ServerEndpoint = RawServer->NativeSocket().local_endpoint();
        EXPECT_TRUE(
            RawClient->Connect(
                "127.0.0.1:" +
                std::to_string(ServerEndpoint.port())));
        auto Server = std::make_shared<Dgram>(RawServer);
        auto Client = std::make_shared<Dgram>(RawClient);
        const std::string Payload = "udp-payload-without-truncation";
        RunCoroutine(IoContext, RunRawDatagram(
            RawDatagramRequest{Client, Server, Payload}));
    }

    TEST(Hysteria2DgramSession, BadKindRejected)
    {
        Net::io_context IoContext;
        auto [ClientProvider, ServerProvider] =
            MemoryDatagramProvider::MakePair(IoContext.get_executor());
        const std::vector<std::uint8_t> Wire{0x01, 0, 0, 0, 0, 0, 0, 0, 0};
        RunCoroutine(IoContext, RunInvalidWire(
            InvalidWireRequest{ClientProvider, ServerProvider, Wire, Error::BadMessage}));
    }

    TEST(Hysteria2DgramSession, BadAtypRejected)
    {
        Net::io_context IoContext;
        auto [ClientProvider, ServerProvider] =
            MemoryDatagramProvider::MakePair(IoContext.get_executor());
        // UDP Kind + Session/packet Id(8) + 非法 ATYP
        const auto Wire = BuildReceiveWire(ReceiveWireRequest{0x99, {}, 0, {}});
        RunCoroutine(IoContext, RunInvalidWire(
            InvalidWireRequest{ClientProvider, ServerProvider, Wire, Error::BadMessage}));
    }

    TEST(Hysteria2DgramSession, PeerClosedEof)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(ClientMemory));
        auto Datagram = std::make_shared<Dgram>(
            std::make_shared<MemoryStream>(std::move(ServerMemory)));
        RunCoroutine(IoContext, RunPeerClosed(PeerClosedRequest{Datagram, Peer}));
    }

/**
 * @file VlessDgramSession.cpp
 * @brief VLESS datagram and UDP tunnel tests.
 */
#include "VlessConnSessionSupport.hpp"

namespace
{
    struct VlessDgramPeerRequest final
    {
        Net::io_context& Io;
        MemoryStream Client;
        MemoryStream Server;
    };

    struct VlessTruncatedFrameRequest final
    {
        Net::io_context& Io;
        MemoryStream Client;
        MemoryStream Server;
        std::vector<std::uint8_t> Wire;
    };

    struct VlessLengthFrameRequest final
    {
        MemoryStream Server;
        std::shared_ptr<Vless::Dgram<>> Datagram;
    };

    auto RunSendToClosedPeer(VlessDgramPeerRequest Request) -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Vless::Dgram<>>(
            std::make_shared<MemoryStream>(std::move(Request.Client)));
        (void)Request.Server.Close();
        const std::string Payload = "x";
        const auto Result = co_await Datagram->AsyncSendDatagram(
            AsU8Span(std::string_view(Payload)));
        EXPECT_TRUE(Result.Failure.Failed());
        (void)Datagram->Close();
    }

    auto RunTruncatedDatagramReader(std::shared_ptr<MemoryStream> Server)
        -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Vless::Dgram<>>(std::move(Server));
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::BadMessage);
        (void)Datagram->Close();
    }

    auto RunTruncatedDatagramFrame(VlessTruncatedFrameRequest Request)
        -> Net::awaitable<void>
    {
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Server));
        const auto ServerDone = SpawnServer(
            Request.Io.get_executor(), RunTruncatedDatagramReader(Server));
        const auto Write = co_await Request.Client.WriteSome(AsBytes(
            std::span<const std::uint8_t>(Request.Wire)));
        (void)Preview::Fault::ToNative(Write.Failure);
        (void)Request.Client.Close();
        const auto Completed = co_await ServerDone->async_receive(Net::use_awaitable);
        EXPECT_TRUE(Completed);
    }

    auto RunPeerClosedDatagram(VlessDgramPeerRequest Request) -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Vless::Dgram<>>(
            std::make_shared<MemoryStream>(std::move(Request.Server)));
        EXPECT_TRUE(Datagram->Executor());
        std::array<std::byte, 8> Buffer{};
        const auto Written = co_await Datagram->WriteSome(
            std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_EQ(Written.Bytes, 4u);
        (void)Request.Client.Close();
        const auto Read = co_await Datagram->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0u);
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_TRUE(Result.Failure.Failed());
        EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::Eof);
        (void)Datagram->Close();
        (void)Datagram->Cancel();
        EXPECT_NE(Datagram->NextLayer(), nullptr);
        const Vless::Dgram<>* ConstDatagram = Datagram.get();
        EXPECT_NE(ConstDatagram->NextLayer(), nullptr);
        EXPECT_TRUE(Datagram->Release());
    }

    auto RunLengthFramedDatagram(VlessLengthFrameRequest Request)
        -> Net::awaitable<void>
    {
        const std::array<std::uint8_t, 4> Wire{0, 2, 'o', 'k'};
        (void)co_await Request.Server.WriteExact(
            AsBytes(std::span<const std::uint8_t>(Wire)));
        std::vector<std::uint8_t> Payload;
        const auto Result = co_await Request.Datagram->AsyncReceiveDatagram(Payload);
        EXPECT_TRUE(Result.Failure.Succeeded());
        EXPECT_EQ(Payload, (std::vector<std::uint8_t>{'o', 'k'}));
        (void)Request.Datagram->Close();
        (void)Request.Server.Close();
    }
}

TEST(VlessDgramSession, SendToClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunSendToClosedPeer(VlessDgramPeerRequest{
            IoContext, std::move(ClientMemory), std::move(ServerMemory)}));
    }

    TEST(VlessDgramSession, TruncatedLengthPrefixRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunTruncatedDatagramFrame(VlessTruncatedFrameRequest{
            IoContext, std::move(ClientMemory), std::move(ServerMemory), {0x00}}));
    }

    TEST(VlessDgramSession, DeclaredPayloadTruncationRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunTruncatedDatagramFrame(VlessTruncatedFrameRequest{
            IoContext, std::move(ClientMemory), std::move(ServerMemory), {0x00, 0x01}}));
    }

    TEST(VlessDgramSession, PeerClosedEof)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunPeerClosedDatagram(VlessDgramPeerRequest{
            IoContext, std::move(ClientMemory), std::move(ServerMemory)}));
    }

    TEST(VlessDgramSession, StreamBackedDatagramUsesLengthFrames)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Datagram = std::make_shared<Vless::Dgram<>>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)));
        RunCoro(IoContext, RunLengthFramedDatagram(VlessLengthFrameRequest{
            std::move(ServerMemory), std::move(Datagram)}));
    }

    TEST(VlessDgramSession, RejectsOverreportedStandardWrite)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportWrite = true;
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw);
        const auto Payload = AsU8Span(std::string_view{"overreport"});

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     const auto Result = co_await Datagram->AsyncSendDatagram(Payload);
                     EXPECT_TRUE(Result.Failure.Failed());
                     EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::InvalidArgument);
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, RejectsOverreportedStandardRead)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->OverreportRead = true;
        auto Datagram = std::make_shared<Vless::Dgram<>>(Raw);

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     std::vector<std::uint8_t> Payload;
                     const auto Result = co_await Datagram->AsyncReceiveDatagram(Payload);
                     EXPECT_TRUE(Result.Failure.Failed());
                     EXPECT_EQ(Result.Failure.Code, Preview::Fault::Code::InvalidArgument);
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, UdpTunnelRejectsStreamWithoutFrameBoundaries)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] = MakeMemoryPair(IoContext.get_executor());
        auto Connection = std::make_shared<Vless::Conn<>>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)), TestUuid());
        Vless::UdpTunnelOptions Options;
        Options.Target = MakeAddress(Vless::AddressType::Ipv4, "127.0.0.1", 53);
        auto Tunnel = std::make_shared<Vless::UdpTunnel>(std::move(Connection), std::move(Options));
        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     const std::array<std::uint8_t, 3> IncompleteFrame{0, 3, 0x41};
                     (void)co_await ServerMemory.WriteExact(
                         AsBytes(std::span<const std::uint8_t>(IncompleteFrame)));
                     const auto Result = co_await Tunnel->Run();
                     EXPECT_FALSE(Result);
                     if (!Result) EXPECT_EQ(Result.error().Code, Preview::Fault::Code::BadMessage);
                     (void)ServerMemory.Close();
                 };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(VlessDgramSession, UdpTunnelRejectsOverreportedRead)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PreviewMockTransport>(IoContext.get_executor());
        Raw->TransportKind = Preview::Transmission::Type::Udp;
        Raw->OverreportRead = true;
        auto Connection = std::make_shared<Vless::Conn<>>(Raw, TestUuid());
        Vless::UdpTunnelOptions Options;
        Options.Target = MakeAddress(Vless::AddressType::Ipv4, "127.0.0.1", 53);
        auto Tunnel = std::make_shared<Vless::UdpTunnel>(std::move(Connection), std::move(Options));

        auto TestCoroutine = [&]() -> Net::awaitable<void>
                 {
                     const auto Result = co_await Tunnel->Run();
                     EXPECT_FALSE(Result);
                     if (!Result) EXPECT_EQ(Result.error().Code, Preview::Fault::Code::InvalidArgument);
                 };
        RunCoro(IoContext, std::move(TestCoroutine));

        EXPECT_TRUE(Raw->IsClosed());
    }


#include "NativeQuicLoopbackSupport.hpp"

namespace
{
    /** @brief 启动随机源失败 client 并等待握手拒绝。 */
    auto RunRandomSourceFailure(
        std::shared_ptr<Preview::Quic::Client> Client) -> Net::awaitable<void>
    {
        Client->Start();
        EXPECT_FALSE(co_await Client->WaitHandshake());
        Client->Close();
    }
    struct StreamDatagramRequest final
    {
        std::shared_ptr<Preview::Quic::Server> Server;
        std::shared_ptr<Preview::Quic::Client> Client;
    };

    struct StreamRoundtripProviders final
    {
        Preview::Quic::SharedStreamProvider Client;
        Preview::Quic::SharedStreamProvider Server;
    };

    /** @brief 完成 QUIC handshake 并检查两侧启动状态。 */
    auto RunHandshake(StreamDatagramRequest Request) -> Net::awaitable<bool>
    {
        const auto Handshake = co_await (
            Request.Client->WaitHandshake() && Request.Server->WaitHandshake());
        EXPECT_TRUE(std::get<0>(Handshake));
        EXPECT_TRUE(std::get<1>(Handshake));
        EXPECT_FALSE(Request.Client->Health().BoundedFailure);
        EXPECT_FALSE(Request.Server->Health().BoundedFailure);
        EXPECT_TRUE(Request.Client->Health().SocketReady);
        EXPECT_TRUE(Request.Client->Health().ReceiveLoopReady);
        EXPECT_TRUE(Request.Client->Health().HandshakeReady);
        EXPECT_TRUE(Request.Server->Health().SocketReady);
        EXPECT_TRUE(Request.Server->Health().ReceiveLoopReady);
        EXPECT_TRUE(Request.Server->Health().HandshakeReady);
        co_return std::get<0>(Handshake) && std::get<1>(Handshake);
    }

    /** @brief 写入数据、接收 FIN 并等待 echo 与传输层 FIN ACK。 */
    auto RunStreamFinRoundtrip(StreamDatagramRequest Request)
        -> Net::awaitable<StreamRoundtripProviders>
    {
        auto ClientStream = co_await Request.Client->OpenBidirectionalStream();
        EXPECT_NE(ClientStream, nullptr);
        if (!ClientStream)
        {
            Request.Client->Close();
            Request.Server->Close();
            co_return StreamRoundtripProviders{};
        }
        std::vector<std::byte> Message(128 * 1024, std::byte{0x5A});
        std::vector<std::byte> Received(Message.size());
        auto AcceptAndRead = [&]() -> Net::awaitable<std::pair<Preview::Quic::SharedStreamProvider, std::size_t>>
        {
            auto Stream = co_await Request.Server->AcceptBidirectionalStream();
            if (!Stream)
            {
                co_return std::pair<Preview::Quic::SharedStreamProvider, std::size_t>{nullptr, 0};
            }
            const auto Count = co_await ReadExactStream(Stream, std::span<std::byte>(Received));
            co_return std::pair{std::move(Stream), Count};
        };
        std::error_code ClientWriteError;
        const auto [ClientWritten, ReceiveResult] = co_await (
            ClientStream->Write(Message, ClientWriteError) && AcceptAndRead());
        auto ServerStream = std::move(ReceiveResult.first);
        const auto ReceivedLength = ReceiveResult.second;
        EXPECT_NE(ServerStream, nullptr);
        EXPECT_EQ(ClientWritten, Message.size());
        EXPECT_FALSE(ClientWriteError);
        EXPECT_EQ(ReceivedLength, Received.size());
        EXPECT_EQ(Received, Message);
        if (ClientWriteError || ClientWritten != Message.size() ||
            ReceivedLength != Received.size())
        {
            Request.Client->Close();
            Request.Server->Close();
            co_return StreamRoundtripProviders{};
        }
        const auto PrematureAcknowledgement =
            co_await ClientStream->WaitForWriteAcknowledgement();
        EXPECT_FALSE(PrematureAcknowledgement);
        if (PrematureAcknowledgement ||
            PrematureAcknowledgement.error().Code != Preview::Fault::Code::InvalidArgument)
        {
            Request.Client->Close();
            Request.Server->Close();
            co_return StreamRoundtripProviders{};
        }
        const auto Shutdown = co_await ClientStream->ShutdownWrite();
        EXPECT_TRUE(Shutdown);
        if (!Shutdown)
        {
            Request.Client->Close();
            Request.Server->Close();
            co_return StreamRoundtripProviders{};
        }
        std::array<std::byte, 1> FinProbe{};
        std::error_code FinError;
        const auto FinRead = co_await ServerStream->Read(FinProbe, FinError);
        EXPECT_EQ(FinRead, 0U);
        EXPECT_FALSE(FinError);
        EXPECT_FALSE(Request.Client->Health().Closed);
        EXPECT_FALSE(Request.Server->Health().Closed);

        std::vector<std::byte> Echo(Message.size());
        std::error_code ServerWriteError;
        const auto [ServerWritten, EchoLength] = co_await (
            ServerStream->Write(Received, ServerWriteError) &&
            ReadExactStream(ClientStream, std::span<std::byte>(Echo)));
        EXPECT_EQ(ServerWritten, Received.size());
        EXPECT_FALSE(ServerWriteError);
        EXPECT_EQ(EchoLength, Echo.size());
        EXPECT_EQ(Echo, Message);
        const auto FinAcknowledged = co_await ClientStream->WaitForWriteAcknowledgement();
        EXPECT_TRUE(FinAcknowledged);
        if (!FinAcknowledged)
        {
            Request.Client->Close();
            Request.Server->Close();
            co_return StreamRoundtripProviders{};
        }
        co_return StreamRoundtripProviders{std::move(ClientStream), std::move(ServerStream)};
    }

    /** @brief 完成 QUIC handshake、stream echo、datagram 和 close。 */
    auto RunStreamDatagramRoundtrip(StreamDatagramRequest Request)
        -> Net::awaitable<void>
    {
        Request.Server->Start();
        Request.Client->Start();
        if (!co_await RunHandshake(Request))
        {
            Request.Client->Close();
            Request.Server->Close();
            co_return;
        }
        const auto Streams = co_await RunStreamFinRoundtrip(Request);
        if (!Streams.Client || !Streams.Server)
        {
            co_return;
        }
        std::error_code ErrorCode;
        auto ClientDatagram = Request.Client->Datagram();
        auto ServerDatagram = Request.Server->Datagram();
        EXPECT_NE(ClientDatagram, nullptr);
        EXPECT_NE(ServerDatagram, nullptr);
        if (!ClientDatagram || !ServerDatagram)
        {
            Request.Client->Close();
            Request.Server->Close();
            co_return;
        }
        const std::array<std::byte, 7> Datagram{
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0x05}, std::byte{0x06}, std::byte{0x07}};
        EXPECT_EQ(co_await ClientDatagram->Send(Datagram, ErrorCode), Datagram.size());
        EXPECT_FALSE(ErrorCode);
        std::array<std::byte, 32> DatagramReceived{};
        EXPECT_EQ(co_await ServerDatagram->Receive(DatagramReceived, ErrorCode), Datagram.size());
        EXPECT_FALSE(ErrorCode);
        EXPECT_TRUE(std::equal(Datagram.begin(), Datagram.end(), DatagramReceived.begin()));
        Streams.Client->Close();
        Streams.Server->Close();
        Request.Client->Close();
        Request.Server->Close();
    }
    struct MaxDatagramRequest final
    {
        std::shared_ptr<Preview::Quic::Server> Server;
        std::shared_ptr<Preview::Quic::Client> Client;
        std::shared_ptr<Net::experimental::channel<void(boost::system::error_code)>> PacketGate;
        std::shared_ptr<std::atomic<bool>> Armed;
        Net::io_context &IoContext;
    };

    /** @brief 验证 native inbox 超限后 drop datagram 仍保持连接可用。 */
    auto RunMaxDatagramScenario(MaxDatagramRequest Request) -> Net::awaitable<void>
    {
        Request.Server->Start();
        Request.Client->Start();
        const auto Handshake = co_await (
            Request.Client->WaitHandshake() && Request.Server->WaitHandshake());
        EXPECT_TRUE(std::get<0>(Handshake));
        EXPECT_TRUE(std::get<1>(Handshake));
        if (!std::get<0>(Handshake) || !std::get<1>(Handshake))
        {
            Request.Client->Close(); Request.Server->Close(); co_return;
        }
        auto ClientDatagram = Request.Client->Datagram();
        EXPECT_NE(ClientDatagram, nullptr);
        if (!ClientDatagram) { Request.Client->Close(); Request.Server->Close(); co_return; }
        co_await Net::post(Request.IoContext.get_executor(), Net::use_awaitable);
        Request.Armed->store(true, std::memory_order_release);
        const std::array<std::byte, 7> First{
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
            std::byte{0x05}, std::byte{0x06}, std::byte{0x07}};
        const std::array<std::byte, 7> Second{
            std::byte{0x11}, std::byte{0x12}, std::byte{0x13}, std::byte{0x14},
            std::byte{0x15}, std::byte{0x16}, std::byte{0x17}};
        std::error_code FirstError;
        std::error_code SecondError;
        EXPECT_EQ(co_await ClientDatagram->Send(First, FirstError), First.size());
        EXPECT_FALSE(FirstError);
        boost::system::error_code GateError;
        co_await Request.PacketGate->async_receive(Net::redirect_error(Net::use_awaitable, GateError));
        EXPECT_FALSE(GateError);
        if (GateError) { Request.Client->Close(); Request.Server->Close(); co_return; }
        EXPECT_EQ(co_await ClientDatagram->Send(Second, SecondError), Second.size());
        EXPECT_FALSE(SecondError);
        GateError.clear();
        co_await Request.PacketGate->async_receive(Net::redirect_error(Net::use_awaitable, GateError));
        EXPECT_FALSE(GateError);
        if (GateError) { Request.Client->Close(); Request.Server->Close(); co_return; }
        EXPECT_GE(Request.Server->Health().DroppedDatagrams, 1U);
        Request.Client->Close(); Request.Server->Close();
    }

    /** @brief 完成双向 unidirectional stream 认证、导出和回环。 */
    auto RunUnidirectionalStreams(StreamDatagramRequest Request)
        -> Net::awaitable<void>
    {
        Request.Server->Start();
        Request.Client->Start();
        const auto Handshake = co_await (
            Request.Client->WaitHandshake() && Request.Server->WaitHandshake());
        EXPECT_TRUE(std::get<0>(Handshake));
        EXPECT_TRUE(std::get<1>(Handshake));
        if (!std::get<0>(Handshake) || !std::get<1>(Handshake))
        {
            Request.Client->Close(); Request.Server->Close(); co_return;
        }
        const std::array<std::uint8_t, 16> Label{
            0x12, 0x3E, 0x45, 0x67, 0xE8, 0x9B, 0x12, 0xD3,
            0xA4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00};
        std::array<std::uint8_t, 32> ClientExport{};
        std::array<std::uint8_t, 32> ServerExport{};
        EXPECT_TRUE(Request.Client->ExportKeyingMaterial(ClientExport, Label, "tuic_password"));
        EXPECT_TRUE(Request.Server->ExportKeyingMaterial(ServerExport, Label, "tuic_password"));
        EXPECT_EQ(ClientExport, ServerExport);
        auto ClientUni = co_await Request.Client->OpenUnidirectionalStream();
        EXPECT_NE(ClientUni, nullptr);
        if (!ClientUni) { Request.Client->Close(); Request.Server->Close(); co_return; }
        std::error_code ErrorCode;
        const std::array<std::byte, 3> ClientMessage{
            std::byte{0x03}, std::byte{0x01}, std::byte{0x02}};
        EXPECT_EQ(co_await ClientUni->Write(ClientMessage, ErrorCode), ClientMessage.size());
        EXPECT_FALSE(ErrorCode);
        auto ServerUni = co_await Request.Server->AcceptUnidirectionalStream();
        EXPECT_NE(ServerUni, nullptr);
        if (!ServerUni) { Request.Client->Close(); Request.Server->Close(); co_return; }
        std::array<std::byte, 8> ServerBuffer{};
        const auto ServerRead = co_await ServerUni->Read(ServerBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(ServerRead, ClientMessage.size());
        EXPECT_TRUE(std::equal(ClientMessage.begin(), ClientMessage.end(), ServerBuffer.begin()));
        auto ServerCreated = co_await Request.Server->OpenUnidirectionalStream();
        EXPECT_NE(ServerCreated, nullptr);
        if (!ServerCreated) { Request.Client->Close(); Request.Server->Close(); co_return; }
        const std::array<std::byte, 2> ServerMessage{std::byte{0xA5}, std::byte{0x5A}};
        EXPECT_EQ(co_await ServerCreated->Write(ServerMessage, ErrorCode), ServerMessage.size());
        EXPECT_FALSE(ErrorCode);
        auto ClientReceived = co_await Request.Client->AcceptUnidirectionalStream();
        EXPECT_NE(ClientReceived, nullptr);
        if (!ClientReceived) { Request.Client->Close(); Request.Server->Close(); co_return; }
        std::array<std::byte, 8> ClientBuffer{};
        const auto ClientRead = co_await ClientReceived->Read(ClientBuffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(ClientRead, ServerMessage.size());
        EXPECT_TRUE(std::equal(ServerMessage.begin(), ServerMessage.end(), ClientBuffer.begin()));
        ClientUni->Close(); ServerUni->Close(); ServerCreated->Close(); ClientReceived->Close();
        Request.Client->Close(); Request.Server->Close();
    }

    TEST(NativeQuicLoopback, RandomSourceFailureRejectsConnection)
    {
        Net::io_context Ioc;
        auto ClientTls = std::make_shared<Ssl::context>(Ssl::context::tlsv13_client);
        auto ClientSocket = std::make_shared<Net::ip::udp::socket>(
            Ioc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
        const Preview::Quic::RandomSource FailingRandom = [](std::uint8_t *, int) { return 0; };
        auto Client = std::make_shared<Preview::Quic::Client>(Preview::Quic::ClientOptions{
            Ioc.get_executor(), ClientSocket,
            Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 1), ClientTls, "localhost",
            FailingRandom});

        RunLoopback(Ioc, RunRandomSourceFailure(Client),
                    LoopbackLifecycle{
                        [Client]() { Client->Close(); }, [] {}, std::chrono::seconds(5)});
    }
    TEST(NativeQuicLoopback, CloseFromForeignExecutor)
    {
        Net::io_context ConnectionIoc;
        Net::io_context CallerIoc;
        auto ClientTls = std::make_shared<Ssl::context>(Ssl::context::tlsv13_client);
        auto Socket = std::make_shared<Net::ip::udp::socket>(
            ConnectionIoc, Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 0));
        auto Client = std::make_shared<Preview::Quic::Client>(Preview::Quic::ClientOptions{
            ConnectionIoc.get_executor(), Socket,
            Net::ip::udp::endpoint(Net::ip::address_v4::loopback(), 1), ClientTls, "localhost"});

        std::promise<void> CloseCalled;
        auto CloseCalledFuture = CloseCalled.get_future();
        std::thread Caller([&CallerIoc, Client, &CloseCalled]() mutable
                            {
                                Net::post(CallerIoc,
                                          [Client = std::move(Client), &CloseCalled]() mutable
                                          {
                                              Client->Close();
                                              CloseCalled.set_value();
                                          });
                                CallerIoc.run();
                            });

        CloseCalledFuture.wait();
        ConnectionIoc.run();
        Caller.join();
        EXPECT_FALSE(Socket->is_open());
    }
    TEST(NativeQuicLoopback, HandshakeStreamAndDatagramRoundtrip)
    {
        Net::io_context Ioc;
        NativeLoopbackPeers Peers(Ioc);
        RunLoopback(Ioc, RunStreamDatagramRoundtrip(
            StreamDatagramRequest{Peers.Server, Peers.Client}),
            LoopbackLifecycle{
            [Server=Peers.Server, Client=Peers.Client]()
            {
                Client->Close();
                Server->Close();
            }, [] {}, std::chrono::seconds(5)});
    }
    TEST(NativeQuicLoopback, DatagramCancelIsOneShotAndKeepsConnectionUsable)
    {
        RunDatagramProviderLifecycle(DatagramProviderAction::Cancel);
    }
    TEST(NativeQuicLoopback, DatagramCloseReturnsBrokenPipeWithoutClosingConnection)
    {
        RunDatagramProviderLifecycle(DatagramProviderAction::Close);
    }
    TEST(NativeQuicLoopback, ServerMaxDatagramsBoundsNativeInbox)
    {
        Net::io_context Ioc;
        auto PacketGate = std::make_shared<Net::experimental::channel<void(boost::system::error_code)>>(
            Ioc.get_executor(), 1);
        auto Armed = std::make_shared<std::atomic<bool>>(false);
        NativeLoopbackPeers Peers(
            Ioc, 1,
            [PacketGate, Armed](const Preview::Quic::ServerLifecycleEvent Event)
            {
                if (Armed->load(std::memory_order_acquire) &&
                    Event.Stage == Preview::Quic::ServerLifecycleStage::PacketAccepted)
                {
                    (void)PacketGate->try_send(boost::system::error_code{});
                }
            });
        RunLoopback(Ioc, RunMaxDatagramScenario(
            MaxDatagramRequest{Peers.Server, Peers.Client, PacketGate, Armed, Ioc}),
            LoopbackLifecycle{
            [Client=Peers.Client, Server=Peers.Server, PacketGate]()
            {
                Client->Close();
                Server->Close();
                PacketGate->close();
            }, [] {}, std::chrono::seconds(5)});
    }
    TEST(NativeQuicLoopback, UnidirectionalStreamsRoundtrip)
    {
        Net::io_context Ioc;
        NativeLoopbackPeers Peers(Ioc);
        RunLoopback(Ioc, RunUnidirectionalStreams(
            StreamDatagramRequest{Peers.Server, Peers.Client}),
            LoopbackLifecycle{
            [Server=Peers.Server, Client=Peers.Client]()
            {
                Client->Close();
                Server->Close();
            }, [] {}, std::chrono::seconds(5)});
    }
} // namespace

#include "../Datagram/Hysteria2DgramSupport.hpp"

namespace
{
    struct StreamRejectRequest final
    {
        std::shared_ptr<Dgram> Connection;
        std::shared_ptr<MemoryStream> Peer;
    };

    auto RunStreamReject(StreamRejectRequest Request) -> Net::awaitable<void>
    {
        Address Source;
        std::vector<std::uint8_t> Payload;
        EXPECT_EQ(co_await Request.Connection->AsyncReceiveFrom(Source, Payload), Error::Unsupported);
        EXPECT_EQ(co_await Request.Connection->AsyncSendTo(
            MakeAddress(AddressType::Ipv4, "127.0.0.1", 53),
            AsU8Span(std::string_view{"payload"})), Error::Unsupported);
        Request.Connection->Close();
        Request.Peer->Close();
    }

    struct ConnStreamRejectRequest final
    {
        std::shared_ptr<Conn> Connection;
        std::shared_ptr<MemoryStream> Peer;
    };

    auto RunConnStreamUdpReject(ConnStreamRejectRequest Request) -> Net::awaitable<void>
    {
        Address Target;
        std::vector<std::uint8_t> Payload;
        EXPECT_EQ(co_await Request.Connection->AsyncSendDatagram(
            MakeAddress(AddressType::Ipv4, "93.184.216.34", 443),
            AsU8Span(std::string_view{"payload"})), Error::NotOpen);
        EXPECT_EQ(co_await Request.Connection->AsyncReceiveDatagram(Target, Payload), Error::NotOpen);
        Request.Connection->Close();
        Request.Peer->Close();
    }

    struct ProviderRoundtripRequest final
    {
        std::shared_ptr<MemoryDatagramProvider> ClientProvider;
        std::shared_ptr<MemoryDatagramProvider> ServerProvider;
        std::shared_ptr<Dgram> Client;
        std::shared_ptr<Dgram> Server;
        Address Target;
        std::string Payload;
        Address *ReceivedTarget;
        std::vector<std::uint8_t> *ReceivedPayload;
    };

    auto RunProviderRoundtrip(ProviderRoundtripRequest Request) -> Net::awaitable<void>
    {
        const auto Payload = AsU8Span(std::string_view(Request.Payload));
        EXPECT_EQ(co_await Request.Client->AsyncSendTo(Request.Target, Payload), Error::None);
        const auto ReceiveError = co_await Request.Server->AsyncReceiveFrom(
            *Request.ReceivedTarget, *Request.ReceivedPayload);
        EXPECT_EQ(ReceiveError, Error::None);
        if (ReceiveError == Error::None)
        {
            EXPECT_EQ(co_await Request.Server->AsyncSendTo(
                *Request.ReceivedTarget, *Request.ReceivedPayload), Error::None);
        }
        Request.Client->Close();
        Request.Server->Close();
    }

    struct ProviderShortWriteRequest final
    {
        std::shared_ptr<MemoryDatagramProvider> ClientProvider;
        std::shared_ptr<Dgram> Client;
        std::shared_ptr<Dgram> Server;
        Address Target;
    };

    auto RunProviderShortWrite(ProviderShortWriteRequest Request) -> Net::awaitable<void>
    {
        Request.ClientProvider->MaxSend = 2;
        EXPECT_EQ(co_await Request.Client->AsyncSendTo(
            Request.Target, AsU8Span(std::string_view{"short"})), Error::IoError);
        Request.ClientProvider->MaxSend = 0;
        const auto Closed = Request.Server->Close();
        EXPECT_TRUE(Closed);
        const auto Activity = Request.Server->Activity();
        EXPECT_TRUE(Activity);
        if (!Activity) co_return;
        const auto Drained = co_await Activity->Drain();
        EXPECT_TRUE(Drained);
        EXPECT_TRUE(Activity->IsRetired());
        if (!Drained) co_return;
        EXPECT_EQ(co_await Request.Client->AsyncSendTo(
            Request.Target, AsU8Span(std::string_view{"closed"})), Error::IoError);
        Request.Client->Close();
    }

    struct IndependentPacketFactoryRequest final
    {
        ExecutorType Executor;
        ClientConfig ClientConfiguration;
        ServerConfig ServerConfiguration;
    };

    auto RunIndependentPacketFactory(IndependentPacketFactoryRequest Request)
        -> Net::awaitable<void>
    {
        const auto Client = co_await Hysteria2::ConnectPacket(
            Request.Executor, "127.0.0.1:1", Request.ClientConfiguration);
        const auto Server = co_await Hysteria2::AcceptPacket(
            Request.Executor, 0U, Request.ServerConfiguration);
        EXPECT_TRUE(Client);
        EXPECT_TRUE(Server);
        if (Client) (void)(*Client)->Close();
        if (Server) (void)(*Server)->Close();
    }

    struct ProviderRoundtripState final
    {
        std::shared_ptr<MemoryDatagramProvider> ClientProvider;
        std::shared_ptr<MemoryDatagramProvider> ServerProvider;
        Address Target;
        Address ReceivedTarget;
        std::vector<std::uint8_t> ReceivedPayload;
    };

    auto RunProviderRoundtripFactory(std::shared_ptr<ProviderRoundtripState> State)
        -> Net::awaitable<void>
    {
        const auto Client = Hysteria2::ConnectPacket(
            State->ClientProvider, ClientConfig{});
        const auto Server = Hysteria2::AcceptPacket(
            State->ServerProvider, ServerConfig{});
        EXPECT_TRUE(Client);
        EXPECT_TRUE(Server);
        if (!Client || !Server) co_return;
        co_await RunProviderRoundtrip(ProviderRoundtripRequest{
            State->ClientProvider, State->ServerProvider, *Client, *Server,
            State->Target, "hysteria2-provider", &State->ReceivedTarget,
            &State->ReceivedPayload});
    }

    struct ProviderShortWriteFactoryRequest final
    {
        std::shared_ptr<MemoryDatagramProvider> ClientProvider;
        std::shared_ptr<MemoryDatagramProvider> ServerProvider;
        Address Target;
    };

    auto RunProviderShortWriteFactory(ProviderShortWriteFactoryRequest Request)
        -> Net::awaitable<void>
    {
        const auto Client = Hysteria2::ConnectPacket(
            Request.ClientProvider, ClientConfig{});
        const auto Server = Hysteria2::AcceptPacket(
            Request.ServerProvider, ServerConfig{});
        EXPECT_TRUE(Client);
        EXPECT_TRUE(Server);
        if (!Client || !Server) co_return;
        co_await RunProviderShortWrite(ProviderShortWriteRequest{
            Request.ClientProvider, *Client, *Server, Request.Target});
    }

    struct EchoServerRequest final
    {
        std::shared_ptr<MemoryStream> ServerStream;
        std::string Payload;
    };

    auto RunEchoServer(EchoServerRequest Request) -> Net::awaitable<void>
    {
        auto [ErrorValue, MessageValue, Connection] = co_await Hysteria2::Accept(
            Request.ServerStream, ServerConfig{"pw123456"});
        if (ErrorValue != Error::None || !Connection)
        {
            EXPECT_TRUE(false) << "Accept Failed";
            co_return;
        }
        EXPECT_EQ(MessageValue.Type, Message::Kind::Tcp);
        EXPECT_EQ(MessageValue.dst.Host, "example.com");
        EXPECT_EQ(MessageValue.dst.Port, 443u);
        EXPECT_EQ(Connection->Parsed().dst.Host, "example.com");
        std::array<std::byte, 1024> Buffer{};
        const auto ReadResult = co_await Connection->ReadSome(Buffer);
        EXPECT_FALSE(ReadResult.Failure.Failed());
        const auto BytesRead = ReadResult.Bytes;
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), BytesRead), Request.Payload);
        const std::span<const std::byte> EchoSpan(Buffer.data(), BytesRead);
        const auto WriteResult = co_await Connection->WriteExact(EchoSpan);
        EXPECT_FALSE(WriteResult.Failure.Failed());
        Connection->Close();
    }

    struct EchoClientRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
        std::string Payload;
    };

    auto RunEchoClient(EchoClientRequest Request) -> Net::awaitable<void>
    {
        const auto ServerDone = SpawnServer(Request.Server->Executor(),
            RunEchoServer(EchoServerRequest{Request.Server, Request.Payload}));
        auto [HandshakeError, Connection] = co_await Hysteria2::Connect(
            Request.Client, ClientConfig{"pw123456"}, MakeAddress(AddressType::Domain, "example.com", 443));
        EXPECT_EQ(HandshakeError, Error::None);
        if (!Connection)
        {
            Request.Server->Close();
            EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
            co_return;
        }
        const auto Payload = std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(Request.Payload.data()), Request.Payload.size());
        const auto WriteResult = co_await Connection->WriteExact(Payload);
        EXPECT_FALSE(WriteResult.Failure.Failed());
        std::array<std::byte, 1024> Buffer{};
        const auto ReadResult = co_await Connection->ReadSome(Buffer);
        EXPECT_FALSE(ReadResult.Failure.Failed());
        const auto BytesRead = ReadResult.Bytes;
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), BytesRead), Request.Payload);
        Connection->Close();
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
    }

    struct Ipv6ServerRequest final
    {
        std::shared_ptr<MemoryStream> ServerStream;
    };

    auto RunIpv6Server(Ipv6ServerRequest Request) -> Net::awaitable<void>
    {
        auto [ErrorValue, MessageValue, Connection] = co_await Hysteria2::Accept(
            Request.ServerStream, ServerConfig{"pw"});
        if (ErrorValue != Error::None || !Connection)
        {
            EXPECT_TRUE(false) << "Accept Failed";
            co_return;
        }
        EXPECT_EQ(MessageValue.dst.Type, AddressType::Ipv6);
        EXPECT_EQ(MessageValue.dst.Port, 8080u);
        Connection->Close();
    }

    struct Ipv6ClientRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
    };

    auto RunIpv6Client(Ipv6ClientRequest Request) -> Net::awaitable<void>
    {
        const auto ServerDone = SpawnServer(Request.Server->Executor(),
            RunIpv6Server(Ipv6ServerRequest{Request.Server}));
        const std::string Ipv6(16, '\x11');
        auto [HandshakeError, Connection] = co_await Hysteria2::Connect(
            Request.Client, ClientConfig{"pw"}, MakeAddress(AddressType::Ipv6, Ipv6, 8080));
        EXPECT_EQ(HandshakeError, Error::None);
        if (Connection) Connection->Close();
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
    }

    struct BadAuthServerRequest final
    {
        std::shared_ptr<MemoryStream> ServerStream;
    };

    auto RunBadAuthServer(BadAuthServerRequest Request) -> Net::awaitable<void>
    {
        auto [ErrorValue, MessageValue, Connection] = co_await Hysteria2::Accept(
            Request.ServerStream, ServerConfig{"Expect-pw"});
        EXPECT_EQ(ErrorValue, Error::BadAuth);
        EXPECT_FALSE(Connection);
        (void)MessageValue;
    }

    struct BadAuthClientRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
    };

    auto RunBadAuthClient(BadAuthClientRequest Request) -> Net::awaitable<void>
    {
        const auto ServerDone = SpawnServer(Request.Server->Executor(),
            RunBadAuthServer(BadAuthServerRequest{Request.Server}));
        auto [HandshakeError, Connection] = co_await Hysteria2::Connect(
            Request.Client, ClientConfig{"wrong-pw"},
            MakeAddress(AddressType::Domain, "example.com", 443));
        EXPECT_EQ(HandshakeError, Error::None);
        if (Connection) Connection->Close();
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
    }

    struct BadMagicServerRequest final
    {
        std::shared_ptr<MemoryStream> ServerStream;
    };

    auto RunBadMagicServer(BadMagicServerRequest Request) -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Conn>(Request.ServerStream, "pw");
        auto [ErrorValue, MessageValue] = co_await Connection->ReadHandshake();
        EXPECT_EQ(ErrorValue, Error::BadMagic);
        (void)MessageValue;
    }

    struct BadMagicClientRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
    };

    auto RunBadMagicClient(BadMagicClientRequest Request) -> Net::awaitable<void>
    {
        const auto ServerDone = SpawnServer(Request.Server->Executor(),
            RunBadMagicServer(BadMagicServerRequest{Request.Server}));
        const std::array<std::uint8_t, 2> Wire{0x02, 0x00};
        const auto WriteResult = co_await Request.Client->WriteExact(
            AsBytes(std::span<const std::uint8_t>(Wire)));
        EXPECT_FALSE(WriteResult.Failure.Failed());
        Request.Client->Close();
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
    }

    struct TruncatedServerRequest final
    {
        std::shared_ptr<MemoryStream> ServerStream;
    };

    auto RunTruncatedServer(TruncatedServerRequest Request) -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Conn>(Request.ServerStream, "pw");
        auto [ErrorValue, MessageValue] = co_await Connection->ReadHandshake();
        EXPECT_EQ(ErrorValue, Error::UnexpectedEof);
        (void)MessageValue;
    }

    struct TruncatedClientRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
    };

    auto RunTruncatedClient(TruncatedClientRequest Request) -> Net::awaitable<void>
    {
        const auto ServerDone = SpawnServer(Request.Server->Executor(),
            RunTruncatedServer(TruncatedServerRequest{Request.Server}));
        const auto Auth = Hysteria2::MakeAuthRequest("pw");
        const auto AuthSpan = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Auth.data()), Auth.size());
        const auto AuthWrite = co_await Request.Client->WriteExact(AsBytes(AuthSpan));
        EXPECT_FALSE(AuthWrite.Failure.Failed());
        const std::array<std::uint8_t, 1> Kind{0x01};
        const auto KindWrite = co_await Request.Client->WriteExact(
            AsBytes(std::span<const std::uint8_t>(Kind)));
        EXPECT_FALSE(KindWrite.Failure.Failed());
        Request.Client->Close();
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
    }

    struct NotOpenRequest final
    {
        std::shared_ptr<Conn> Connection;
        std::shared_ptr<MemoryStream> Peer;
    };

    auto RunNotOpen(NotOpenRequest Request) -> Net::awaitable<void>
    {
        std::array<std::byte, 64> Buffer{};
        const auto ReadResult = co_await Request.Connection->ReadSome(Buffer);
        EXPECT_EQ(ReadResult.Bytes, 0U);
        EXPECT_TRUE(ReadResult.Failure.Failed());
        EXPECT_EQ(ReadResult.Failure.Native.value(), static_cast<int>(Error::NotOpen));
        const auto WriteResult = co_await Request.Connection->WriteExact(
            std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_TRUE(WriteResult.Failure.Failed());
        EXPECT_EQ(WriteResult.Failure.Native.value(), static_cast<int>(Error::NotOpen));
        const auto Payload = AsU8Span(std::string_view{"x"});
        EXPECT_EQ(co_await Request.Connection->AsyncSendDatagram(
            MakeAddress(AddressType::Ipv4, "1.1.1.1", 80), Payload), Error::NotOpen);
        Address Source;
        std::vector<std::uint8_t> Output;
        EXPECT_EQ(co_await Request.Connection->AsyncReceiveDatagram(Source, Output), Error::NotOpen);
        Request.Connection->Close();
        Request.Connection->Cancel();
        EXPECT_TRUE(Request.Connection->Executor());
        EXPECT_NE(Request.Connection->NextLayer(), nullptr);
        const Conn *ConstConnection = Request.Connection.get();
        EXPECT_NE(ConstConnection->NextLayer(), nullptr);
        EXPECT_NE(Request.Connection->lowest_layer<MemoryStream>(), nullptr);
        auto Released = Request.Connection->Release();
        EXPECT_TRUE(Released);
        EXPECT_EQ(Request.Connection->NextLayer(), nullptr);
        Request.Peer->Close();
    }

    struct ClosedPeerRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Peer;
    };

    auto RunClosedPeer(ClosedPeerRequest Request) -> Net::awaitable<void>
    {
        Request.Peer->Close();
        auto [ErrorValue, Connection] = co_await Hysteria2::Connect(
            Request.Client, ClientConfig{"pw"}, MakeAddress(AddressType::Ipv4, "1.1.1.1", 80));
        EXPECT_EQ(ErrorValue, Error::IoError);
        EXPECT_FALSE(Connection);
    }

    struct ReceiveTcpServerRequest final
    {
        std::shared_ptr<MemoryStream> ServerStream;
    };

    auto RunReceiveTcpServer(ReceiveTcpServerRequest Request) -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Conn>(Request.ServerStream, "pw");
        auto [ErrorValue, MessageValue] = co_await Connection->ReadHandshake();
        EXPECT_EQ(ErrorValue, Error::None);
        if (ErrorValue != Error::None) co_return;
        EXPECT_EQ(MessageValue.Type, Message::Kind::Tcp);
        Address Source;
        std::vector<std::uint8_t> Output;
        EXPECT_EQ(co_await Connection->AsyncReceiveDatagram(Source, Output), Error::Unsupported);
    }

    struct ReceiveTcpClientRequest final
    {
        std::shared_ptr<MemoryStream> Client;
        std::shared_ptr<MemoryStream> Server;
    };

    auto RunReceiveTcpClient(ReceiveTcpClientRequest Request) -> Net::awaitable<void>
    {
        const auto ServerDone = SpawnServer(Request.Server->Executor(),
            RunReceiveTcpServer(ReceiveTcpServerRequest{Request.Server}));
        const auto Auth = Hysteria2::MakeAuthRequest("pw");
        const auto Target = MakeAddress(AddressType::Ipv4, "1.2.3.4", 80);
        const std::span<const std::uint8_t> EmptyPayload;
        const auto TcpFrame = Hysteria2::BuildTcp(Target, EmptyPayload);
        const auto AuthWrite = co_await Request.Client->WriteExact(
            AsBytes(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Auth.data()), Auth.size())));
        const auto FrameWrite = co_await Request.Client->WriteExact(
            AsBytes(std::span<const std::uint8_t>(TcpFrame)));
        const auto ExtraFrameWrite = co_await Request.Client->WriteExact(
            AsBytes(std::span<const std::uint8_t>(TcpFrame)));
        EXPECT_FALSE(AuthWrite.Failure.Failed());
        EXPECT_FALSE(FrameWrite.Failure.Failed());
        EXPECT_FALSE(ExtraFrameWrite.Failure.Failed());
        Request.Client->Close();
        EXPECT_TRUE(co_await ServerDone->async_receive(Net::use_awaitable));
    }
}

    TEST(Hysteria2ConnSession, StreamBackedDatagramIsRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto Datagram = std::make_shared<Dgram>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)));
        RunCoroutine(IoContext, RunStreamReject(StreamRejectRequest{
            Datagram, Peer}));
}
    TEST(Hysteria2ConnSession, IndependentDatagramFactoryUsesUdpTransport)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunIndependentPacketFactory(IndependentPacketFactoryRequest{
            IoContext.get_executor(), ClientConfig{"pw"}, ServerConfig{"pw"}}));
    }
    TEST(Hysteria2DgramProvider, MemoryProviderRoundtrip)
    {
        Net::io_context IoContext;
        auto [ClientProvider, ServerProvider] =
            MemoryDatagramProvider::MakePair(IoContext.get_executor());
        auto State = std::make_shared<ProviderRoundtripState>();
        State->ClientProvider = ClientProvider;
        State->ServerProvider = ServerProvider;
        State->Target = MakeAddress(AddressType::Domain, "example.com", 443);
        RunCoroutine(IoContext, RunProviderRoundtripFactory(State));

        EXPECT_EQ(State->ReceivedTarget.Host, "example.com");
        EXPECT_EQ(State->ReceivedTarget.Port, 443u);
        EXPECT_EQ(std::string(State->ReceivedPayload.begin(), State->ReceivedPayload.end()),
                  "hysteria2-provider");
    }

    /** @brief 标准 Hysteria2 UDPMessage 分片往返场景的拥有型状态。 */
    struct ReferenceUdpRoundtripState final
    {
        std::shared_ptr<Dgram> Client;
        std::shared_ptr<Dgram> Server;
        Address Target;
        Address ReceivedTarget;
        Address EchoTarget;
        std::vector<std::uint8_t> Payload;
        std::vector<std::uint8_t> ReceivedPayload;
        std::vector<std::uint8_t> EchoPayload;
    };

    auto RunReferenceUdpRoundtrip(
        std::shared_ptr<ReferenceUdpRoundtripState> State) -> Net::awaitable<void>
    {
        const auto Send = co_await State->Client->AsyncSendTo(State->Target, State->Payload);
        EXPECT_EQ(Send, Error::None);
        if (Send != Error::None)
        {
            State->Client->Close();
            State->Server->Close();
            co_return;
        }
        const auto Receive = co_await State->Server->AsyncReceiveFrom(
            State->ReceivedTarget, State->ReceivedPayload);
        EXPECT_EQ(Receive, Error::None);
        if (Receive != Error::None)
        {
            State->Client->Close();
            State->Server->Close();
            co_return;
        }
        EXPECT_EQ(State->ReceivedTarget.Host, State->Target.Host);
        EXPECT_EQ(State->ReceivedTarget.Port, State->Target.Port);
        EXPECT_EQ(State->ReceivedPayload, State->Payload);
        const auto Reply = co_await State->Server->AsyncSendTo(
            State->ReceivedTarget, State->ReceivedPayload);
        EXPECT_EQ(Reply, Error::None);
        if (Reply != Error::None)
        {
            State->Client->Close();
            State->Server->Close();
            co_return;
        }
        const auto Echo = co_await State->Client->AsyncReceiveFrom(
            State->EchoTarget, State->EchoPayload);
        EXPECT_EQ(Echo, Error::None);
        EXPECT_EQ(State->EchoTarget.Host, State->Target.Host);
        EXPECT_EQ(State->EchoTarget.Port, State->Target.Port);
        EXPECT_EQ(State->EchoPayload, State->Payload);
        State->Client->Close();
        State->Server->Close();
    }

    TEST(Hysteria2DgramProvider, QuicProviderUsesReferenceUdpWire)
    {
        Net::io_context IoContext;
        auto [ClientProvider, ServerProvider] =
            MemoryDatagramProvider::MakePair(IoContext.get_executor());
        auto Client = std::make_shared<Dgram>(
            std::make_shared<DatagramAdapter>(ClientProvider), true);
        auto Server = std::make_shared<Dgram>(
            std::make_shared<DatagramAdapter>(ServerProvider), true);
        auto State = std::make_shared<ReferenceUdpRoundtripState>();
        State->Client = Client;
        State->Server = Server;
        State->Target = MakeAddress(AddressType::Domain, "example.com", 443);
        State->Payload.resize(4096U);
        for (std::size_t Index = 0; Index < State->Payload.size(); ++Index)
        {
            State->Payload[Index] = static_cast<std::uint8_t>((Index * 31U + 7U) & 0xFFU);
        }
        RunCoroutine(IoContext, RunReferenceUdpRoundtrip(State));

        ASSERT_EQ(ClientProvider->Sent.size(), 4U);
        ASSERT_EQ(ServerProvider->Sent.size(), 4U);
        for (const auto *Frames : {&ClientProvider->Sent, &ServerProvider->Sent})
        {
            for (std::size_t Index = 0; Index < Frames->size(); ++Index)
            {
                const auto &Wire = (*Frames)[Index];
                ASSERT_LE(Wire.size(), 1200U);
                ASSERT_GE(Wire.size(), 8U);
                EXPECT_EQ(Wire[6], std::byte{static_cast<std::uint8_t>(Index)});
                EXPECT_EQ(Wire[7], std::byte{4});
            }
        }
    }

    TEST(Hysteria2DgramProvider, ShortWriteAndCloseAreErrors)
    {
        Net::io_context IoContext;
        auto [ClientProvider, ServerProvider] =
            MemoryDatagramProvider::MakePair(IoContext.get_executor());
        const auto Target = MakeAddress(
            AddressType::Ipv4,
            "127.0.0.1",
            53);
        RunCoroutine(IoContext, RunProviderShortWriteFactory(
            ProviderShortWriteFactoryRequest{ClientProvider, ServerProvider, Target}));
    }

    TEST(Hysteria2ConnSession, ClientServerEchoRoundtrip)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        const std::string Payload = "hysteria2 echo payload";
        RunCoroutine(IoContext, RunEchoClient(EchoClientRequest{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory)), Payload}));
    }

    TEST(Hysteria2ConnSession, Ipv6TargetHandshake)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunIpv6Client(Ipv6ClientRequest{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory))}));
    }

    TEST(Hysteria2ConnSession, StreamBackedUdpCommandIsRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(ServerMemory));
        auto Connection = std::make_shared<Conn>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)), "pw");
        RunCoroutine(IoContext, RunConnStreamUdpReject(
            ConnStreamRejectRequest{Connection, Peer}));
    }

    TEST(Hysteria2ConnSession, BadAuthRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunBadAuthClient(BadAuthClientRequest{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory))}));
    }

    TEST(Hysteria2ConnSession, BadMagicRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext, RunBadMagicClient(BadMagicClientRequest{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory))}));
    }

    TEST(Hysteria2ConnSession, TruncatedTargetFrame)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext, RunTruncatedClient(TruncatedClientRequest{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory))}));
    }

    TEST(Hysteria2ConnSession, NotOpenRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunNotOpen(NotOpenRequest{
            std::make_shared<Conn>(
                std::make_shared<MemoryStream>(std::move(ClientMemory)), "pw"),
            std::make_shared<MemoryStream>(std::move(ServerMemory))}));
    }

    TEST(Hysteria2ConnSession, ConnectToClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext, RunClosedPeer(ClosedPeerRequest{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory))}));
    }

    TEST(Hysteria2ConnSession, ReceiveTcpFrameAsDatagram)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunReceiveTcpClient(ReceiveTcpClientRequest{
            std::make_shared<MemoryStream>(std::move(ClientMemory)),
            std::make_shared<MemoryStream>(std::move(ServerMemory))}));
    }

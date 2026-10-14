#include "Hysteria2DgramSessionSupport.hpp"

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
        EXPECT_EQ(co_await Request.Connection->AsyncReceiveFrom(Source, Payload), Error::NotSupported);
        EXPECT_EQ(co_await Request.Connection->AsyncSendTo(
            MakeAddress(AddressType::Ipv4, "127.0.0.1", 53),
            AsU8Span(std::string_view{"payload"})), Error::NotSupported);
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
        Request.Server->Close();
        EXPECT_EQ(co_await Request.Client->AsyncSendTo(
            Request.Target, AsU8Span(std::string_view{"closed"})), Error::IoError);
        Request.Client->Close();
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
        std::error_code ErrorCode;
        const auto BytesRead = co_await Connection->async_read_some(Buffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), BytesRead), Request.Payload);
        const std::span<const std::byte> EchoSpan(Buffer.data(), BytesRead);
        (void)co_await Connection->async_write_some(EchoSpan, ErrorCode);
        EXPECT_FALSE(ErrorCode);
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
        std::error_code ErrorCode;
        (void)co_await Connection->async_write_some(Payload, ErrorCode);
        EXPECT_FALSE(ErrorCode);
        std::array<std::byte, 1024> Buffer{};
        const auto BytesRead = co_await Connection->async_read_some(Buffer, ErrorCode);
        EXPECT_FALSE(ErrorCode);
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
        std::error_code ErrorCode;
        (void)co_await Request.Client->async_write_some(AsBytes(std::span<const std::uint8_t>(Wire)), ErrorCode);
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
        std::error_code ErrorCode;
        const auto AuthSpan = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t *>(Auth.data()), Auth.size());
        (void)co_await Request.Client->async_write_some(AsBytes(AuthSpan), ErrorCode);
        const std::array<std::uint8_t, 1> Kind{0x01};
        (void)co_await Request.Client->async_write_some(AsBytes(std::span<const std::uint8_t>(Kind)), ErrorCode);
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
        std::error_code ErrorCode;
        const auto BytesRead = co_await Request.Connection->async_read_some(Buffer, ErrorCode);
        EXPECT_EQ(BytesRead, 0u);
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Error::NotOpen));
        ErrorCode.clear();
        (void)co_await Request.Connection->async_write_some(
            std::span<const std::byte>(Buffer.data(), 4), ErrorCode);
        EXPECT_TRUE(ErrorCode);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Error::NotOpen));
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
        EXPECT_EQ(co_await Connection->AsyncReceiveDatagram(Source, Output), Error::NotSupported);
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
        std::error_code ErrorCode;
        (void)co_await Request.Client->async_write_some(
            AsBytes(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t *>(Auth.data()), Auth.size())), ErrorCode);
        (void)co_await Request.Client->async_write_some(
            AsBytes(std::span<const std::uint8_t>(TcpFrame)), ErrorCode);
        (void)co_await Request.Client->async_write_some(
            AsBytes(std::span<const std::uint8_t>(TcpFrame)), ErrorCode);
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
        const ClientConfig ClientConfiguration{"pw"};
        const ServerConfig ServerConfiguration{"pw"};
        auto ClientDatagram = Hysteria2::ConnectPacket(
            IoContext.get_executor(),
            "127.0.0.1:1",
            ClientConfiguration);
        auto ServerDatagram = Hysteria2::AcceptPacket(
            IoContext.get_executor(),
            0,
            ServerConfiguration);
        ASSERT_NE(ClientDatagram, nullptr);
        ASSERT_NE(ServerDatagram, nullptr);
        ClientDatagram->Close();
        ServerDatagram->Close();
    }
    TEST(Hysteria2DgramProvider, MemoryProviderRoundtrip)
    {
        Net::io_context IoContext;
        auto [ClientProvider, ServerProvider] =
            MemoryDatagramProvider::MakePair(IoContext.get_executor());
        auto Client = Hysteria2::ConnectPacket(
            ClientProvider,
            ClientConfig{});
        auto Server = Hysteria2::AcceptPacket(
            ServerProvider,
            ServerConfig{});
        ASSERT_NE(Client, nullptr);
        ASSERT_NE(Server, nullptr);

        const auto Target = MakeAddress(
            AddressType::Domain,
            "example.com",
            443);
        Address ReceivedTarget;
        std::vector<std::uint8_t> ReceivedPayload;
        RunCoroutine(IoContext, RunProviderRoundtrip(ProviderRoundtripRequest{
            ClientProvider, ServerProvider, Client, Server, Target,
            "hysteria2-provider", &ReceivedTarget, &ReceivedPayload}));

        EXPECT_EQ(ReceivedTarget.Host, "example.com");
        EXPECT_EQ(ReceivedTarget.Port, 443u);
        EXPECT_EQ(std::string(ReceivedPayload.begin(), ReceivedPayload.end()),
                  "hysteria2-provider");
    }

    TEST(Hysteria2DgramProvider, QuicProviderUsesReferenceUdpWire)
    {
        Net::io_context IoContext;
        auto [ClientProvider, ServerProvider] =
            MemoryDatagramProvider::MakePair(IoContext.get_executor());
        auto Transport = std::make_shared<DatagramAdapter>(ClientProvider);
        auto Client = std::make_shared<Dgram>(std::move(Transport), true);
        const auto Target = MakeAddress(
            AddressType::Domain,
            "example.com",
            443);
        const auto Payload = AsU8Span(
            std::string_view{"udp-reference-wire"});

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                EXPECT_EQ(
                    co_await Client->AsyncSendTo(Target, Payload),
                    Error::None);
                Client->Close();
                ServerProvider->Close();
            });

        ASSERT_EQ(ClientProvider->Sent.size(), 1U);
        const auto &Wire = ClientProvider->Sent.front();
        ASSERT_GE(Wire.size(), 8U);
        EXPECT_EQ(Wire[0], std::byte{0});
        EXPECT_EQ(Wire[1], std::byte{0});
        EXPECT_EQ(Wire[2], std::byte{0});
        EXPECT_EQ(Wire[3], std::byte{0});
        EXPECT_EQ(Wire[4], std::byte{0});
        EXPECT_EQ(Wire[5], std::byte{0});
        EXPECT_EQ(Wire[6], std::byte{0});
        EXPECT_EQ(Wire[7], std::byte{1});
    }

    TEST(Hysteria2DgramProvider, ShortWriteAndCloseAreErrors)
    {
        Net::io_context IoContext;
        auto [ClientProvider, ServerProvider] =
            MemoryDatagramProvider::MakePair(IoContext.get_executor());
        auto Client = Hysteria2::ConnectPacket(
            ClientProvider,
            ClientConfig{});
        auto Server = Hysteria2::AcceptPacket(
            ServerProvider,
            ServerConfig{});
        ASSERT_NE(Client, nullptr);
        ASSERT_NE(Server, nullptr);
        const auto Target = MakeAddress(
            AddressType::Ipv4,
            "127.0.0.1",
            53);

        RunCoroutine(IoContext, RunProviderShortWrite(ProviderShortWriteRequest{
            ClientProvider, Client, Server, Target}));
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

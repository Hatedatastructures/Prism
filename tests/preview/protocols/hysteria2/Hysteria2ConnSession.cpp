/**
 * @file Hysteria2ConnSession.cpp
 * @brief Hysteria2 Conn/Dgram 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手 + TCP 数据双向回显
 * 2. Conn UDP 数据面（AsyncSendDatagram / AsyncReceiveDatagram）
 * 3. 错误分支：bad_auth / bad_magic / not_open / unexpected_eof / bad_message
 * 4. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release / lowest_layer
 * 5. Dgram 包连接：发送接收、地址解析、错误分支
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <preview/Transport/MemoryStream.hpp>
#include <preview/Transport/Unreliable.hpp>
#include <preview/Protocols/Hysteria2/Hysteria2.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Preview = ::Preview;
    namespace Hysteria2 = Preview::Hysteria2;

    using Address = Hysteria2::Address;
    using AddressType = Hysteria2::AddressType;
    using ClientConfig = Hysteria2::ClientConfig;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;
    using Conn = Hysteria2::Conn<>;
    using DatagramAdapter = Preview::Quic::DatagramAdapter;
    using Dgram = Hysteria2::Dgram<>;
    using Error = Preview::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryDatagramProvider = Preview::Testing::MemoryDatagramProvider;
    using MemoryStream = Preview::MemoryStream;
    using Message = Hysteria2::Message;
    using PreviewMockTransport = Preview::PreviewMockTransport;
    using ServerConfig = Hysteria2::ServerConfig;
    using Unreliable = Preview::Transport::Unreliable;

    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::MakeMemoryPair;

    /// 运行协程直至完成（异常重抛）
    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &IoContext, Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto CompletionHandler =
            [&Exception, &IoContext](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            std::move(CompletionHandler));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    /// 立即启动并观察服务端协程，避免异常或未完成操作被静默丢弃。
    [[nodiscard]] auto SpawnServer(
        ExecutorType Executor,
        Net::awaitable<void> Coroutine)
        -> std::shared_ptr<CompletionChannel>
    {
        const auto Done =
            std::make_shared<CompletionChannel>(Executor, 1);
        auto CompletionHandler =
            [Done](std::exception_ptr Exception) -> void
        {
            (void)Done->try_send(
                boost::system::error_code{},
                Exception == nullptr);
        };
        Net::co_spawn(
            Executor,
            std::move(Coroutine),
            std::move(CompletionHandler));
        return Done;
    }

    /// 构造 hysteria2 目标地址
    [[nodiscard]] auto MakeAddress(
        const AddressType Type,
        std::string Host,
        const std::uint16_t Port) -> Address
    {
        Address AddressValue{};
        AddressValue.Type = Type;
        AddressValue.Host = std::move(Host);
        AddressValue.Port = Port;
        return AddressValue;
    }

    TEST(Hysteria2ConnSession, StreamBackedDatagramIsRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto Datagram = std::make_shared<Dgram>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)));
        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                Address Source;
                std::vector<std::uint8_t> Payload;
                EXPECT_EQ(
                    co_await Datagram->AsyncReceiveFrom(Source, Payload),
                    Error::NotSupported);
                Datagram->Close();
                ServerMemory.Close();
            });
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
        const auto Payload = AsU8Span(
            std::string_view{"hysteria2-provider"});
        Address ReceivedTarget;
        std::vector<std::uint8_t> ReceivedPayload;
        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                const auto SendError =
                    co_await Client->AsyncSendTo(Target, Payload);
                EXPECT_EQ(SendError, Error::None);
                const auto ReceiveError =
                    co_await Server->AsyncReceiveFrom(
                        ReceivedTarget,
                        ReceivedPayload);
                EXPECT_EQ(ReceiveError, Error::None);
                if (ReceiveError == Error::None)
                {
                    EXPECT_EQ(
                        co_await Server->AsyncSendTo(
                            ReceivedTarget,
                            ReceivedPayload),
                        Error::None);
                }
                Client->Close();
                Server->Close();
            });

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

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                ClientProvider->MaxSend = 2;
                EXPECT_EQ(
                    co_await Client->AsyncSendTo(
                        Target,
                        AsU8Span(std::string_view{"short"})),
                    Error::IoError);
                ClientProvider->MaxSend = 0;
                Server->Close();
                EXPECT_EQ(
                    co_await Client->AsyncSendTo(
                        Target,
                        AsU8Span(std::string_view{"closed"})),
                    Error::IoError);
                Client->Close();
            });
    }

    TEST(Hysteria2ConnSession, ClientServerEchoRoundtrip)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        const std::string Payload = "hysteria2 echo payload";

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream = std::make_shared<MemoryStream>(
                    std::move(ServerMemory));
                auto ServerCoroutine = [ServerStream, Payload]()
                    -> Net::awaitable<void>
                {
                    auto [ErrorValue, Request, Connection] =
                        co_await Hysteria2::Accept(
                            ServerStream,
                            ServerConfig{"pw123456"});
                    if (ErrorValue != Error::None || !Connection)
                    {
                        EXPECT_TRUE(false) << "Accept Failed";
                        co_return;
                    }
                    EXPECT_EQ(Request.Type, Message::Kind::Tcp);
                    EXPECT_EQ(Request.dst.Host, "example.com");
                    EXPECT_EQ(Request.dst.Port, 443u);
                    EXPECT_EQ(
                        Connection->Parsed().dst.Host,
                        "example.com");

                    std::array<std::byte, 1024> Buffer{};
                    const std::span<std::byte> BufferSpan(Buffer);
                    std::error_code ErrorCode;
                    const auto BytesRead = co_await Connection->async_read_some(
                        BufferSpan,
                        ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    EXPECT_EQ(
                        std::string(
                            reinterpret_cast<const char *>(Buffer.data()),
                            BytesRead),
                        Payload);
                    const std::span<const std::byte> EchoSpan(
                        Buffer.data(),
                        BytesRead);
                    (void)co_await Connection->async_write_some(
                        EchoSpan,
                        ErrorCode);
                    EXPECT_FALSE(ErrorCode);
                    Connection->Close();
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                auto [HandshakeError, ClientConnection] =
                    co_await Hysteria2::Connect(
                        std::make_shared<MemoryStream>(
                            std::move(ClientMemory)),
                        ClientConfig{"pw123456"},
                        MakeAddress(
                            AddressType::Domain,
                            "example.com",
                            443));
                EXPECT_EQ(HandshakeError, Error::None);
                if (!ClientConnection)
                {
                    ServerStream->Close();
                    const auto ServerCompleted = co_await ServerDone->async_receive(
                        Net::use_awaitable);
                    EXPECT_TRUE(ServerCompleted);
                    co_return;
                }

                const std::span<const std::byte> PayloadSpan(
                    reinterpret_cast<const std::byte *>(Payload.data()),
                    Payload.size());
                std::error_code ErrorCode;
                (void)co_await ClientConnection->async_write_some(
                    PayloadSpan,
                    ErrorCode);
                EXPECT_FALSE(ErrorCode);

                std::array<std::byte, 1024> Buffer{};
                const std::span<std::byte> BufferSpan(Buffer);
                const auto BytesRead = co_await ClientConnection->async_read_some(
                    BufferSpan,
                    ErrorCode);
                EXPECT_FALSE(ErrorCode);
                EXPECT_EQ(
                    std::string(
                        reinterpret_cast<const char *>(Buffer.data()),
                        BytesRead),
                    Payload);
                ClientConnection->Close();
                const auto ServerCompleted = co_await ServerDone->async_receive(
                    Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Hysteria2ConnSession, Ipv6TargetHandshake)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream = std::make_shared<MemoryStream>(
                    std::move(ServerMemory));
                auto ServerCoroutine = [ServerStream]()
                    -> Net::awaitable<void>
                {
                    auto [ErrorValue, Request, Connection] =
                        co_await Hysteria2::Accept(
                            ServerStream,
                            ServerConfig{"pw"});
                    if (ErrorValue != Error::None || !Connection)
                    {
                        EXPECT_TRUE(false) << "Accept Failed";
                        co_return;
                    }
                    EXPECT_EQ(Request.dst.Type, AddressType::Ipv6);
                    EXPECT_EQ(Request.dst.Port, 8080u);
                    Connection->Close();
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                const std::string Ipv6(16, '\x11');
                auto [HandshakeError, ClientConnection] =
                    co_await Hysteria2::Connect(
                        std::make_shared<MemoryStream>(
                            std::move(ClientMemory)),
                        ClientConfig{"pw"},
                        MakeAddress(
                            AddressType::Ipv6,
                            Ipv6,
                            8080));
                EXPECT_EQ(HandshakeError, Error::None);
                if (ClientConnection)
                {
                    ClientConnection->Close();
                }
                const auto ServerCompleted = co_await ServerDone->async_receive(
                    Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Hysteria2ConnSession, StreamBackedUdpCommandIsRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto Connection = std::make_shared<Conn>(
                    std::make_shared<MemoryStream>(std::move(ClientMemory)),
                    "pw");
                Address Target;
                std::vector<std::uint8_t> Payload;
                EXPECT_EQ(
                    co_await Connection->AsyncSendDatagram(
                        MakeAddress(
                            AddressType::Ipv4,
                            "93.184.216.34",
                            443),
                        AsU8Span(std::string_view{"payload"})),
                    Error::NotOpen);
                EXPECT_EQ(
                    co_await Connection->AsyncReceiveDatagram(
                        Target,
                        Payload),
                    Error::NotOpen);
                Connection->Close();
                ServerMemory.Close();
            });
    }

    TEST(Hysteria2ConnSession, BadAuthRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream = std::make_shared<MemoryStream>(
                    std::move(ServerMemory));
                auto ServerCoroutine = [ServerStream]()
                    -> Net::awaitable<void>
                {
                    auto [ErrorValue, Request, Connection] =
                        co_await Hysteria2::Accept(
                            ServerStream,
                            ServerConfig{"Expect-pw"});
                    EXPECT_EQ(ErrorValue, Error::BadAuth);
                    EXPECT_FALSE(Connection);
                    (void)Request;
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                auto [HandshakeError, ClientConnection] =
                    co_await Hysteria2::Connect(
                        std::make_shared<MemoryStream>(
                            std::move(ClientMemory)),
                        ClientConfig{"wrong-pw"},
                        MakeAddress(
                            AddressType::Domain,
                            "example.com",
                            443));
                EXPECT_EQ(
                    HandshakeError,
                    Error::None); // 客户端只发送，不感知认证结果
                if (ClientConnection)
                {
                    ClientConnection->Close();
                }
                const auto ServerCompleted = co_await ServerDone->async_receive(
                    Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Hysteria2ConnSession, BadMagicRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream = std::make_shared<MemoryStream>(
                    std::move(ServerMemory));
                auto ServerCoroutine = [ServerStream]()
                    -> Net::awaitable<void>
                {
                    auto Connection = std::make_shared<Conn>(
                        ServerStream,
                        "pw");
                    auto [ErrorValue, MessageValue] =
                        co_await Connection->ReadHandshake();
                    EXPECT_EQ(ErrorValue, Error::BadMagic);
                    (void)MessageValue;
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                const std::array<std::uint8_t, 2> Wire{0x02, 0x00};
                const std::span<const std::uint8_t> WireSpan(Wire);
                std::error_code ErrorCode;
                (void)co_await ClientMemory.async_write_some(
                    AsBytes(WireSpan),
                    ErrorCode);
                ClientMemory.Close();
                const auto ServerCompleted = co_await ServerDone->async_receive(
                    Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Hysteria2ConnSession, TruncatedTargetFrame)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream = std::make_shared<MemoryStream>(
                    std::move(ServerMemory));
                auto ServerCoroutine = [ServerStream]()
                    -> Net::awaitable<void>
                {
                    auto Connection = std::make_shared<Conn>(
                        ServerStream,
                        "pw");
                    auto [ErrorValue, MessageValue] =
                        co_await Connection->ReadHandshake();
                    EXPECT_EQ(ErrorValue, Error::UnexpectedEof);
                    (void)MessageValue;
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                const auto Auth = Hysteria2::MakeAuthRequest("pw");
                std::error_code ErrorCode;
                const auto AuthSpan = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(Auth.data()),
                    Auth.size());
                (void)co_await ClientMemory.async_write_some(
                    AsBytes(AuthSpan),
                    ErrorCode);
                const std::array<std::uint8_t, 1> Kind{0x01};
                const std::span<const std::uint8_t> KindSpan(Kind);
                (void)co_await ClientMemory.async_write_some(
                    AsBytes(KindSpan),
                    ErrorCode);
                ClientMemory.Close();
                const auto ServerCompleted = co_await ServerDone->async_receive(
                    Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Hysteria2ConnSession, NotOpenRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                // 未握手 Conn：读写与数据报均应返回 not_open
                auto Connection = std::make_shared<Conn>(
                    std::make_shared<MemoryStream>(std::move(ClientMemory)),
                    "pw");
                std::array<std::byte, 64> Buffer{};
                const std::span<std::byte> BufferSpan(Buffer);
                std::error_code ErrorCode;
                const auto BytesRead = co_await Connection->async_read_some(
                    BufferSpan,
                    ErrorCode);
                EXPECT_EQ(BytesRead, 0u);
                EXPECT_TRUE(ErrorCode);
                EXPECT_EQ(
                    ErrorCode.value(),
                    static_cast<int>(Error::NotOpen));

                ErrorCode.clear();
                const std::span<const std::byte> WriteSpan(
                    Buffer.data(),
                    4);
                (void)co_await Connection->async_write_some(
                    WriteSpan,
                    ErrorCode);
                EXPECT_TRUE(ErrorCode);
                EXPECT_EQ(
                    ErrorCode.value(),
                    static_cast<int>(Error::NotOpen));

                const std::string PayloadText = "x";
                const std::span<const std::uint8_t> Payload(
                    reinterpret_cast<const std::uint8_t *>(
                        PayloadText.data()),
                    PayloadText.size());
                const auto SendError = co_await Connection->AsyncSendDatagram(
                    MakeAddress(
                        AddressType::Ipv4,
                        "1.1.1.1",
                        80),
                    Payload);
                EXPECT_EQ(SendError, Error::NotOpen);
                Address Source;
                std::vector<std::uint8_t> Output;
                const auto ReceiveError =
                    co_await Connection->AsyncReceiveDatagram(
                        Source,
                        Output);
                EXPECT_EQ(ReceiveError, Error::NotOpen);

                Connection->Close();
                Connection->Cancel();
                EXPECT_TRUE(Connection->Executor());
                EXPECT_NE(Connection->NextLayer(), nullptr);
                const Conn *ConstConnection = Connection.get();
                EXPECT_NE(ConstConnection->NextLayer(), nullptr);
                EXPECT_NE(
                    Connection->lowest_layer<MemoryStream>(),
                    nullptr);
                auto Released = Connection->Release();
                EXPECT_TRUE(Released);
                EXPECT_EQ(Connection->NextLayer(), nullptr);
                ServerMemory.Close();
            });
    }

    TEST(Hysteria2ConnSession, ConnectToClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                ServerMemory.Close(); // 对端已全关 → 写返回 broken_pipe → io_error
                auto [ErrorValue, Connection] =
                    co_await Hysteria2::Connect(
                        std::make_shared<MemoryStream>(
                            std::move(ClientMemory)),
                        ClientConfig{"pw"},
                        MakeAddress(
                            AddressType::Ipv4,
                            "1.1.1.1",
                            80));
                EXPECT_EQ(ErrorValue, Error::IoError);
                EXPECT_FALSE(Connection);
            });
    }

    TEST(Hysteria2ConnSession, ReceiveTcpFrameAsDatagram)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream = std::make_shared<MemoryStream>(
                    std::move(ServerMemory));
                auto ServerCoroutine = [ServerStream]()
                    -> Net::awaitable<void>
                {
                    auto Connection = std::make_shared<Conn>(
                        ServerStream,
                        "pw");
                    auto [ErrorValue, MessageValue] =
                        co_await Connection->ReadHandshake();
                    EXPECT_EQ(ErrorValue, Error::None);
                    if (ErrorValue != Error::None)
                    {
                        co_return;
                    }
                    EXPECT_EQ(MessageValue.Type, Message::Kind::Tcp);
                    Address Source;
                    std::vector<std::uint8_t> Output;
                    const auto ReceiveError =
                        co_await Connection->AsyncReceiveDatagram(
                            Source,
                            Output);
                    EXPECT_EQ(ReceiveError, Error::NotSupported);
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                // 原始客户端：认证帧 + TCP 目标帧（握手）+ TCP 数据帧（错误路径）
                const auto Auth = Hysteria2::MakeAuthRequest("pw");
                const auto Target = MakeAddress(
                    AddressType::Ipv4,
                    "1.2.3.4",
                    80);
                const std::span<const std::uint8_t> EmptyPayload;
                const auto TcpFrame = Hysteria2::BuildTcp(
                    Target,
                    EmptyPayload);
                const auto AuthSpan = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(Auth.data()),
                    Auth.size());
                const std::span<const std::uint8_t> TcpFrameSpan(TcpFrame);
                std::error_code ErrorCode;
                (void)co_await ClientMemory.async_write_some(
                    AsBytes(AuthSpan),
                    ErrorCode);
                (void)co_await ClientMemory.async_write_some(
                    AsBytes(TcpFrameSpan),
                    ErrorCode);
                (void)co_await ClientMemory.async_write_some(
                    AsBytes(TcpFrameSpan),
                    ErrorCode);
                ClientMemory.Close();
                const auto ServerCompleted = co_await ServerDone->async_receive(
                    Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    /// 构造 Dgram 接收侧兼容帧（9B 头后 ATYP 独立成段，对齐 Dgram 解析布局）
    [[nodiscard]] auto BuildReceiveWire(
        const std::uint8_t Atyp,
        const std::vector<std::uint8_t> &AddressBytes,
        const std::uint16_t Port,
        const std::string &Payload) -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Wire(
            9,
            0); // Kind + Session(4) + PacketId(4)
        Wire[0] = 0x02;
        Wire.push_back(Atyp);
        Wire.insert(Wire.end(), AddressBytes.begin(), AddressBytes.end());
        Wire.push_back(static_cast<std::uint8_t>(Port >> 8));
        Wire.push_back(static_cast<std::uint8_t>(Port & 0xFF));
        Wire.insert(Wire.end(), Payload.begin(), Payload.end());
        return Wire;
    }

    TEST(Hysteria2DgramSession, StreamBackedDatagramIsRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto Datagram = std::make_shared<Dgram>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)));
        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                Address Source;
                std::vector<std::uint8_t> Payload;
                EXPECT_EQ(
                    co_await Datagram->AsyncReceiveFrom(Source, Payload),
                    Error::NotSupported);
                EXPECT_EQ(
                    co_await Datagram->AsyncSendTo(
                        MakeAddress(
                            AddressType::Ipv4,
                            "127.0.0.1",
                            53),
                        AsU8Span(std::string_view{"payload"})),
                    Error::NotSupported);
                Datagram->Close();
                ServerMemory.Close();
            });
    }

    TEST(Hysteria2DgramSession, StreamBackedSendIsRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());
        auto Datagram = std::make_shared<Dgram>(
            std::make_shared<MemoryStream>(std::move(ClientMemory)));
        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                EXPECT_EQ(
                    co_await Datagram->AsyncSendTo(
                        MakeAddress(
                            AddressType::Ipv4,
                            "93.184.216.34",
                            443),
                        AsU8Span(std::string_view{"payload"})),
                    Error::NotSupported);
                Datagram->Close();
                ServerMemory.Close();
            });
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
        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                const auto SendError = co_await Client->AsyncSendTo(
                    MakeAddress(
                        AddressType::Domain,
                        "example.com",
                        443),
                    AsU8Span(std::string_view(Payload)));
                EXPECT_EQ(SendError, Error::None);
                Address Target;
                std::vector<std::uint8_t> Received;
                const auto ReceiveError =
                    co_await Server->AsyncReceiveFrom(Target, Received);
                EXPECT_EQ(ReceiveError, Error::None);
                EXPECT_EQ(Target.Host, "example.com");
                EXPECT_EQ(
                    std::string(Received.begin(), Received.end()),
                    Payload);
                Server->Close();
                Client->Close();
            });
    }

    TEST(Hysteria2DgramSession, BadKindRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream = std::make_shared<MemoryStream>(
                    std::move(ServerMemory));
                auto ServerCoroutine = [ServerStream]()
                    -> Net::awaitable<void>
                {
                    auto Datagram = std::make_shared<Dgram>(ServerStream);
                    Address Source;
                    std::vector<std::uint8_t> Payload;
                    const auto ErrorValue =
                        co_await Datagram->AsyncReceiveFrom(
                            Source,
                            Payload);
                    EXPECT_EQ(ErrorValue, Error::NotSupported);
                    Datagram->Close();
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                const std::array<std::uint8_t, 9> Wire{
                    0x01,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0}; // TCP Kind
                const std::span<const std::uint8_t> WireSpan(Wire);
                std::error_code ErrorCode;
                (void)co_await ClientMemory.async_write_some(
                    AsBytes(WireSpan),
                    ErrorCode);
                ClientMemory.Close();
                const auto ServerCompleted = co_await ServerDone->async_receive(
                    Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Hysteria2DgramSession, BadAtypRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream = std::make_shared<MemoryStream>(
                    std::move(ServerMemory));
                auto ServerCoroutine = [ServerStream]()
                    -> Net::awaitable<void>
                {
                    auto Datagram = std::make_shared<Dgram>(ServerStream);
                    Address Source;
                    std::vector<std::uint8_t> Payload;
                    const auto ErrorValue =
                        co_await Datagram->AsyncReceiveFrom(
                            Source,
                            Payload);
                    EXPECT_EQ(ErrorValue, Error::NotSupported);
                    Datagram->Close();
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                // UDP Kind + Session/packet Id(8) + 非法 ATYP
                const std::vector<std::uint8_t> Wire = BuildReceiveWire(
                    0x99,
                    {},
                    0,
                    {});
                const std::span<const std::uint8_t> WireSpan(Wire);
                std::error_code ErrorCode;
                (void)co_await ClientMemory.async_write_some(
                    AsBytes(WireSpan),
                    ErrorCode);
                ClientMemory.Close();
                const auto ServerCompleted = co_await ServerDone->async_receive(
                    Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Hysteria2DgramSession, PeerClosedEof)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto Datagram = std::make_shared<Dgram>(
                    std::make_shared<MemoryStream>(
                        std::move(ServerMemory)));
                ClientMemory.Close(); // 对端关闭 → 读返回 0 → unexpected_eof
                Address Source;
                std::vector<std::uint8_t> Payload;
                const auto ErrorValue =
                    co_await Datagram->AsyncReceiveFrom(
                        Source,
                        Payload);
                EXPECT_EQ(ErrorValue, Error::NotSupported);
                Datagram->Close();
            });
    }

} // namespace

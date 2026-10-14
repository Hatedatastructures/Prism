/**
 * @file Ss2022DgramSession.cpp
 * @brief SS2022 UDP 数据报会话测试（Dgram 成功路径）。
 * @details 覆盖客户端发送、服务端回显、Session ID/首包编号、伪造报文
 *          隔离和错误密码路径；每个测试都在同一协程内完成收发和收口。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Transport/Unreliable.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Shadowsocks = Preview::Shadowsocks2022;

    using Address = Shadowsocks::Address;
    using AddressType = Shadowsocks::AddressType;
    using ClientConfig = Shadowsocks::ClientConfig;
    using Dgram = Shadowsocks::Dgram<>;
    using Error = Preview::Error;
    using MemoryStream = Preview::MemoryStream;
    using ServerConfig = Shadowsocks::ServerConfig;
    using SharedDgram = Shadowsocks::SharedDgram;
    using Unreliable = Preview::Transport::Unreliable;

    struct RootCompletion final
    {
        std::exception_ptr Failure;
    };

    auto CompleteRoot(
        RootCompletion &State,
        std::exception_ptr Failure) -> void
    {
        if (!State.Failure)
        {
            State.Failure = std::move(Failure);
        }
    }

    /** @brief 驱动根协程直至真实完成，并保留首个异常。 */
    auto RunCoroutine(
        Net::io_context &IoContext,
        Net::awaitable<void> Operation) -> void
    {
        RootCompletion State;
        auto Completion = [&State](std::exception_ptr Failure)
        { CompleteRoot(State, std::move(Failure)); };
        IoContext.restart();
        Net::co_spawn(IoContext, std::move(Operation), std::move(Completion));
        IoContext.run();
        if (State.Failure)
        {
            std::rethrow_exception(State.Failure);
        }
    }

    struct DatagramPairCleanup final
    {
        SharedDgram Client;
        SharedDgram Server;

        ~DatagramPairCleanup()
        {
            if (Client)
            {
                Client->Close();
            }
            if (Server)
            {
                Server->Close();
            }
        }
    };

    struct SessionCleanup final
    {
        std::shared_ptr<Dgram> Client;
        std::shared_ptr<Dgram> Client2;
        std::shared_ptr<MemoryStream> Peer;

        ~SessionCleanup()
        {
            if (Client)
            {
                Client->Close();
            }
            if (Client2)
            {
                Client2->Close();
            }
            if (Peer)
            {
                Peer->Close();
            }
        }
    };

    struct HijackCleanup final
    {
        SharedDgram Client;
        SharedDgram Server;
        std::shared_ptr<Unreliable> Attacker;

        ~HijackCleanup()
        {
            if (Attacker)
            {
                Attacker->Close();
            }
            if (Client)
            {
                Client->Close();
            }
            if (Server)
            {
                Server->Close();
            }
        }
    };

    [[nodiscard]] auto MakeAddress(
        const AddressType Type,
        std::string Host,
        const std::uint16_t Port) -> Address
    {
        Address Result;
        Result.Type = Type;
        Result.Host = std::move(Host);
        Result.Port = Port;
        return Result;
    }

    [[nodiscard]] auto ReceiveWithDeadline(
        const SharedDgram &Datagram,
        Address &Source,
        std::vector<std::uint8_t> &Payload) -> Net::awaitable<std::optional<Error>>
    {
        Net::steady_timer Timer(Datagram->Executor());
        Timer.expires_after(std::chrono::milliseconds(250));
        using Net::experimental::awaitable_operators::operator||;
        auto Result = co_await (
            Datagram->AsyncReceiveFrom(Source, Payload) ||
            Timer.async_wait(Net::use_awaitable));
        if (Result.index() == 1)
        {
            Datagram->Close();
            co_return std::nullopt;
        }
        co_return std::get<0>(std::move(Result));
    }

    [[nodiscard]] auto MakeKey(const std::uint8_t First)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Key{};
        for (std::size_t Index = 0; Index < Key.size(); ++Index)
        {
            Key[Index] = static_cast<std::uint8_t>(First + Index);
        }
        return Key;
    }

    struct DatagramEndpoints final
    {
        SharedDgram Client;
        SharedDgram Server;
    };

    struct DgramPairRequest final
    {
        DatagramEndpoints Endpoints;
        std::string Message;
        Address Target;
    };

    auto RunClientToServerDatagram(DgramPairRequest Request)
        -> Net::awaitable<void>
    {
        DatagramPairCleanup Cleanup{
            Request.Endpoints.Client, Request.Endpoints.Server};
        const auto SendError = co_await Request.Endpoints.Client->AsyncSendTo(
            Request.Target, Preview::AsU8Span(Request.Message));
        EXPECT_EQ(SendError, Error::None);
        Address Source;
        std::vector<std::uint8_t> ReceivedPayload;
        const auto ReceiveError =
            co_await Request.Endpoints.Server->AsyncReceiveFrom(
                Source, ReceivedPayload);
        EXPECT_EQ(ReceiveError, Error::None);
        EXPECT_EQ(
            std::string(ReceivedPayload.begin(), ReceivedPayload.end()),
            Request.Message);
    }

    struct SessionIdPair final
    {
        std::shared_ptr<Dgram> Client;
        std::shared_ptr<Dgram> Client2;
        std::shared_ptr<MemoryStream> Peer;
    };

    auto RunSessionIdInspection(
        SessionIdPair Pair,
        std::array<std::uint8_t, 16> Key) -> Net::awaitable<void>
    {
        SessionCleanup Cleanup{Pair.Client, Pair.Client2, Pair.Peer};
        EXPECT_NE(Pair.Client->SessionId(), Pair.Client2->SessionId());
        const auto Target = MakeAddress(AddressType::Ipv4, "192.0.2.1", 443);
        const std::string Message = "first";
        const auto SendError = co_await Pair.Client->AsyncSendTo(
            Target, Preview::AsU8Span(Message));
        EXPECT_EQ(SendError, Error::None);
        std::array<std::uint8_t, 2048> Wire{};
        std::error_code ErrorCode;
        const auto Count = co_await Pair.Peer->async_read_some(
            Preview::AsBytes(std::span<std::uint8_t>(Wire)), ErrorCode);
        EXPECT_FALSE(ErrorCode);
        EXPECT_GT(Count, Shadowsocks::SeparateHdrLen);
        if (Count <= Shadowsocks::SeparateHdrLen)
        {
            co_return;
        }
        std::vector<std::uint8_t> Packet(
            Wire.begin(), Wire.begin() + static_cast<std::ptrdiff_t>(Count));
        std::array<std::uint8_t, Shadowsocks::SessionIdLen> Session{};
        std::uint64_t PacketId = 99;
        std::uint8_t HeaderType = 0xFF;
        Address ParsedAddress;
        std::vector<std::uint8_t> ParsedPayload;
        const Shadowsocks::UdpParseInput ParseInput{
            Key, Packet, &ParsedAddress, &ParsedPayload, &Session,
            &PacketId, nullptr, &HeaderType, nullptr};
        EXPECT_EQ(Shadowsocks::ParseUdpPacket(ParseInput), Error::None);
        EXPECT_EQ(Session, Pair.Client->SessionId());
        EXPECT_EQ(PacketId, 0u);
        EXPECT_EQ(HeaderType, Shadowsocks::HeaderTypeClient);
    }

    auto RunBidirectionalEcho(DgramPairRequest Request)
        -> Net::awaitable<void>
    {
        DatagramPairCleanup Cleanup{
            Request.Endpoints.Client, Request.Endpoints.Server};
        const auto SendError = co_await Request.Endpoints.Client->AsyncSendTo(
            Request.Target, Preview::AsU8Span(Request.Message));
        EXPECT_EQ(SendError, Error::None);
        Address Source;
        std::vector<std::uint8_t> ReceivedPayload;
        const auto ReceiveError =
            co_await Request.Endpoints.Server->AsyncReceiveFrom(
                Source, ReceivedPayload);
        EXPECT_EQ(ReceiveError, Error::None);
        const auto ResponseError =
            co_await Request.Endpoints.Server->AsyncSendTo(
                Source, ReceivedPayload);
        EXPECT_EQ(ResponseError, Error::None);
        Address ResponseSource;
        std::vector<std::uint8_t> EchoedPayload;
        const auto ClientReceiveError =
            co_await Request.Endpoints.Client->AsyncReceiveFrom(
                ResponseSource, EchoedPayload);
        EXPECT_EQ(ClientReceiveError, Error::None);
        EXPECT_EQ(
            std::string(EchoedPayload.begin(), EchoedPayload.end()),
            Request.Message);
    }

    struct HijackEndpoints final
    {
        SharedDgram Client;
        SharedDgram Server;
        std::shared_ptr<Unreliable> Attacker;
    };

    auto RunInvalidHijack(
        HijackEndpoints Endpoints,
        std::array<std::uint8_t, 16> Key) -> Net::awaitable<void>
    {
        HijackCleanup Cleanup{
            Endpoints.Client, Endpoints.Server, Endpoints.Attacker};
        const auto Target = MakeAddress(AddressType::Domain, "example.com", 443);
        const std::string Message = "valid";
        const auto ValidPayload = Preview::AsU8Span(Message);
        EXPECT_EQ(
            co_await Endpoints.Client->AsyncSendTo(Target, ValidPayload),
            Error::None);
        Address Source;
        std::vector<std::uint8_t> Payload;
        EXPECT_EQ(
            co_await Endpoints.Server->AsyncReceiveFrom(Source, Payload),
            Error::None);
        EXPECT_EQ(
            std::string(Payload.begin(), Payload.end()), Message);
        auto BadKey = MakeKey(0xEE);
        std::array<std::uint8_t, Shadowsocks::SessionIdLen> BadSession{};
        BadSession.fill(0xD1);
        std::vector<std::uint8_t> BadWire;
        const Shadowsocks::UdpBuildInput BuildInput{
            BadKey, 0, &Target, ValidPayload, BadSession};
        const auto Built = Shadowsocks::BuildUdpPacket(BuildInput, BadWire);
        EXPECT_TRUE(Built);
        if (!Built)
        {
            co_return;
        }
        std::error_code WriteError;
        const auto Written = co_await Endpoints.Attacker->async_write_some(
            Preview::AsBytes(std::span<const std::uint8_t>(BadWire)),
            WriteError);
        EXPECT_EQ(Written, BadWire.size());
        EXPECT_FALSE(WriteError);
        Payload.clear();
        EXPECT_NE(
            co_await Endpoints.Server->AsyncReceiveFrom(Source, Payload),
            Error::None);
        EXPECT_EQ(
            co_await Endpoints.Server->AsyncSendTo(Source, ValidPayload),
            Error::None);
        Address ResponseSource;
        std::vector<std::uint8_t> Response;
        const auto ClientError = co_await ReceiveWithDeadline(
            Endpoints.Client, ResponseSource, Response);
        EXPECT_TRUE(ClientError.has_value());
        if (!ClientError.has_value())
        {
            co_return;
        }
        EXPECT_EQ(*ClientError, Error::None);
        EXPECT_EQ(
            std::string(Response.begin(), Response.end()), Message);
    }

    auto RunBadPassword(DgramPairRequest Request) -> Net::awaitable<void>
    {
        DatagramPairCleanup Cleanup{
            Request.Endpoints.Client, Request.Endpoints.Server};
        const auto Target = MakeAddress(AddressType::Ipv4, "127.0.0.1", 7777);
        const std::string Message = "bad-key";
        EXPECT_EQ(
            co_await Request.Endpoints.Client->AsyncSendTo(
                Target, Preview::AsU8Span(Message)),
            Error::None);
        Address Source;
        std::vector<std::uint8_t> ReceivedPayload;
        const auto ReceiveError = co_await ReceiveWithDeadline(
            Request.Endpoints.Server, Source, ReceivedPayload);
        if (ReceiveError.has_value())
        {
            EXPECT_NE(*ReceiveError, Error::None);
        }
        else
        {
            SUCCEED();
        }
    }

    TEST(Ss2022DgramSession, ClientToServerDatagram)
    {
        Net::io_context IoContext;
        ServerConfig ServerOptions;
        const auto Key = MakeKey(0x01);
        ServerOptions.Psk = Key;
        const auto Server = Shadowsocks::AcceptPacket(
            IoContext.get_executor(), 0, ServerOptions);
        DatagramPairCleanup Cleanup{nullptr, Server};
        ASSERT_NE(Server, nullptr);
        const auto *ServerUdp = dynamic_cast<Unreliable *>(Server->NextLayer());
        ASSERT_NE(ServerUdp, nullptr);
        const auto ServerPort = ServerUdp->NativeSocket().local_endpoint().port();
        ClientConfig ClientOptions;
        ClientOptions.Psk = Key;
        const auto Client = Shadowsocks::ConnectPacket(
            IoContext.get_executor(),
            "127.0.0.1:" + std::to_string(ServerPort),
            ClientOptions);
        Cleanup.Client = Client;
        ASSERT_NE(Client, nullptr);
        RunCoroutine(
            IoContext,
            RunClientToServerDatagram(DgramPairRequest{
                DatagramEndpoints{Client, Server},
                "ss2022-Dgram",
                MakeAddress(AddressType::Ipv4, "127.0.0.1", 12345)}));
    }

    TEST(Ss2022DgramSession, ClientSessionIdsAndFirstPacketId)
    {
        Net::io_context IoContext;
        auto [ClientInput, PeerInput] = Preview::MakeMemoryPair(IoContext.get_executor());
        const auto Key = MakeKey(0x42);
        auto Client = std::make_shared<Dgram>(
            std::make_shared<MemoryStream>(std::move(ClientInput)),
            Key,
            Shadowsocks::UdpRole::Client);
        auto Peer = std::make_shared<MemoryStream>(std::move(PeerInput));
        auto [Client2Input, UnusedPeerInput] =
            Preview::MakeMemoryPair(IoContext.get_executor());
        (void)UnusedPeerInput;
        auto Client2 = std::make_shared<Dgram>(
            std::make_shared<MemoryStream>(std::move(Client2Input)),
            Key,
            Shadowsocks::UdpRole::Client);
        RunCoroutine(
            IoContext,
            RunSessionIdInspection(
                SessionIdPair{Client, Client2, Peer}, Key));
    }

    TEST(Ss2022DgramSession, BidirectionalEcho)
    {
        Net::io_context IoContext;
        ServerConfig ServerOptions;
        const auto Key = MakeKey(0x11);
        ServerOptions.Psk = Key;
        const auto Server = Shadowsocks::AcceptPacket(
            IoContext.get_executor(), 0, ServerOptions);
        DatagramPairCleanup Cleanup{nullptr, Server};
        ASSERT_NE(Server, nullptr);
        const auto *ServerUdp = dynamic_cast<Unreliable *>(Server->NextLayer());
        ASSERT_NE(ServerUdp, nullptr);
        const auto ServerPort = ServerUdp->NativeSocket().local_endpoint().port();
        ClientConfig ClientOptions;
        ClientOptions.Psk = Key;
        const auto Client = Shadowsocks::ConnectPacket(
            IoContext.get_executor(),
            "127.0.0.1:" + std::to_string(ServerPort),
            ClientOptions);
        Cleanup.Client = Client;
        ASSERT_NE(Client, nullptr);
        RunCoroutine(
            IoContext,
            RunBidirectionalEcho(DgramPairRequest{
                DatagramEndpoints{Client, Server},
                "echo-me",
                MakeAddress(AddressType::Ipv4, "127.0.0.1", 9999)}));
    }

    TEST(Ss2022DgramSession, InvalidDatagramCannotHijackPeer)
    {
        Net::io_context IoContext;
        const auto Key = MakeKey(0x51);
        ServerConfig ServerOptions;
        ServerOptions.Psk = Key;
        const auto Server = Shadowsocks::AcceptPacket(
            IoContext.get_executor(), 0, ServerOptions);
        DatagramPairCleanup PairCleanup{nullptr, Server};
        ASSERT_NE(Server, nullptr);
        const auto *ServerUdp = dynamic_cast<Unreliable *>(Server->NextLayer());
        ASSERT_NE(ServerUdp, nullptr);
        const auto ServerPort = ServerUdp->NativeSocket().local_endpoint().port();
        ClientConfig ClientOptions;
        ClientOptions.Psk = Key;
        const auto Client = Shadowsocks::ConnectPacket(
            IoContext.get_executor(),
            "127.0.0.1:" + std::to_string(ServerPort),
            ClientOptions);
        PairCleanup.Client = Client;
        ASSERT_NE(Client, nullptr);
        auto Attacker = std::make_shared<Unreliable>(IoContext.get_executor());
        HijackCleanup Cleanup{Client, Server, Attacker};
        ASSERT_TRUE(Attacker->Connect(
            "127.0.0.1:" + std::to_string(ServerPort)));
        RunCoroutine(
            IoContext,
            RunInvalidHijack(
                HijackEndpoints{Client, Server, Attacker}, Key));
    }

    TEST(Ss2022DgramSession, BadPasswordRejected)
    {
        Net::io_context IoContext;
        ServerConfig ServerOptions;
        const auto ServerKey = MakeKey(0x31);
        ServerOptions.Psk = ServerKey;
        const auto Server = Shadowsocks::AcceptPacket(
            IoContext.get_executor(), 0, ServerOptions);
        DatagramPairCleanup Cleanup{nullptr, Server};
        ASSERT_NE(Server, nullptr);
        const auto *ServerUdp = dynamic_cast<Unreliable *>(Server->NextLayer());
        ASSERT_NE(ServerUdp, nullptr);
        const auto ServerPort = ServerUdp->NativeSocket().local_endpoint().port();
        ClientConfig ClientOptions;
        ClientOptions.Psk.fill(0x99);
        const auto Client = Shadowsocks::ConnectPacket(
            IoContext.get_executor(),
            "127.0.0.1:" + std::to_string(ServerPort),
            ClientOptions);
        Cleanup.Client = Client;
        ASSERT_NE(Client, nullptr);
        RunCoroutine(
            IoContext,
            RunBadPassword(DgramPairRequest{
                DatagramEndpoints{Client, Server},
                "bad-key",
                MakeAddress(AddressType::Ipv4, "127.0.0.1", 7777)}));
    }

    TEST(Ss2022DgramSession, UdpDisabledRejectsAcceptPacket)
    {
        Net::io_context IoContext;
        ServerConfig Config;
        Config.Psk = MakeKey(0x61);
        Config.EnableUdp = false;
        const auto Server = Shadowsocks::AcceptPacket(
            IoContext.get_executor(), 0, Config);
        EXPECT_EQ(Server, nullptr);
    }
} // namespace

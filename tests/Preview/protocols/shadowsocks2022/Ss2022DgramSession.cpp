/**
 * @file Ss2022DgramSession.cpp
 * @brief SS2022 UDP 数据报会话测试（Dgram 成功路径）
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

    template <typename Awaitable>
    auto RunCoroutine(
        Net::io_context &IoContext,
        Awaitable Coroutine) -> void
    {
        std::exception_ptr Exception;
        auto Completion =
            [&Exception, &IoContext](std::exception_ptr ErrorValue) -> void
        {
            Exception = ErrorValue;
            IoContext.stop();
        };
        Net::co_spawn(
            IoContext,
            std::move(Coroutine),
            std::move(Completion));
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

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

    [[nodiscard]] auto MakeKey(const std::uint8_t First) -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Key{};
        for (std::size_t Index = 0; Index < Key.size(); ++Index)
        {
            Key[Index] = static_cast<std::uint8_t>(First + Index);
        }
        return Key;
    }

    TEST(Ss2022DgramSession, ClientToServerDatagram)
    {
        Net::io_context IoContext;
        ServerConfig ServerOptions;
        const auto Key = MakeKey(0x01);
        ServerOptions.password = "pass123";
        ServerOptions.Psk = Key;
        ServerOptions.UsePsk = true;
        const auto Server = Shadowsocks::AcceptPacket(
            IoContext.get_executor(),
            0,
            ServerOptions);
        ASSERT_NE(Server, nullptr);

        const auto *ServerUdp =
            dynamic_cast<Unreliable *>(Server->NextLayer());
        ASSERT_NE(ServerUdp, nullptr);
        const auto ServerPort =
            ServerUdp->NativeSocket().local_endpoint().port();

        ClientConfig ClientOptions;
        ClientOptions.password = "pass123";
        ClientOptions.Psk = Key;
        ClientOptions.UsePsk = true;
        const auto ServerEndpoint =
            "127.0.0.1:" + std::to_string(ServerPort);
        const auto Client = Shadowsocks::ConnectPacket(
            IoContext.get_executor(),
            ServerEndpoint,
            ClientOptions);
        ASSERT_NE(Client, nullptr);

        const auto Target = MakeAddress(AddressType::Ipv4, "127.0.0.1", 12345);
        const std::string Message = "ss2022-Dgram";
        const auto Payload = Preview::AsU8Span(Message);
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto SendError = co_await Client->AsyncSendTo(Target, Payload);
            EXPECT_EQ(SendError, Error::None);

            Address Source;
            std::vector<std::uint8_t> ReceivedPayload;
            const auto ReceiveError =
                co_await Server->AsyncReceiveFrom(Source, ReceivedPayload);
            EXPECT_EQ(ReceiveError, Error::None);
            const std::string Received(
                ReceivedPayload.begin(),
                ReceivedPayload.end());
            EXPECT_EQ(Received, Message);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        Client->Close();
        Server->Close();
    }

    TEST(Ss2022DgramSession, ClientSessionIdsAndFirstPacketId)
    {
        Net::io_context IoContext;
        auto [ClientInput, PeerInput] =
            Preview::MakeMemoryPair(IoContext.get_executor());
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

        EXPECT_NE(Client->SessionId(), Client2->SessionId());
        const auto Target = MakeAddress(AddressType::Ipv4, "192.0.2.1", 443);
        const std::string Message = "first";
        const auto Payload = Preview::AsU8Span(Message);
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto SendError =
                co_await Client->AsyncSendTo(Target, Payload);
            EXPECT_EQ(SendError, Error::None);

            std::array<std::uint8_t, 2048> Wire{};
            auto WireBytes = std::span<std::uint8_t>(Wire);
            auto WireBuffer = Preview::AsBytes(WireBytes);
            std::error_code ErrorCode;
            const auto Count =
                co_await Peer->async_read_some(WireBuffer, ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_GT(Count, Shadowsocks::SeparateHdrLen);
            if (Count <= Shadowsocks::SeparateHdrLen)
            {
                co_return;
            }

            std::vector<std::uint8_t> Packet(
                Wire.begin(),
                Wire.begin() + static_cast<std::ptrdiff_t>(Count));
            std::array<std::uint8_t, Shadowsocks::SessionIdLen> Session{};
            std::uint64_t PacketId = 99;
            std::uint8_t HeaderType = 0xFF;
            Address ParsedAddress;
            std::vector<std::uint8_t> ParsedPayload;
            const Shadowsocks::UdpParseInput ParseInput{
                Key,
                Packet,
                &ParsedAddress,
                &ParsedPayload,
                &Session,
                &PacketId,
                nullptr,
                &HeaderType,
                nullptr};
            EXPECT_EQ(Shadowsocks::ParseUdpPacket(ParseInput), Error::None);
            EXPECT_EQ(Session, Client->SessionId());
            EXPECT_EQ(PacketId, 0u);
            EXPECT_EQ(HeaderType, Shadowsocks::HeaderTypeClient);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        Client->Close();
        Client2->Close();
        Peer->Close();
    }

    TEST(Ss2022DgramSession, BidirectionalEcho)
    {
        Net::io_context IoContext;
        ServerConfig ServerOptions;
        ServerOptions.password = "echo-pass";
        const auto Key = MakeKey(0x11);
        ServerOptions.Psk = Key;
        ServerOptions.UsePsk = true;
        const auto Server = Shadowsocks::AcceptPacket(
            IoContext.get_executor(),
            0,
            ServerOptions);
        ASSERT_NE(Server, nullptr);
        const auto *ServerUdp =
            dynamic_cast<Unreliable *>(Server->NextLayer());
        ASSERT_NE(ServerUdp, nullptr);
        const auto ServerPort =
            ServerUdp->NativeSocket().local_endpoint().port();

        ClientConfig ClientOptions;
        ClientOptions.password = "echo-pass";
        ClientOptions.Psk = Key;
        ClientOptions.UsePsk = true;
        const auto ServerEndpoint =
            "127.0.0.1:" + std::to_string(ServerPort);
        const auto Client = Shadowsocks::ConnectPacket(
            IoContext.get_executor(),
            ServerEndpoint,
            ClientOptions);
        ASSERT_NE(Client, nullptr);

        const auto Target = MakeAddress(AddressType::Ipv4, "127.0.0.1", 9999);
        const std::string Message = "echo-me";
        const auto Payload = Preview::AsU8Span(Message);
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto SendError = co_await Client->AsyncSendTo(Target, Payload);
            EXPECT_EQ(SendError, Error::None);

            Address Source;
            std::vector<std::uint8_t> ReceivedPayload;
            const auto ReceiveError =
                co_await Server->AsyncReceiveFrom(Source, ReceivedPayload);
            EXPECT_EQ(ReceiveError, Error::None);
            const auto ResponseError =
                co_await Server->AsyncSendTo(Source, ReceivedPayload);
            EXPECT_EQ(ResponseError, Error::None);

            Address ResponseSource;
            std::vector<std::uint8_t> EchoedPayload;
            const auto ClientReceiveError =
                co_await Client->AsyncReceiveFrom(
                    ResponseSource,
                    EchoedPayload);
            EXPECT_EQ(ClientReceiveError, Error::None);
            const std::string Echoed(
                EchoedPayload.begin(),
                EchoedPayload.end());
            EXPECT_EQ(Echoed, Message);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        Client->Close();
        Server->Close();
    }

    TEST(Ss2022DgramSession, InvalidDatagramCannotHijackPeer)
    {
        Net::io_context IoContext;
        const auto Key = MakeKey(0x51);
        ServerConfig ServerOptions;
        ServerOptions.UsePsk = true;
        ServerOptions.Psk = Key;
        const auto Server = Shadowsocks::AcceptPacket(
            IoContext.get_executor(),
            0,
            ServerOptions);
        ASSERT_NE(Server, nullptr);
        const auto *ServerUdp =
            dynamic_cast<Unreliable *>(Server->NextLayer());
        ASSERT_NE(ServerUdp, nullptr);
        const auto ServerPort =
            ServerUdp->NativeSocket().local_endpoint().port();

        ClientConfig ClientOptions;
        ClientOptions.UsePsk = true;
        ClientOptions.Psk = Key;
        const auto ServerEndpoint =
            "127.0.0.1:" + std::to_string(ServerPort);
        const auto Client = Shadowsocks::ConnectPacket(
            IoContext.get_executor(),
            ServerEndpoint,
            ClientOptions);
        ASSERT_NE(Client, nullptr);

        auto Attacker = std::make_shared<Unreliable>(
            IoContext.get_executor());
        ASSERT_TRUE(Attacker->Connect(ServerEndpoint));

        const auto Target = MakeAddress(AddressType::Domain, "example.com", 443);
        const std::string Message = "valid";
        const auto ValidPayload = Preview::AsU8Span(Message);
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto SendError =
                co_await Client->AsyncSendTo(Target, ValidPayload);
            EXPECT_EQ(SendError, Error::None);

            Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ReceiveError =
                co_await Server->AsyncReceiveFrom(Source, Payload);
            EXPECT_EQ(ReceiveError, Error::None);
            const std::string Received(Payload.begin(), Payload.end());
            EXPECT_EQ(Received, Message);

            auto BadKey = MakeKey(0xEE);
            std::array<std::uint8_t, Shadowsocks::SessionIdLen> BadSession{};
            BadSession.fill(0xD1);
            std::vector<std::uint8_t> BadWire;
            const Shadowsocks::UdpBuildInput BuildInput{
                BadKey,
                0,
                &Target,
                ValidPayload,
                BadSession};
            const auto Built =
                Shadowsocks::BuildUdpPacket(BuildInput, BadWire);
            EXPECT_TRUE(Built);
            if (!Built)
            {
                co_return;
            }

            std::error_code WriteError;
            auto BadWireBytes = std::span<const std::uint8_t>(BadWire);
            auto BadWireBuffer = Preview::AsBytes(BadWireBytes);
            const auto Written = co_await Attacker->async_write_some(
                BadWireBuffer,
                WriteError);
            EXPECT_EQ(Written, BadWire.size());
            EXPECT_FALSE(WriteError);

            Payload.clear();
            const auto BadError =
                co_await Server->AsyncReceiveFrom(Source, Payload);
            EXPECT_NE(BadError, Error::None);

            const auto ResponseError =
                co_await Server->AsyncSendTo(Source, ValidPayload);
            EXPECT_EQ(ResponseError, Error::None);
            Address ResponseSource;
            std::vector<std::uint8_t> Response;
            const auto ClientError = co_await ReceiveWithDeadline(
                Client,
                ResponseSource,
                Response);
            EXPECT_TRUE(ClientError.has_value());
            if (!ClientError.has_value())
            {
                co_return;
            }
            EXPECT_EQ(*ClientError, Error::None);
            const std::string Echoed(Response.begin(), Response.end());
            EXPECT_EQ(Echoed, Message);
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        Attacker->Close();
        Client->Close();
        Server->Close();
    }

    TEST(Ss2022DgramSession, BadPasswordRejected)
    {
        Net::io_context IoContext;
        ServerConfig ServerOptions;
        ServerOptions.password = "Server-pass";
        const auto ServerKey = MakeKey(0x31);
        ServerOptions.Psk = ServerKey;
        ServerOptions.UsePsk = true;
        const auto Server = Shadowsocks::AcceptPacket(
            IoContext.get_executor(),
            0,
            ServerOptions);
        ASSERT_NE(Server, nullptr);
        const auto *ServerUdp =
            dynamic_cast<Unreliable *>(Server->NextLayer());
        ASSERT_NE(ServerUdp, nullptr);
        const auto ServerPort =
            ServerUdp->NativeSocket().local_endpoint().port();

        ClientConfig ClientOptions;
        ClientOptions.password = "wrong-pass";
        ClientOptions.Psk.fill(0x99);
        ClientOptions.UsePsk = true;
        const auto ServerEndpoint =
            "127.0.0.1:" + std::to_string(ServerPort);
        const auto Client = Shadowsocks::ConnectPacket(
            IoContext.get_executor(),
            ServerEndpoint,
            ClientOptions);
        ASSERT_NE(Client, nullptr);

        const auto Target = MakeAddress(AddressType::Ipv4, "127.0.0.1", 7777);
        const std::string Message = "bad-key";
        const auto Payload = Preview::AsU8Span(Message);
        auto Coroutine = [&]() -> Net::awaitable<void>
        {
            const auto SendError = co_await Client->AsyncSendTo(Target, Payload);
            EXPECT_EQ(SendError, Error::None);

            Address Source;
            std::vector<std::uint8_t> ReceivedPayload;
            const auto ReceiveError = co_await ReceiveWithDeadline(
                Server,
                Source,
                ReceivedPayload);
            if (ReceiveError.has_value())
            {
                EXPECT_NE(*ReceiveError, Error::None);
            }
            else
            {
                SUCCEED();
            }
        };
        RunCoroutine(IoContext, std::move(Coroutine));
        Client->Close();
        Server->Close();
    }

    TEST(Ss2022DgramSession, UdpDisabledRejectsAcceptPacket)
    {
        Net::io_context IoContext;
        ServerConfig Config;
        Config.UsePsk = true;
        Config.Psk = MakeKey(0x61);
        Config.EnableUdp = false;

        const auto Server = Shadowsocks::AcceptPacket(
            IoContext.get_executor(), 0, Config);
        EXPECT_EQ(Server, nullptr);
    }
} // namespace

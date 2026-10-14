/**
 * @file Ss2022CodecDeep.cpp
 * @brief Shadowsocks 2022 Codec / Conn / Dgram 剩余分支深度测试
 * @details 覆盖 EncodeAddress / ParseAddress / ParseVarHeader 的
 *          ipv6 与截断分支、ChunkCodec 的起始 Nonce 与全部错误路径、
 *          UDP 数据报编解码的成功与错误路径、握手 Parser 的错误分支，
 *          Conn / Dgram 装饰器透传方法。
 */
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <vector>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Shadowsocks2022/Codec.hpp>
#include <Preview/Protocols/Shadowsocks2022/Conn.hpp>
#include <Preview/Protocols/Shadowsocks2022/Dgram.hpp>
#include <Preview/Protocols/Shadowsocks2022/RequestState.hpp>
#include <Preview/Protocols/Shadowsocks2022/RequestWire.hpp>
#include <Preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp>
#include <gtest/gtest.h>
namespace
{
    namespace Net = boost::asio;
    namespace SS2022 = Preview::Shadowsocks2022;
    namespace ss = SS2022;
    namespace Shadowsocks2022 = SS2022;
    using Net::experimental::awaitable_operators::operator&&;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::Transmission;
    struct FactoryHandshakeResult
    {
        Error ClientError{Error::IoError};
        Error ServerError{Error::IoError};
        bool ClientConnected{false};
        ss::Message Request{};
    };
    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;
    struct EagerTask final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };
    auto CompleteEager(EagerTask State, std::exception_ptr Failure) -> void
    {
        if (!*State.Failure) *State.Failure = std::move(Failure);
        (void)State.Done->try_send(boost::system::error_code{});
    }
    auto SpawnEager(Net::any_io_executor Executor, Net::awaitable<void> Operation) -> EagerTask
    {
        EagerTask State{std::make_shared<CompletionChannel>(Executor, 1), std::make_shared<std::exception_ptr>()};
        Net::co_spawn(Executor, std::move(Operation), [State](std::exception_ptr ErrorValue)
        { CompleteEager(State, std::move(ErrorValue)); });
        return State;
    }
    auto AwaitEager(EagerTask State) -> Net::awaitable<std::exception_ptr>
    {
        (void)co_await State.Done->async_receive(Net::use_awaitable);
        co_return *State.Failure;
    }
    struct DgramCleanup final
    {
        std::shared_ptr<Shadowsocks2022::Dgram<>> Datagram;
        std::shared_ptr<MemoryStream> Peer;
        ~DgramCleanup()
        {
            if (Datagram)
            {
                Datagram->Close();
            }
            if (Peer)
            {
                Peer->Close();
            }
        }
    };
    auto RunFactoryServer(const std::shared_ptr<MemoryStream> &Endpoint, ss::ServerConfig Config,
                          const std::shared_ptr<FactoryHandshakeResult> &Result) -> Net::awaitable<void>
    {
        try
        {
            auto Value = co_await ss::Accept(Endpoint, Config);
            Result->ServerError = std::get<0>(Value);
            Result->Request = std::get<1>(std::move(Value));
        }
        catch (...)
        {
            Endpoint->Close();
            throw;
        }
    }
    auto RunFactoryClient(const std::shared_ptr<MemoryStream> &Endpoint, ss::ClientConfig Config,
                          const std::shared_ptr<FactoryHandshakeResult> &Result) -> Net::awaitable<void>
    {
        try
        {
            const ss::Address Target{ss::AddressType::Domain, "example.com", 443};
            auto Value = co_await ss::Connect(Endpoint, Config, Target);
            Result->ClientError = std::get<0>(Value);
            Result->ClientConnected = std::get<1>(std::move(Value)) != nullptr;
        }
        catch (...)
        {
            Endpoint->Close();
            throw;
        }
    }
    auto RunFactoryHandshake(const ss::ClientConfig &ClientConfig, const ss::ServerConfig &ServerConfig)
        -> Net::awaitable<FactoryHandshakeResult>
    {
        auto [ClientRawValue, ServerRawValue] =
            MakeMemoryPair(co_await Net::this_coro::executor);
        auto ClientRaw = std::make_shared<MemoryStream>(std::move(ClientRawValue));
        auto ServerRaw = std::make_shared<MemoryStream>(std::move(ServerRawValue));
        auto Result = std::make_shared<FactoryHandshakeResult>();
        auto ServerTask = SpawnEager(ServerRaw->Executor(), RunFactoryServer(ServerRaw, ServerConfig, Result));
        auto ClientTask = SpawnEager(ClientRaw->Executor(), RunFactoryClient(ClientRaw, ClientConfig, Result));
        auto Failures = co_await (AwaitEager(std::move(ServerTask)) && AwaitEager(std::move(ClientTask)));
        ClientRaw->Close();
        ServerRaw->Close();
        std::exception_ptr Failure = std::get<0>(Failures);
        if (!Failure) Failure = std::get<1>(Failures);
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
        co_return *Result;
    }
    /** @brief 驱动协程运行并保留首个异常。 */
    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Failure;
        auto Completion = [&Failure](std::exception_ptr ErrorValue)
        {
            if (!Failure)
            {
                Failure = std::move(ErrorValue);
            }
        };
        IoContext.restart();
        Net::co_spawn(IoContext, std::move(Coroutine), std::move(Completion));
        IoContext.run();
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }
    struct FactoryHandshakeRequest final
    {
        ss::ClientConfig Client;
        ss::ServerConfig Server;
    };
    auto StoreFactoryHandshake(
        FactoryHandshakeRequest Request,
        const std::shared_ptr<FactoryHandshakeResult> &Result)
        -> Net::awaitable<void>
    {
        *Result = co_await RunFactoryHandshake(Request.Client, Request.Server);
    }
    auto ExecuteFactoryHandshake(FactoryHandshakeRequest Request)
        -> FactoryHandshakeResult
    {
        Net::io_context IoContext;
        auto Result = std::make_shared<FactoryHandshakeResult>();
        RunCoroutine(
            IoContext,
            StoreFactoryHandshake(std::move(Request), Result));
        return *Result;
    }
    /** @brief 从初始值列表构造字节向量。 */
    auto MakeBytes(std::initializer_list<std::uint8_t> List)
        -> std::vector<std::uint8_t>
    {
        return std::vector<std::uint8_t>(List);
    }
    struct InitialPayloadRequest final
    {
        Net::io_context &IoContext;
        std::vector<std::uint8_t> Wire;
        std::array<std::uint8_t, 16> Psk;
    };
    auto RunInitialServer(std::shared_ptr<MemoryStream> Server,
                          std::array<std::uint8_t, 16> Psk,
                          std::shared_ptr<std::pair<Error, ss::SharedConn>> Result)
        -> Net::awaitable<void>
    {
        try
        {
            auto Connection = std::make_shared<ss::Conn<>>(Psk);
            const auto [ErrorCode, Parsed] =
                co_await Connection->ReadHandshake(Server);
            EXPECT_EQ(Parsed.InitialPayload, "shadowtls early payload");
            *Result = {
                ErrorCode,
                ErrorCode == Error::None ? Connection : ss::SharedConn{}};
        }
        catch (...)
        {
            Server->Close();
            throw;
        }
    }
    auto RunInitialDrain(std::shared_ptr<MemoryStream> Client,
                         std::shared_ptr<std::pair<std::size_t, std::error_code>> Result)
        -> Net::awaitable<void>
    {
        try
        {
            std::array<std::byte, 128> Response{};
            std::error_code ErrorCode;
            const auto Count =
                co_await Client->async_read_some(Response, ErrorCode);
            *Result = {Count, ErrorCode};
        }
        catch (...)
        {
            Client->Close();
            throw;
        }
    }
    auto RunInitialPayload(InitialPayloadRequest Request) -> Net::awaitable<void>
    {
        auto [ClientEndpoint, ServerEndpoint] = MakeMemoryPair(Request.IoContext.get_executor());
        auto Client = std::make_shared<MemoryStream>(std::move(ClientEndpoint));
        auto Server = std::make_shared<MemoryStream>(std::move(ServerEndpoint));
        Server->SetTimeout(std::chrono::seconds(1));
        auto ServerResult = std::make_shared<std::pair<Error, ss::SharedConn>>();
        auto DrainResult = std::make_shared<std::pair<std::size_t, std::error_code>>();
        auto ServerTask = SpawnEager(Server->Executor(), RunInitialServer(Server, Request.Psk, ServerResult));
        auto DrainTask = SpawnEager(Client->Executor(), RunInitialDrain(Client, DrainResult));
        std::exception_ptr Failure;
        try
        {
            EXPECT_FALSE(co_await Client->WriteAll(Request.Wire));
        }
        catch (...)
        {
            Failure = std::current_exception();
            Client->Close();
            Server->Close();
        }
        const auto ServerFailure = co_await AwaitEager(std::move(ServerTask));
        if (!Failure && ServerFailure)
        {
            Failure = ServerFailure;
            Client->Close();
            Server->Close();
        }
        const auto DrainFailure = co_await AwaitEager(std::move(DrainTask));
        if (!Failure && DrainFailure)
        {
            Failure = DrainFailure;
        }
        if (Failure)
        {
            Client->Close();
            Server->Close();
            std::rethrow_exception(Failure);
        }
        EXPECT_FALSE(DrainResult->second);
        EXPECT_GT(DrainResult->first, 0U);
        EXPECT_EQ(ServerResult->first, Error::None);
        EXPECT_TRUE(ServerResult->second);
        if (ServerResult->second)
        {
            std::array<std::byte, 128> Buffer{};
            std::error_code ErrorCode;
            const auto Count = co_await ServerResult->second->async_read_some(Buffer, ErrorCode);
            EXPECT_FALSE(ErrorCode);
            EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Count),
                      "shadowtls early payload");
            ServerResult->second->Close();
        }
        Client->Close();
        Server->Close();
    }
    auto RunDgramWireExchange(std::shared_ptr<Shadowsocks2022::Dgram<>> Datagram,
                              std::shared_ptr<MemoryStream> Peer,
                              std::array<std::uint8_t, 16> Key)
        -> Net::awaitable<void>
    {
        ss::Address Target{};
        Target.Type = ss::AddressType::Domain;
        Target.Host = "example.com";
        Target.Port = 80;
        EXPECT_EQ(co_await Datagram->AsyncSendTo(
                      Target, AsU8Span(std::string_view{"pkt"})), Error::None);
        std::array<std::uint8_t, 2048> Raw{};
        std::error_code ErrorCode;
        const auto Count = co_await Peer->async_read_some(
            AsBytes(std::span<std::uint8_t>(Raw)), ErrorCode);
        const auto Request = std::vector<std::uint8_t>(Raw.begin(), Raw.begin() + Count);
        ss::Address RequestTarget{};
        std::vector<std::uint8_t> RequestPayload;
        std::array<std::uint8_t, ss::SessionIdLen> ClientSession{};
        std::uint64_t RequestPacketId = 0;
        std::uint64_t RequestTimestamp = 0;
        std::uint8_t RequestType = 0;
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{
            Key, Request, &RequestTarget, &RequestPayload, &ClientSession,
            &RequestPacketId, &RequestTimestamp, &RequestType, nullptr}), Error::None);
        EXPECT_EQ(RequestType, ss::HeaderTypeClient);
        const std::array<std::uint8_t, ss::SessionIdLen> ServerSession{
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};
        const auto Response = ss::BuildUdpPacket(ss::UdpBuildInput{
            Key, 0, &RequestTarget, RequestPayload, ServerSession, 0,
            ClientSession, ss::HeaderTypeServer});
        EXPECT_FALSE(co_await Peer->WriteAll(Response));
        ss::Address Source{};
        std::vector<std::uint8_t> Payload;
        EXPECT_EQ(co_await Datagram->AsyncReceiveFrom(Source, Payload), Error::None);
        EXPECT_EQ(Source.Host, "example.com");
        EXPECT_EQ(Source.Port, 80);
    }
    auto RunFakeConnServer(std::shared_ptr<MemoryStream> Server,
                           std::array<std::uint8_t, 16> Psk)
        -> Net::awaitable<void>
    {
        std::array<std::uint8_t, 16 + 45 + 128> Buffer{};
        std::error_code ErrorCode;
        const auto Count = co_await Server->async_read_some(
            AsBytes(std::span<std::uint8_t>(Buffer)), ErrorCode);
        EXPECT_GT(Count, 16U + 45U);
        const auto Salt = std::span<const std::uint8_t>(Buffer.data(), 16);
        std::array<std::uint8_t, 16> ServerSalt{};
        ServerSalt.fill(0x77);
        ss::ChunkCodec Codec(ss::SessionKey(Psk, ServerSalt, 16));
        std::array<std::uint8_t, ss::RespFixedHdrPlain> Plain{};
        Plain[0] = ss::HeaderTypeServer;
        std::memcpy(Plain.data() + 9, Salt.data(), 16);
        EXPECT_FALSE(co_await Server->WriteAll(ServerSalt));
        EXPECT_FALSE(co_await Server->WriteAll(Codec.SealRaw(Plain)));
        EXPECT_FALSE(co_await Server->WriteAll(Codec.SealRaw({})));
    }
    struct ConnDecoratorStreams final
    {
        std::shared_ptr<Shadowsocks2022::Conn<>> Connection;
        std::shared_ptr<MemoryStream> Server;
        MemoryStream ClientMemory;
    };
    auto RunConnDecoratorPath(
        ConnDecoratorStreams Request,
        std::array<std::uint8_t, 16> Psk)
        -> Net::awaitable<void>
    {
        auto ClientTransport = std::make_shared<MemoryStream>(
            std::move(Request.ClientMemory));
        auto ServerTask = SpawnEager(
            Request.Server->Executor(), RunFakeConnServer(Request.Server, Psk));
        std::exception_ptr Failure;
        bool Released = false;
        try
        {
            std::error_code ErrorCode;
            std::array<std::byte, 4> Buffer{};
            EXPECT_EQ(
                co_await Request.Connection->async_read_some(Buffer, ErrorCode),
                0U);
            EXPECT_TRUE(ErrorCode);
            ErrorCode.clear();
            EXPECT_EQ(
                co_await Request.Connection->async_write_some(Buffer, ErrorCode),
                0U);
            EXPECT_TRUE(ErrorCode);
            ss::Address Target{};
            Target.Type = ss::AddressType::Domain;
            Target.Host = "example.com";
            Target.Port = 443;
            EXPECT_EQ(
                co_await Request.Connection->WriteHandshake(
                    ClientTransport, Target),
                Error::None);
            (void)Request.Connection->Executor();
            EXPECT_NE(Request.Connection->NextLayer(), nullptr);
            const auto *ConstConnection = Request.Connection.get();
            EXPECT_NE(ConstConnection->NextLayer(), nullptr);
            Request.Connection->Cancel();
            ss::Address DatagramTarget{};
            DatagramTarget.Type = ss::AddressType::Ipv4;
            DatagramTarget.Host = "1.2.3.4";
            DatagramTarget.Port = 53;
            EXPECT_EQ(
                co_await Request.Connection->AsyncSendDatagram(
                    DatagramTarget, AsU8Span(std::string_view{"udp"})),
                Error::None);
            EXPECT_NE(Request.Connection->Release(), nullptr);
            Released = true;
        }
        catch (...)
        {
            Failure = std::current_exception();
            Request.Connection->Cancel();
            ClientTransport->Close();
        }
        if (!Released)
        {
            (void)Request.Connection->Release();
        }
        if (Failure)
        {
            Request.Server->Close();
        }
        const auto ServerFailure = co_await AwaitEager(std::move(ServerTask));
        Request.Server->Close();
        if (!Failure)
        {
            Failure = ServerFailure;
        }
        if (Failure)
        {
            std::rethrow_exception(Failure);
        }
    }
    auto RunConnAndDgramDecorators(Net::io_context &IoContext)
        -> Net::awaitable<void>
    {
        const std::array<std::uint8_t, 16> Key{0x55, 0x55, 0x55, 0x55,
                                               0x55, 0x55, 0x55, 0x55,
                                               0x55, 0x55, 0x55, 0x55,
                                               0x55, 0x55, 0x55, 0x55};
        auto [A, B] = MakeMemoryPair(IoContext.get_executor());
        auto Datagram = std::make_shared<Shadowsocks2022::Dgram<>>(
            std::make_shared<MemoryStream>(std::move(A)), Key);
        DgramCleanup DatagramCleanup{Datagram, nullptr};
        EXPECT_EQ(Datagram->TransportType(), Transmission::Type::Udp);
        (void)Datagram->Executor();
        EXPECT_NE(Datagram->NextLayer(), nullptr);
        const auto *ConstDatagram = Datagram.get();
        EXPECT_NE(ConstDatagram->NextLayer(), nullptr);
        EXPECT_NE(Datagram->Stream(), nullptr);
        Datagram->Cancel();
        Datagram->Close();
        EXPECT_NE(Datagram->Release(), nullptr);
        auto [C, D] = MakeMemoryPair(IoContext.get_executor());
        auto Peer = std::make_shared<MemoryStream>(std::move(D));
        auto Datagram2 = std::make_shared<Shadowsocks2022::Dgram<>>(
            std::make_shared<MemoryStream>(std::move(C)), Key);
        DgramCleanup WireCleanup{Datagram2, Peer};
        co_await RunDgramWireExchange(Datagram2, Peer, Key);
        auto [E, F] = MakeMemoryPair(IoContext.get_executor());
        auto Server = std::make_shared<MemoryStream>(std::move(F));
        auto Connection = std::make_shared<Shadowsocks2022::Conn<>>(IoContext.get_executor(), Key);
        co_await RunConnDecoratorPath(
            ConnDecoratorStreams{Connection, Server, std::move(E)}, Key);
    }
    TEST(Ss2022CodecDeep, ReadHandshakeRetainsInitialPayload)
    {
        Net::io_context IoContext;
        const std::array<std::uint8_t, 16> Psk{0x10, 0x11, 0x12, 0x13,
                                               0x14, 0x15, 0x16, 0x17,
                                               0x18, 0x19, 0x1A, 0x1B,
                                               0x1C, 0x1D, 0x1E, 0x1F};
        ss::Message Request;
        Request.dst = ss::Address{ss::AddressType::Domain, "early.example", 443};
        Request.InitialPayload = "shadowtls early payload";
        ss::Serializer Serializer(Psk);
        Serializer.Reset(
            Request,
            static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                           std::chrono::system_clock::now().time_since_epoch())
                                           .count()));
        ASSERT_FALSE(Serializer.IsDone());
        std::vector<std::uint8_t> Wire;
        std::array<std::uint8_t, 4096> Chunk{};
        while (!Serializer.IsDone())
        {
            std::error_code ErrorCode;
            const auto Count = Serializer.Get(boost::asio::buffer(Chunk), ErrorCode);
            ASSERT_FALSE(ErrorCode);
            ASSERT_GT(Count, 0U);
            Wire.insert(Wire.end(), Chunk.begin(), Chunk.begin() + Count);
        }
        RunCoroutine(IoContext, RunInitialPayload(InitialPayloadRequest{IoContext, std::move(Wire), Psk}));
    }
    auto RunAddressBranches() -> void
    {
        ss::Address Address{};
        Address.Type = ss::AddressType::Ipv6;
        Address.Host.assign(16, 'q');
        Address.Port = 8080;
        const auto EncodedIpv6 = ss::EncodeAddress(Address);
        EXPECT_EQ(EncodedIpv6.size(), 19u);
        EXPECT_EQ(EncodedIpv6[0], 0x04);
        std::size_t Offset = 0;
        EXPECT_EQ(ss::ParseAddress(std::span<const std::uint8_t>(MakeBytes({0x01, 8, 8})), Address, Offset),
                  Error::NeedMore);
        Offset = 0;
        std::vector<std::uint8_t> Ipv6Wire{0x04};
        Ipv6Wire.insert(Ipv6Wire.end(), 5, 0x42);
        EXPECT_EQ(ss::ParseAddress(Ipv6Wire, Address, Offset), Error::NeedMore);
        Offset = 0;
        Ipv6Wire.assign(17, 0);
        Ipv6Wire[0] = 0x04;
        Ipv6Wire.insert(Ipv6Wire.end(), 2, 0);
        EXPECT_EQ(ss::ParseAddress(Ipv6Wire, Address, Offset), Error::None);
        EXPECT_EQ(Address.Host, std::string(16, 0));
        std::span<const std::uint8_t> Payload;
        EXPECT_EQ(ss::ParseVarHeader(std::span<const std::uint8_t>(MakeBytes({0x01, 8, 8})), Address, Payload),
                  Error::NeedMore);
        EXPECT_EQ(ss::ParseVarHeader(std::span<const std::uint8_t>(MakeBytes({0x04, 1})), Address, Payload),
                  Error::NeedMore);
        std::vector<std::uint8_t> Ipv6VarHeader{0x04};
        Ipv6VarHeader.insert(Ipv6VarHeader.end(), 16, 0x42);
        Ipv6VarHeader.push_back(0x00);
        Ipv6VarHeader.push_back(0x50);
        Ipv6VarHeader.push_back(0x00);
        Ipv6VarHeader.push_back(0x00);
        Ipv6VarHeader.push_back('x');
        EXPECT_EQ(ss::ParseVarHeader(Ipv6VarHeader, Address, Payload), Error::None);
        EXPECT_EQ(Address.Type, ss::AddressType::Ipv6);
        EXPECT_EQ(Address.Port, 80u);
        EXPECT_EQ(Payload.size(), 1u);
        std::vector<std::uint8_t> DomainTruncated{0x03, 0x05, 'a'};
        EXPECT_EQ(ss::ParseVarHeader(DomainTruncated, Address, Payload), Error::NeedMore);
        std::vector<std::uint8_t> DomainValid{0x03, 0x03, 'a', 'b', 'c', 0x00, 0x50, 0x00, 0x00};
        EXPECT_EQ(ss::ParseVarHeader(DomainValid, Address, Payload), Error::None);
        EXPECT_EQ(Address.Host, "abc");
    }
    TEST(Ss2022CodecDeep, AddressBranches)
    {
        RunAddressBranches();
    }
    TEST(Ss2022CodecDeep, AcceptFactoryUsesRawPsk)
    {
        const std::array<std::uint8_t, 16> Psk{
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE};
        ss::ClientConfig Client;
        Client.Psk = Psk;
        ss::ServerConfig Server;
        Server.Psk = Psk;
        const auto Result = ExecuteFactoryHandshake(
            FactoryHandshakeRequest{Client, Server});
        EXPECT_EQ(Result.ClientError, Error::None);
        EXPECT_EQ(Result.ServerError, Error::None);
        EXPECT_TRUE(Result.ClientConnected);
        EXPECT_EQ(Result.Request.dst.Host, "example.com");
        EXPECT_EQ(Result.Request.dst.Port, 443u);
    }
    TEST(Ss2022CodecDeep, AcceptFactoryRejectsWrongRawPsk)
    {
        ss::ClientConfig Client;
        Client.Psk.fill(0xA5);
        ss::ServerConfig Server;
        Server.Psk.fill(0x5A);
        const auto Result = ExecuteFactoryHandshake(
            FactoryHandshakeRequest{Client, Server});
        EXPECT_EQ(Result.ServerError, Error::BadAuth);
        EXPECT_NE(Result.ClientError, Error::None);
        EXPECT_FALSE(Result.ClientConnected);
    }
    TEST(Ss2022CodecDeep, AcceptFactoryUsesExplicitPsk)
    {
        const std::array<std::uint8_t, 16> Psk{
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40};
        ss::ClientConfig Client;
        Client.Psk = Psk;
        ss::ServerConfig Server;
        Server.Psk = Psk;
        const auto Result = ExecuteFactoryHandshake(
            FactoryHandshakeRequest{Client, Server});
        EXPECT_EQ(Result.ClientError, Error::None);
        EXPECT_EQ(Result.ServerError, Error::None);
        EXPECT_TRUE(Result.ClientConnected);
    }
    auto RunChunkCodecErrors() -> void
    {
        std::array<std::uint8_t, 16> Key{};
        const std::array<std::uint8_t, 15> ShortKey{};
        const std::array<std::uint8_t, 12> Nonce{};
        const std::array<std::uint8_t, 11> ShortNonce{};
        std::vector<std::uint8_t> Sealed;
        EXPECT_EQ(ss::detail::AeadSeal(
                      ss::detail::AeadInput{ShortKey, Nonce, std::array<std::uint8_t, 1>{0x42}}, Sealed),
                  0U);
        EXPECT_EQ(ss::detail::AeadSeal(
                      ss::detail::AeadInput{Key, ShortNonce, std::array<std::uint8_t, 1>{0x42}}, Sealed),
                  0U);
        EXPECT_TRUE(ss::ChunkCodec(ShortKey).Seal(std::array<std::uint8_t, 1>{0x42}).empty());
        ss::ChunkCodec Codec(std::span<const std::uint8_t>(Key), 3);
        ss::ChunkCodec Decoder(std::span<const std::uint8_t>(Key), 3);
        EXPECT_FALSE(Codec.OpenLen(std::span<const std::uint8_t>(MakeBytes({1, 2}))).has_value());
        std::vector<std::uint8_t> BadHeader(18, 0);
        BadHeader[17] = 0xFF;
        EXPECT_FALSE(Codec.OpenLen(BadHeader).has_value());
        const auto Wire = Decoder.Seal(AsU8Span(std::string_view{"hello"}));
        std::size_t Consumed = 0;
        const auto Plain = Codec.Open(Wire, Consumed);
        EXPECT_EQ(Plain.size(), 5u);
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(Plain.data()), Plain.size()), "hello");
        EXPECT_EQ(Consumed, Wire.size());
        ss::ChunkCodec Codec2(std::span<const std::uint8_t>(Key), 3);
        ss::ChunkCodec Decoder2(std::span<const std::uint8_t>(Key), 3);
        const auto Fin = Decoder2.Finish();
        std::size_t FinConsumed = 0;
        EXPECT_TRUE(Codec2.Open(Fin, FinConsumed).empty());
        EXPECT_EQ(FinConsumed, 18u);
        ss::ChunkCodec Codec3(std::span<const std::uint8_t>(Key), 3);
        ss::ChunkCodec Decoder3(std::span<const std::uint8_t>(Key), 3);
        const auto Big = Decoder3.Seal(AsU8Span(std::string_view{"12345678"}));
        std::size_t Consumed3 = 0;
        EXPECT_TRUE(Codec3.Open(std::span<const std::uint8_t>(Big).first(20), Consumed3).empty());
        ss::ChunkCodec Codec4(std::span<const std::uint8_t>(Key), 3);
        EXPECT_TRUE(Codec4.OpenPayload(std::span<const std::uint8_t>(MakeBytes({1, 2}))).empty());
        std::vector<std::uint8_t> BadBody(17, 0);
        BadBody[16] = 0xFF;
        EXPECT_TRUE(Codec4.OpenPayload(BadBody).empty());
        ss::ChunkCodec Codec5(std::span<const std::uint8_t>(Key), 3);
        ss::ChunkCodec Decoder5(std::span<const std::uint8_t>(Key), 3);
        std::vector<std::uint8_t> MaxPayload(ss::MaxChunkSize, 0xAB);
        const auto MaxWire = Decoder5.Seal(MaxPayload);
        EXPECT_FALSE(MaxWire.empty());
        std::vector<std::uint8_t> TooLarge(static_cast<std::size_t>(ss::MaxChunkSize) + 1, 0xAB);
        EXPECT_TRUE(Codec5.Seal(TooLarge).empty());
        ss::ChunkCodec RetryEncoder{std::span<const std::uint8_t>(Key)};
        ss::ChunkCodec RetryDecoder{std::span<const std::uint8_t>(Key)};
        const auto RetryWire = RetryEncoder.Seal(AsU8Span(std::string_view{"retry"}));
        std::size_t RetryConsumed = 0;
        EXPECT_TRUE(RetryDecoder.Open(std::span<const std::uint8_t>(RetryWire).first(20), RetryConsumed).empty());
        const auto RetryPlain = RetryDecoder.Open(RetryWire, RetryConsumed);
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(RetryPlain.data()), RetryPlain.size()), "retry");
        ss::ChunkCodec Codec6(std::span<const std::uint8_t>(Key), 3);
        ss::ChunkCodec Decoder6(std::span<const std::uint8_t>(Key), 3);
        std::vector<std::uint8_t> BigPayload(20000, 0xAB);
        const auto BigWire = Decoder6.Seal(BigPayload);
        EXPECT_TRUE(Codec6.OpenLen(std::span<const std::uint8_t>(BigWire).first(18)).has_value());
    }
    TEST(Ss2022CodecDeep, ChunkCodecErrors)
    {
        RunChunkCodecErrors();
    }
    TEST(Ss2022CodecDeep, SessionKeyOutputBufferMatchesVector)
    {
        const std::array<std::uint8_t, 16> Psk{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                               0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        const std::array<std::uint8_t, 16> Salt{0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99,
                                                0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11};
        const auto VectorResult = ss::SessionKey(Psk, Salt, 16);
        std::array<std::uint8_t, 16> BufferResult{};
        ss::SessionKey(Psk, Salt, std::span<std::uint8_t>(BufferResult));
        EXPECT_EQ(std::vector<std::uint8_t>(BufferResult.begin(), BufferResult.end()), VectorResult);
    }
    auto RunSessionKeyAndUdp() -> void
    {
        std::array<std::uint8_t, 16> Psk{};
        Psk.fill(0x11);
        std::array<std::uint8_t, 16> Salt{};
        Salt.fill(0x22);
        const auto Key = ss::SessionKey(Psk, Salt, 16);
        EXPECT_EQ(Key.size(), 16u);
        ss::Address Destination{};
        Destination.Type = ss::AddressType::Ipv4;
        Destination.Host = "1.2.3.4";
        Destination.Port = 443;
        const auto Packet = ss::BuildUdpPacket(
            ss::UdpBuildInput{Key, 7, &Destination, AsU8Span(std::string_view{"Data"})});
        EXPECT_GT(Packet.size(), 16u);
        ss::Address ParsedDestination{};
        std::vector<std::uint8_t> ParsedPayload;
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{Key, Packet, &ParsedDestination, &ParsedPayload}), Error::None);
        EXPECT_EQ(ParsedDestination.Host, "1.2.3.4");
        EXPECT_EQ(std::string_view(reinterpret_cast<const char *>(ParsedPayload.data()), ParsedPayload.size()),
                  "Data");
        for (const auto Length : std::array<std::size_t, 6>{0, 7, 8, 15, 17, 32})
        {
            const std::vector<std::uint8_t> ShortKey(Length, 0x33);
            EXPECT_TRUE(ss::BuildUdpPacket(
                            ss::UdpBuildInput{ShortKey, 7, &Destination, AsU8Span(std::string_view{"Data"})})
                            .empty())
                << "Build 应拒绝 key length=" << Length;
            EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{ShortKey, Packet, &ParsedDestination, &ParsedPayload}),
                      Error::BadLength)
                << "Parse 应拒绝 key length=" << Length;
        }
        std::vector<std::uint8_t> Oversized(ss::MaxUdpPayload + 1, 0xAA);
        EXPECT_TRUE(ss::BuildUdpPacket(
                        ss::UdpBuildInput{Key, 8, &Destination, Oversized})
                        .empty());
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{Key, Packet, nullptr, &ParsedPayload}),
                  Error::BadLength);
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{Key, std::span<const std::uint8_t>(Packet).first(10),
                                                            &ParsedDestination, &ParsedPayload}),
                  Error::BadLength);
        std::array<std::uint8_t, 16> WrongKey{};
        WrongKey.fill(0x99);
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{WrongKey, Packet, &ParsedDestination, &ParsedPayload}),
                  Error::BadAuth);
        auto BadType = Packet;
        BadType[16] ^= 0x01;
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{Key, BadType, &ParsedDestination, &ParsedPayload}),
                  Error::BadAuth);
        auto BadTag = Packet;
        BadTag.back() ^= 0x01;
        EXPECT_EQ(ss::ParseUdpPacket(ss::UdpParseInput{Key, BadTag, &ParsedDestination, &ParsedPayload}),
                  Error::BadAuth);
    }
    TEST(Ss2022CodecDeep, SessionKeyAndUdp)
    {
        RunSessionKeyAndUdp();
    }
    TEST(Ss2022CodecDeep, RejectsUnknownAddressTypeInVarHeader)
    {
        const std::vector<std::uint8_t> Wire{0xFF, 0x00, 0x00, 0x50, 0x00, 0x00};
        ss::Address Target{};
        std::span<const std::uint8_t> Payload;
        EXPECT_EQ(ss::ParseVarHeader(Wire, Target, Payload), Error::BadAddress);
    }
    TEST(Ss2022CodecDeep, DistinguishesEmptyPayloadFromBadAuthentication)
    {
        const std::array<std::uint8_t, 16> Key{0x01, 0x02, 0x03, 0x04,
                                                0x05, 0x06, 0x07, 0x08,
                                                0x09, 0x0A, 0x0B, 0x0C,
                                                0x0D, 0x0E, 0x0F, 0x10};
        ss::Address Target{};
        Target.Type = ss::AddressType::Ipv4;
        Target.Host = "192.0.2.1";
        Target.Port = 443;
        const auto EmptyPacket = ss::BuildUdpPacket(
            ss::UdpBuildInput{Key, 99, &Target, std::span<const std::uint8_t>{}});
        ASSERT_FALSE(EmptyPacket.empty());
        ss::Address ParsedTarget{};
        std::vector<std::uint8_t> ParsedPayload{0xFF};
        EXPECT_EQ(ss::ParseUdpPacket(
                      ss::UdpParseInput{Key, EmptyPacket, &ParsedTarget, &ParsedPayload}),
                  Error::None);
        EXPECT_TRUE(ParsedPayload.empty());
        auto TamperedPacket = EmptyPacket;
        TamperedPacket.back() ^= 0x01;
        EXPECT_EQ(ss::ParseUdpPacket(
                      ss::UdpParseInput{Key, TamperedPacket, &ParsedTarget, &ParsedPayload}),
                  Error::BadAuth);
    }
    auto RunHandshakeParserErrors() -> void
    {
        std::array<std::uint8_t, 16> Psk{};
        Psk.fill(0x11);
        ss::Serializer Serializer(Psk);
        ss::Message Message{};
        Message.dst.Type = ss::AddressType::Ipv4;
        Message.dst.Host = "8.8.8.8";
        Message.dst.Port = 53;
        Message.InitialPayload = "hello";
        Serializer.Reset(Message, 1000);
        std::array<std::uint8_t, 2048> Buffer{};
        std::error_code ErrorCode;
        const auto Count = Serializer.Get(Net::buffer(Buffer.data(), Buffer.size()), ErrorCode);
        const auto Wire = std::vector<std::uint8_t>(Buffer.begin(), Buffer.begin() + Count);
        ss::Parser Parser(Psk);
        EXPECT_EQ(Parser.Put(Net::buffer(Wire), ErrorCode), Wire.size());
        EXPECT_TRUE(Parser.IsDone());
        EXPECT_EQ(Parser.Get().dst.Host, "8.8.8.8");
        EXPECT_EQ(Parser.Get().InitialPayload, "hello");
        Parser.Reset();
        EXPECT_EQ(Parser.Put(Net::buffer(MakeBytes({0x01})), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::NeedMore));
        Parser.Reset();
        auto Tampered = Wire;
        Tampered[30] ^= 0x01;
        EXPECT_EQ(Parser.Put(Net::buffer(Tampered), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::AuthFailed));
        Parser.Reset();
        const auto Truncated = std::vector<std::uint8_t>(Wire.begin(), Wire.end() - 40);
        EXPECT_EQ(Parser.Put(Net::buffer(Truncated), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::NeedMore));
        Parser.Reset();
        auto Tampered2 = Wire;
        Tampered2[Tampered2.size() - 1] ^= 0x01;
        EXPECT_EQ(Parser.Put(Net::buffer(Tampered2), ErrorCode), 0u);
        EXPECT_EQ(ErrorCode, make_error_code(Error::AuthFailed));
    }
    TEST(Ss2022CodecDeep, HandshakeParserErrors)
    {
        RunHandshakeParserErrors();
    }
    TEST(Ss2022CodecDeep, ConnAndDgramDecorators)
    {
        Net::io_context IoContext;
        RunCoroutine(IoContext, RunConnAndDgramDecorators(IoContext));
    }
} // namespace

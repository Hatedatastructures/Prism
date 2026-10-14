/**
 * @file TrojanConnSession.cpp
 * @brief Trojan Conn/Dgram 会话层双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 Connect / 服务端 Accept 握手（domain / ipv4 目标）+ 双向回显
 * 2. 预读缓冲消费路径（ReadSome 的 Used_ > 0 分支）
 * 3. UDP 数据面：ConnectPacket / AcceptPacket + Dgram 收发往返
 * 4. 错误分支：bad_auth / bad_magic / bad_message / not_supported / io_error
 * 5. 装饰器链方法：Executor / Close / Cancel / NextLayer / Release
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Trojan/Trojan.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trojan = Preview::Trojan;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using Preview::PreviewMockTransport;
    using Preview::SharedTransmission;

    /// 构造 trojan 目标地址
    auto MakeAddress(Trojan::AddressType Type, std::string Host, std::uint16_t Port)
        -> Trojan::Address
    {
        Trojan::Address Address{};
        Address.Type = Type;
        Address.Host = std::move(Host);
        Address.Port = Port;
        return Address;
    }

    using CompletionChannel = Net::experimental::channel<void(boost::system::error_code)>;

    struct EagerVoidTask final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    /** @brief 立即启动 void awaitable，并拥有 completion/首异常状态。 */
    auto SpawnEagerVoid(Net::any_io_executor Executor, Net::awaitable<void> Operation)
        -> EagerVoidTask
    {
        EagerVoidTask State{
            std::make_shared<CompletionChannel>(Executor, 1),
            std::make_shared<std::exception_ptr>()};
        Net::co_spawn(
            Executor,
            std::move(Operation),
            [State](std::exception_ptr ErrorValue)
            {
                *State.Failure = ErrorValue;
                (void)State.Done->try_send(boost::system::error_code{});
            });
        return State;
    }

    /** @brief 等待 eager void task 的真实 completion，并传播首异常。 */
    auto WaitEagerVoid(EagerVoidTask State) -> Net::awaitable<void>
    {
        (void)co_await State.Done->async_receive(Net::use_awaitable);
        if (*State.Failure)
        {
            std::rethrow_exception(*State.Failure);
        }
    }

    using HandshakeResult = std::expected<Trojan::AcceptedConnection, Preview::Fault::Failure>;

    struct EagerHandshakeTask final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Failure;
        std::shared_ptr<std::optional<HandshakeResult>> Result;
    };

    /** @brief 立即启动 Trojan Accept，并拥有 typed handshake result。 */
    auto SpawnEagerAccept(
        Net::any_io_executor Executor,
        SharedTransmission Server,
        Trojan::ServerConfig Config) -> EagerHandshakeTask
    {
        EagerHandshakeTask State{
            std::make_shared<CompletionChannel>(Executor, 1),
            std::make_shared<std::exception_ptr>(),
            std::make_shared<std::optional<HandshakeResult>>()};
        Net::co_spawn(
            Executor,
            Trojan::Accept(std::move(Server), Config),
            [State](std::exception_ptr ErrorValue, HandshakeResult Result)
            {
                *State.Failure = ErrorValue;
                if (!ErrorValue)
                {
                    *State.Result = std::move(Result);
                }
                (void)State.Done->try_send(boost::system::error_code{});
            });
        return State;
    }

    /** @brief 等待 typed Accept completion 并返回 owning result。 */
    auto WaitEagerAccept(EagerHandshakeTask State) -> Net::awaitable<HandshakeResult>
    {
        (void)co_await State.Done->async_receive(Net::use_awaitable);
        if (*State.Failure)
        {
            std::rethrow_exception(*State.Failure);
        }
        if (!State.Result->has_value())
        {
            throw std::runtime_error("Trojan Accept completion had no result");
        }
        co_return std::move(**State.Result);
    }

    /** @brief 在拥有任务退栈后关闭两端并等待实际 I/O drain。 */
    auto CloseAndDrain(SharedTransmission Client, SharedTransmission Server)
        -> Net::awaitable<void>
    {
        const auto ClientClose = Client->Close();
        const auto ServerClose = Server->Close();
        EXPECT_TRUE(ClientClose && ServerClose);
        const auto ClientDrain = co_await Client->Activity()->Drain();
        const auto ServerDrain = co_await Server->Activity()->Drain();
        EXPECT_TRUE(ClientDrain && ServerDrain);
    }

    /** @brief 关闭单个协议 owner 并等待其 I/O activity 完全退栈。 */
    auto CloseAndDrain(SharedTransmission Connection) -> Net::awaitable<void>
    {
        if (!Connection)
        {
            co_return;
        }
        const auto Close = Connection->Close();
        EXPECT_TRUE(Close);
        const auto Drain = co_await Connection->Activity()->Drain();
        EXPECT_TRUE(Drain);
    }

    enum class RejectClientAction
    {
        RawWire,
        Connect,
        ConnectPacket
    };

    struct HandshakeRejectRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        Trojan::ServerConfig Config;
        std::vector<std::uint8_t> Wire;
        Trojan::Address Target;
        std::string ClientPassword;
        Error Expected;
        RejectClientAction Action;
    };

    /** @brief 接收流/UDP 禁用或非法握手并验证错误码与空连接。 */
    auto RunHandshakeRejectServer(HandshakeRejectRequest Request) -> Net::awaitable<void>
    {
        if (Request.Action == RejectClientAction::ConnectPacket)
        {
            auto Result = co_await Trojan::AcceptPacket(
                std::move(Request.Server), Request.Config);
            EXPECT_FALSE(Result);
            if (Result) co_return;
            EXPECT_EQ(Result.error().Code,
                      Preview::Fault::ToCode(Preview::make_error_code(Request.Expected)));
            co_return;
        }
        auto Result = co_await Trojan::Accept(
            std::move(Request.Server), Request.Config);
        EXPECT_FALSE(Result);
        if (Result) co_return;
        EXPECT_EQ(Result.error().Code,
                  Preview::Fault::ToCode(Preview::make_error_code(Request.Expected)));
    }

    /** @brief 驱动 raw wire、Connect 或 ConnectPacket 错误握手并等待 server。 */
    auto RunHandshakeReject(HandshakeRejectRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnEagerVoid(
            Request.Server->Executor(),
            RunHandshakeRejectServer(Request));
        std::exception_ptr ParentFailure;
        try
        {
            if (Request.Action == RejectClientAction::RawWire)
            {
                const auto Write = co_await Request.Client->WriteExact(
                    AsBytes(std::span<const std::uint8_t>(Request.Wire)));
                EXPECT_FALSE(Write.Failure.Failed());
                EXPECT_EQ(Write.Bytes, Request.Wire.size());
            }
            else if (Request.Action == RejectClientAction::ConnectPacket)
            {
                auto Result = co_await Trojan::ConnectPacket(
                    Request.Client,
                    Trojan::ClientConfig{Request.ClientPassword},
                    Request.Target);
                EXPECT_TRUE(Result);
                if (Result) EXPECT_TRUE(*Result);
            }
            else
            {
                auto Result = co_await Trojan::Connect(Trojan::ConnectParameters{
                    Request.Client,
                    Trojan::ClientConfig{Request.ClientPassword},
                    Request.Target});
                EXPECT_TRUE(Result);
                if (Result) EXPECT_TRUE(*Result);
            }
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        const auto Shutdown = co_await Request.Client->WriteShutdown();
        EXPECT_TRUE(Shutdown);
        if (!Shutdown)
        {
            const auto ClientClose = Request.Client->Close();
            EXPECT_TRUE(ClientClose);
        }
        co_await WaitEagerVoid(std::move(ServerTask));
        co_await CloseAndDrain(Request.Client, Request.Server);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }


    struct EchoRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        std::string Payload;
    };

    /** @brief Trojan 服务端认证、读取并回显一个 stream payload。 */
    auto RunEchoServer(EchoRequest Request) -> Net::awaitable<void>
    {
        Trojan::ServerConfig Config;
        Config.Password = "pw123456";
        Config.EnableUdp = true;
        auto Result = co_await Trojan::Accept(
            std::move(Request.Server), Config);
        EXPECT_TRUE(Result);
        if (!Result)
        {
            co_return;
        }
        EXPECT_TRUE(Result->Connection);
        if (!Result->Connection) co_return;
        auto RequestValue = std::move(Result->Request);
        auto Connection = std::move(Result->Connection);
        EXPECT_EQ(RequestValue.Cmd, Trojan::Command::Connect);
        EXPECT_EQ(RequestValue.Target.Host, "example.com");
        EXPECT_EQ(RequestValue.Target.Port, 443u);
        EXPECT_EQ(Connection->Request().Target.Host, "example.com");
        std::array<std::byte, 1024> Buffer{};
        const auto Read = co_await Connection->ReadExact(
            std::span<std::byte>(Buffer.data(), Request.Payload.size()));
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_EQ(Read.Bytes, Request.Payload.size());
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Read.Bytes),
                  Request.Payload);
        const auto Written = co_await Connection->WriteExact(
            std::span<const std::byte>(Buffer.data(), Read.Bytes));
        EXPECT_FALSE(Written.Failure.Failed());
        EXPECT_EQ(Written.Bytes, Read.Bytes);
        co_await CloseAndDrain(Connection);
    }

    /** @brief 驱动 Trojan stream raw handshake 与双向回显。 */
    auto RunEcho(EchoRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnEagerVoid(
            Request.Server->Executor(),
            RunEchoServer(EchoRequest{Request.Client, Request.Server, Request.Payload}));
        std::exception_ptr ParentFailure;
        try
        {
            const auto Credential = Trojan::Credential("pw123456");
            const auto Header = Trojan::BuildRequest(
                Credential, Trojan::Command::Connect,
                MakeAddress(Trojan::AddressType::Domain, "example.com", 443));
            std::vector<std::uint8_t> Wire = Header;
            Wire.insert(Wire.end(), Request.Payload.begin(), Request.Payload.end());
            const auto Write = co_await Request.Client->WriteExact(
                AsBytes(std::span<const std::uint8_t>(Wire)));
            EXPECT_FALSE(Write.Failure.Failed());
            EXPECT_EQ(Write.Bytes, Wire.size());
            std::array<std::byte, 1024> Echo{};
            const auto Read = co_await Request.Client->ReadExact(
                std::span<std::byte>(Echo.data(), Request.Payload.size()));
            EXPECT_FALSE(Read.Failure.Failed());
            EXPECT_EQ(Read.Bytes, Request.Payload.size());
            EXPECT_EQ(std::string(reinterpret_cast<const char *>(Echo.data()), Read.Bytes),
                      Request.Payload);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await WaitEagerVoid(std::move(ServerTask));
        co_await CloseAndDrain(Request.Client, Request.Server);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    struct FactoryIpv4Request final
    {
        SharedTransmission Client;
        SharedTransmission Server;
    };

    /** @brief 驱动 Trojan factory Connect/Accept 的 IPv4 场景。 */
    auto RunFactoryIpv4(FactoryIpv4Request Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnEagerAccept(
            Request.Server->Executor(),
            Request.Server, Trojan::ServerConfig{"pw"});
        SharedTransmission ClientConnection;
        std::exception_ptr ParentFailure;
        try
        {
            auto Result = co_await Trojan::Connect(Trojan::ConnectParameters{
                Request.Client, Trojan::ClientConfig{"pw"},
                MakeAddress(Trojan::AddressType::Ipv4, "1.2.3.4", 80)});
            EXPECT_TRUE(Result);
            if (Result) EXPECT_TRUE(*Result);
            if (Result && *Result) ClientConnection = std::move(*Result);
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        auto ServerResult = co_await WaitEagerAccept(std::move(ServerTask));
        EXPECT_TRUE(ServerResult);
        if (ServerResult) EXPECT_TRUE(ServerResult->Connection);
        if (ServerResult && ServerResult->Connection)
        {
            EXPECT_EQ(ServerResult->Request.Cmd, Trojan::Command::Connect);
            EXPECT_EQ(ServerResult->Request.Target.Type, Trojan::AddressType::Ipv4);
            EXPECT_EQ(ServerResult->Request.Target.Host, "1.2.3.4");
            EXPECT_EQ(ServerResult->Request.Target.Port, 80u);
            co_await CloseAndDrain(ServerResult->Connection);
        }
        co_await CloseAndDrain(ClientConnection);
        co_await CloseAndDrain(Request.Client, Request.Server);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    struct UdpRoundtripRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
    };

    /** @brief Trojan UDP server side receives both original datagrams. */
    auto RunUdpRoundtripServer(UdpRoundtripRequest Request) -> Net::awaitable<void>
    {
        Trojan::ServerConfig Config;
        Config.Password = "pw";
        Config.EnableUdp = true;
        auto AcceptResult = co_await Trojan::AcceptPacket(
            std::move(Request.Server), Config);
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (!AcceptResult || !AcceptResult->Connection) co_return;
        auto RequestValue = std::move(AcceptResult->Request);
        auto Datagram = std::move(AcceptResult->Connection);
        EXPECT_TRUE(Datagram);
        if (!Datagram)
        {
            co_return;
        }
        EXPECT_EQ(RequestValue.Cmd, Trojan::Command::UdpAssociate);
        EXPECT_EQ(Datagram->TransportType(), Preview::Transmission::Type::Udp);
        for (int Index = 0; Index < 2; ++Index)
        {
            Trojan::Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Source, Payload);
            EXPECT_TRUE(ReceiveError.Failure.Succeeded());
            if (Index == 0)
            {
                EXPECT_EQ(Source.Type, Trojan::AddressType::Domain);
                EXPECT_EQ(Source.Host, "example.com");
                EXPECT_EQ(Source.Port, 53u);
            }
            else
            {
                EXPECT_EQ(Source.Type, Trojan::AddressType::Ipv4);
                EXPECT_EQ(Source.Host, "8.8.8.8");
                EXPECT_EQ(Source.Port, 443u);
            }
            const std::string Expected = Index == 0 ? "dns query" : "second pkt";
            EXPECT_EQ(std::string(Payload.begin(), Payload.end()), Expected);
        }
        EXPECT_TRUE(Datagram->Stream());
        co_await CloseAndDrain(Datagram);
    }

    /** @brief 驱动 Trojan UDP client，并等待服务端收到两包。 */
    auto RunUdpRoundtrip(UdpRoundtripRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnEagerVoid(
            Request.Server->Executor(),
            RunUdpRoundtripServer(UdpRoundtripRequest{Request.Client, Request.Server}));
        SharedTransmission ClientDatagram;
        std::exception_ptr ParentFailure;
        try
        {
            auto ConnectResult = co_await Trojan::ConnectPacket(
                Request.Client, Trojan::ClientConfig{"pw"},
                MakeAddress(Trojan::AddressType::Domain, "example.com", 53));
            EXPECT_TRUE(ConnectResult);
        if (ConnectResult) EXPECT_TRUE(*ConnectResult);
            if (ConnectResult && *ConnectResult)
            {
                auto Datagram = std::move(*ConnectResult);
                const std::string First = "dns query";
                const auto FirstError = co_await Datagram->AsyncSendTo(
                    MakeAddress(Trojan::AddressType::Domain, "example.com", 53), AsU8Span(First));
                EXPECT_TRUE(FirstError.Failure.Succeeded());
                const std::string Second = "second pkt";
                const auto SecondError = co_await Datagram->AsyncSendTo(
                    MakeAddress(Trojan::AddressType::Ipv4, "8.8.8.8", 443), AsU8Span(Second));
                EXPECT_TRUE(SecondError.Failure.Succeeded());
                ClientDatagram = std::move(Datagram);
            }
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await WaitEagerVoid(std::move(ServerTask));
        if (ClientDatagram)
        {
            co_await CloseAndDrain(ClientDatagram);
        }
        co_await CloseAndDrain(Request.Client, Request.Server);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    /** @brief 接收 Trojan Mux 命令并返回握手 tuple。 */
    auto RunMuxAccept(SharedTransmission Server)
        -> Net::awaitable<std::expected<Trojan::AcceptedConnection, Preview::Fault::Failure>>
    {
        co_return co_await Trojan::Accept(
            std::move(Server), Trojan::ServerConfig{"pw"});
    }

    struct MuxHandoffRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
    };

    /** @brief 驱动 Trojan Mux 命令并验证 TCP handoff。 */
    auto RunMuxHandoff(MuxHandoffRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnEagerAccept(
            Request.Server->Executor(), Request.Server, Trojan::ServerConfig{"pw"});
        std::exception_ptr ParentFailure;
        try
        {
            const auto Wire = Trojan::BuildRequest(
                Trojan::Credential("pw"), Trojan::Command::Mux,
                MakeAddress(Trojan::AddressType::Domain, "example.com", 443));
            const auto Write = co_await Request.Client->WriteExact(
                AsBytes(std::span<const std::uint8_t>(Wire)));
            EXPECT_FALSE(Write.Failure.Failed());
            EXPECT_EQ(Write.Bytes, Wire.size());
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        auto AcceptResult = co_await WaitEagerAccept(std::move(ServerTask));
        EXPECT_TRUE(AcceptResult);
        if (AcceptResult) EXPECT_TRUE(AcceptResult->Connection);
        if (AcceptResult && AcceptResult->Connection)
        {
            EXPECT_EQ(AcceptResult->Request.Cmd, Trojan::Command::Mux);
            co_await CloseAndDrain(AcceptResult->Connection);
        }
        co_await CloseAndDrain(Request.Client, Request.Server);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    struct DecoratorChainRequest final
    {
        SharedTransmission Client;
        SharedTransmission Peer;
    };

    /** @brief 验证 Trojan Conn 装饰器导航、组合读写和 Release。 */
    auto RunDecoratorChain(DecoratorChainRequest Request) -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Trojan::Conn<>>(
            std::move(Request.Client), "pw");
        EXPECT_TRUE(Connection->Executor());
        EXPECT_NE(Connection->NextLayer(), nullptr);
        EXPECT_NE(Connection->lowest_layer<MemoryStream>(), nullptr);
        const auto *ConstConnection = Connection.get();
        EXPECT_NE(ConstConnection->NextLayer(), nullptr);
        const std::string Payload = "passthrough";
        const auto Written = co_await Connection->WriteExact(
            std::span<const std::byte>(
                reinterpret_cast<const std::byte *>(Payload.data()), Payload.size()));
        EXPECT_FALSE(Written.Failure.Failed());
        EXPECT_EQ(Written.Bytes, Payload.size());
        std::array<std::byte, 64> Buffer{};
        const auto PeerRead = co_await Request.Peer->ReadExact(
            std::span<std::byte>(Buffer.data(), Payload.size()));
        EXPECT_FALSE(PeerRead.Failure.Failed());
        EXPECT_EQ(PeerRead.Bytes, Payload.size());
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), PeerRead.Bytes), Payload);
        const auto PeerWrite = co_await Request.Peer->WriteExact(
            std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_FALSE(PeerWrite.Failure.Failed());
        EXPECT_EQ(PeerWrite.Bytes, 4u);
        std::array<std::uint8_t, 4> Destination{};
        const auto Received = co_await Connection->ReadExact(AsBytes(std::span(Destination)));
        EXPECT_FALSE(Received.Failure.Failed());
        EXPECT_EQ(Received.Bytes, Destination.size());
        const auto Close = Connection->Close();
        EXPECT_TRUE(Close);
        const auto Cancel = Connection->Cancel();
        EXPECT_TRUE(Cancel);
        const auto Drain = co_await Connection->Activity()->Drain();
        EXPECT_TRUE(Drain);
        auto Released = Connection->Release();
        EXPECT_TRUE(Released);
        const auto PeerClose = Request.Peer->Close();
        EXPECT_TRUE(PeerClose);
        const auto PeerDrain = co_await Request.Peer->Activity()->Drain();
        EXPECT_TRUE(PeerDrain);
        EXPECT_EQ(Connection->NextLayer(), nullptr);
    }

    /// 运行协程直至完成（异常重抛）
    template <typename A>
    auto RunCoroutine(Net::io_context &IoContext, A Coroutine) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(IoContext, std::move(Coroutine),
                      [&](std::exception_ptr ErrorValue)
                      {
                          Exception = ErrorValue;
                          IoContext.stop();
                      });
        IoContext.run();
        if (Exception)
        {
            std::rethrow_exception(Exception);
        }
    }

    TEST(TrojanConnSession, ConnectAcceptEcho)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const std::string Payload = "trojan echo payload";
        RunCoroutine(IoContext, RunEcho(EchoRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)), Payload}));
    }

    TEST(TrojanConnSession, FactoryConnectAcceptIpv4)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunFactoryIpv4(FactoryIpv4Request{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream))}));
    }

    TEST(TrojanConnSession, UdpDgramRoundtrip)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunUdpRoundtrip(UdpRoundtripRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream))}));
    }

    TEST(TrojanConnSession, BadAuthRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const auto Credential = Trojan::Credential("wrong-pw");
        std::vector<std::uint8_t> Wire(Credential.begin(), Credential.end());
        Wire.insert(Wire.end(), {'\r', '\n', 0x01, 0x01, 1, 2, 3, 4, 0, 80, '\r', '\n'});
        RunCoroutine(IoContext, RunHandshakeReject(HandshakeRejectRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Trojan::ServerConfig{"Expect-pw"}, Wire,
            MakeAddress(Trojan::AddressType::Domain, "example.com", 443),
            "wrong-pw", Error::BadAuth, RejectClientAction::RawWire}));
    }

    TEST(TrojanConnSession, BadMagicCrlfRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const auto Credential = Trojan::Credential("pw");
        std::vector<std::uint8_t> Wire(Credential.begin(), Credential.end());
        Wire.insert(Wire.end(), {'\r', 'X'});
        RunCoroutine(IoContext, RunHandshakeReject(HandshakeRejectRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Trojan::ServerConfig{"pw"}, Wire,
            MakeAddress(Trojan::AddressType::Domain, "example.com", 443),
            "pw", Error::BadMagic, RejectClientAction::RawWire}));
    }

    TEST(TrojanConnSession, BadCommandRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const auto Credential = Trojan::Credential("pw");
        std::vector<std::uint8_t> Wire(Credential.begin(), Credential.end());
        Wire.insert(Wire.end(), {'\r', '\n', 0x99, 0x01, 1, 1, 0, 0, 0, 0, '\r', '\n'});
        RunCoroutine(IoContext, RunHandshakeReject(HandshakeRejectRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Trojan::ServerConfig{"pw"}, Wire,
            MakeAddress(Trojan::AddressType::Domain, "example.com", 443),
            "pw", Error::BadMessage, RejectClientAction::RawWire}));
    }

    TEST(TrojanConnSession, MuxCommandAcceptedByTcpHandoff)
    {
        Net::io_context Ioc;
        auto [Client, Server] = MakeMemoryPair(Ioc.get_executor());
        RunCoroutine(Ioc, RunMuxHandoff(MuxHandoffRequest{
            std::make_shared<MemoryStream>(std::move(Client)),
            std::make_shared<MemoryStream>(std::move(Server))}));
    }

    TEST(TrojanConnSession, TcpDisabledRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        Trojan::ServerConfig Config{"pw"};
        Config.EnableTcp = false;
        RunCoroutine(IoContext, RunHandshakeReject(HandshakeRejectRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Config, {}, MakeAddress(Trojan::AddressType::Domain, "example.com", 443),
            "pw", Error::NotSupported, RejectClientAction::Connect}));
    }

    TEST(TrojanConnSession, UdpDisabledRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        Trojan::ServerConfig Config{"pw"};
        Config.EnableUdp = false;
        RunCoroutine(IoContext, RunHandshakeReject(HandshakeRejectRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Config, {}, MakeAddress(Trojan::AddressType::Domain, "example.com", 53),
            "pw", Error::NotSupported, RejectClientAction::ConnectPacket}));
    }

    TEST(TrojanConnSession, BadAtypRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const auto Credential = Trojan::Credential("pw");
        std::vector<std::uint8_t> Wire(Credential.begin(), Credential.end());
        Wire.insert(Wire.end(), {'\r', '\n', 0x01, 0x99});
        RunCoroutine(IoContext, RunHandshakeReject(HandshakeRejectRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Trojan::ServerConfig{"pw"}, Wire,
            MakeAddress(Trojan::AddressType::Domain, "example.com", 443),
            "pw", Error::BadMessage, RejectClientAction::RawWire}));
    }

    TEST(TrojanConnSession, BadTailCrlfRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const auto Credential = Trojan::Credential("pw");
        std::vector<std::uint8_t> Wire(Credential.begin(), Credential.end());
        Wire.insert(Wire.end(), {'\r', '\n', 0x01, 0x01, 1, 2, 3, 4, 0x00, 0x50, '\r', 'X'});
        RunCoroutine(IoContext, RunHandshakeReject(HandshakeRejectRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Trojan::ServerConfig{"pw"}, Wire,
            MakeAddress(Trojan::AddressType::Domain, "example.com", 443),
            "pw", Error::BadMagic, RejectClientAction::RawWire}));
    }

    TEST(TrojanConnSession, TruncatedHeaderEof)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        const auto Credential = Trojan::Credential("pw");
        std::vector<std::uint8_t> Wire(Credential.begin(), Credential.end());
        Wire.push_back('\r');
        RunCoroutine(IoContext, RunHandshakeReject(HandshakeRejectRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            Trojan::ServerConfig{"pw"}, Wire,
            MakeAddress(Trojan::AddressType::Domain, "example.com", 443),
            "pw", Error::IoError, RejectClientAction::RawWire}));
    }

    auto RunWriteToClosedPeer(
        std::shared_ptr<MemoryStream> ClientOwner,
        std::shared_ptr<MemoryStream> ServerOwner) -> Net::awaitable<void>
    {
        co_await CloseAndDrain(ServerOwner);
        auto Result = co_await Trojan::Connect(Trojan::ConnectParameters{
            ClientOwner, Trojan::ClientConfig{"pw"},
            MakeAddress(Trojan::AddressType::Ipv4, "1.1.1.1", 80)});
        EXPECT_FALSE(Result);
        if (!Result)
        {
            EXPECT_EQ(Result.error().Code, Preview::Fault::Code::ConnectionAborted);
        }
        co_await CloseAndDrain(ClientOwner);
    }

    TEST(TrojanConnSession, WriteToClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        auto ClientOwner = std::make_shared<MemoryStream>(std::move(ClientStream));
        auto ServerOwner = std::make_shared<MemoryStream>(std::move(ServerStream));
        RunCoroutine(IoContext, RunWriteToClosedPeer(ClientOwner, ServerOwner));
    }

    TEST(TrojanConnSession, DecoratorChain)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());
        RunCoroutine(IoContext, RunDecoratorChain(DecoratorChainRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream))}));
    }

} // namespace

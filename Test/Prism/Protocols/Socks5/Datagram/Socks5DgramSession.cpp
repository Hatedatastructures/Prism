/**
 * @file Socks5DgramSession.cpp
 * @brief SOCKS5 Dgram 包连接双向测试（Client + Server 视角）
 * @details 覆盖：
 * 1. 客户端 ConnectPacket / 服务端 AcceptPacket（UDP_ASSOCIATE 握手）→ 数据报往返
 * 2. 地址解析：IPv4 / 域名 / IPv6
 * 3. 错误分支：bad_message（RSV/FRAG 非法、ATYP 非法）/ io_error / unexpected_eof
 * 4. 装饰器链方法：Executor / TransportType / NextLayer / Stream / Release
 * @note 使用 MakeMemoryPair 建立内存传输对，同一进程内双向互操作。
 */

#include <gtest/gtest.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Prism = ::Prism;
    namespace Socks5 = Prism::Socks5;

    using Address = Socks5::Address;
    using AddressType = Socks5::AddressType;
    using ClientConfig = Socks5::ClientConfig;
    using Dgram = Socks5::Dgram<>;
    using Error = Prism::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Prism::MemoryStream;
    using SharedMemoryStream = std::shared_ptr<MemoryStream>;
    using PrismMockTransport = Prism::PrismMockTransport;
    using ServerConfig = Socks5::ServerConfig;
    using Transmission = Prism::Transmission;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

    struct EagerTask final
    {
        std::shared_ptr<CompletionChannel> Done;
        std::shared_ptr<std::exception_ptr> Failure;
    };

    using Prism::AsBytes;
    using Prism::AsU8Span;
    using Prism::MakeMemoryPair;

    /** @brief 在发起 typed I/O 前将成对的内存端点转交给共享 owner。 */
    [[nodiscard]] auto MakeOwnedMemoryPair(ExecutorType Executor)
        -> std::pair<SharedMemoryStream, SharedMemoryStream>
    {
        auto [Client, Server] = MakeMemoryPair(std::move(Executor));
        return {std::make_shared<MemoryStream>(std::move(Client)),
                std::make_shared<MemoryStream>(std::move(Server))};
    }

    /// 运行协程直至完成（异常重抛）
    template <typename Awaitable>
    auto RunCoro(Net::io_context &IoContext, Awaitable Coroutine) -> void
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
        -> EagerTask
    {
        EagerTask State{
            std::make_shared<CompletionChannel>(Executor, 1),
            std::make_shared<std::exception_ptr>()};
        auto CompletionHandler =
            [State](std::exception_ptr Exception) -> void
        {
            *State.Failure = Exception;
            (void)State.Done->try_send(
                boost::system::error_code{},
                Exception == nullptr);
        };
        Net::co_spawn(
            Executor,
            std::move(Coroutine),
            std::move(CompletionHandler));
        return State;
    }

    /** @brief 等待 server operation 的真实完成并传播首异常。 */
    auto WaitServer(EagerTask State) -> Net::awaitable<bool>
    {
        const auto Completed =
            co_await State.Done->async_receive(Net::use_awaitable);
        if (*State.Failure)
        {
            std::rethrow_exception(*State.Failure);
        }
        co_return Completed;
    }

    /// 构造 SOCKS5 目标地址。
    [[nodiscard]] auto MakeAddress(
        const AddressType Type,
        std::string Host,
        const std::uint16_t Port) -> Address
    {
        Address Result{};
        Result.Type = Type;
        Result.Host = std::move(Host);
        Result.Port = Port;
        return Result;
    }

    struct DatagramRoundtripRequest final
    {
        Net::io_context &IoContext;
        SharedMemoryStream ClientMemory;
        SharedMemoryStream ServerMemory;
    };

    auto RunRoundtripServer(std::shared_ptr<MemoryStream> ServerStream)
        -> Net::awaitable<void>
    {
        ServerConfig Config;
        Config.EnableUdp = true;
        const auto Accepted = co_await Socks5::AcceptPacket(ServerStream, Config);
        if (!Accepted || !Accepted->Connection)
        {
            EXPECT_TRUE(false) << "AcceptPacket Failed";
            co_return;
        }
        const auto &Request = Accepted->RequestValue;
        const auto Datagram = Accepted->Connection;
        EXPECT_EQ(Request.Cmd, Socks5::Command::UdpAssociate);
        EXPECT_EQ(Datagram->TransportType(), Transmission::Type::Udp);
        for (int Index = 0; Index < 2; ++Index)
        {
            Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ReceiveError =
                co_await Datagram->AsyncReceiveFrom(Source, Payload);
            EXPECT_EQ(ReceiveError, Error::None);
            if (Index == 0)
            {
                EXPECT_EQ(Source.Type, AddressType::Domain);
                EXPECT_EQ(Source.Host, "example.com");
                EXPECT_EQ(Source.Port, 53u);
                EXPECT_EQ(std::string(Payload.begin(), Payload.end()), "dns query");
            }
            else
            {
                EXPECT_EQ(Source.Type, AddressType::Ipv4);
                EXPECT_EQ(Source.Host, "8.8.8.8");
                EXPECT_EQ(Source.Port, 443u);
                EXPECT_EQ(std::string(Payload.begin(), Payload.end()), "second pkt");
            }
        }
        EXPECT_TRUE(Datagram->Stream());
        EXPECT_NE(Datagram->NextLayer(), nullptr);
        EXPECT_NE(Datagram->lowest_layer<MemoryStream>(), nullptr);
        const Dgram *ConstDatagram = Datagram.get();
        EXPECT_NE(ConstDatagram->NextLayer(), nullptr);
        EXPECT_TRUE(Datagram->Executor());

        std::array<std::byte, 8> RawBuffer{};
        const std::span<std::byte> RawSpan(RawBuffer);
        const auto Read = co_await Datagram->ReadSome(RawSpan);
        EXPECT_FALSE(Read.Failure.Failed());
        EXPECT_EQ(Read.Bytes, 4u);
        const auto Close = Datagram->Close();
        EXPECT_TRUE(Close);
        const auto Cancel = Datagram->Cancel();
        EXPECT_TRUE(Cancel);
        const auto Drain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(Drain);
        auto Released = Datagram->Release();
        EXPECT_TRUE(Released);
    }

    auto RunSendReceiveRoundtrip(DatagramRoundtripRequest Request)
        -> Net::awaitable<void>
    {
        auto ClientStream = std::move(Request.ClientMemory);
        auto ServerStream = std::move(Request.ServerMemory);
        const auto ServerDone = SpawnServer(
            Request.IoContext.get_executor(), RunRoundtripServer(ServerStream));
        const auto Connected = co_await Socks5::ConnectPacket(
            ClientStream, ClientConfig{},
            MakeAddress(AddressType::Domain, "example.com", 53));
        EXPECT_TRUE(Connected);
        if (!Connected || !*Connected)
        {
            const auto ClientClose = ClientStream->Close();
            EXPECT_TRUE(ClientClose);
            const auto ServerClose = ServerStream->Close();
            EXPECT_TRUE(ServerClose);
            const auto ServerCompleted =
                co_await WaitServer(std::move(ServerDone));
            EXPECT_TRUE(ServerCompleted);
            const auto ClientDrain = co_await ClientStream->Activity()->Drain();
            EXPECT_TRUE(ClientDrain);
            const auto ServerDrain = co_await ServerStream->Activity()->Drain();
            EXPECT_TRUE(ServerDrain);
            co_return;
        }
        const auto Datagram = *Connected;

        const std::string FirstPayloadText = "dns query";
        const auto FirstPayload = AsU8Span(std::string_view(FirstPayloadText));
        const auto FirstError = co_await Datagram->AsyncSendTo(
            MakeAddress(AddressType::Domain, "example.com", 53), FirstPayload);
        EXPECT_EQ(FirstError, Error::None);
        const std::string SecondPayloadText = "second pkt";
        const auto SecondPayload = AsU8Span(std::string_view(SecondPayloadText));
        const auto SecondError = co_await Datagram->AsyncSendTo(
            MakeAddress(AddressType::Ipv4, "8.8.8.8", 443), SecondPayload);
        EXPECT_EQ(SecondError, Error::None);

        std::array<std::byte, 4> RawBuffer{};
        const std::span<const std::byte> RawSpan(RawBuffer);
        const auto Written = co_await Datagram->WriteSome(RawSpan);
        EXPECT_FALSE(Written.Failure.Failed());
        EXPECT_EQ(Written.Bytes, 4u);
        const auto ServerCompleted = co_await WaitServer(std::move(ServerDone));
        EXPECT_TRUE(ServerCompleted);
        const auto DatagramClose = Datagram->Close();
        EXPECT_TRUE(DatagramClose);
        const auto DatagramDrain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(DatagramDrain);
        const auto ClientClose = ClientStream->Close();
        EXPECT_TRUE(ClientClose);
        const auto ServerClose = ServerStream->Close();
        EXPECT_TRUE(ServerClose);
        const auto ClientDrain = co_await ClientStream->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
        const auto ServerDrain = co_await ServerStream->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
    }

    struct Ipv6Request final
    {
        Net::io_context &IoContext;
        SharedMemoryStream ClientMemory;
        SharedMemoryStream ServerMemory;
    };

    auto RunIpv6Server(std::shared_ptr<MemoryStream> ServerStream) -> Net::awaitable<void>
    {
        ServerConfig Config;
        Config.EnableUdp = true;
        const auto Accepted = co_await Socks5::AcceptPacket(ServerStream, Config);
        if (!Accepted || !Accepted->Connection)
        {
            co_return;
        }
        const auto &Request = Accepted->RequestValue;
        const auto Datagram = Accepted->Connection;
        Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ReceiveError, Error::None);
        EXPECT_EQ(Source.Type, AddressType::Ipv6);
        EXPECT_EQ(Source.Host, std::string(16, '\x21'));
        EXPECT_EQ(Source.Port, 8080u);
        EXPECT_EQ(std::string(Payload.begin(), Payload.end()), "v6 pkt");
        const auto Close = Datagram->Close();
        EXPECT_TRUE(Close);
        const auto Drain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(Drain);
        (void)Request;
    }

    auto RunIpv6Receive(Ipv6Request Request) -> Net::awaitable<void>
    {
        auto ClientStream = std::move(Request.ClientMemory);
        auto ServerStream = std::move(Request.ServerMemory);
        const auto ServerDone = SpawnServer(
            Request.IoContext.get_executor(), RunIpv6Server(ServerStream));
        const auto Connected = co_await Socks5::ConnectPacket(
            ClientStream, ClientConfig{},
            MakeAddress(AddressType::Domain, "example.com", 53));
        EXPECT_TRUE(Connected);
        if (!Connected || !*Connected)
        {
            const auto ClientClose = ClientStream->Close();
            EXPECT_TRUE(ClientClose);
            const auto ServerClose = ServerStream->Close();
            EXPECT_TRUE(ServerClose);
            const auto ServerCompleted =
                co_await WaitServer(std::move(ServerDone));
            EXPECT_TRUE(ServerCompleted);
            const auto ClientDrain = co_await ClientStream->Activity()->Drain();
            EXPECT_TRUE(ClientDrain);
            const auto ServerDrain = co_await ServerStream->Activity()->Drain();
            EXPECT_TRUE(ServerDrain);
            co_return;
        }
        const auto Datagram = *Connected;
        const std::string PayloadText = "v6 pkt";
        const auto Payload = AsU8Span(std::string_view(PayloadText));
        const auto SendError = co_await Datagram->AsyncSendTo(
            MakeAddress(AddressType::Ipv6, std::string(16, '\x21'), 8080), Payload);
        EXPECT_EQ(SendError, Error::None);
        const auto Shutdown = co_await ClientStream->WriteShutdown();
        EXPECT_TRUE(Shutdown);
        const auto ServerCompleted = co_await WaitServer(std::move(ServerDone));
        EXPECT_TRUE(ServerCompleted);
        const auto DatagramClose = Datagram->Close();
        EXPECT_TRUE(DatagramClose);
        const auto ClientClose = ClientStream->Close();
        EXPECT_TRUE(ClientClose);
        const auto ServerClose = ServerStream->Close();
        EXPECT_TRUE(ServerClose);
        const auto DatagramDrain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(DatagramDrain);
        const auto ClientDrain = co_await ClientStream->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
        const auto ServerDrain = co_await ServerStream->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
    }

    struct WireErrorRequest final
    {
        Net::io_context &IoContext;
        SharedMemoryStream ClientMemory;
        SharedMemoryStream ServerMemory;
        std::vector<std::uint8_t> Wire;
        Error Expected;
    };

    auto RunWireErrorServer(std::shared_ptr<MemoryStream> ServerStream,
                            const Error Expected) -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Dgram>(std::move(ServerStream));
        Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ReceiveError, Expected);
        const auto Close = Datagram->Close();
        EXPECT_TRUE(Close);
        const auto Drain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(Drain);
    }

    auto RunWireErrorCase(WireErrorRequest Request) -> Net::awaitable<void>
    {
        auto ServerStream = Request.ServerMemory;
        const auto ServerDone = SpawnServer(
            Request.IoContext.get_executor(), RunWireErrorServer(ServerStream, Request.Expected));
        const std::span<const std::uint8_t> WireSpan(Request.Wire);
        const auto WireBuffer = AsBytes(WireSpan);
        const auto Write = co_await Request.ClientMemory->WriteExact(WireBuffer);
        EXPECT_FALSE(Write.Failure.Failed());
        EXPECT_EQ(Write.Bytes, WireBuffer.size());
        const auto Shutdown = co_await Request.ClientMemory->WriteShutdown();
        EXPECT_TRUE(Shutdown);
        if (!Shutdown)
        {
            const auto ClientClose = Request.ClientMemory->Close();
            EXPECT_TRUE(ClientClose);
        }
        const auto ServerCompleted = co_await WaitServer(std::move(ServerDone));
        EXPECT_TRUE(ServerCompleted);
        const auto ClientClose = Request.ClientMemory->Close();
        EXPECT_TRUE(ClientClose);
        const auto ServerClose = ServerStream->Close();
        EXPECT_TRUE(ServerClose);
        const auto ClientDrain = co_await Request.ClientMemory->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
        const auto ServerDrain = co_await ServerStream->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
    }

    struct PeerClosedRequest final
    {
        SharedMemoryStream ClientMemory;
        SharedMemoryStream ServerMemory;
    };

    auto RunPeerClosed(PeerClosedRequest Request) -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Dgram>(Request.ServerMemory);
        const auto Shutdown = co_await Request.ClientMemory->WriteShutdown();
        EXPECT_TRUE(Shutdown);
        Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ReceiveError, Error::IoError);
        const auto Close = Datagram->Close();
        EXPECT_TRUE(Close);
        const auto Cancel = Datagram->Cancel();
        EXPECT_TRUE(Cancel);
        const auto Drain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(Drain);
        const auto ClientClose = Request.ClientMemory->Close();
        EXPECT_TRUE(ClientClose);
        const auto ServerClose = Request.ServerMemory->Close();
        EXPECT_TRUE(ServerClose);
        const auto ClientDrain = co_await Request.ClientMemory->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
        const auto ServerDrain = co_await Request.ServerMemory->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
        EXPECT_NE(Datagram->NextLayer(), nullptr);
        auto Released = Datagram->Release();
        EXPECT_TRUE(Released);
    }

    struct SendClosedRequest final
    {
        SharedMemoryStream ClientMemory;
        SharedMemoryStream ServerMemory;
    };

    auto RunSendToClosedPeer(SendClosedRequest Request) -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Dgram>(Request.ClientMemory);
        const auto ServerClose = Request.ServerMemory->Close();
        EXPECT_TRUE(ServerClose);
        const auto ServerDrain = co_await Request.ServerMemory->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
        const std::string PayloadText = "x";
        const auto Payload = AsU8Span(std::string_view(PayloadText));
        const auto Target = MakeAddress(AddressType::Domain, "example.com", 53);
        const auto SendError = co_await Datagram->AsyncSendTo(Target, Payload);
        EXPECT_EQ(SendError, Error::IoError);
        const auto DatagramClose = Datagram->Close();
        EXPECT_TRUE(DatagramClose);
        const auto DatagramDrain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(DatagramDrain);
        const auto ClientClose = Request.ClientMemory->Close();
        EXPECT_TRUE(ClientClose);
        const auto ClientDrain = co_await Request.ClientMemory->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
    }

    auto RunOverreportedWrite(std::shared_ptr<Dgram> Datagram) -> Net::awaitable<void>
    {
        const auto Target = MakeAddress(AddressType::Domain, "example.com", 443);
        const auto Payload = AsU8Span(std::string_view{"overreport"});
        const auto SendError = co_await Datagram->AsyncSendTo(Target, Payload);
        EXPECT_EQ(SendError, Error::BadLength);
    }

    auto RunOverreportedRead(std::shared_ptr<Dgram> Datagram) -> Net::awaitable<void>
    {
        Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(ReceiveError, Error::BadLength);
    }

    TEST(Socks5DgramSession, SendReceiveRoundtrip)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeOwnedMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunSendReceiveRoundtrip(DatagramRoundtripRequest{
                              IoContext, std::move(ClientMemory), std::move(ServerMemory)}));
    }

    TEST(Socks5DgramSession, Ipv6Receive)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeOwnedMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunIpv6Receive(Ipv6Request{
                              IoContext, std::move(ClientMemory), std::move(ServerMemory)}));
    }

    TEST(Socks5DgramSession, BadRsvRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeOwnedMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunWireErrorCase(WireErrorRequest{
                              IoContext, std::move(ClientMemory), std::move(ServerMemory),
                              {0x00, 0x00, 0x01}, Error::BadMessage}));
    }

    TEST(Socks5DgramSession, BadAtypRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeOwnedMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunWireErrorCase(WireErrorRequest{
                              IoContext, std::move(ClientMemory), std::move(ServerMemory),
                              {0x00, 0x00, 0x00, 0x99}, Error::BadMessage}));
    }

    TEST(Socks5DgramSession, HeaderWithoutPayload)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeOwnedMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunWireErrorCase(WireErrorRequest{
                              IoContext, std::move(ClientMemory), std::move(ServerMemory),
                              {0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x00, 0x50},
                              Error::UnexpectedEof}));
    }

    TEST(Socks5DgramSession, PeerClosedEof)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeOwnedMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunPeerClosed(PeerClosedRequest{
                              std::move(ClientMemory), std::move(ServerMemory)}));
    }

    TEST(Socks5DgramSession, SendToClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeOwnedMemoryPair(IoContext.get_executor());

        RunCoro(IoContext, RunSendToClosedPeer(SendClosedRequest{
                              std::move(ClientMemory), std::move(ServerMemory)}));
    }

    TEST(Socks5DgramSession, RejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PrismMockTransport>(
            IoContext.get_executor());
        Raw->OverreportWrite = true;
        auto Datagram = std::make_shared<Dgram>(Raw);
        RunCoro(IoContext, RunOverreportedWrite(Datagram));
    }

    TEST(Socks5DgramSession, RejectsOverreportedRead)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PrismMockTransport>(
            IoContext.get_executor());
        Raw->OverreportRead = true;
        auto Datagram = std::make_shared<Dgram>(Raw);

        RunCoro(IoContext, RunOverreportedRead(Datagram));
    }
} // namespace

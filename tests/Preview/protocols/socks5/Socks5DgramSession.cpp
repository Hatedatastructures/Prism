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

#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Socks5/Socks5.hpp>
#include <TestSupport/Preview/PreviewMockTransport.hpp>

namespace Net = boost::asio;

namespace
{
    namespace Preview = ::Preview;
    namespace Socks5 = Preview::Socks5;

    using Address = Socks5::Address;
    using AddressType = Socks5::AddressType;
    using ClientConfig = Socks5::ClientConfig;
    using Dgram = Socks5::Dgram<>;
    using Error = Preview::Error;
    using ExecutorType = Net::any_io_executor;
    using MemoryStream = Preview::MemoryStream;
    using PreviewMockTransport = Preview::PreviewMockTransport;
    using ServerConfig = Socks5::ServerConfig;
    using Transmission = Preview::Transmission;
    using CompletionChannel =
        Net::experimental::channel<void(boost::system::error_code, bool)>;

    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::MakeMemoryPair;

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

    TEST(Socks5DgramSession, SendReceiveRoundtrip)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoro(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream =
                    std::make_shared<MemoryStream>(std::move(ServerMemory));
                auto ServerCoroutine =
                    [ServerStream]() -> Net::awaitable<void>
                {
                    ServerConfig Config;
                    Config.EnableUdp = true;
                    auto [ErrorValue, Request, Datagram] =
                        co_await Socks5::AcceptPacket(ServerStream, Config);
                    if (ErrorValue != Error::None || !Datagram)
                    {
                        EXPECT_TRUE(false) << "AcceptPacket Failed";
                        co_return;
                    }
                    EXPECT_EQ(Request.Cmd, Socks5::Command::UdpAssociate);
                    EXPECT_EQ(
                        Datagram->TransportType(),
                        Transmission::Type::Udp);

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
                            EXPECT_EQ(
                                std::string(Payload.begin(), Payload.end()),
                                "dns query");
                        }
                        else
                        {
                            EXPECT_EQ(Source.Type, AddressType::Ipv4);
                            EXPECT_EQ(Source.Host, "8.8.8.8");
                            EXPECT_EQ(Source.Port, 443u);
                            EXPECT_EQ(
                                std::string(Payload.begin(), Payload.end()),
                                "second pkt");
                        }
                    }

                    EXPECT_TRUE(Datagram->Stream());
                    EXPECT_NE(Datagram->NextLayer(), nullptr);
                    EXPECT_NE(
                        Datagram->lowest_layer<MemoryStream>(),
                        nullptr);
                    const Dgram *ConstDatagram = Datagram.get();
                    EXPECT_NE(ConstDatagram->NextLayer(), nullptr);
                    EXPECT_TRUE(Datagram->Executor());

                    std::array<std::byte, 8> RawBuffer{};
                    const std::span<std::byte> RawSpan(RawBuffer);
                    std::error_code ErrorCode;
                    const auto BytesRead =
                        co_await Datagram->async_read_some(RawSpan, ErrorCode);
                    EXPECT_EQ(BytesRead, 4u);
                    Datagram->Close();
                    Datagram->Cancel();
                    auto Released = Datagram->Release();
                    EXPECT_TRUE(Released);
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                auto [HandshakeError, Datagram] =
                    co_await Socks5::ConnectPacket(
                        std::make_shared<MemoryStream>(std::move(ClientMemory)),
                        ClientConfig{},
                        MakeAddress(AddressType::Domain, "example.com", 53));
                EXPECT_EQ(HandshakeError, Error::None);
                if (!Datagram)
                {
                    ServerStream->Close();
                    const auto ServerCompleted =
                        co_await ServerDone->async_receive(Net::use_awaitable);
                    EXPECT_TRUE(ServerCompleted);
                    co_return;
                }

                const std::string FirstPayloadText = "dns query";
                const auto FirstPayload =
                    AsU8Span(std::string_view(FirstPayloadText));
                const auto FirstError = co_await Datagram->AsyncSendTo(
                    MakeAddress(AddressType::Domain, "example.com", 53),
                    FirstPayload);
                EXPECT_EQ(FirstError, Error::None);

                const std::string SecondPayloadText = "second pkt";
                const auto SecondPayload =
                    AsU8Span(std::string_view(SecondPayloadText));
                const auto SecondError = co_await Datagram->AsyncSendTo(
                    MakeAddress(AddressType::Ipv4, "8.8.8.8", 443),
                    SecondPayload);
                EXPECT_EQ(SecondError, Error::None);

                std::array<std::byte, 4> RawBuffer{};
                const std::span<const std::byte> RawSpan(RawBuffer);
                std::error_code ErrorCode;
                const auto BytesWritten =
                    co_await Datagram->async_write_some(RawSpan, ErrorCode);
                EXPECT_EQ(BytesWritten, 4u);
                Datagram->Close();
                const auto ServerCompleted =
                    co_await ServerDone->async_receive(Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Socks5DgramSession, Ipv6Receive)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoro(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream =
                    std::make_shared<MemoryStream>(std::move(ServerMemory));
                auto ServerCoroutine =
                    [ServerStream]() -> Net::awaitable<void>
                {
                    ServerConfig Config;
                    Config.EnableUdp = true;
                    auto [ErrorValue, Request, Datagram] =
                        co_await Socks5::AcceptPacket(ServerStream, Config);
                    if (ErrorValue != Error::None || !Datagram)
                    {
                        co_return;
                    }
                    Address Source;
                    std::vector<std::uint8_t> Payload;
                    const auto ReceiveError =
                        co_await Datagram->AsyncReceiveFrom(Source, Payload);
                    EXPECT_EQ(ReceiveError, Error::None);
                    EXPECT_EQ(Source.Type, AddressType::Ipv6);
                    EXPECT_EQ(Source.Host, std::string(16, '\x21'));
                    EXPECT_EQ(Source.Port, 8080u);
                    EXPECT_EQ(
                        std::string(Payload.begin(), Payload.end()),
                        "v6 pkt");
                    Datagram->Close();
                    (void)Request;
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                auto [HandshakeError, Datagram] =
                    co_await Socks5::ConnectPacket(
                        std::make_shared<MemoryStream>(std::move(ClientMemory)),
                        ClientConfig{},
                        MakeAddress(AddressType::Domain, "example.com", 53));
                EXPECT_EQ(HandshakeError, Error::None);
                if (!Datagram)
                {
                    ServerStream->Close();
                    const auto ServerCompleted =
                        co_await ServerDone->async_receive(Net::use_awaitable);
                    EXPECT_TRUE(ServerCompleted);
                    co_return;
                }

                const std::string PayloadText = "v6 pkt";
                const auto Payload =
                    AsU8Span(std::string_view(PayloadText));
                const auto SendError = co_await Datagram->AsyncSendTo(
                    MakeAddress(
                        AddressType::Ipv6,
                        std::string(16, '\x21'),
                        8080),
                    Payload);
                EXPECT_EQ(SendError, Error::None);
                Datagram->Close();
                const auto ServerCompleted =
                    co_await ServerDone->async_receive(Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Socks5DgramSession, BadRsvRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoro(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream =
                    std::make_shared<MemoryStream>(std::move(ServerMemory));
                auto ServerCoroutine =
                    [ServerStream]() -> Net::awaitable<void>
                {
                    auto Datagram = std::make_shared<Dgram>(ServerStream);
                    Address Source;
                    std::vector<std::uint8_t> Payload;
                    const auto ReceiveError =
                        co_await Datagram->AsyncReceiveFrom(Source, Payload);
                    EXPECT_EQ(ReceiveError, Error::BadMessage);
                    Datagram->Close();
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                const std::array<std::uint8_t, 3> Wire{0x00, 0x00, 0x01};
                const std::span<const std::uint8_t> WireSpan(Wire);
                const auto WireBuffer = AsBytes(WireSpan);
                std::error_code ErrorCode;
                co_await ClientMemory.async_write_some(WireBuffer, ErrorCode);
                ClientMemory.Close();
                const auto ServerCompleted =
                    co_await ServerDone->async_receive(Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Socks5DgramSession, BadAtypRejected)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoro(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream =
                    std::make_shared<MemoryStream>(std::move(ServerMemory));
                auto ServerCoroutine =
                    [ServerStream]() -> Net::awaitable<void>
                {
                    auto Datagram = std::make_shared<Dgram>(ServerStream);
                    Address Source;
                    std::vector<std::uint8_t> Payload;
                    const auto ReceiveError =
                        co_await Datagram->AsyncReceiveFrom(Source, Payload);
                    EXPECT_EQ(ReceiveError, Error::BadMessage);
                    Datagram->Close();
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                const std::array<std::uint8_t, 4> Wire{
                    0x00,
                    0x00,
                    0x00,
                    0x99};
                const std::span<const std::uint8_t> WireSpan(Wire);
                const auto WireBuffer = AsBytes(WireSpan);
                std::error_code ErrorCode;
                co_await ClientMemory.async_write_some(WireBuffer, ErrorCode);
                ClientMemory.Close();
                const auto ServerCompleted =
                    co_await ServerDone->async_receive(Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Socks5DgramSession, HeaderWithoutPayload)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoro(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto ServerStream =
                    std::make_shared<MemoryStream>(std::move(ServerMemory));
                auto ServerCoroutine =
                    [ServerStream]() -> Net::awaitable<void>
                {
                    auto Datagram = std::make_shared<Dgram>(ServerStream);
                    Address Source;
                    std::vector<std::uint8_t> Payload;
                    const auto ReceiveError =
                        co_await Datagram->AsyncReceiveFrom(Source, Payload);
                    EXPECT_EQ(ReceiveError, Error::UnexpectedEof);
                    Datagram->Close();
                };
                const auto ServerDone = SpawnServer(
                    IoContext.get_executor(),
                    ServerCoroutine());

                const std::array<std::uint8_t, 10> Wire{
                    0x00,
                    0x00,
                    0x00,
                    0x01,
                    0x01,
                    0x02,
                    0x03,
                    0x04,
                    0x00,
                    0x50};
                const std::span<const std::uint8_t> WireSpan(Wire);
                const auto WireBuffer = AsBytes(WireSpan);
                std::error_code ErrorCode;
                co_await ClientMemory.async_write_some(WireBuffer, ErrorCode);
                ClientMemory.Close();
                const auto ServerCompleted =
                    co_await ServerDone->async_receive(Net::use_awaitable);
                EXPECT_TRUE(ServerCompleted);
            });
    }

    TEST(Socks5DgramSession, PeerClosedEof)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoro(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto Datagram = std::make_shared<Dgram>(
                    std::make_shared<MemoryStream>(std::move(ServerMemory)));
                ClientMemory.Close();
                Address Source;
                std::vector<std::uint8_t> Payload;
                const auto ReceiveError =
                    co_await Datagram->AsyncReceiveFrom(Source, Payload);
                EXPECT_EQ(ReceiveError, Error::IoError);
                Datagram->Close();
                Datagram->Cancel();
                EXPECT_NE(Datagram->NextLayer(), nullptr);
                auto Released = Datagram->Release();
                EXPECT_TRUE(Released);
            });
    }

    TEST(Socks5DgramSession, SendToClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientMemory, ServerMemory] =
            MakeMemoryPair(IoContext.get_executor());

        RunCoro(
            IoContext,
            [&]() -> Net::awaitable<void>
            {
                auto Datagram = std::make_shared<Dgram>(
                    std::make_shared<MemoryStream>(std::move(ClientMemory)));
                ServerMemory.Close();
                const std::string PayloadText = "x";
                const auto Payload =
                    AsU8Span(std::string_view(PayloadText));
                const auto Target =
                    MakeAddress(AddressType::Domain, "example.com", 53);
                const auto SendError =
                    co_await Datagram->AsyncSendTo(Target, Payload);
                EXPECT_EQ(SendError, Error::IoError);
                Datagram->Close();
            });
    }

    TEST(Socks5DgramSession, RejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PreviewMockTransport>(
            IoContext.get_executor());
        Raw->OverreportWrite = true;
        auto Datagram = std::make_shared<Dgram>(Raw);
        const auto Target =
            MakeAddress(AddressType::Domain, "example.com", 443);
        const auto Payload = AsU8Span(std::string_view{"overreport"});

        auto TestCoroutine = [&]() -> Net::awaitable<void>
        {
            const auto SendError =
                co_await Datagram->AsyncSendTo(Target, Payload);
            EXPECT_EQ(SendError, Error::BadLength);
        };
        RunCoro(IoContext, std::move(TestCoroutine));
    }

    TEST(Socks5DgramSession, RejectsOverreportedRead)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PreviewMockTransport>(
            IoContext.get_executor());
        Raw->OverreportRead = true;
        auto Datagram = std::make_shared<Dgram>(Raw);

        auto TestCoroutine = [&]() -> Net::awaitable<void>
        {
            Address Source;
            std::vector<std::uint8_t> Payload;
            const auto ReceiveError =
                co_await Datagram->AsyncReceiveFrom(Source, Payload);
            EXPECT_EQ(ReceiveError, Error::BadLength);
        };
        RunCoro(IoContext, std::move(TestCoroutine));
    }
} // namespace

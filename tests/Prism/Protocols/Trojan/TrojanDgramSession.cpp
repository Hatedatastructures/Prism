/**
 * @file TrojanDgramSession.cpp
 * @brief Trojan Dgram 场景、错误帧和装饰器生命周期测试。
 * @details Dgram owner 独立持有其 memory transport 与 raw frame helper。
 */

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Foundation/Error.hpp>
#include <Prism/Protocols/Trojan/Trojan.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <TestSupport/Prism/PrismMockTransport.hpp>
#include <gtest/gtest.h>

namespace
{
    namespace Net = boost::asio;
    namespace Trojan = Prism::Trojan;
    using Prism::AsBytes;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using Prism::PrismMockTransport;
    using Prism::SharedTransmission;
    using DatagramRunResult = Prism::Contract::Io::PacketTransferResult;

    /** @brief 测试侧保留原协议错误覆盖并读取 typed Failure 分类。 */
    auto DatagramStatus(const DatagramRunResult& Result) -> Prism::Fault::Code
    {
        return Result.Failure.Code;
    }

    auto FaultStatus(Error Value) -> Prism::Fault::Code
    {
        return Prism::Fault::ToCode(Prism::make_error_code(Value));
    }

    template <typename Awaitable>
    auto RunCoroutine(Net::io_context &IoContext, Awaitable Operation) -> void
    {
        std::exception_ptr Exception;
        Net::co_spawn(
            IoContext,
            std::move(Operation),
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

    /** @brief 构造 Trojan Dgram 测试目标地址。 */
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

    /** @brief 立即启动 Dgram server operation 并保存首异常。 */
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

    /** @brief 等待已启动 Dgram server completion 并传播首异常。 */
    auto WaitEagerVoid(EagerVoidTask State) -> Net::awaitable<void>
    {
        (void)co_await State.Done->async_receive(Net::use_awaitable);
        if (*State.Failure)
        {
            std::rethrow_exception(*State.Failure);
        }
    }

    struct DgramFrameRequest final
    {
        SharedTransmission Client;
        SharedTransmission Server;
        std::vector<std::uint8_t> Wire;
        Error Expected;
    };

    /** @brief 接收 Dgram 原始帧并验证指定错误后关闭连接。 */
    auto RunDgramFrameServer(DgramFrameRequest Request) -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Trojan::Dgram<>>(std::move(Request.Server));
        Trojan::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ErrorValue = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(DatagramStatus(ErrorValue), FaultStatus(Request.Expected));
        const auto Close = Datagram->Close();
        EXPECT_TRUE(Close);
        const auto Drain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(Drain);
    }

    /** @brief 发送一个 Dgram 原始错误帧并等待 server operation。 */
    auto RunDgramFrame(DgramFrameRequest Request) -> Net::awaitable<void>
    {
        auto ServerTask = SpawnEagerVoid(
            Request.Server->Executor(),
            RunDgramFrameServer(Request));
        std::exception_ptr ParentFailure;
        try
        {
            const auto Write = co_await Request.Client->WriteExact(
                AsBytes(std::span<const std::uint8_t>(Request.Wire)));
            EXPECT_FALSE(Write.Failure.Failed());
            EXPECT_EQ(Write.Bytes, Request.Wire.size());
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
        const auto ClientClose = Request.Client->Close();
        EXPECT_TRUE(ClientClose);
        const auto ServerClose = Request.Server->Close();
        EXPECT_TRUE(ServerClose);
        const auto ClientDrain = co_await Request.Client->Activity()->Drain();
        EXPECT_TRUE(ClientDrain);
        const auto ServerDrain = co_await Request.Server->Activity()->Drain();
        EXPECT_TRUE(ServerDrain);
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }

    struct DgramPeerCloseRequest final
    {
        SharedTransmission Datagram;
        SharedTransmission Peer;
    };

    /** @brief 验证 Trojan Dgram 透传、对端 EOF、释放和取消顺序。 */
    auto RunDgramPeerClosed(DgramPeerCloseRequest Request) -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Trojan::Dgram<>>(std::move(Request.Datagram));
        EXPECT_TRUE(Datagram->Executor());
        std::array<std::byte, 8> Buffer{};
        const auto Written = co_await Datagram->WriteSome(
            std::span<const std::byte>(Buffer.data(), 4));
        EXPECT_FALSE(Written.Failure.Failed());
        EXPECT_EQ(Written.Bytes, 4u);
        const auto PeerShutdown = co_await Request.Peer->WriteShutdown();
        EXPECT_TRUE(PeerShutdown);
        const auto Read = co_await Datagram->ReadSome(Buffer);
        EXPECT_EQ(Read.Bytes, 0u);
        Trojan::Address Source;
        std::vector<std::uint8_t> Payload;
        const auto ReceiveError = co_await Datagram->AsyncReceiveFrom(Source, Payload);
        EXPECT_EQ(DatagramStatus(ReceiveError), FaultStatus(Error::IoError));
        const auto Close = Datagram->Close();
        EXPECT_TRUE(Close);
        const auto Cancel = Datagram->Cancel();
        EXPECT_TRUE(Cancel);
        const auto Drain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(Drain);
        const auto PeerClose = Request.Peer->Close();
        EXPECT_TRUE(PeerClose);
        const auto PeerDrain = co_await Request.Peer->Activity()->Drain();
        EXPECT_TRUE(PeerDrain);
        EXPECT_NE(Datagram->NextLayer(), nullptr);
        const auto *ConstDatagram = Datagram.get();
        EXPECT_NE(ConstDatagram->NextLayer(), nullptr);
        auto Released = Datagram->Release();
        EXPECT_TRUE(Released);
    }

    /** @brief 验证 Trojan Dgram 对端关闭时写入失败。 */
    auto RunDgramSendClosed(DgramPeerCloseRequest Request) -> Net::awaitable<void>
    {
        auto Datagram = std::make_shared<Trojan::Dgram<>>(std::move(Request.Datagram));
        const auto PeerClose = Request.Peer->Close();
        EXPECT_TRUE(PeerClose);
        const auto PeerDrain = co_await Request.Peer->Activity()->Drain();
        EXPECT_TRUE(PeerDrain);
        const auto ErrorValue = co_await Datagram->AsyncSendTo(
            MakeAddress(Trojan::AddressType::Domain, "example.com", 53),
            AsU8Span(std::string_view{"x"}));
        EXPECT_EQ(DatagramStatus(ErrorValue), FaultStatus(Error::IoError));
        const auto DatagramClose = Datagram->Close();
        EXPECT_TRUE(DatagramClose);
        const auto DatagramDrain = co_await Datagram->Activity()->Drain();
        EXPECT_TRUE(DatagramDrain);
    }

    TEST(TrojanDgramSession, SendToClosedPeer)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext, RunDgramSendClosed(DgramPeerCloseRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream))}));
    }

    TEST(TrojanDgramSession, BadCrlfRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext, RunDgramFrame(DgramFrameRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            {0x01, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x04, 'X', '\n', 'a', 'b', 'c', 'd'},
            Error::BadMagic}));
    }

    TEST(TrojanDgramSession, BadAtypRejected)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext, RunDgramFrame(DgramFrameRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            {0x99}, Error::BadMessage}));
    }

    TEST(TrojanDgramSession, LenExceedsRemaining)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext, RunDgramFrame(DgramFrameRequest{
            std::make_shared<MemoryStream>(std::move(ClientStream)),
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            {0x01, 1, 2, 3, 4, 0x00, 0x50, 0x01, 0xF4, '\r', '\n', 'a', 'b', 'c'},
            Error::IoError}));
    }

    TEST(TrojanDgramSession, PeerClosedEof)
    {
        Net::io_context IoContext;
        auto [ClientStream, ServerStream] = MakeMemoryPair(IoContext.get_executor());

        RunCoroutine(IoContext, RunDgramPeerClosed(DgramPeerCloseRequest{
            std::make_shared<MemoryStream>(std::move(ServerStream)),
            std::make_shared<MemoryStream>(std::move(ClientStream))}));
    }

    TEST(TrojanDgramSession, RejectsOverreportedWrite)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PrismMockTransport>(IoContext.get_executor());
        Raw->OverreportWrite = true;
        auto Datagram = std::make_shared<Trojan::Dgram<>>(Raw);

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     const auto ErrorCode = co_await Datagram->AsyncSendTo(
                         MakeAddress(Trojan::AddressType::Domain, "example.com", 443),
                         AsU8Span(std::string_view{"overreport"}));
                     EXPECT_EQ(DatagramStatus(ErrorCode), FaultStatus(Error::BadLength));
                 });
    }

    TEST(TrojanDgramSession, RejectsOverreportedRead)
    {
        Net::io_context IoContext;
        auto Raw = std::make_shared<PrismMockTransport>(IoContext.get_executor());
        Raw->OverreportRead = true;
        auto Datagram = std::make_shared<Trojan::Dgram<>>(Raw);

        RunCoroutine(IoContext,
                 [&]() -> Net::awaitable<void>
                 {
                     Trojan::Address Source;
                     std::vector<std::uint8_t> Payload;
                     const auto ErrorCode = co_await Datagram->AsyncReceiveFrom(Source, Payload);
                     EXPECT_EQ(DatagramStatus(ErrorCode), FaultStatus(Error::BadLength));
                 });
    }

} // namespace

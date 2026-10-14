/**
 * @file WsConnSession.cpp
 * @brief 验证 WebSocket 建连后的双向会话回显。
 */
#include "WsFactorySupport.hpp"
#include "WsConnSessionSupport.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
#include <Preview/Transport/MemoryStream.hpp>
#include <Preview/Protocols/Ws/Detail/Codec.hpp>
#include <Preview/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>
namespace
{
    namespace Net = boost::asio;
    namespace Ws = Preview::Ws;
    namespace TestSupport = Preview::Tests::WsConnSessionSupport;
    using Preview::AsBytes;
    using Preview::AsU8Span;
    using Preview::Error;
    using Preview::MakeMemoryPair;
    using Preview::MemoryStream;
    using TestSupport::CloseAndWait;
    using TestSupport::EchoRequest;
    using TestSupport::EagerTask;
    using TestSupport::PairCompletion;
    using TestSupport::RunCoro;
    using TestSupport::SpawnEager;
    using TestSupport::TestKey;
    /** @brief 服务端完成 Upgrade、接收并回显 websocket payload。 */
    auto RunEchoServer(std::shared_ptr<MemoryStream> Server,
                       std::string Payload) -> Net::awaitable<void>
    {
        auto Accepted = co_await Preview::Ws::Accept(
            Preview::Tests::WsFactorySupport::MakeAcceptOptionsForTest(
                Server, Ws::ServerOptions{}));
        if (!Accepted)
        {
            EXPECT_TRUE(false) << "Accept failed: "
                               << Preview::Fault::Describe(Accepted.error().Code);
            co_return;
        }
        EXPECT_EQ(Accepted->Key, TestKey);
        auto Connection = std::move(Accepted->Connection);
        std::array<std::byte, 1024> Buffer{};
        std::error_code ErrorCode;
        const auto Read = co_await Connection->ReadSome(Buffer);
        ErrorCode = Preview::Fault::ToNative(Read.Failure);
        const auto Count = Read.Bytes;
        EXPECT_FALSE(ErrorCode);
        EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()), Count),
                  Payload);
        const auto Write = co_await Connection->WriteSome(std::span<const std::byte>(Buffer.data(), Count));
        ErrorCode = Preview::Fault::ToNative(Write.Failure);
        EXPECT_FALSE(ErrorCode);
        const auto CloseResult = Connection->Close();
        EXPECT_TRUE(CloseResult);
        const auto DrainResult = co_await Connection->Activity()->Drain();
        EXPECT_TRUE(DrainResult);
    }
    /** @brief 驱动客户端 Upgrade 与双向回显。 */
    auto RunHandshakeClientServerEcho(EchoRequest Request)
        -> Net::awaitable<void>
    {
        auto Client = std::make_shared<MemoryStream>(std::move(Request.Pair.Client));
        auto Server = std::make_shared<MemoryStream>(std::move(Request.Pair.Server));
        auto ServerTask = SpawnEager(Server->Executor(),
                                     RunEchoServer(Server, Request.Payload));
        std::exception_ptr ParentFailure;
        try
        {
            const Ws::ClientOptions Config{"example.com", TestKey};
            auto ClientBytes =
                Preview::Tests::WsFactorySupport::WebSocketTestBytes();
            auto Connected = co_await Preview::Ws::Connect(
                Preview::Ws::ConnectOptions{Client, ClientBytes, Config});
            EXPECT_TRUE(Connected);
            if (Connected)
            {
                auto Connection = std::move(Connected->Connection);
                EXPECT_EQ(Connected->Accept, Ws::Detail::ComputeAccept(TestKey));
                std::error_code ErrorCode;
                const auto Write = co_await Connection->WriteSome(
                    std::span<const std::byte>(
                        reinterpret_cast<const std::byte *>(Request.Payload.data()),
                        Request.Payload.size()));
                ErrorCode = Preview::Fault::ToNative(Write.Failure);
                EXPECT_FALSE(ErrorCode);
                EXPECT_EQ(ClientBytes->AvailableBlocks(), 64U);
                const auto ShutdownResult = co_await Connection->WriteShutdown();
                EXPECT_TRUE(ShutdownResult);
                EXPECT_EQ(ClientBytes->AvailableBlocks(), 64U);
                std::array<std::byte, 1024> Buffer{};
                const auto Read = co_await Connection->ReadSome(Buffer);
                ErrorCode = Preview::Fault::ToNative(Read.Failure);
                const auto Count = Read.Bytes;
                EXPECT_FALSE(ErrorCode);
                EXPECT_EQ(std::string(reinterpret_cast<const char *>(Buffer.data()),
                                      Count),
                          Request.Payload);
                const auto CloseResult = Connection->Close();
                EXPECT_TRUE(CloseResult);
                const auto DrainResult = co_await Connection->Activity()->Drain();
                EXPECT_TRUE(DrainResult);
            }
        }
        catch (...)
        {
            ParentFailure = std::current_exception();
        }
        co_await CloseAndWait(PairCompletion{Client, Server, std::move(ServerTask)});
        if (ParentFailure)
        {
            std::rethrow_exception(ParentFailure);
        }
    }
    TEST(WsConnSession, HandshakeClientServerEcho)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunHandshakeClientServerEcho(
                               EchoRequest{{std::move(Client), std::move(Server)},
                                           "ws echo payload"}));
    }
}

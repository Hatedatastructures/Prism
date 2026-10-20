/**
 * @file WsConnClose.cpp
 * @brief 验证未开放 WebSocket 连接的失败、取消、关闭与 Release。
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
#include <Prism/Foundation/ByteSpan.hpp>
#include <Prism/Transport/MemoryStream.hpp>
#include <Prism/Protocols/Ws/Detail/StreamOwner.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>
#include <gtest/gtest.h>
namespace
{
    namespace Net = boost::asio;
    namespace Ws = Prism::Ws;
    namespace TestSupport = Prism::Tests::WsConnSessionSupport;
    using Prism::AsBytes;
    using Prism::AsU8Span;
    using Prism::Error;
    using Prism::MakeMemoryPair;
    using Prism::MemoryStream;
    using TestSupport::RunCoro;
    /** @brief 验证未握手 Conn 的读写、装饰器和 Release。 */
    auto RunNotOpenRejected(MemoryStream Client) -> Net::awaitable<void>
    {
        auto Connection = std::make_shared<Ws::Detail::StreamOwner<>>(std::make_shared<MemoryStream>(std::move(Client)), Prism::Tests::WsFactorySupport::WebSocketTestBytes(), false);
        std::array<std::byte, 64> Buffer{};
        std::error_code ErrorCode;
        const auto Read = co_await Connection->ReadSome(Buffer);
        ErrorCode = Prism::Fault::ToNative(Read.Failure);
        const auto ReadSize = Read.Bytes;
        EXPECT_EQ(ReadSize, 0u);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Error::NotOpen));
        ErrorCode.clear();
        const auto Write = co_await Connection->WriteSome(std::span<const std::byte>(Buffer.data(), 4));
        ErrorCode = Prism::Fault::ToNative(Write.Failure);
        EXPECT_EQ(ErrorCode.value(), static_cast<int>(Error::NotOpen));
        const auto CloseResult = Connection->Close();
        EXPECT_TRUE(CloseResult);
        const auto CancelResult = Connection->Cancel();
        EXPECT_TRUE(CancelResult);
        EXPECT_FALSE(Connection->Release());
        const auto DrainResult = co_await Connection->Activity()->Drain();
        EXPECT_TRUE(DrainResult);
        EXPECT_TRUE(Connection->Executor());
        EXPECT_NE(Connection->NextLayer(), nullptr);
        EXPECT_NE(Connection->lowest_layer<MemoryStream>(), nullptr);
        const Ws::Detail::StreamOwner<> *ConstConnection = Connection.get();
        EXPECT_NE(ConstConnection->NextLayer(), nullptr);
        auto Released = Connection->Release();
        EXPECT_TRUE(Released);
        EXPECT_EQ(Connection->NextLayer(), nullptr);
        EXPECT_TRUE(Connection->Accept().empty());
    }
    TEST(WsConnSession, NotOpenRejected)
    {
        Net::io_context IoContext;
        auto [Client, Server] = MakeMemoryPair(IoContext.get_executor());
        RunCoro(IoContext, RunNotOpenRejected(std::move(Client)));
    }
}

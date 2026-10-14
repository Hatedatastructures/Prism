/**
 * @file WsFactorySupport.hpp
 * @brief WebSocket 测试工厂选项与有界字节池。
 * @details 测试侧显式填入传输和 BytePool owner，不提供默认连接或兼容入口。
 */
#pragma once

#include <memory>
#include <utility>

#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Protocols/Ws/Ws.hpp>

namespace Preview::Tests::WsFactorySupport
{
    /** @brief 返回测试进程显式创建的共享 WebSocket 字节池。 */
    [[nodiscard]] inline auto WebSocketTestBytes()
        -> std::shared_ptr<Preview::Memory::BytePool>
    {
        static auto Bytes = std::make_shared<Preview::Memory::BytePool>(
            Preview::Memory::BytePoolOptions{64U * 1024U, 64U});
        return Bytes;
    }

    /** @brief 为客户端测试选项移交底层 owner 与有界帧池。 */
    [[nodiscard]] inline auto MakeConnectOptionsForTest(
        Preview::SharedTransmission Transport,
        Preview::Ws::ClientOptions Options)
        -> Preview::Ws::ConnectOptions
    {
        return Preview::Ws::ConnectOptions{
            std::move(Transport), WebSocketTestBytes(), std::move(Options)};
    }

    /** @brief 为服务端测试选项移交底层 owner 与有界帧池。 */
    [[nodiscard]] inline auto MakeAcceptOptionsForTest(
        Preview::SharedTransmission Transport,
        Preview::Ws::ServerOptions Options)
        -> Preview::Ws::AcceptOptions
    {
        return Preview::Ws::AcceptOptions{
            std::move(Transport), WebSocketTestBytes(), std::move(Options)};
    }
} // namespace Preview::Tests::WsFactorySupport
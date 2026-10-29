/**
 * @file FactorySupport.hpp
 * @brief WebSocket 测试工厂选项与有界字节池。
 * @details 测试侧显式填入传输和 BytePool owner，不提供默认连接或兼容入口。
 */
#pragma once

#include <memory>
#include <utility>

#include <Prism/Foundation/Memory/BytePool.hpp>
#include <Prism/Protocols/Ws/Ws.hpp>

namespace Prism::Tests::WsFactorySupport
{
    /** @brief 返回测试进程显式创建的共享 WebSocket 字节池。 */
    [[nodiscard]] inline auto WebSocketTestBytes()
        -> std::shared_ptr<Prism::Memory::BytePool>
    {
        static auto Bytes = std::make_shared<Prism::Memory::BytePool>(
            Prism::Memory::BytePoolOptions{64U * 1024U, 64U});
        return Bytes;
    }

    /** @brief 为客户端测试选项移交底层 owner 与有界帧池。 */
    [[nodiscard]] inline auto MakeConnectOptionsForTest(
        Prism::SharedTransmission Transport,
        Prism::Ws::ClientOptions Options)
        -> Prism::Ws::ConnectOptions
    {
        return Prism::Ws::ConnectOptions{
            std::move(Transport), WebSocketTestBytes(), std::move(Options)};
    }

    /** @brief 为服务端测试选项移交底层 owner 与有界帧池。 */
    [[nodiscard]] inline auto MakeAcceptOptionsForTest(
        Prism::SharedTransmission Transport,
        Prism::Ws::ServerOptions Options)
        -> Prism::Ws::AcceptOptions
    {
        return Prism::Ws::AcceptOptions{
            std::move(Transport), WebSocketTestBytes(), std::move(Options)};
    }
} // namespace Prism::Tests::WsFactorySuppor

/**
 * @file Conn.hpp
 * @brief Native 方案连接装饰器（TLS 握手 + 直通）
 * @details 对底层传输执行服务端 TLS 握手（Encrypted::SslHandshake），
 *          成功后透传（传输透明，读即明文数据）。作为 stealth 兜底
 *          方案：无内层伪装，识别失败时回落到原生 TLS。
 */

#pragma once

#include <preview/Foundation/Error.hpp>
#include <preview/Foundation/Memory/Container.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Transport/Encrypted.hpp>
#include <preview/Protocols/Native/Types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ssl.hpp>

#include <cstddef>
#include <memory>
#include <span>
#include <string>

namespace Preview::Native
{

    namespace net = boost::asio;

    /**
     * @brief 执行服务端 TLS 握手并返回直通传输
     * @param raw 底层传输（所有权转移）
     * @param SslCtx TLS 服务端上下文（证书已配置）
     * @return 握手成功的加密传输；失败返回 nullptr
     * @details TLS 握手成功后传输透明（无内层协议处理）。
     */
    [[nodiscard]] inline auto Accept(SharedTransmission raw, net::ssl::context &SslCtx)
        -> net::awaitable<SharedTransmission>
    {
        if (!raw)
        {
            co_return nullptr;
        }
        auto [Code, Stream, recovered] = co_await Preview::Transport::Encrypted::SslHandshake(
            std::move(raw), SslCtx);
        (void)Code;
        (void)recovered;
        if (!Stream)
        {
            co_return nullptr;
        }
        co_return std::make_shared<Preview::Transport::Encrypted>(std::move(Stream));
    }

} // namespace Preview::Native

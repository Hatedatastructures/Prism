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
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <variant>

namespace Preview::Native
{

    /**
     * @brief 执行服务端 TLS 握手并返回直通传输
     * @param Raw 底层传输（所有权转移）
     * @param SslCtx TLS 服务端上下文（证书已配置）
     * @return 握手成功的加密传输；失败返回 nullptr
     * @details TLS 握手成功后传输透明（无内层协议处理）。
     */
    [[nodiscard]] inline auto Accept(
        SharedTransmission Raw,
        Net::ssl::context &SslCtx) -> Net::awaitable<SharedTransmission>
    {
        if (!Raw)
        {
            co_return nullptr;
        }
        auto [ErrorCode, Stream, Recovered] =
            co_await Preview::Transport::Encrypted::SslHandshake(std::move(Raw), SslCtx);
        (void)ErrorCode;
        if (!Stream)
        {
            if (Recovered)
            {
                Recovered->Close();
            }
            co_return nullptr;
        }
        co_return std::make_shared<Preview::Transport::Encrypted>(std::move(Stream));
    }

    /**
     * @brief 执行客户端 TLS 握手并返回直通传输
     * @param Raw 底层传输（所有权转移）
     * @param SslCtx TLS 客户端上下文
     * @param ServerName 可选 SNI
     * @return 握手成功的加密传输；失败返回空并关闭底层传输
     * @details 与 Accept 对称，握手包含有限超时，避免客户端永久等待。
     */
    [[nodiscard]] inline auto Connect(
        SharedTransmission Raw,
        Net::ssl::context &SslCtx,
        std::string_view ServerName = {}) -> Net::awaitable<SharedTransmission>
    {
        if (!Raw)
        {
            co_return nullptr;
        }
        Preview::Transport::Connector Connector(std::move(Raw), {});
        auto Stream = std::make_shared<Preview::Transport::Encrypted::StreamType>(
            std::move(Connector), SslCtx);
        if (!ServerName.empty())
        {
            const auto Host = std::string(ServerName);
            if (SSL_set_tlsext_host_name(Stream->native_handle(), Host.c_str()) != 1)
            {
                auto Recovered = Stream->next_layer().Release();
                if (Recovered)
                {
                    Recovered->Close();
                }
                co_return nullptr;
            }
        }

        const auto Executor = Stream->get_executor();
        Net::steady_timer Deadline(Executor);
        Deadline.expires_after(std::chrono::seconds(30));
        auto DoHandshake = [Stream]() -> Net::awaitable<boost::system::error_code>
        {
            boost::system::error_code Error;
            co_await Stream->async_handshake(Net::ssl::stream_base::client,
                                             Net::redirect_error(Net::use_awaitable, Error));
            co_return Error;
        };
        using Net::experimental::awaitable_operators::operator||;
        const auto Result = co_await (DoHandshake() || Deadline.async_wait(Net::use_awaitable));
        if (Result.index() == 1)
        {
            auto Recovered = Stream->next_layer().Release();
            if (Recovered)
            {
                Recovered->Cancel();
                Recovered->Close();
            }
            co_return nullptr;
        }
        if (std::get<0>(Result))
        {
            auto Recovered = Stream->next_layer().Release();
            if (Recovered)
            {
                Recovered->Close();
            }
            co_return nullptr;
        }
        co_return std::make_shared<Preview::Transport::Encrypted>(std::move(Stream));
    }

} // namespace Preview::Native

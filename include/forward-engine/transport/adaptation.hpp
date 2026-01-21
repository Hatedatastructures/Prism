#pragma once

#include "obscura.hpp"
#include <boost/asio.hpp>

namespace ngx::transport
{
    namespace net = boost::asio;

    /**
     * @brief socket 异步 IO 适配器
     * @note 自动适配 TCP (async_read_some/async_write_some) 和 UDP (async_receive/async_send)
     */
    struct adaptation
    {
        /**
         * @brief 异步读取
         */
        template <typename ExternalSocket, typename ExternalBuffer, typename CompletionToken>
        static auto async_read(ExternalSocket &socket, const ExternalBuffer &buffer, CompletionToken &&token)
        {
            if constexpr (requires { socket.async_read_some(buffer, token); })
            {
                // TCP: 使用 async_read_some
                return socket.async_read_some(buffer, std::forward<CompletionToken>(token));
            }
            else
            {
                // UDP: 使用 async_receive
                return socket.async_receive(buffer, std::forward<CompletionToken>(token));
            }
        }

        /**
         * @brief 异步写入
         */
        template <typename ExternalSocket, typename ExternalBuffer, typename CompletionToken>
        static auto async_write(ExternalSocket &socket, const ExternalBuffer &buffer, CompletionToken &&token)
        {
            if constexpr (requires { socket.async_write_some(buffer, token); })
            {
                // TCP: 使用 net::async_write 保证完整写入 (流式)
                return net::async_write(socket, buffer, std::forward<CompletionToken>(token));
            }
            else
            {
                // UDP: 使用 async_send (数据报)
                return socket.async_send(buffer, std::forward<CompletionToken>(token));
            }
        }
    };
}

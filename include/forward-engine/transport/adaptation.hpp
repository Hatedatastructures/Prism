/**
 * @file adaptation.hpp
 * @brief Socket 异步 IO 适配器
 * @details 统一 TCP 和 UDP 的异步读写接口，屏蔽底层 API 差异。
 */
#pragma once

#include <boost/asio.hpp>

/**
 * @namespace ngx::transport
 * @brief 传输层 (Data Plane)
 * @details 负责底层的数据搬运、连接管理和协议封装。
 * 包含 IO 适配器、连接池、隧道封装等组件。
 */
namespace ngx::transport
{
    namespace net = boost::asio;

    /**
     * @brief Socket 异步 IO 适配器
     * @details 自动适配 TCP (`async_read_some`/`async_write_some`) 和 UDP (`async_receive`/`async_send`)。
     * 提供统一的泛型接口，屏蔽底层 API 差异。
     */
    struct adaptation
    {
        /**
         * @brief 异步读取
         * @tparam ExternalSocket Socket 类型
         * @tparam ExternalBuffer 缓冲区类型
         * @tparam CompletionToken 完成处理标记类型
         * @param socket Socket 对象引用
         * @param buffer 接收缓冲区
         * @param token 完成处理标记
         * @return 根据 Token 推导的返回值 (通常是 `net::awaitable<std::size_t>`)
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
         * @tparam ExternalSocket Socket 类型
         * @tparam ExternalBuffer 缓冲区类型
         * @tparam CompletionToken 完成处理标记类型
         * @param socket Socket 对象引用
         * @param buffer 发送缓冲区
         * @param token 完成处理标记
         * @return 根据 Token 推导的返回值 (通常是 `net::awaitable<std::size_t>`)
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

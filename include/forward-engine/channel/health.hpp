#pragma once

#include <boost/asio.hpp>

namespace ngx::channel
{
    namespace net = boost::asio;

    /**
     * @brief socket 健康状态
     */
    enum class socket_state
    {
        healthy,  // 健康，可复用
        has_data, // 有待读数据
        fin,      // 对端已关闭
        error,    // socket 错误
        invalid   // 无效 socket
    };

    /**
     * @brief 完整的 socket 健康检测
     * @param s 待检测的 TCP socket
     * @return socket 健康状态
     * @details 依次检查 SO_ERROR、available、peek 三个维度，
     * 综合判断 socket 是否可安全复用。
     */
    [[nodiscard]] socket_state health(const net::ip::tcp::socket &s);

    /**
     * @brief 快速 socket 健康检测
     * @param s 待检测的 TCP socket
     * @return true 表示健康，false 表示不健康
     * @details 检查 SO_ERROR、available 和 FIN 状态。
     * 当 available == 0 时，通过非阻塞 recv(MSG_PEEK) 检测对端是否已发 FIN，
     * 避免将已关闭的连接放入连接池。
     */
    [[nodiscard]] bool healthy_fast(const net::ip::tcp::socket &s);
} // namespace ngx::channel

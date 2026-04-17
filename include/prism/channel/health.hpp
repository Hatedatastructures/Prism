/**
 * @file health.hpp
 * @brief Socket 健康检测模块
 * @details 提供 TCP socket 健康状态检测功能，用于连接池复用前的有效性验证。
 * 在将连接归还到连接池之前，需要检测 socket 是否仍然健康可用，
 * 避免将已关闭或错误的连接放入池中供后续复用。
 * 检测维度包括 SO_ERROR，获取 socket 的待处理错误码；
 * available，检查是否有待读取数据（可能是对端 FIN）；
 * peek，通过 MSG_PEEK 预读检测对端是否已发送 FIN。
 * 健康状态分类包括 healthy 连接健康可安全复用；
 * has_data 有待读数据可能是延迟数据或 FIN；
 * fin 对端已关闭不可复用；error socket 发生错误不可复用；
 * invalid socket 无效（未打开或已关闭）。
 * 使用场景包括连接池归还前检测确保复用的连接仍然有效；
 * 连接池取出前检测避免使用已失效的连接；
 * 定期健康检查清理池中的失效连接。
 * @note 健康检测是连接池复用的关键环节，必须在使用前进行。
 * @warning 检测操作会读取 socket 状态，可能影响后续数据读取。
 */
#pragma once

#include <boost/asio.hpp>

namespace psm::channel
{
    namespace net = boost::asio;

    /**
     * @enum socket_state
     * @brief socket 健康状态
     */
    enum class socket_state
    {
        /** @brief 健康，可安全复用 */
        healthy,
        /** @brief 有待读数据，可能是延迟数据或 FIN */
        has_data,
        /** @brief 对端已关闭，不可复用 */
        fin,
        /** @brief socket 发生错误，不可复用 */
        error,
        /** @brief socket 无效（未打开或已关闭） */
        invalid
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
} // namespace psm::channel

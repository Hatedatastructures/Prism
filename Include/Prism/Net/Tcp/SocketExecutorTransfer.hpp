/**
 * @file SocketExecutorTransfer.hpp
 * @brief 在无在途 I/O 时把已接纳 TCP socket 的 native owner 移交到目标 executor。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <expected>

namespace Prism::Network::Tcp
{
    namespace Net = boost::asio;
    using TcpSocket = Net::ip::tcp::socket;

    /**
     * @brief 把已接纳 TCP socket 转交给目标 executor，并返回唯一 owning socket。
     * @details 输入：Socket 按值移交；Executor 是目标 socket executor。调用前必须确保
     *          socket 没有任何在途 I/O、控制交付或其他并发访问。输出：成功值是唯一 socket
     *          owner；调用者可将它移入 Reliable，之后最终关闭归该传输 owner。失败时 native
     *          handle 由无分配 guard 用平台 API 关闭，不回退到源 executor。目标 executor 的
     *          execution context 必须保持存活到 socket 的 I/O、取消、关闭和真实 drain 结束。
     *          Release/assign/系统异常以 Fault::Failure 保留原生 category/value；无法映射的
     *          异常返回 ResourceUnavailable。此函数不执行半关闭，不保留 socket 别名。
     */
    [[nodiscard]] auto MoveAcceptedSocket(
        TcpSocket Socket, Net::any_io_executor Executor)
        -> std::expected<TcpSocket, Prism::Fault::Failure>;
} // TCP 所有权移交

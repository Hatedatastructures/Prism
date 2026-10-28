/** @file Deadline.hpp @brief 单个已接收数据报的解析、交换与应答期限。 */
#pragma once
#include <Prism/Foundation/Fault/Code.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <chrono>

namespace Prism::Protocols
{
    struct DatagramDeadline final
    {
        boost::asio::any_io_executor Executor;
        std::chrono::milliseconds Timeout;
    };

    /**
     * @brief 接管一次串行交换；超时取消子操作并等待全部操作退栈后返回 Timeout。
     * @details 在协议 executor 上执行，非正期限禁用计时；输入借用窗口须由调用方
     *          保活到返回。这里只执行取消竞速，socket 与载体最终关闭归协议 session。
     */
    [[nodiscard]] auto AwaitDatagramDeadline(
        boost::asio::awaitable<Prism::Fault::Code> Operation,
        DatagramDeadline Deadline) -> boost::asio::awaitable<Prism::Fault::Code>;
}

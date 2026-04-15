/**
 * @file read.hpp
 * @brief 共享 I/O 读取工具函数
 * @details 提供跨协议的通用读取辅助函数，包括 read_at_least 和
 * read_remaining。这些函数封装了从传输层批量读取数据的协程逻辑，
 * 被 Trojan 和 VLESS relay 共同使用，消除重复代码。
 * 所有函数返回 net::awaitable，遵循项目纯协程设计。
 */

#pragma once

#include <cstddef>
#include <span>
#include <system_error>
#include <utility>

#include <boost/asio.hpp>

#include <prism/channel/transport/transmission.hpp>
#include <prism/fault/handling.hpp>

namespace psm::protocol::common
{
    namespace net = boost::asio;

    /**
     * @brief 批量读取至少指定数量的字节
     * @param transport 传输层引用
     * @param buffer 输出缓冲区
     * @param min_size 最小读取字节数
     * @return 协程对象，完成后返回错误码和实际读取字节数
     * @details 循环调用 async_read_some 直到读取至少 min_size 字节。
     * 遇到错误或 EOF 时提前返回，返回已读取的字节数和对应的错误码。
     */
    inline auto read_at_least(channel::transport::transmission &transport,
                              const std::span<std::byte> buffer,
                              const std::size_t min_size)
        -> net::awaitable<std::pair<fault::code, std::size_t>>
    {
        std::size_t total = 0;
        while (total < min_size)
        {
            std::error_code ec;
            const auto n = co_await transport.async_read_some(buffer.subspan(total), ec);
            if (ec)
            {
                co_return std::pair{fault::to_code(ec), total};
            }
            if (n == 0)
            {
                co_return std::pair{fault::code::eof, total};
            }
            total += n;
        }
        co_return std::pair{fault::code::success, total};
    }

    /**
     * @brief 精确补读剩余字节
     * @param transport 传输层引用
     * @param buffer 输出缓冲区
     * @param current 当前已读字节数
     * @param target 目标字节数
     * @return 协程对象，完成后返回错误码和最终读取字节数
     * @details 从 current 位置继续读取，直到达到 target 字节。
     * 遇到错误或 EOF 时提前返回，返回已读取的字节数和对应的错误码。
     */
    inline auto read_remaining(channel::transport::transmission &transport,
                               const std::span<std::byte> buffer,
                               std::size_t current,
                               const std::size_t target)
        -> net::awaitable<std::pair<fault::code, std::size_t>>
    {
        while (current < target)
        {
            std::error_code ec;
            const auto n = co_await transport.async_read_some(buffer.subspan(current), ec);
            if (ec)
            {
                co_return std::pair{fault::to_code(ec), current};
            }
            if (n == 0)
            {
                co_return std::pair{fault::code::eof, current};
            }
            current += n;
        }
        co_return std::pair{fault::code::success, current};
    }
} // namespace psm::protocol::common

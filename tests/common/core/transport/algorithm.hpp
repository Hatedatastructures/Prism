/**
 * @file algorithm.hpp
 * @brief 组合操作（Composed Operations，借鉴 Boost.Beast/Asio 精髓）
 * @details 提供基于 stream concept 的高层组合算法：
 *          - async_read_exact()：读满指定字节（内部循环补读）
 *          - async_write_exact()：写满指定字节（内部循环补写）
 *          组合算法不关心底层协议细节，直接使用 stream 原语，
 *          与 Beast 的 http::async_read / websocket::async_write 同构。
 * @note 全部协程实现，内部不分配堆内存。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

#include <common/core/error.hpp>
#include <common/core/transport/stream.hpp>

namespace preview
{

    /**
     * @brief 读满 buf.size() 字节（内部循环补读）
     * @tparam S stream concept 满足类型
     * @param s 目标流
     * @param buf 输出缓冲
     * @return 错误码；EOF（对端提前关闭）= unexpected_eof
     * @note 超时由流的 set_timeout 控制（如有）
     */
    template <stream S>
    auto async_read_exact(S &s, std::span<std::uint8_t> buf) -> net::awaitable<protocol_ec>
    {
        std::size_t done = 0;
        while (done < buf.size())
        {
            const auto n = co_await s.read_some(buf.subspan(done));
            if (n == 0)
            {
                co_return make_error_code(error::unexpected_eof);
            }
            done += n;
        }
        co_return {};
    }

    /**
     * @brief 写满 buf.size() 字节
     * @tparam S stream concept 满足类型
     * @param s 目标流
     * @param buf 输入缓冲
     * @return 错误码（write_all 语义：全部写入或失败）
     */
    template <stream S>
    auto async_write_exact(S &s, std::span<const std::uint8_t> buf) -> net::awaitable<protocol_ec>
    {
        co_return co_await s.write_all(buf);
    }

    /**
     * @brief 带超时读满指定字节
     * @param s 目标流
     * @param buf 输出缓冲
     * @param timeout 读超时（0 = 不设置）
     * @return 错误码；超时 = timeout
     */
    template <stream S>
    auto async_read_exact(S &s, std::span<std::uint8_t> buf, std::chrono::milliseconds timeout)
        -> net::awaitable<protocol_ec>
    {
        if (timeout.count() > 0)
        {
            s.set_timeout(timeout);
        }
        co_return co_await async_read_exact(s, buf);
    }

} // namespace preview

/**
 * @file Stream.hpp
 * @brief 统一异步传输 concept（对齐 Transmission 抽象）
 * @details 定义测试库统一异步传输接口 concept，基于
 * Transmission 抽象（AsyncReadSome / AsyncWriteSome / Close /
 * Cancel / IsOpen / Executor），协程友好的无阻塞 I/O 约定。
 * @note 全局为协程接口（net::awaitable），禁止阻塞 I/O。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>

namespace Preview
{

    namespace net = boost::asio;

    /// 统一异步传输 concept
    /// @tparam T 传输类型（MemoryStream / Reliable / 协议连接）
    template <typename T>
    concept Stream =
        requires(T &s, std::span<std::byte> wbuf, std::span<const std::byte> rbuf, std::error_code &ec) {
            /// 异步读取（至多 wbuf.size() 字节，0 = 对端关闭）
            { s.AsyncReadSome(wbuf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
            /// 异步写入（至多 rbuf.size() 字节）
            { s.AsyncWriteSome(rbuf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
            /// 同步关闭（读写均不可用）
            { s.Close() } -> std::same_as<void>;
            /// 取消未完成异步操作
            { s.Cancel() } -> std::same_as<void>;
            /// 是否处于打开状态
            { s.IsOpen() } -> std::same_as<bool>;
            /// 获取执行器
            { s.Executor() } -> std::same_as<net::any_io_executor>;
        };

    /// 可关闭传输（在 Stream 基础上支持 Shutdown 语义，预留）
    template <typename T>
    concept ClosableStream = Stream<T>;

} // namespace Preview

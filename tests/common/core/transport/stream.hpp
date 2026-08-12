/**
 * @file stream.hpp
 * @brief 统一异步传输 concept（对齐 transmission 抽象）
 * @details 定义测试库统一异步传输接口 concept，基于
 * transmission 抽象（async_read_some / async_write_some / close /
 * cancel / is_open / executor），协程友好的无阻塞 I/O 约定。
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

namespace psmtest
{

    namespace net = boost::asio;

    /// 统一异步传输 concept
    /// @tparam T 传输类型（memory_stream / socket_stream / 协议连接）
    template <typename T>
    concept stream = requires(T &s, std::span<std::byte> wbuf,
                              std::span<const std::byte> rbuf,
                              std::error_code &ec)
    {
        /// 异步读取（至多 wbuf.size() 字节，0 = 对端关闭）
        { s.async_read_some(wbuf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
        /// 异步写入（至多 rbuf.size() 字节）
        { s.async_write_some(rbuf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
        /// 同步关闭（读写均不可用）
        { s.close() } -> std::same_as<void>;
        /// 取消未完成异步操作
        { s.cancel() } -> std::same_as<void>;
        /// 是否处于打开状态
        { s.is_open() } -> std::same_as<bool>;
        /// 获取执行器
        { s.executor() } -> std::same_as<net::any_io_executor>;
    };

    /// 可关闭传输（在 stream 基础上支持 shutdown 语义，预留）
    template <typename T>
    concept closable_stream = stream<T>;

} // namespace psmtest

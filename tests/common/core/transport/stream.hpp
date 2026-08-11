/**
 * @file stream.hpp
 * @brief 统一异步流抽象（concept）
 * @details 借鉴 Boost.Asio AsyncReadStream/AsyncWriteStream 与
 *          Boost.Beast stream 概念：所有协议对象工作在统一的异步流上。
 *          除读写外补充生命周期操作（shutdown 半关 / close / cancel /
 *          set_timeout / is_open / executor），满足全协议通用需求。
 * @note 全部为协程接口（net::awaitable），禁止阻塞 I/O。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>

namespace psmtest
{

    namespace net = boost::asio;

    /// 统一异步流 concept
    /// @tparam T 流类型（memory_stream / socket_stream / 协议会话）
    template <typename T>
    concept stream = requires(T &s, std::span<std::uint8_t> wbuf,
                              std::span<const std::uint8_t> rbuf,
                              std::chrono::milliseconds ms)
    {
        /// 读取最多 wbuf.size() 字节，返回实际读取数（0 = 对端关闭）
        { s.read_some(wbuf) } -> std::same_as<net::awaitable<std::size_t>>;
        /// 写入全部 rbuf 字节，返回错误码（成功 = 空）
        { s.write_all(rbuf) } -> std::same_as<net::awaitable<boost::system::error_code>>;
        /// 优雅半关（发送 FIN，仍可读）
        { s.shutdown() } -> std::same_as<net::awaitable<void>>;
        /// 立即关闭（读写均不可用）
        { s.close() } -> std::same_as<net::awaitable<void>>;
        /// 取消挂起操作（挂起的读写立即返回）
        { s.cancel() } -> std::same_as<void>;
        /// 设置读超时（0 = 禁用）
        { s.set_timeout(ms) } -> std::same_as<void>;
        /// 流是否打开
        { s.is_open() } -> std::same_as<bool>;
        /// 获取执行器
        { s.executor() } -> std::same_as<net::any_io_executor>;
    };

    /// 可关闭（半关）流：在 stream 基础上补充 shutdown_write 语义
    /// @note 协议会话的 shutdown() 语义：发送 FIN 后仍可读对端数据
    template <typename T>
    concept closable_stream = stream<T>;

} // namespace psmtest

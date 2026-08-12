/**
 * @file transport_base.hpp
 * @brief 传输流抽象基类（类型擦除，对齐 Prism 主库 shared_transmission）
 * @details 虚接口与 transport::stream concept 同构；内存流 / 套接字流
 *          均继承本基类，协议握手（client_base::connect /
 *          server_base::accept）通过基类指针操作底层传输，
 *          实现"换传输不改协议"的多态组合。
 * @note 热路径性能测试使用模板（stream concept）零虚调用；
 *          本基类服务于多态切换场景。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/transport/stream.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

namespace psmtest
{

    /// 传输流抽象基类
    class transport_base
    {
    public:
        virtual ~transport_base() = default;

        /// 读取最多 buf.size() 字节
        virtual auto read_some(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t> = 0;

        /// 写入全部 buf 字节
        virtual auto write_all(std::span<const std::uint8_t> buf) -> net::awaitable<protocol_ec> = 0;

        /// 优雅半关
        virtual auto shutdown() -> net::awaitable<void> = 0;

        /// 立即关闭
        virtual auto close() -> net::awaitable<void> = 0;

        /// 取消挂起操作
        virtual auto cancel() -> void = 0;

        /// 设置读超时
        virtual auto set_timeout(std::chrono::milliseconds ms) -> void = 0;

        /// 流是否打开
        [[nodiscard]] virtual auto is_open() const -> bool = 0;

        /// 获取执行器
        [[nodiscard]] virtual auto executor() const -> net::any_io_executor = 0;
    };

} // namespace psmtest

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

// DEPRECATED: 旧骨架（Beast 模板方法模式），新协议 conn 统一使用 psmtest::transmission
// （core/transmission.hpp）。本文件仅保留供迁移期兼容，勿在新代码中使用。

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

#include <common/core/error.hpp>
#include <common/core/transport/stream.hpp>

namespace psmtest
{

    /// 传输流抽象基类
    class transport_base
    {
    public:
        virtual ~transport_base() = default;

        /**
         * @brief 读取最多 buf.size() 字节
         * @param buf 接收缓冲区
         * @return 实际读取字节数；0 = 对端关闭或 EOF
         */
        virtual auto read_some(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 写入全部 buf 字节
         * @param buf 待写数据
         * @return 错误码（成功 = 空）
         */
        virtual auto write_all(std::span<const std::uint8_t> buf) -> net::awaitable<protocol_ec> = 0;

        /**
         * @brief 优雅半关
         */
        virtual auto shutdown() -> net::awaitable<void> = 0;

        /**
         * @brief 立即关闭
         */
        virtual auto close() -> net::awaitable<void> = 0;

        /**
         * @brief 取消挂起操作
         */
        virtual auto cancel() -> void = 0;

        /**
         * @brief 设置读超时
         * @param ms 超时毫秒数（0 = 禁用）
         */
        virtual auto set_timeout(std::chrono::milliseconds ms) -> void = 0;

        /**
         * @brief 流是否打开
         * @return 打开返回 true
         */
        [[nodiscard]] virtual auto is_open() const -> bool = 0;

        /**
         * @brief 获取执行器
         * @return 关联的执行器
         */
        [[nodiscard]] virtual auto executor() const -> net::any_io_executor = 0;
    };

} // namespace psmtest

/**
 * @file session_base.hpp
 * @brief 会话抽象基类（统一生命周期接口）
 * @details 借鉴 Boost.Beast stream 概念：所有协议会话继承本基类，
 *          上层（转发层 / 测试框架）通过基类指针切换协议零成本。
 *          基类定义统一的生命周期接口，派生协议实现具体编解码。
 * @note 与 transport::stream concept 保持同构，session_base 满足 stream。
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

    /// 会话抽象基类
    class session_base
    {
    public:
        virtual ~session_base() = default;

        /// @brief 读取最多 buf.size() 字节（解包后的明文数据）
        /// @return 实际读取字节数；0 = 对端关闭
        virtual auto read_some(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t> = 0;

        /// @brief 写入全部 buf 字节（加密封包后发送）
        /// @return 错误码（成功 = 空）
        virtual auto write_all(std::span<const std::uint8_t> buf) -> net::awaitable<protocol_ec> = 0;

        /// @brief 优雅半关（发送 FIN，仍可读对端数据）
        virtual auto shutdown() -> net::awaitable<void> = 0;

        /// @brief 立即关闭（读写均不可用）
        virtual auto close() -> net::awaitable<void> = 0;

        /// @brief 取消挂起操作
        virtual auto cancel() -> void = 0;

        /// @brief 设置读超时（0 = 禁用）
        virtual auto set_timeout(std::chrono::milliseconds ms) -> void = 0;

        /// 流是否打开
        [[nodiscard]] virtual auto is_open() const -> bool = 0;

        /// 获取执行器
        [[nodiscard]] virtual auto executor() const -> net::any_io_executor = 0;
    };

    /// 会话基类必须满足 stream concept
    static_assert(stream<session_base>, "session_base 必须满足 stream concept");

} // namespace psmtest

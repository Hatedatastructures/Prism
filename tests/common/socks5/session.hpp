/**
 * @file session.hpp
 * @brief SOCKS5 透传会话（握手后数据直通，满足 session_base）
 * @details SOCKS5 无分块/加密：握手完成后数据在明文传输上直接转发。
 *          本会话对底层流做透明包装，提供统一 session_base 接口。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/session_base.hpp>
#include <common/core/transport/transport_base.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace psmtest::socks5
{

    /// @brief SOCKS5 透传会话
    class session : public session_base
    {
    public:
        /// @brief 构造
        /// @param raw 底层传输（所有权移交）
        explicit session(std::shared_ptr<transport_base> raw)
            : raw_(std::move(raw))
        {
        }

        /// 读取数据（透传）
        auto read_some(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t> override
        {
            if (!raw_ || !raw_->is_open())
                co_return 0;
            co_return co_await raw_->read_some(buf);
        }

        /// 写入数据（透传）
        auto write_all(std::span<const std::uint8_t> buf) -> net::awaitable<protocol_ec> override
        {
            if (!raw_ || !raw_->is_open())
                co_return make_error_code(error::broken_pipe);
            co_return co_await raw_->write_all(buf);
        }

        /// 半关
        auto shutdown() -> net::awaitable<void> override
        {
            if (raw_)
                co_await raw_->shutdown();
            co_return;
        }

        /// 关闭
        auto close() -> net::awaitable<void> override
        {
            if (raw_)
                co_await raw_->close();
            co_return;
        }

        /// 取消挂起操作
        auto cancel() -> void override
        {
            if (raw_)
                raw_->cancel();
        }

        /// 设置读超时
        auto set_timeout(std::chrono::milliseconds ms) -> void override
        {
            if (raw_)
                raw_->set_timeout(ms);
        }

        /// 流是否打开
        [[nodiscard]] auto is_open() const -> bool override
        {
            return raw_ && raw_->is_open();
        }

        /// 获取执行器
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return raw_ ? raw_->executor() : net::any_io_executor{};
        }

    private:
        std::shared_ptr<transport_base> raw_;
    };

} // namespace psmtest::socks5

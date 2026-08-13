/**
 * @file stream.hpp
 * @brief 多路复用流传输适配器（stream_handle → transmission）
 * @details 包装 mux 虚拟流句柄，将其暴露为新传输接口，作为上层协议
 * server/client（vless/trojan/socks5/...）的挂载点。流无底层链，
 * next_layer() 返回 nullptr（叶子节点）。
 * @note stream_handle::close() / reset() 为协程（体内无挂起点），
 * 必须经 co_spawn 驱动执行，适配器以 shared_ptr 捕获句柄保活。
 * @note n == 0 的读返回视为对端关闭，ec 置 error::unexpected_eof。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include <common/core/byte_span.hpp>
#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/mux/session.hpp>

namespace psmtest::mux
{

    /**
     * @class stream_transmission
     * @brief 流传输适配器（stream_handle → transmission）
     * @details 将 mux 虚拟流句柄包装为 transmission 接口，供上层协议
     * 会话直接挂载（装饰器链叶子节点）。
     */
    class stream_transmission : public transmission
    {
    public:
        /**
         * @brief 构造
         * @param handle mux 虚拟流句柄（所有权移交）
         */
        explicit stream_transmission(std::shared_ptr<stream_handle> handle) : handle_(std::move(handle))
        {
        }

        /**
         * @brief 获取执行器
         * @return 流执行器（句柄为空时返回默认执行器）
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return handle_ ? handle_->executor() : net::any_io_executor{};
        }

        /**
         * @brief 异步读取部分数据
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数
         * @details 转调 stream_handle::read_some；n == 0（对端关闭/
         * 半关/超时）时 ec 置 error::unexpected_eof。
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!handle_)
            {
                ec = make_error_code(error::not_open);
                co_return 0;
            }
            const auto n = co_await handle_->read_some(as_u8(buffer));
            if (n == 0)
            {
                ec = make_error_code(error::unexpected_eof);
            }
            else
            {
                ec.clear();
            }
            co_return n;
        }

        /**
         * @brief 异步写入部分数据
         * @param buffer 待写数据
         * @param ec 错误码输出参数
         * @return 实际写入字节数
         * @details 转调 stream_handle::write_all（内部完整写入），
         * 错误经 boost→std 隐式转换存入 ec。
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            if (!handle_)
            {
                ec = make_error_code(error::not_open);
                co_return 0;
            }
            const auto err = co_await handle_->write_all(as_u8(buffer));
            if (err)
            {
                ec = err;
                co_return 0;
            }
            ec.clear();
            co_return buffer.size();
        }

        /**
         * @brief 关闭流
         * @details stream_handle::close() 是协程，经 co_spawn 投递到
         * 流执行器上执行；lambda 按值捕获句柄保证存活。
         */
        void close() override
        {
            auto handle = handle_;
            if (!handle)
            {
                return;
            }
            net::co_spawn(
                handle->executor(), [handle]() -> net::awaitable<void> { co_await handle->close(); },
                net::detached);
        }

        /**
         * @brief 重置流（发 RST，对端读返回 0）
         * @details 与 close() 同样经 co_spawn 投递执行；区别是向对端
         * 发送重置帧，对端挂起读被唤醒并返回 0。
         */
        void reset()
        {
            auto handle = handle_;
            if (!handle)
            {
                return;
            }
            net::co_spawn(
                handle->executor(), [handle]() -> net::awaitable<void> { co_await handle->reset(); },
                net::detached);
        }

        /**
         * @brief 取消挂起操作
         */
        void cancel() override
        {
            if (handle_)
            {
                handle_->cancel();
            }
        }

        /**
         * @brief 流是否打开
         * @return true = 句柄存活且未关闭
         */
        [[nodiscard]] auto is_open() const -> bool
        {
            return handle_ && handle_->is_open();
        }

        /**
         * @brief 获取底层流句柄
         * @return mux 虚拟流句柄
         */
        [[nodiscard]] auto handle() const noexcept -> std::shared_ptr<stream_handle>
        {
            return handle_;
        }

    private:
        std::shared_ptr<stream_handle> handle_; ///< mux 虚拟流句柄
    };

    /// 流传输共享指针
    using shared_stream = std::shared_ptr<stream_transmission>;

} // namespace psmtest::mux

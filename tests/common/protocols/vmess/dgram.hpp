/**
 * @file dgram.hpp
 * @brief VMess UDP 包连接对象（transmission 装饰器）
 * @details UDP 数据面连接：将底层流连接（vmess::conn，chunk 即包
 * 边界）包装为包级 API。包级 API 无地址参数（目标固定来自指令头）。
 * 一次 async_send_to = 加密并发送一个数据分块（长度密文 + 载荷
 * 密文）；async_receive_from 读到该分块即完整数据报。
 * @note 继承 preview::transmission，构造函数传入底层流连接（相当于
 * socket 收发的持有者），对齐 conn 的装饰器链模式。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <common/core/error.hpp>
#include <common/core/transmission.hpp>
#include <common/protocols/vmess/conn.hpp>

namespace preview::vmess
{

    /**
     * @class dgram
     * @brief VMess UDP 包连接对象（transmission 装饰器）
     * @details 持有底层流连接（vmess::conn，已握手）的独占所有权，
     * 对外暴露包级 API（async_send_to / async_receive_from）。
     * 由工厂（connect_packet / accept_packet）创建。
     */
    template <preview::memory::restrict Memory = preview::memory::session_resource<>>
    class dgram : public preview::transmission, public std::enable_shared_from_this<dgram<Memory>>
    {
    public:
        /**
         * @brief 构造函数（工厂调用）
         * @param stream 底层流连接（已握手，所有权移交）
         */
        explicit dgram(shared_transmission stream) : next_layer_(std::move(stream))
        {
        }

        /**
         * @brief 获取执行器（委托底层流连接）
         */
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return next_layer_->executor();
        }

        /**
         * @brief 传输类型（经底层委托，TCP 承载数据报）
         */
        [[nodiscard]] auto transport_type() const noexcept -> type override
        {
            return type::udp;
        }

        /**
         * @brief 发送一个 UDP 数据报（加密一个 chunk）
         * @param payload 数据报载荷
         * @return 错误码
         */
        [[nodiscard]] auto async_send_to(std::span<const std::uint8_t> payload) -> net::awaitable<error>
        {
            return async_send_datagram_impl(payload);
        }

        /**
         * @brief 接收一个 UDP 数据报（解密一个 chunk）
         * @param payload 输出数据报载荷
         * @return 错误码
         */
        [[nodiscard]] auto async_receive_from(std::vector<std::uint8_t> &payload) -> net::awaitable<error>
        {
            return async_receive_datagram_impl(payload);
        }

        /**
         * @brief 透传读取（底层流原样）
         */
        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_read_some(buffer, ec);
        }

        /**
         * @brief 透传写入（底层流原样）
         */
        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override
        {
            co_return co_await next_layer_->async_write_some(buffer, ec);
        }

        /**
         * @brief 关闭底层流连接
         */
        void close() override
        {
            next_layer_->close();
        }

        /**
         * @brief 取消挂起操作
         */
        void cancel() override
        {
            next_layer_->cancel();
        }

        /**
         * @brief 获取底层传输（装饰器链导航）
         */
        [[nodiscard]] auto next_layer() noexcept -> preview::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 获取底层传输（const 版本）
         */
        [[nodiscard]] auto next_layer() const noexcept -> const preview::transmission * override
        {
            return next_layer_.get();
        }

        /**
         * @brief 释放底层传输所有权
         */
        [[nodiscard]] auto release() -> shared_transmission override
        {
            return std::move(next_layer_);
        }

        /**
         * @brief 获取底层流连接
         */
        [[nodiscard]] auto stream() const noexcept -> shared_transmission
        {
            return next_layer_;
        }

    private:
        /**
         * @brief 转调底层数据报发送（chunk 加密）
         */
        [[nodiscard]] auto async_send_datagram_impl(std::span<const std::uint8_t> payload)
            -> net::awaitable<error>
        {
            auto *c = dynamic_cast<conn<Memory> *>(next_layer_.get());
            if (!c)
            {
                co_return error::not_open;
            }
            co_return co_await c->async_send_datagram(payload);
        }

        /**
         * @brief 转调底层数据报接收（chunk 解密）
         */
        [[nodiscard]] auto async_receive_datagram_impl(std::vector<std::uint8_t> &payload)
            -> net::awaitable<error>
        {
            auto *c = dynamic_cast<conn<Memory> *>(next_layer_.get());
            if (!c)
            {
                co_return error::not_open;
            }
            co_return co_await c->async_receive_datagram(payload);
        }

        shared_transmission next_layer_; ///< 底层流连接（嵌入，同一条 TCP）
    };

    /// 包连接共享指针
    using shared_dgram = std::shared_ptr<dgram<>>;

} // namespace preview::vmess

/**
 * @file transmission.hpp
 * @brief 传输层抽象接口
 * @details 定义了通用的流式传输接口，支持 TCP、UDP 以及协议装饰器。
 * 该接口采用纯协程设计，使用 `net::awaitable` 作为异步操作返回类型。
 * 所有具体的传输实现（如 TCP、UDP）和协议装饰器（如 Trojan）都应继承此接口。
 */

#pragma once

#include <boost/asio.hpp>
#include <cstddef>
#include <functional>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

#include <forward-engine/gist/compatible.hpp>

namespace ngx::transport
{
    namespace net = boost::asio;

    /**
     * @class transmission
     * @brief 传输层抽象接口
     * @details 提供了异步读写、关闭、取消等基本操作，是分层流式架构的核心。
     * 该接口使用纯协程设计，直接返回 `net::awaitable`，简化异步操作调用。
     * 所有异步操作通过 `std::error_code&` 参数返回错误，避免异常开销。
     */
    class transmission
    {
    public:
        using executor_type = net::any_io_executor;

        virtual ~transmission() = default;

    /**
     * @brief 检查传输是否可靠（如 TCP）
     * @details 用于优化路径选择，避免 dynamic_cast。
     */
    [[nodiscard]] virtual bool is_reliable() const noexcept { return false; }

        /**
         * @brief 获取关联的执行器（Executor）
         * @return `executor_type` 执行器
         */
        virtual executor_type executor() const = 0;

        // 兼容 Asio Concept
        executor_type get_executor() const
        {
            return executor();
        }

        /**
         * @brief 异步读取数据
         * @param buffer 接收缓冲区（`std::span<std::byte>` 类型）
         * @param ec 错误码输出参数
         * @details 从传输层读取一些数据到缓冲区。返回实际读取的字节数，错误通过 `ec` 返回。
         * 如果操作成功，`ec` 为 `std::error_code()`；否则包含错误信息。
         * @return `net::awaitable<std::size_t>` 异步操作，完成后返回读取的字节数
         */
        virtual auto async_read_some(std::span<std::byte> buffer, std::error_code& ec) 
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 异步写入数据
         * @param buffer 发送缓冲区（`std::span<const std::byte>` 类型）
         * @param ec 错误码输出参数
         * @details 将缓冲区中的数据写入传输层。返回实际写入的字节数，错误通过 `ec` 返回。
         * 如果操作成功，`ec` 为 `std::error_code()`；否则包含错误信息。
         * @return `net::awaitable<std::size_t>` 异步操作，完成后返回写入的字节数
         */
        virtual auto async_write_some(std::span<const std::byte> buffer, std::error_code& ec) 
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 关闭传输层
         * @details 关闭底层连接或资源。关闭后，所有未完成的异步操作将被取消。
         */
        virtual void close() = 0;

        /**
         * @brief 取消所有未完成的异步操作
         * @details 取消当前所有挂起的异步读写操作。
         */
        virtual void cancel() = 0;
    };

    /**
     * @brief 传输层智能指针类型
     */
    using transmission_pointer = std::unique_ptr<transmission>;

    /**
     * @brief 基于 Boost.Asio包装的异步读取数据到传输对象
     * @tparam MutableBufferSequence 可变缓冲区序列类型，满足 MutableBufferSequence 概念
     * @tparam CompletionToken 完成令牌类型，满足 CompletionToken 要求
     * @param trans 传输对象引用
     * @param buffers 要读取的缓冲区序列
     * @param token 完成令牌，用于处理异步操作结果
     * @return 异步操作初始化结果，具体类型取决于 CompletionToken
     */
    template <typename MutableBufferSequence, typename CompletionToken>
    auto async_read_some(transmission &trans, const MutableBufferSequence &buffers, CompletionToken &&token)
    {
        auto init = [&trans, buffers](auto handler) mutable
        {
            auto first = net::buffer_sequence_begin(buffers);
            std::span<std::byte> span(reinterpret_cast<std::byte *>(first->data()), first->size());

            auto work = [&trans, span, handler = std::move(handler)]() mutable -> net::awaitable<void>
            {
                std::error_code ec;
                const auto n = co_await trans.async_read_some(span, ec);
                
                boost::system::error_code b_ec;
                if (ec)
                {
                    if (ec.category() == ngx::gist::category())
                    {
                        b_ec = boost::system::error_code(ec.value(), boost::system::category());
                    }
                    else
                    {
                        b_ec = boost::system::error_code(ec.value(), boost::system::generic_category());
                    }
                }
                
                handler(b_ec, n);
            };
            net::co_spawn(trans.executor(), std::move(work), net::detached);
        };

        return net::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(std::move(init), token);
    }

    /**
     * @brief 基于 Boost.Asio包装的异步写入数据到传输对象
     * @tparam ConstBufferSequence 常量缓冲区序列类型，满足 ConstBufferSequence 概念
     * @tparam CompletionToken 完成令牌类型，满足 CompletionToken 要求
     * @param trans 传输对象引用
     * @param buffers 要写入的缓冲区序列
     * @param token 完成令牌，用于处理异步操作结果
     * @return 异步操作初始化结果，具体类型取决于 CompletionToken
     */
    template <typename ConstBufferSequence, typename CompletionToken>
    auto async_write_some(transmission &trans, const ConstBufferSequence &buffers, CompletionToken &&token)
    {
        auto init = [&trans, buffers](auto handler) mutable
        {
            auto first = net::buffer_sequence_begin(buffers);
            std::span<const std::byte> span(reinterpret_cast<const std::byte *>(first->data()), first->size());
            auto work = [&trans, span, handler = std::move(handler)]() mutable -> net::awaitable<void>
            {
                std::error_code ec;
                const auto n = co_await trans.async_write_some(span, ec);
                
                boost::system::error_code b_ec;
                if (ec)
                {
                    if (ec.category() == ngx::gist::category())
                    {
                        b_ec = boost::system::error_code(ec.value(), boost::system::category());
                    }
                    else
                    {
                        b_ec = boost::system::error_code(ec.value(), boost::system::generic_category());
                    }
                }

                handler(b_ec, n);
            };
            net::co_spawn(trans.executor(), std::move(work), net::detached);
        };

        return net::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(std::move(init), token);
    }

} // namespace ngx::transport

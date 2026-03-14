/**
 * @file transmission.hpp
 * @brief 传输层抽象接口
 * @details 定义了通用的流式传输接口，支持 TCP、UDP 以及协议装饰器。
 * 该接口采用纯协程设计，使用 net::awaitable 作为异步操作返回类型。
 * 所有具体的传输实现（如 TCP、UDP）和协议装饰器（如 Trojan）
 * 都应继承此接口。传输抽象 transmission 接口定义了所有传输层
 * 必须实现的基本操作。协程设计方面，所有异步操作返回 net::awaitable，
 * 简化异步操作调用。错误码返回通过 std::error_code& 参数返回错误，
 * 避免异常开销。智能指针 transmission_pointer 自动管理传输层生命周期。
 * 设计特性包括分层架构，支持 TCP、UDP 和协议装饰器（如 Trojan）
 * 的分层设计；概念适配，提供 get_executor 方法，
 * 兼容 Boost.Asio 的执行器概念；错误码映射，
 * 自动映射项目错误码到 Boost.System 错误码；异步包装，
 * 提供 async_read_some 和 async_write_some 包装函数，简化调用。
 * @note 该接口是传输层的核心抽象，所有传输实现都必须继承此接口。
 * @warning 接口方法都是纯虚函数，必须由子类实现。
 */
#pragma once

#include <boost/asio.hpp>
#include <cstddef>
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
     * 该接口使用纯协程设计，直接返回 net::awaitable，简化异步操作调用。
     * 所有异步操作通过 std::error_code& 参数返回错误，避免异常开销。
     * 核心职责包括可靠性标识，is_reliable 方法标识传输层是否可靠（TCP/UDP）；
     * 执行器管理，executor 方法返回关联的执行器；异步读取，
     * async_read_some 方法从传输层读取数据；异步写入，
     * async_write_some 方法向传输层写入数据；连接管理，
     * close 和 cancel 方法管理连接生命周期。设计原则包括纯虚接口，
     * 所有方法都是纯虚函数，强制子类实现；协程优先，
     * 异步操作返回协程，避免回调地狱；错误码返回，
     * 通过参数返回错误码，避免异常开销；概念兼容，
     * 提供 get_executor 方法，兼容 Boost.Asio 概念。
     * @note 该接口是传输层的核心抽象，所有传输实现都必须继承此接口。
     * @warning 接口方法都是纯虚函数，必须由子类实现。
     * @throws std::bad_alloc 如果内存分配失败
     * @throws std::runtime_error 如果网络 IO 失败
     */
    class transmission
    {
    public:
        using executor_type = net::any_io_executor;

        /**
         * @brief 虚析构函数
         * @details 确保子类的析构函数被正确调用。
         * @note 该析构函数是默认的，不执行任何操作。
         */
        virtual ~transmission() = default;

        /**
         * @brief 检查传输是否可靠（如 TCP）
         * @details 用于优化路径选择，避免 dynamic_cast。
         * 可靠传输（TCP）保证数据有序送达，不可靠传输（UDP）
         * 不保证数据送达和顺序。
         * @return bool 是否可靠（true 表示可靠，false 表示不可靠）
         * @note 默认实现返回 false，可靠传输层（如 reliable）应重写此方法。
         * @warning 此方法不抛出异常。
         */
        [[nodiscard]] virtual bool is_reliable() const noexcept { return false; }

        /**
         * @brief 获取关联的执行器（Executor）
         * @details 返回传输层关联的执行器，用于调度异步操作。
         * 执行器是 Boost.Asio 的核心概念，用于执行异步操作和调度任务。
         * @return executor_type 执行器
         * @note 该方法是纯虚函数，必须由子类实现。
         * @warning 返回的执行器必须在传输层生命周期内保持有效。
         */
        [[nodiscard]] virtual executor_type executor() const = 0;

        /**
         * @brief 获取关联的执行器（兼容 Asio Concept）
         * @details 返回传输层关联的执行器，用于兼容 Boost.Asio 的执行器概念。
         * 该方法是 executor 的别名，用于 Boost.Asio 的标准接口。
         * @return executor_type 执行器
         * @note 该方法委托给 executor 方法。
         * @warning 返回的执行器必须在传输层生命周期内保持有效。
         */
        [[nodiscard]] executor_type get_executor() const
        {
            return executor();
        }

        /**
         * @brief 异步读取数据
         * @details 从传输层读取一些数据到缓冲区。返回实际读取的字节数，
         * 错误通过 ec 返回。如果操作成功，ec 为 std::error_code；
         * 否则包含错误信息。读取特性包括非阻塞，
         * 该方法是异步的，不会阻塞调用线程；协程返回，
         * 返回 net::awaitable，可在协程中使用 co_await 等待；
         * 错误码返回，通过 ec 参数返回错误，避免异常开销；
         * 部分读取，可能读取比请求更少的数据，这是正常的。
         * @param buffer 接收缓冲区（std::span<std::byte> 类型）
         * @param ec 错误码输出参数，用于返回错误信息
         * @return net::awaitable<std::size_t> 异步操作，完成后返回读取的字节数
         * @note 该方法是纯虚函数，必须由子类实现。
         * @warning 缓冲区必须有效，且在整个异步操作期间保持有效。
         * @throws std::bad_alloc 如果内存分配失败
         */
        virtual auto async_read_some(std::span<std::byte> buffer, std::error_code& ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 异步写入数据
         * @details 将缓冲区中的数据写入传输层。返回实际写入的字节数，
         * 错误通过 ec 返回。如果操作成功，ec 为 std::error_code；
         * 否则包含错误信息。写入特性包括非阻塞，
         * 该方法是异步的，不会阻塞调用线程；协程返回，
         * 返回 net::awaitable，可在协程中使用 co_await 等待；
         * 错误码返回，通过 ec 参数返回错误，避免异常开销；
         * 部分写入，可能写入比请求更少的数据，这是正常的。
         * @param buffer 发送缓冲区（std::span<const std::byte> 类型）
         * @param ec 错误码输出参数，用于返回错误信息
         * @return net::awaitable<std::size_t> 异步操作，完成后返回写入的字节数
         * @note 该方法是纯虚函数，必须由子类实现。
         * @warning 缓冲区必须有效，且在整个异步操作期间保持有效。
         * @throws std::bad_alloc 如果内存分配失败
         */
        virtual auto async_write_some(std::span<const std::byte> buffer, std::error_code& ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 关闭传输层
         * @details 关闭底层连接或资源。关闭后，所有未完成的异步操作将被取消。
         * 该方法用于优雅关闭连接，确保资源被正确释放。
         * 关闭特性包括资源释放，释放底层 socket 和相关资源；
         * 操作取消，取消所有未完成的异步操作；幂等操作，
         * 多次调用不会产生副作用。
         * @note 该方法是纯虚函数，必须由子类实现。
         * @warning 关闭后传输层对象不再可用，不应再调用其任何方法。
         * @throws 子类实现可能抛出异常
         */
        virtual void close() = 0;

        /**
         * @brief 取消所有未完成的异步操作
         * @details 取消当前所有挂起的异步读写操作。
         * 该方法用于快速终止所有正在进行的异步操作。
         * 取消特性包括异步取消，取消所有挂起的异步操作；
         * 错误返回，被取消的操作将返回 operation_canceled 错误；
         * 幂等操作，多次调用不会产生副作用。
         * @note 该方法是纯虚函数，必须由子类实现。
         * @warning 取消后，相关操作将失败并返回错误码。
         * @throws 子类实现可能抛出异常
         */
        virtual void cancel() = 0;
    };

    /**
     * @brief 传输层智能指针类型
     * @details 用于管理传输层对象的生命周期。智能指针自动调用 delete 释放对象。
     * 该类型是传输层对象的通用智能指针类型，用于所有传输层操作。
     * 使用场景包括工厂返回，工厂方法返回智能指针，自动管理生命周期；
     * 函数参数，函数参数使用智能指针传递，避免所有权问题；
     * 成员变量，成员变量使用智能指针，自动管理资源。
     * @note 该智能指针是独占式所有权，不支持共享。
     * @warning 不应直接删除智能指针指向的对象，应让智能指针自动管理。
     */
    using transmission_pointer = std::unique_ptr<transmission>;

    /**
     * @brief 基于 Boost.Asio 包装的异步读取数据到传输对象
     * @details 这是一个包装函数，将 Boost.Asio 的异步读取接口适配到传输层接口。
     * 该函数支持 Boost.Asio 的缓冲区序列和完成令牌，简化异步操作调用。
     * 包装逻辑包括缓冲区转换，将 Boost.Asio 缓冲区序列转换为 std::span；
     * 错误码映射，将项目错误码映射到 Boost.System 错误码；
     * 协程包装，在协程中调用传输层的异步读取方法；
     * 完成令牌，支持协程、回调等多种完成令牌。错误码映射方面，
     * 项目错误码如果错误码类别是项目错误码，映射到 Boost.System 类别；
     * 标准错误码否则映射到 Boost.System 通用类别。
     * @tparam MutableBufferSequence 可变缓冲区序列类型，满足 MutableBufferSequence 概念
     * @tparam CompletionToken 完成令牌类型，满足 CompletionToken 要求
     * @param trans 传输对象引用
     * @param buffers 要读取的缓冲区序列
     * @param token 完成令牌，用于处理异步操作结果
     * @return 异步操作初始化结果，具体类型取决于 CompletionToken
     * @note 该函数是模板，可自动推导返回类型。
     * @warning 缓冲区序列必须在整个异步操作期间保持有效。
     * @throws std::bad_alloc 如果内存分配失败
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
     * @brief 基于 Boost.Asio 包装的异步写入数据到传输对象
     * @details 这是一个包装函数，将 Boost.Asio 的异步写入接口适配到传输层接口。
     * 该函数支持 Boost.Asio 的缓冲区序列和完成令牌，简化异步操作调用。
     * 包装逻辑包括缓冲区转换，将 Boost.Asio 缓冲区序列转换为 std::span；
     * 错误码映射，将项目错误码映射到 Boost.System 错误码；
     * 协程包装，在协程中调用传输层的异步写入方法；
     * 完成令牌，支持协程、回调等多种完成令牌。错误码映射方面，
     * 项目错误码如果错误码类别是项目错误码，映射到 Boost.System 类别；
     * 标准错误码否则映射到 Boost.System 通用类别。
     * @tparam ConstBufferSequence 常量缓冲区序列类型，满足 ConstBufferSequence 概念
     * @tparam CompletionToken 完成令牌类型，满足 CompletionToken 要求
     * @param trans 传输对象引用
     * @param buffers 要写入的缓冲区序列
     * @param token 完成令牌，用于处理异步操作结果
     * @return 异步操作初始化结果，具体类型取决于 CompletionToken
     * @note 该函数是模板，可自动推导返回类型。
     * @warning 缓冲区序列必须在整个异步操作期间保持有效。
     * @throws std::bad_alloc 如果内存分配失败
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

}

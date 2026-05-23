/**
 * @file transmission.hpp
 * @brief 传输层流式抽象接口
 * @details 定义异步流的核心概念，参照 Boost.Asio 的 AsyncReadStream/AsyncWriteStream
 * 设计。基类只提供流的基本操作（async_read_some、async_write_some、executor），
 * 不包含组合操作（async_write、async_read）或类型特定操作（shutdown_write）。
 * 组合操作通过自由函数 transport::async_write() / transport::async_read() 提供，
 * 类型特定操作由具体传输类型自行定义。
 * 装饰器链通过 next_layer() / lowest_layer<T>() 导航，替代 dynamic_cast 链式解包。
 * @note 所有异步操作返回 net::awaitable，错误通过 std::error_code& 参数返回。
 * @note 智能指针 shared_transmission 自动管理传输层生命周期。
 */
#pragma once

#include <boost/asio.hpp>
#include <boost/asio/any_completion_handler.hpp>
#include <cstddef>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

#include <prism/fault/compatible.hpp>

namespace psm::transport
{
    namespace net = boost::asio;

    namespace detail
    {
        inline auto to_boost_ec(const std::error_code &ec)
            -> boost::system::error_code
        {
            if (!ec)
                return {};
            if (ec.category() == psm::fault::category())
                return {ec.value(), boost::system::category()};
            return {ec.value(), boost::system::generic_category()};
        }
    } // namespace detail

    /**
     * @class transmission
     * @brief 传输层流式抽象接口
     * @details 参照 Boost.Asio AsyncStream 概念设计的最小流接口。
     * 基类职责：定义流的读、写、执行器、关闭、取消、装饰器导航。
     * 不包含：组合操作（async_write/async_read 是自由函数）、
     * 类型特定操作（shutdown_write 是 reliable 的方法）。
     * 所有异步操作返回 net::awaitable，错误码通过 ec 参数返回。
     * @note 所有传输实现都必须继承此接口。
     */
    class transmission
    {
    public:
        using executor_type = net::any_io_executor;

        /**
         * @brief 传输层类型标识
         * @details 用于区分 TCP 流和 UDP 数据报，替代语义不清的 is_reliable()。
         * 装饰器通过 next_layer() 链委托到底层传输获取真实类型。
         */
        enum class type
        {
            tcp, ///< 可靠流式传输（TCP）
            udp  ///< 不可靠数据报传输（UDP）
        };

        virtual ~transmission() = default;

        /**
         * @brief 获取传输层类型
         * @details 默认沿 next_layer() 链委托到底层。叶子节点必须覆写返回真实类型。
         * @return type 传输类型（tcp 或 udp）
         */
        [[nodiscard]] virtual auto transport_type() const noexcept
            -> type
        {
            auto *n = next_layer();
            return n ? n->transport_type() : type::tcp;
        }

        /**
         * @brief 获取关联的执行器
         * @return executor_type 执行器
         */
        [[nodiscard]] virtual executor_type executor() const = 0;

        /**
         * @brief 获取关联的执行器（兼容 Asio Concept）
         * @return executor_type 执行器
         */
        [[nodiscard]] executor_type get_executor() const
        {
            return executor();
        }

        /**
         * @brief 异步读取部分数据
         * @details 从传输层读取一些数据到缓冲区，可能少于缓冲区大小。
         * 这是 Boost.AsyncReadStream 概念的核心操作。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取的字节数
         */
        virtual auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 异步写入部分数据
         * @details 将缓冲区中的部分数据写入传输层，可能少于缓冲区大小。
         * 这是 Boost.AsyncWriteStream 概念的核心操作。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入的字节数
         */
        virtual auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief Completion-handler 风格异步读取
         * @details 用于 ssl::stream 等 Asio 流适配器的零协程路径。
         * 热路径实现（reliable、preview）覆写此方法直接委托给底层 socket。
         * 默认实现通过 co_spawn 桥接到 awaitable 接口。
         * @param buffer 目标缓冲区
         * @param handler 完成处理器
         */
        virtual void async_read_some(std::span<std::byte> buffer,
            net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
        {
            auto ex = executor();
            net::co_spawn(ex,
                [this, buffer, h = std::move(handler)]() mutable -> net::awaitable<void>
                {
                    std::error_code ec;
                    const auto n = co_await async_read_some(buffer, ec);
                    std::move(h)(detail::to_boost_ec(ec), n);
                },
                net::detached);
        }

        /**
         * @brief Completion-handler 风格异步写入
         * @details 用于 ssl::stream 等 Asio 流适配器的零协程路径。
         * @param buffer 源数据缓冲区
         * @param handler 完成处理器
         */
        virtual void async_write_some(std::span<const std::byte> buffer,
            net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
        {
            auto ex = executor();
            net::co_spawn(ex,
                [this, buffer, h = std::move(handler)]() mutable -> net::awaitable<void>
                {
                    std::error_code ec;
                    const auto n = co_await async_write_some(buffer, ec);
                    std::move(h)(detail::to_boost_ec(ec), n);
                },
                net::detached);
        }

        /**
         * @brief 关闭传输层
         * @details 释放底层资源，关闭后传输层对象不再可用。
         */
        virtual void close() = 0;

        /**
         * @brief 取消所有未完成的异步操作
         * @details 被取消的操作将返回 operation_canceled 错误。
         */
        virtual void cancel() = 0;

        /**
         * @brief 获取内层传输（装饰器链导航）
         * @details 装饰器（preview、snapshot、seal、protocol conn）覆写此方法返回
         * 被包装的内层传输。叶子节点（reliable、unreliable）返回 nullptr。
         * @return transmission* 内层传输指针，叶子节点返回 nullptr
         */
        [[nodiscard]] virtual auto next_layer() noexcept
            -> transmission *
        {
            return nullptr;
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return const transmission* 内层传输指针，叶子节点返回 nullptr
         */
        [[nodiscard]] virtual auto next_layer() const noexcept
            -> const transmission *
        {
            return nullptr;
        }

        /**
         * @brief 沿装饰器链导航到链底并转型为目标类型
         * @details 沿 next_layer() 走到链底，然后 dynamic_cast 为目标类型。
         * 替代所有 dynamic_cast<preview*>/dynamic_cast<snapshot*> 剥壳循环。
         * 用法：trans->lowest_layer<reiable>() 获取底层 TCP 传输。
         * @tparam T 目标类型（如 reliable、transmission）
         * @return T* 目标类型指针，找不到返回 nullptr
         */
        template <typename T>
        [[nodiscard]] T *lowest_layer() noexcept
        {
            auto *current = this;
            while (auto *n = current->next_layer())
                current = n;
            return dynamic_cast<T *>(current);
        }

        /**
         * @brief 沿装饰器链导航到链底并转型为目标类型（const 版本）
         * @tparam T 目标类型
         * @return const T* 目标类型指针，找不到返回 nullptr
         */
        template <typename T>
        [[nodiscard]] const T *lowest_layer() const noexcept
        {
            const auto *current = this;
            while (const auto *n = current->next_layer())
                current = n;
            return dynamic_cast<const T *>(current);
        }

    };

    /**
     * @brief 传输层智能指针类型
     */
    using shared_transmission = std::shared_ptr<transmission>;

    // ── 组合操作自由函数 ──

    /**
     * @brief 完整写入操作（自由函数）
     * @details 循环调用 async_write_some 直到所有数据发送完毕。
     * 参照 Boost.Asio 的 net::async_write 设计，作为自由函数而非成员方法。
     * @param t 传输对象引用
     * @param buffer 要写入的数据
     * @param ec 错误码输出参数
     * @return 实际写入的总字节数
     */
    inline auto async_write(transmission &t, std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        std::size_t total_written = 0;
        while (total_written < buffer.size())
        {
            const auto remaining = buffer.subspan(total_written);
            const auto n = co_await t.async_write_some(remaining, ec);
            if (ec || n == 0)
            {
                co_return total_written;
            }
            total_written += n;
        }
        co_return total_written;
    }

    /**
     * @brief 完整读取操作（自由函数）
     * @details 循环调用 async_read_some 直到缓冲区填满。
     * 参照 Boost.Asio 的 net::async_read 设计，作为自由函数而非成员方法。
     * @param t 传输对象引用
     * @param buffer 接收数据的缓冲区
     * @param ec 错误码输出参数
     * @return 实际读取的总字节数
     */
    inline auto async_read(transmission &t, std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        std::size_t total_read = 0;
        while (total_read < buffer.size())
        {
            const auto remaining = buffer.subspan(total_read);
            const auto n = co_await t.async_read_some(remaining, ec);
            if (ec || n == 0)
            {
                co_return total_read;
            }
            total_read += n;
        }
        co_return total_read;
    }

} // namespace psm::transport

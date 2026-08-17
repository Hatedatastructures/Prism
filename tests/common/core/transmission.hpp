/**
 * @file transmission.hpp
 * @brief 传输层抽象接口
 * @details 借鉴 Boost.Asio AsyncReadStream/AsyncWriteStream 的最小接口设计。
 *          核心职责：统一的异步读写、关闭、取消、装饰器链导航。
 *          协议封装（socks5/vless/vmess/...）继承本基类成为传输层装饰器，
 *          next_layer() 返回被包装的内层传输，实现多协议无缝切换。
 *          调用方通过 shared_transmission（shared_ptr）管理生命周期，
 *          release() 可提前转移底层传输所有权。
 * @note 所有异步方法返回 net::awaitable，通过 ec 出参返回错误。
 * @note 热路径零分配，span 视图直接传递，不拷贝数据。
 */

#pragma once

#include <boost/asio/any_completion_handler.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <span>
#include <system_error>
#include <utility>

#include <common/core/error.hpp>

namespace preview
{

    namespace net = boost::asio;

    namespace detail
    {

        /**
         * @brief 将 std::error_code 转为 boost::system::error_code
         * @details 协议库错误分类映射到 boost 侧，其余归 generic。
         * @param ec 源错误码
         * @return 转换后的 boost 错误码
         */
        [[nodiscard]] inline auto to_ec(const std::error_code &ec) noexcept -> boost::system::error_code
        {
            if (!ec)
            {
                return {};
            }
            if (ec.category() == error_category())
            {
                return make_error_code(static_cast<error>(ec.value()));
            }
            return boost::system::error_code(ec.value(), boost::system::generic_category());
        }

    } // namespace detail

    /**
     * @class transmission
     * @brief 传输层抽象接口
     * @details 定义所有传输层的统一行为：异步读写、关闭、取消与
     * 装饰器链导航。协议封装类（conn）继承本基类，将底层传输
     * 包装为协议感知的传输层。装饰器链模式：preview → protocol
     * conn → reliable，通过 next_layer() 逐层导航。
     * @note 所有实现必须继承本接口。
     */
    class transmission
    {
    public:
        /// 执行器类型
        using executor_type = net::any_io_executor;

        /// 传输类型（tcp / udp）
        enum class type : std::uint8_t
        {
            /// 可靠流式传输（TCP）
            tcp,
            /// 不可靠数据报传输（UDP）
            udp,
        };

        virtual ~transmission() noexcept = default;

        /**
         * @brief 获取传输类型
         * @details 默认委托 next_layer() 询问底层，叶子节点返回 tcp。
         * 装饰器（协议 conn）链式委托到底层传输获取真实类型。
         * @return type 传输类型（tcp / udp）
         */
        [[nodiscard]] virtual auto transport_type() const noexcept -> type
        {
            auto *n = next_layer();
            if (n)
            {
                return n->transport_type();
            }
            return type::tcp;
        }

        /**
         * @brief 获取执行器
         * @return executor_type 执行器
         * @details 返回传输层关联的执行器，用于协程调度和异步操作。
         */
        [[nodiscard]] virtual auto executor() const -> executor_type = 0;

        /**
         * @brief 获取执行器（Asio executor 概念兼容）
         * @return executor_type 执行器
         */
        [[nodiscard]] auto get_executor() const -> executor_type
        {
            return executor();
        }

        /**
         * @brief 异步读取部分数据
         * @details 从传输层读取一些数据到缓冲区，可能少于缓冲区大小。
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取的字节数
         */
        [[nodiscard]] virtual auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 异步写入部分数据
         * @details 将缓冲区中的部分数据写入传输层，可能少于缓冲区大小。
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入的字节数
         */
        [[nodiscard]] virtual auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief Completion-handler 风格异步读取
         * @details 用于 Asio 流适配器的零协程路径。默认实现通过
         * co_spawn 桥接到 awaitable 接口。
         * @param buffer 目标缓冲区
         * @param handler 完成处理器
         */
        virtual void
        async_read_some(std::span<std::byte> buffer,
                        net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
        {
            auto ex = executor();
            net::co_spawn(
                ex,
                [this, buffer, h = std::move(handler)]() mutable -> net::awaitable<void>
                {
                    std::error_code ec;
                    const auto n = co_await async_read_some(buffer, ec);
                    std::move(h)(detail::to_ec(ec), n);
                },
                net::detached);
        }

        /**
         * @brief Completion-handler 风格异步写入
         * @param buffer 源数据缓冲区
         * @param handler 完成处理器
         */
        virtual void
        async_write_some(std::span<const std::byte> buffer,
                         net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
        {
            auto ex = executor();
            net::co_spawn(
                ex,
                [this, buffer, h = std::move(handler)]() mutable -> net::awaitable<void>
                {
                    std::error_code ec;
                    const auto n = co_await async_write_some(buffer, ec);
                    std::move(h)(detail::to_ec(ec), n);
                },
                net::detached);
        }

        /**
         * @brief 异步读取直至缓冲区读满（组合操作）
         * @param buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数（满 = buffer.size()；EOF 提前返回）
         * @details 循环调用 async_read_some 直至读满或 EOF/错误。
         * 默认实现基于虚接口组合，派生类可按需覆写优化。
         */
        [[nodiscard]] auto async_read(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            std::size_t done = 0;
            while (done < buffer.size())
            {
                const auto n = co_await async_read_some(buffer.subspan(done), ec);
                if (ec)
                {
                    co_return done;
                }
                if (n == 0)
                {
                    co_return done; // EOF / 半关 / 取消
                }
                done += n;
            }
            co_return done;
        }

        /**
         * @brief 异步写入直至缓冲区写满（组合操作）
         * @param buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入字节数（满 = buffer.size()）
         * @details 循环调用 async_write_some 直至写满或错误。
         * 默认实现基于虚接口组合，派生类可按需覆写优化。
         */
        [[nodiscard]] auto async_write(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            std::size_t done = 0;
            while (done < buffer.size())
            {
                const auto n = co_await async_write_some(buffer.subspan(done), ec);
                if (ec)
                {
                    co_return done;
                }
                if (n == 0)
                {
                    ec = make_error_code(error::broken_pipe);
                    co_return done;
                }
                done += n;
            }
            co_return done;
        }

        /**
         * @brief 关闭传输层
         * @details 释放底层资源，关闭后传输层对象不再可用。
         */
        virtual void close() = 0;

        /**
         * @brief 取消所有未完成的异步操作
         * @details 被取消的操作将以 operation_canceled 错误完成。
         */
        virtual void cancel() = 0;

        /**
         * @brief 半关写方向（向对端发送 EOF）
         * @details 默认实现沿装饰器链转发；叶子节点必须实现。
         * 半关后本端仍可读，对端读返回 0（EOF）。
         */
        virtual void shutdown()
        {
            if (auto *n = next_layer())
            {
                n->shutdown();
            }
        }

        /**
         * @brief 设置读超时
         * @param ms 超时毫秒数（0 = 禁用）
         * @details 默认实现沿装饰器链转发；叶子节点必须实现。
         * 超时后挂起的读以 operation_timed_out 完成。
         */
        virtual void set_timeout(std::chrono::milliseconds ms)
        {
            if (auto *n = next_layer())
            {
                n->set_timeout(ms);
            }
        }

        /**
         * @brief 检查传输层是否打开
         * @return 打开返回 true
         * @details 默认实现沿装饰器链转发；叶子节点必须实现。
         */
        [[nodiscard]] virtual auto is_open() const -> bool
        {
            if (auto *n = next_layer())
            {
                return n->is_open();
            }
            return false;
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         * @details 装饰器（协议 conn）覆写此方法返回被包装的内层传输。
         * 叶子节点（如 memory_stream 的裸传输）返回 nullptr。
         * @return 内层传输指针，叶子节点返回 nullptr
         */
        [[nodiscard]] virtual auto next_layer() noexcept -> transmission *
        {
            return nullptr;
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 内层传输指针，叶子节点返回 nullptr
         */
        [[nodiscard]] virtual auto next_layer() const noexcept -> const transmission *
        {
            return nullptr;
        }

        /**
         * @brief 沿装饰器链导航到链底并转型为目标类型
         * @details 替代逐层 dynamic_cast 剥壳循环。
         * @tparam T 目标类型（如 memory_stream、reliable）
         * @return 目标类型指针，找不到返回 nullptr
         */
        template <typename T>
        [[nodiscard]] auto lowest_layer() noexcept -> T *
        {
            auto *current = this;
            while (auto *n = current->next_layer())
            {
                current = n;
            }
            return dynamic_cast<T *>(current);
        }

        /**
         * @brief 沿装饰器链导航到链底并转型为目标类型（const 版本）
         * @tparam T 目标类型
         * @return 目标类型指针，找不到返回 nullptr
         */
        template <typename T>
        [[nodiscard]] auto lowest_layer() const noexcept -> const T *
        {
            auto *current = this;
            while (auto *n = current->next_layer())
            {
                current = n;
            }
            return dynamic_cast<const T *>(current);
        }

        /**
         * @brief 释放底层传输所有权
         * @details 释放持有的内层传输指针。用于将底层连接转移给
         * 其他组件管理。转移后不应再调用读写方法。
         * @return 底层传输共享指针
         */
        [[nodiscard]] virtual auto release() -> std::shared_ptr<transmission>
        {
            return {};
        }
    };

    /// 传输层共享指针（自动管理生命周期）
    using shared_transmission = std::shared_ptr<transmission>;

    /**
     * @brief 传输接口概念（模板约束用）
     * @tparam T 传输类型（transmission 派生类或满足接口的鸭子类型）
     * @details 供工厂/薄层模板参数约束：要求异步读写、关闭与取消。
     * transmission 基类自身满足本概念，具体派生类亦满足。
     */
    template <typename T>
    concept transmission_like =
        requires(T &t, std::span<std::byte> buf, std::span<const std::byte> wbuf, std::error_code &ec) {
            { t.async_read_some(buf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
            { t.async_write_some(wbuf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
            { t.close() } -> std::same_as<void>;
            { t.cancel() } -> std::same_as<void>;
            { t.shutdown() } -> std::same_as<void>;
            { t.set_timeout(std::chrono::milliseconds{0}) } -> std::same_as<void>;
            { t.is_open() } -> std::same_as<bool>;
            { t.executor() } -> std::same_as<net::any_io_executor>;
        };

    static_assert(transmission_like<transmission>);

} // namespace preview

/**
 * @file Transmission.hpp
 * @brief 传输层抽象接口
 * @details 借鉴 Boost.Asio AsyncReadStream/AsyncWriteStream 的最小接口设计。
 *          核心职责：统一的异步读写、关闭、取消、装饰器链导航。
 *          协议封装（socks5/vless/vmess/...）继承本基类成为传输层装饰器，
 *          NextLayer() 返回被包装的内层传输，实现多协议无缝切换。
 *          调用方通过 SharedTransmission（shared_ptr）管理生命周期，
 *          Release() 可提前转移底层传输所有权。
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

#include <common/Core/Error.hpp>

namespace Preview
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
        [[nodiscard]] inline auto ToEc(const std::error_code &ec) noexcept -> boost::system::error_code
        {
            if (!ec)
            {
                return {};
            }
            if (ec.category() == ErrorCategory())
            {
                return make_error_code(static_cast<Error>(ec.value()));
            }
            return boost::system::error_code(ec.value(), boost::system::generic_category());
        }

    } // namespace detail

    /**
     * @class Transmission
     * @brief 传输层抽象接口
     * @details 定义所有传输层的统一行为：异步读写、关闭、取消与
     * 装饰器链导航。协议封装类（Conn）继承本基类，将底层传输
     * 包装为协议感知的传输层。装饰器链模式：Preview → Protocol
     * Conn → Reliable，通过 NextLayer() 逐层导航。
     * @note 所有实现必须继承本接口。
     */
    class Transmission
    {
    public:
        /// 执行器类型
        using ExecutorType = net::any_io_executor;
        using executor_type = net::any_io_executor;

        /// 传输类型（Tcp / udp）
        enum class Type : std::uint8_t
        {
            /// 可靠流式传输（TCP）
            Tcp,
            /// 不可靠数据报传输（UDP）
            Udp,
        };

        virtual ~Transmission() noexcept = default;

        /**
         * @brief 获取传输类型
         * @details 默认委托 NextLayer() 询问底层，叶子节点返回 Tcp。
         * 装饰器（协议 Conn）链式委托到底层传输获取真实类型。
         * @return Type 传输类型（Tcp / udp）
         */
        [[nodiscard]] virtual auto TransportType() const noexcept -> Type
        {
            auto *N = NextLayer();
            if (N)
            {
                return N->TransportType();
            }
            return Type::Tcp;
        }

        /**
         * @brief 获取执行器
         * @return ExecutorType 执行器
         * @details 返回传输层关联的执行器，用于协程调度和异步操作。
         */
        [[nodiscard]] virtual auto Executor() const -> ExecutorType = 0;

        /**
         * @brief 获取执行器（Asio Executor 概念兼容）
         * @return ExecutorType 执行器
         */
        [[nodiscard]] auto get_executor() const -> ExecutorType
        {
            return Executor();
        }

        /**
         * @brief 异步读取部分数据
         * @details 从传输层读取一些数据到缓冲区，可能少于缓冲区大小。
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取的字节数
         */
        [[nodiscard]] virtual auto async_read_some(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief 异步写入部分数据
         * @details 将缓冲区中的部分数据写入传输层，可能少于缓冲区大小。
         * @param Buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入的字节数
         */
        [[nodiscard]] virtual auto async_write_some(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;

        /**
         * @brief Completion-handler 风格异步读取
         * @details 用于 Asio 流适配器的零协程路径。默认实现通过
         * co_spawn 桥接到 awaitable 接口。
         * @param Buffer 目标缓冲区
         * @param handler 完成处理器
         */
        virtual void
        async_read_some(std::span<std::byte> Buffer,
                        net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
        {
            auto Ex = Executor();
            net::co_spawn(
                Ex,
                [this, Buffer, h = std::move(handler)]() mutable -> net::awaitable<void>
                {
                    std::error_code ec;
                    const auto N = co_await async_read_some(Buffer, ec);
                    std::move(h)(detail::ToEc(ec), N);
                },
                net::detached);
        }

        /**
         * @brief Completion-handler 风格异步写入
         * @param Buffer 源数据缓冲区
         * @param handler 完成处理器
         */
        virtual void
        async_write_some(std::span<const std::byte> Buffer,
                         net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
        {
            auto Ex = Executor();
            net::co_spawn(
                Ex,
                [this, Buffer, h = std::move(handler)]() mutable -> net::awaitable<void>
                {
                    std::error_code ec;
                    const auto N = co_await async_write_some(Buffer, ec);
                    std::move(h)(detail::ToEc(ec), N);
                },
                net::detached);
        }

        /**
         * @brief 异步读取直至缓冲区读满（组合操作）
         * @param Buffer 接收缓冲区
         * @param ec 错误码输出参数
         * @return 实际读取字节数（满 = Buffer.size()；EOF 提前返回）
         * @details 循环调用 async_read_some 直至读满或 EOF/错误。
         * 默认实现基于虚接口组合，派生类可按需覆写优化。
         */
        [[nodiscard]] auto AsyncRead(std::span<std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                const auto N = co_await async_read_some(Buffer.subspan(Done), ec);
                if (ec)
                {
                    co_return Done;
                }
                if (N == 0)
                {
                    co_return Done; // EOF / 半关 / 取消
                }
                Done += N;
            }
            co_return Done;
        }

        /**
         * @brief 异步写入直至缓冲区写满（组合操作）
         * @param Buffer 发送缓冲区
         * @param ec 错误码输出参数
         * @return 实际写入字节数（满 = Buffer.size()）
         * @details 循环调用 async_write_some 直至写满或错误。
         * 默认实现基于虚接口组合，派生类可按需覆写优化。
         */
        [[nodiscard]] auto AsyncWrite(std::span<const std::byte> Buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>
        {
            std::size_t Done = 0;
            while (Done < Buffer.size())
            {
                const auto N = co_await async_write_some(Buffer.subspan(Done), ec);
                if (ec)
                {
                    co_return Done;
                }
                if (N == 0)
                {
                    ec = make_error_code(Error::BrokenPipe);
                    co_return Done;
                }
                Done += N;
            }
            co_return Done;
        }

        /**
         * @brief 关闭传输层
         * @details 释放底层资源，关闭后传输层对象不再可用。
         */
        virtual void Close() = 0;

        /**
         * @brief 取消所有未完成的异步操作
         * @details 被取消的操作将以 operation_canceled 错误完成。
         */
        virtual void Cancel() = 0;

        /**
         * @brief 半关写方向（向对端发送 EOF）
         * @details 默认实现沿装饰器链转发；叶子节点必须实现。
         * 半关后本端仍可读，对端读返回 0（EOF）。
         */
        virtual void Shutdown()
        {
            if (auto *N = NextLayer())
            {
                N->Shutdown();
            }
        }

        /**
         * @brief 设置读超时
         * @param ms 超时毫秒数（0 = 禁用）
         * @details 默认实现沿装饰器链转发；叶子节点必须实现。
         * 超时后挂起的读以 operation_timed_out 完成。
         */
        virtual void SetTimeout(std::chrono::milliseconds ms)
        {
            if (auto *N = NextLayer())
            {
                N->SetTimeout(ms);
            }
        }

        /**
         * @brief 检查传输层是否打开
         * @return 打开返回 true
         * @details 默认实现沿装饰器链转发；叶子节点必须实现。
         */
        [[nodiscard]] virtual auto IsOpen() const -> bool
        {
            if (auto *N = NextLayer())
            {
                return N->IsOpen();
            }
            return false;
        }

        /**
         * @brief 获取内层传输（装饰器链导航）
         * @details 装饰器（协议 Conn）覆写此方法返回被包装的内层传输。
         * 叶子节点（如 MemoryStream 的裸传输）返回 nullptr。
         * @return 内层传输指针，叶子节点返回 nullptr
         */
        [[nodiscard]] virtual auto NextLayer() noexcept -> Transmission *
        {
            return nullptr;
        }

        /**
         * @brief 获取内层传输（const 版本）
         * @return 内层传输指针，叶子节点返回 nullptr
         */
        [[nodiscard]] virtual auto NextLayer() const noexcept -> const Transmission *
        {
            return nullptr;
        }

        /**
         * @brief 沿装饰器链导航到链底并转型为目标类型
         * @details 替代逐层 dynamic_cast 剥壳循环。
         * @tparam T 目标类型（如 MemoryStream、Reliable）
         * @return 目标类型指针，找不到返回 nullptr
         */
        template <typename T>
        [[nodiscard]] auto lowest_layer() noexcept -> T *
        {
            auto *current = this;
            while (auto *N = current->NextLayer())
            {
                current = N;
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
            while (auto *N = current->NextLayer())
            {
                current = N;
            }
            return dynamic_cast<const T *>(current);
        }

        /**
         * @brief 释放底层传输所有权
         * @details 释放持有的内层传输指针。用于将底层连接转移给
         * 其他组件管理。转移后不应再调用读写方法。
         * @return 底层传输共享指针
         */
        [[nodiscard]] virtual auto Release() -> std::shared_ptr<Transmission>
        {
            return {};
        }
    };

    /// 传输层共享指针（自动管理生命周期）
    using SharedTransmission = std::shared_ptr<Transmission>;

    /**
     * @brief 传输接口概念（模板约束用）
     * @tparam T 传输类型（Transmission 派生类或满足接口的鸭子类型）
     * @details 供工厂/薄层模板参数约束：要求异步读写、关闭与取消。
     * Transmission 基类自身满足本概念，具体派生类亦满足。
     */
    template <typename T>
    concept TransmissionLike =
        requires(T &t, std::span<std::byte> buf, std::span<const std::byte> wbuf, std::error_code &ec) {
            { t.async_read_some(buf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
            { t.async_write_some(wbuf, ec) } -> std::same_as<net::awaitable<std::size_t>>;
            { t.Close() } -> std::same_as<void>;
            { t.Cancel() } -> std::same_as<void>;
            { t.Shutdown() } -> std::same_as<void>;
            { t.SetTimeout(std::chrono::milliseconds{0}) } -> std::same_as<void>;
            { t.IsOpen() } -> std::same_as<bool>;
            { t.Executor() } -> std::same_as<net::any_io_executor>;
        };

    static_assert(TransmissionLike<Transmission>);

} // namespace Preview

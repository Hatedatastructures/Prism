/**
 * @file coro.hpp
 * @brief 协程安全的会话前缀保存/恢复机制
 * @details 提供保存点（savepoint）机制，在 co_await 恢复后立即还原
 * active_prefix。解决 thread_local 在同一线程多协程间被覆盖的问题。
 *
 * 核心思路：
 * - session::start() 通过 co_spawn 启动协程时，scope_guard 设置 active_prefix
 * - 在每个 co_await 可能挂起点，通过 savepoint 在恢复后还原前缀
 * - co_spawn 独立协程（如 mux core）在入口处通过 scope_guard 建立自己的前缀
 *
 * @note header-only，零外部依赖（不含 spdlog）。
 */

#pragma once

#include <prism/trace/context.hpp>

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include <variant>
#include <utility>


namespace psm::trace
{

    namespace net = boost::asio;

    /**
     * @class savepoint
     * @brief 协程挂起/恢复时的前缀保存点
     * @details 在构造时记录目标前缀指针，提供 restore() 方法。
     * 用法：在 co_await 表达式外创建 savepoint，
     * await_ready=false 时在 await_resume 中调用 restore()。
     */
    class savepoint
    {
    public:
        explicit savepoint(session_prefix &pfx) noexcept
            : prefix_(&pfx)
        {
        }

        void restore() noexcept
        {
            if (prefix_->is_alive())
                active_prefix = prefix_;
        }

    private:
        session_prefix *prefix_;
    };

    /**
     * @brief 协程安全的前缀恢复包装器
     * @tparam T awaitable 返回值类型
     * @param pfx 当前会话的前缀数据引用
     * @param aw 待包装的 awaitable 对象
     * @return 包装后的 awaitable，结果与原始 aw 相同
     * @details 用法示例:
     * @code
     *   co_await trace::with_prefix(self->prefix_, self->diversion());
     * @endcode
     */
    template <typename T>
    auto with_prefix(session_prefix &pfx, net::awaitable<T> aw)
        -> net::awaitable<T>
    {
        savepoint sp(pfx);
        sp.restore();
        auto result = co_await std::move(aw);
        sp.restore();
        co_return std::move(result);
    }

    /**
     * @brief with_prefix 的 void 返回值特化
     */
    template <>
    inline auto with_prefix<void>(session_prefix &pfx, net::awaitable<void> aw)
        -> net::awaitable<void>
    {
        savepoint sp(pfx);
        sp.restore();
        co_await std::move(aw);
        sp.restore();
    }

    /**
     * @brief awaitable_operators::operator|| 的前缀恢复包装
     * @tparam L 左操作数返回类型
     * @tparam R 右操作数返回类型
     * @param pfx 当前会话的前缀数据引用
     * @param left 左侧 awaitable
     * @param right 右侧 awaitable
     * @return net::awaitable<std::variant<L, R>>
     * @details 用于替代裸 co_await (a || b)，在并发操作恢复后还原前缀。
     */
    template <typename L, typename R>
    auto with_prefix_or(session_prefix &pfx,
                        net::awaitable<L> left,
                        net::awaitable<R> right)
        -> net::awaitable<std::variant<L, R>>
    {
        using boost::asio::experimental::awaitable_operators::operator||;
        savepoint sp(pfx);
        sp.restore();
        auto result = co_await (std::move(left) || std::move(right));
        sp.restore();
        co_return std::move(result);
    }

} // namespace psm::trace

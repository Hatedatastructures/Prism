/**
 * @file token.hpp
 * @brief 协程安全的自定义 Completion Token
 * @details 通过包装 Boost 内置 awaitable_handler，在 I/O 回调时
 * 自动恢复捕获的 prefix，解决 thread_local active_prefix 在
 * 同一线程多协程间被覆盖导致的日志前缀错乱问题。
 *
 * 核心思路：
 *   co_await timer.async_wait(trace::use_prefix_awaitable)
 *                        ↓
 *   async_result::initiate() 捕获当前 active_prefix → 存入 wrapper handler
 *                        ↓
 *   I/O 完成，wrapper handler 先恢复 active_prefix 再调用底层 awaitable_handler
 *                        ↓
 *   协程恢复时 active_prefix 已经正确
 *
 * @note header-only，依赖 context.hpp（active_prefix）和 Boost.Asio。
 */

#pragma once

#include <prism/trace/context.hpp>

#include <boost/asio.hpp>
#include <utility>


namespace psm::trace
{

    namespace net = boost::asio;

    /**
     * @class use_prefix_awaitable_t
     * @brief 自定义 Completion Token 类型
     * @details 空 struct，作为 CompletionToken 传递给 Asio 异步操作。
     * 通过 async_result 特化注入 prefix 恢复逻辑。
     */
    template <typename Executor = net::any_io_executor>
    struct use_prefix_awaitable_t
    {
    };

    template <typename Executor>
    inline constexpr use_prefix_awaitable_t<Executor> use_prefix_awaitable_v{};

    inline constexpr use_prefix_awaitable_t<> use_prefix_awaitable =
        use_prefix_awaitable_v<net::any_io_executor>;

    namespace detail
    {

        /**
         * @class prefix_restore_handler
         * @brief 前缀恢复包装 handler
         * @details 构造时捕获 active_prefix，在 operator() 调用时
         * 先恢复 active_prefix 再转发给底层 awaitable_handler。
         */
        template <typename Handler>
        class prefix_restore_handler
        {
        public:
            explicit prefix_restore_handler(Handler &&h,
                session_prefix *captured)
                : handler_(std::move(h)), captured_prefix_(captured)
            {
            }

            prefix_restore_handler(prefix_restore_handler &&) = default;
            prefix_restore_handler(const prefix_restore_handler &) = delete;
            auto operator=(prefix_restore_handler &&)
                -> prefix_restore_handler & = delete;
            auto operator=(const prefix_restore_handler &)
                -> prefix_restore_handler & = delete;

            template <typename... Args>
            void operator()(Args &&...args)
            {
                if (captured_prefix_)
                    active_prefix = captured_prefix_;
                std::move(handler_)(std::forward<Args>(args)...);
            }

            using executor_type =
                typename net::associated_executor<Handler>::type;

            auto get_executor() const noexcept
                -> typename net::associated_executor<Handler>::type
            {
                return net::get_associated_executor(handler_);
            }

            using allocator_type =
                typename net::associated_allocator<Handler>::type;

            auto get_allocator() const noexcept
                -> typename net::associated_allocator<Handler>::type
            {
                return net::get_associated_allocator(handler_);
            }

            using cancellation_slot_type =
                typename net::associated_cancellation_slot<Handler>::type;

            auto get_cancellation_slot() const noexcept
                -> typename net::associated_cancellation_slot<Handler>::type
            {
                return net::get_associated_cancellation_slot(handler_);
            }

            using immediate_executor_type =
                typename net::associated_immediate_executor<Handler,
                    executor_type>::type;

            auto get_immediate_executor() const noexcept
                -> typename net::associated_immediate_executor<Handler,
                    executor_type>::type
            {
                return net::get_associated_immediate_executor(
                    handler_, net::get_associated_executor(handler_));
            }

        private:
            Handler handler_;
            session_prefix *captured_prefix_;
        };

    } // namespace detail

} // namespace psm::trace

template <typename Executor, typename R, typename... Args>
class boost::asio::async_result<psm::trace::use_prefix_awaitable_t<Executor>, R(Args...)>
{
public:
    using handler_type = psm::trace::detail::prefix_restore_handler<
        typename boost::asio::async_result<
            boost::asio::use_awaitable_t<Executor>, R(Args...)>::handler_type>;

    using return_type =
        typename boost::asio::async_result<boost::asio::use_awaitable_t<Executor>,
            R(Args...)>::return_type;

    template <typename Initiation, typename... InitArgs>
    static return_type initiate(Initiation initiation,
        psm::trace::use_prefix_awaitable_t<Executor>, InitArgs... args)
    {
        auto *captured = psm::trace::active_prefix;
        co_await [&](auto *frame) -> boost::asio::detail::awaitable_thread<Executor> *
        {
            typename boost::asio::async_result<
                boost::asio::use_awaitable_t<Executor>, R(Args...)>::handler_type
                inner_handler(frame->detach_thread());

            handler_type wrapper(std::move(inner_handler), captured);

            std::move(initiation)(std::move(wrapper), std::move(args)...);
            return nullptr;
        };

        for (;;) {}
#if defined(_MSC_VER) && !defined(__clang__)
        co_return;
#endif
    }
};

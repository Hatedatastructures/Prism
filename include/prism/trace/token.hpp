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

    inline constexpr use_prefix_awaitable_t<> use_prefix_awaitable = use_prefix_awaitable_v<net::any_io_executor>;

    namespace detail
    {

        /**
         * @class prefix_restore_handler
         * @brief 前缀恢复包装 handler
         * @details 构造时捕获 active_prefix 对应的 shared_ptr 副本，
         * 在 operator() 调用时先恢复 active_prefix 再转发给底层 awaitable_handler。
         * @note 持有 shared_ptr 副本保活 session_prefix。即使 session/core 在
         * 协程挂起期间析构（释放对 prefix 的 shared_ptr 引用），handler 仍持有
         * 最后一个引用，prefix 内存不释放。这是 IOCP 回调路径防悬垂的关键。
         */
        template <typename Handler>
        class prefix_restore_handler
        {
        public:
            explicit prefix_restore_handler(Handler &&h,
                std::shared_ptr<session_prefix> captured)
                : handler_(std::move(h)), captured_prefix_(std::move(captured))
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
                // captured_prefix_ 持有 shared_ptr 副本，必不为 nullptr（除非原本就 null）
                // 但仍检查 is_alive() 以处理 scope_guard 析构后的状态（magic 置零）
                if (captured_prefix_ && captured_prefix_->is_alive())
                    active_prefix = captured_prefix_.get();
                std::move(handler_)(std::forward<Args>(args)...);
            }

            using executor_type =
                net::associated_executor<Handler>::type;

            [[nodiscard]] auto get_executor() const noexcept
                -> net::associated_executor<Handler>::type
            {
                return net::get_associated_executor(handler_);
            }

            using allocator_type = net::associated_allocator<Handler>::type;

            [[nodiscard]] auto get_allocator() const noexcept
                -> net::associated_allocator<Handler>::type
            {
                return net::get_associated_allocator(handler_);
            }

            using cancellation_slot_type = net::associated_cancellation_slot<Handler>::type;

            [[nodiscard]] auto get_cancellation_slot() const noexcept
                -> net::associated_cancellation_slot<Handler>::type
            {
                return net::get_associated_cancellation_slot(handler_);
            }

            using immediate_executor_type = net::associated_immediate_executor<Handler, executor_type>::type;

            [[nodiscard]] auto get_immediate_executor() const noexcept
                -> net::associated_immediate_executor<Handler, executor_type>::type
            {
                return net::get_associated_immediate_executor(handler_, net::get_associated_executor(handler_));
            }

        private:
            Handler handler_;
            std::shared_ptr<session_prefix> captured_prefix_;
        };

    } // namespace detail

} // namespace psm::trace

template <typename Executor, typename R, typename... Args>
class boost::asio::async_result<psm::trace::use_prefix_awaitable_t<Executor>, R(Args...)>
{
public:
    using handler_type = psm::trace::detail::prefix_restore_handler<
        typename boost::asio::async_result<boost::asio::use_awaitable_t<Executor>, R(Args...)>::handler_type>;

    using return_type =
        typename boost::asio::async_result<boost::asio::use_awaitable_t<Executor>,
            R(Args...)>::return_type;

    template <typename Initiation, typename... InitArgs>
    static return_type initiate(Initiation initiation,
        psm::trace::use_prefix_awaitable_t<Executor>, InitArgs... args)
    {
        // 捕获 active_prefix 对应的 shared_ptr 副本（通过 shared_from_this）
        // 这样 handler 持有 prefix 的引用计数，prefix 不会在协程挂起期间析构
        std::shared_ptr<psm::trace::session_prefix> captured;
        if (psm::trace::active_prefix)
        {
            captured = psm::trace::active_prefix->shared_from_this();
        }
        co_await [&](auto *frame) -> boost::asio::detail::awaitable_thread<Executor> *
        {
            typename boost::asio::async_result<
                boost::asio::use_awaitable_t<Executor>, R(Args...)>::handler_type
                inner_handler(frame->detach_thread());

            handler_type wrapper(std::move(inner_handler), std::move(captured));

            std::move(initiation)(std::move(wrapper), std::move(args)...);
            return nullptr;
        };

        for (;;) {}
#if defined(_MSC_VER) && !defined(__clang__)
        co_return;
#endif
    }
};

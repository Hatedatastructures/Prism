/**
 * @file token.hpp
 * @brief 自定义 Completion Token（thread_local 已移除后的兼容包装）
 * @details use_prefix_awaitable 作为 Boost.Asio 的 completion token，
 * 内部等同于 use_awaitable。保留是为了避免大规模替换调用方代码。
 *
 * @note thread_local 已删除，本文件不再做 prefix 恢复。
 * 所有 trace 调用通过显式 prefix 参数传递。
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
     * @brief 兼容 Completion Token（等同 use_awaitable_t）
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
         * @brief 兼容 wrapper handler（no-op passthrough）
         * @details 不再做 prefix 恢复，直接转发给底层 handler。
         *         保留 shared_ptr 副本用于 IOCP 回调防悬垂。
         */
        template <typename Handler>
        class prefix_restore_handler
        {
        public:
            explicit prefix_restore_handler(Handler &&h,
                std::shared_ptr<trace_context> captured)
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
            std::shared_ptr<trace_context> captured_prefix_;
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
        // thread_local 已删除，不再捕获 active_prefix
        // captured 始终为 nullptr，handler passthrough 不做 prefix 恢复
        std::shared_ptr<psm::trace::trace_context> captured;
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

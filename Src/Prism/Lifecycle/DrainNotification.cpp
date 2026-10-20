/** @file DrainNotification.cpp @brief 执行域排空通知许可实现。 */
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Lifecycle/Detail/DrainNotification.hpp>

#include <boost/asio/execution/context.hpp>
#include <boost/asio/query.hpp>

#include <atomic>
#include <memory>

namespace Prism::Lifecycle::Detail
{
    boost::asio::execution_context::id DrainNotification::id;

    DrainNotification::DrainNotification(boost::asio::execution_context &Context)
        : service(Context), Available_(std::make_shared<std::atomic<bool>>(true))
    {
    }

    auto DrainNotification::Bind(const boost::asio::any_io_executor &Executor)
        -> std::shared_ptr<const std::atomic<bool>>
    {
        auto &Context = boost::asio::query(Executor, boost::asio::execution::context);
        return boost::asio::use_service<DrainNotification>(Context).Available_;
    }

    auto DrainNotification::shutdown() -> void
    {
        Available_->store(false, std::memory_order_release);
    }
}

namespace Prism::Lifecycle
{
    auto BindDrainNotification(const Net::any_io_executor& Executor)
        -> std::shared_ptr<const std::atomic<bool>>
    {
        return Detail::DrainNotification::Bind(Executor);
    }
}

/**
 * @file DrainNotification.hpp
 * @brief 执行域 service 收尾期间的排空通知许可。
 * @details 在实际 channel 构造之后绑定，保证本 service 先于该 channel service
 *          shutdown。许可按共享值保活，不拥有 execution_context；外部域仍由调用者
 *          保活至排空。域结束只禁止新通知，不清零预约、不改变失败、不伪造完成。
 *          本许可没有取消或半关闭能力，最终关闭仍归载体 owner。
 */
#pragma once
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/execution_context.hpp>
#include <atomic>
#include <memory>

namespace Prism::Lifecycle::Detail
{
    /** @brief 原执行域的通知许可，service shutdown 后不可再次开放。 */
    class DrainNotification final : public boost::asio::execution_context::service
    {
    public:
        static boost::asio::execution_context::id id;
        explicit DrainNotification(boost::asio::execution_context &Context);

        /** @brief 仅在 channel 已构造的冷路径绑定；共享许可覆盖晚到的完成回调。 */
        [[nodiscard]] static auto Bind(const boost::asio::any_io_executor &Executor)
            -> std::shared_ptr<const std::atomic<bool>>
            ;

    private:
        auto shutdown() -> void override;
        std::shared_ptr<std::atomic<bool>> Available_;
    };
}

/**
 * @file CarrierActivity.hpp
 * @brief 载体真实异步操作的封止、执行域与退栈契约。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <expected>

namespace Preview::Contract
{
    /**
     * @brief 由传输或协议实际 owner 实现的操作生命周期能力。
     * @details owner 必须在准入成功时立即预约，在最后一次 completion/协程退栈后
     *          才归还；不能用 shared_ptr 计数、已提交关闭或队列为空代替操作完成。
     *          调用者持有此能力到 Drain 返回；实现必须 pin 实际 executor/context。
     *          此能力不执行写半关闭，不取得共享 socket 的最终关闭权限。
     */
    class CarrierActivity
    {
    public:
        virtual ~CarrierActivity() = default;

        /** @brief 封止后续操作准入；不分配、不投递，不提前归还已有预约。 */
        virtual auto Seal() noexcept -> void = 0;

        /** @brief 返回准入时已固定的真实执行域；不猜测调用方 executor。 */
        [[nodiscard]] virtual auto Executor() const -> boost::asio::any_io_executor = 0;

        /**
         * @brief 独立读取本 owner 的真实物理退休回执，不执行关闭或重试。
         * @return 准入已封止、所有预约与 completion 已退栈且所属关闭责任完成才为真。
         * @note 历史业务 Failure 不改变真实完成事实；未知交付、blocked 或仍在途必须为假。
         *       仅拥有 Run 预约的实现只证明该 Run 退栈，不能据此推断借用 socket 关闭。
         */
        [[nodiscard]] virtual auto IsRetired() const noexcept -> bool = 0;

        /**
         * @brief 等待已预约的实际操作及完成通知退栈。
         * @return 真实完成才成功；取消、不可交付或资源仍在途保留 Failure/Native。
         * @note 实现必须采用取消值结果；失败继续保留实际 owner，不提供默认成功。
         */
        [[nodiscard]] virtual auto Drain()
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> = 0;
    };
}

/** @file CarrierCloseReceipt.hpp @brief 装饰载体的独立真实关闭回执 owner。 */
#pragma once
#include <Prism/Foundation/Fault/Failure.hpp>
#include <boost/asio/awaitable.hpp>
#include <expected>
namespace Prism::Contract
{
    /**
     * @brief 关闭 owner 持有本回执到真实底层和本层活动全部退栈。
     * @details 输入：冷构造转移共享回执，无 buffer 借用或 wrapper 生存期要求。
     *          ConfirmExternalClose 只能在底层真实 close/drain 后调用，向原 executor 交付
     *          终态；不执行底层关闭、不代表半关闭。Drain 保留原始 Failure，等待本层全部
     *          I/O 和控制预约真实归还；已接受但丢失的交付继续保留，取消不冒充完成。
     *          最终关闭者仍是底层 carrier 的 owning close owner，本回执只拥有传输控制状态。
     *          executor 固定于载体冷构造；回执不反向拥有协议绑定或配置快照。
     */
    class CarrierCloseReceipt
    {
    public:
        virtual ~CarrierCloseReceipt() = default;
        /**
         * @brief 等待当前 close attempt 的终态，并保留其首个 Failure。
         * @details 尚无 close attempt 时立即成功；开始后，同步拒绝、OnClose 失败/异常以及
         *          丢弃或 quarantine 都发布一个可重复读取、可被多个 waiter 观察的终态。
         *          已受理的投递在 executor 暂停期间仍保持 pending，直到动作完成或被 quarantine。
         *          成功只表示关闭动作已在 owner executor 完成派发尝试；不等待投递对象析构，也不表示
         *          物理关闭或 Drain 完成。
         *          等待者取消只结束该 waiter，不改变共享回执。
         */
        [[nodiscard]] virtual auto AwaitCloseDispatch()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return std::expected<void, Prism::Fault::Failure>{};
        }
        virtual auto ConfirmExternalClose() noexcept -> void = 0;
        [[nodiscard]] virtual auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> = 0;
    };
}

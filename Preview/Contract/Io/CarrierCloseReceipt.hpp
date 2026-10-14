/** @file CarrierCloseReceipt.hpp @brief 装饰载体的独立真实关闭回执 owner。 */
#pragma once
#include <Preview/Foundation/Fault/Failure.hpp>
#include <boost/asio/awaitable.hpp>
#include <expected>
namespace Preview::Contract
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
        virtual auto ConfirmExternalClose() noexcept -> void = 0;
        [[nodiscard]] virtual auto Drain()
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> = 0;
    };
}

/** @file ActivityGroupFactory.hpp @brief TLS、Pad 与载体装饰层的活动组合工厂。 */
#pragma once

#include <Prism/Contract/Io/CarrierActivity.hpp>

#include <memory>
#include <vector>

namespace Prism::Transport
{
    namespace Detail
    {
        class ForwardActivity;
    }

    /**
     * @brief 构造父活动先退栈、随后逐个退休子活动的组合 owner。
     * @param Parent 本层活动；调用方必须提供有效 owner。
     * @param Children 每个都持有独立退休回执的子活动集合。
     * @return 组合后的只读活动视图；失败作为 Drain 的领域结果返回。
     * @details 输入按值接管共享引用；本工厂不发起 I/O、取消、半关闭或最终关闭。组合 owner
     *          先排空 Parent，确认 Parent 退休后才封止并逐个排空 Children；调用方仍是资源关闭者。
     *          Drain 按各 activity 自身执行器恢复，不建立额外 executor。
     */
    [[nodiscard]] auto MakeActivityGroup(
        std::shared_ptr<Contract::CarrierActivity> Parent,
        std::vector<std::shared_ptr<Contract::CarrierActivity>> Children)
        -> std::shared_ptr<Contract::CarrierActivity>;

    /**
     * @brief 保存 Forward activity 与“本层已转交最终关闭”这一权限事实。
     * @details Parent 与 Child 的共享引用归本对象持有；本对象不取消或关闭资源。调用方在成功
     *          转交 Child 的最终 Close 后必须调用 RequireChildDrain，再调用 Activity()->Drain()；
     *          否则 Drain 只证明 Parent 已退栈。执行器沿用 Parent，不切换执行域。
     */
    class ForwardActivityOwner final
    {
    public:
        ForwardActivityOwner(std::shared_ptr<Contract::CarrierActivity> Parent,
                             std::shared_ptr<Contract::CarrierActivity> Child);

        [[nodiscard]] auto Activity() const noexcept
            -> std::shared_ptr<Contract::CarrierActivity>;

        auto RequireChildDrain() noexcept -> void;

    private:
        std::shared_ptr<Detail::ForwardActivity> State_;
    };
}

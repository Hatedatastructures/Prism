/** @file ActivityGroup.hpp @brief 父操作先退出，再封止并排空其真实writer和TLS子owner。 */
#pragma once
#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <boost/asio/this_coro.hpp>
#include <vector>
#include <memory>
namespace Preview::Transport::Detail
{
    /**
     * @brief 把父前门 activity 与若干真实子 owner activity 冻结成一个可排空集合的组合器。
     * @details 输入所有权：构造把 Parent 与 Children 移进堆上 State（:34-:36，成员 :28-:32），此后
     *          经 State_（:56）共享持有；延长的是两个 activity 对象的生命周期，不据其宣称资源已关闭。
     *          输出与错误：Drain()（:39-:40）先排空 Parent 再按序排空 Children，首个失败即原样
     *          std::unexpected 上抛（:48、:52），其后的 Child 不再被排空，也没有默认成功。
     *          取消：DrainState 先 throw_if_cancelled(false)（:46），取消以值交付；基类契约见
     *          Preview/Contract/Io/CarrierActivity.hpp:32-:38。本类型自身没有 Cancel 入口。
     *          半关闭：本文件无任何 shutdown 调用点；基类明确该能力不执行写半关闭
     *          （Preview/Contract/Io/CarrierActivity.hpp:19），写方向由 WriteDriver::WriteShutdown 负责。
     *          最终关闭者：Seal()（:37）只封止 Parent 的准入，Child 不受该调用封止；行使关闭权的
     *          是链上 OwnsClose() 为真的那一层（Transmission.hpp:124），本类型不关闭任何资源。
     *          executor：Executor()（:38）固定返回 Parent 的执行域；Child->Drain()（:51）续体的内部
     *          执行域由 Child 自身实现决定，本文件不加约束，也不在此另建 strand。
     * @note 未定义：Child 的封止时机，以及 Parent 或首个 Child 失败后剩余 Child 由谁排空，本文件无
     *       答案，须由关闭链 owner（Transmission::ControlOwner 与 Writer）决定，本卡只登记读到的事实。
     */
    class ActivityGroup final : public Preview::Contract::CarrierActivity
    {
        struct State final
        {
            std::shared_ptr<Preview::Contract::CarrierActivity> Parent;
            std::vector<std::shared_ptr<Preview::Contract::CarrierActivity>> Children;
        };
    public:
        ActivityGroup(std::shared_ptr<Preview::Contract::CarrierActivity> Parent,
            std::vector<std::shared_ptr<Preview::Contract::CarrierActivity>> Children)
            : State_(std::make_shared<State>(std::move(Parent), std::move(Children))) {}
        auto Seal() noexcept -> void override { State_->Parent->Seal(); }
        /** @brief 聚合每个实际 owner 的独立回执；任何缺失或在途成员都阻止退休。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            if (!State_->Parent || !State_->Parent->IsRetired()) return false;
            for (const auto& Child : State_->Children)
                if (!Child || !Child->IsRetired()) return false;
            return true;
        }
        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override { return State_->Parent->Executor(); }
        [[nodiscard]] auto Drain() -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>> override
        { return DrainState(State_); }
    private:
        /** @brief 帧持有冷建冻结集合，关闭热路径不复制子owner列表。 */
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Owner)
            -> boost::asio::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            auto Result = co_await Owner->Parent->Drain();
            for (const auto& Child : Owner->Children)
            {
                const auto ChildResult = co_await Child->Drain();
                if (!ChildResult && Result) Result = std::unexpected(ChildResult.error());
            }
            co_return Result;
        }
        std::shared_ptr<State> State_;
    };
}

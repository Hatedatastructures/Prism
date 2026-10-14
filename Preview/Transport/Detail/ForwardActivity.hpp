/** @file ForwardActivity.hpp @brief 转交最终关闭后才等待真实child；借用层只排空自身。 */
#pragma once
#include <Preview/Contract/Io/CarrierActivity.hpp>
#include <boost/asio/this_coro.hpp>
#include <atomic>
#include <memory>
namespace Preview::Transport::Detail
{
    /**
     * @brief 只在本层确实转交了最终 Close 时才连带排空 child 的 CarrierActivity 转发门。
     * @details 输入所有权：构造把 Parent（本层前门）与 Child（内层真实 owner）移进堆上 State
     *          （:36-:37，成员 :32-:33），经 State_（:54）共享持有；持有 activity 不等于其资源已关闭。
     *          输出与错误：Drain()（:42-:43）先排空 Parent，失败原样 std::unexpected 上抛（:50）；
     *          仅当 CloseForwarded 为真才继续排空 Child 并返回其结果（:51），否则直接成功返回（:52）。
     *          取消：DrainState 先 throw_if_cancelled(false)（:48），取消以值交付，基类契约见
     *          Preview/Contract/Io/CarrierActivity.hpp:32-:38；本类型无 Cancel 入口，取消动作属上层。
     *          半关闭：本文件无 shutdown 调用点，写方向由 WriteDriver::WriteShutdown 与 leaf 载体处理。
     *          最终关闭者：Seal()（:40）只封止 Parent 准入；RequireChildDrain()（:39）是上层在 Close
     *          成功交付后记录的一次性权限事实，本类型不关闭任何资源，也不得据此宣称 child 已完成；
     *          行使关闭权的是链上 OwnsClose() 为真的层（Transmission.hpp:124）。
     *          executor：Executor()（:41）固定为 Parent 的执行域；CloseForwarded 是 State 内唯一原子
     *          成员（:33），Drain 只 acquire 读它一次（:51）。
     * @note 未定义：RequireChildDrain() 与 Drain() 的先后顺序无代码约束——Drain 已越过 :51 之后再
     *       调用不会生效；该次序由调用方（Preview.hpp:96、Replay.hpp:125）决定，本卡不改代码。
     */
    class ForwardActivity final : public Contract::CarrierActivity
    {
        struct State final
        {
            State(std::shared_ptr<Contract::CarrierActivity> Own, std::shared_ptr<Contract::CarrierActivity> Inner)
                : Parent(std::move(Own)), Child(std::move(Inner)) {}
            std::shared_ptr<Contract::CarrierActivity> Parent, Child;
            std::atomic<bool> CloseForwarded{false};
        };
    public:
        ForwardActivity(std::shared_ptr<Contract::CarrierActivity> Parent, std::shared_ptr<Contract::CarrierActivity> Child)
            : State_(std::make_shared<State>(std::move(Parent), std::move(Child))) {}
        /** @brief 只记录已转交最终Close的权限事实；不能据此宣称child完成。 */
        auto RequireChildDrain() noexcept -> void { State_->CloseForwarded.store(true, std::memory_order_release); }
        auto Seal() noexcept -> void override { State_->Parent->Seal(); }
        /** @brief 借用层只证明自身；已转交最终关闭的层还必须取得真实 child 回执。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            if (!State_->Parent || !State_->Parent->IsRetired()) return false;
            if (!State_->CloseForwarded.load(std::memory_order_acquire)) return true;
            return State_->Child && State_->Child->IsRetired();
        }
        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override { return State_->Parent->Executor(); }
        [[nodiscard]] auto Drain() -> boost::asio::awaitable<std::expected<void, Fault::Failure>> override
        { return DrainState(State_); }
    private:
        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Owner)
            -> boost::asio::awaitable<std::expected<void, Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            auto Result = co_await Owner->Parent->Drain();
            if (Owner->CloseForwarded.load(std::memory_order_acquire))
            {
                const auto ChildResult = co_await Owner->Child->Drain();
                if (!ChildResult && Result) Result = std::unexpected(ChildResult.error());
            }
            co_return Result;
        }
        std::shared_ptr<State> State_;
    };
}

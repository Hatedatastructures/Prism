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
     * @details 输入所有权：构造把 Parent 与 Children 移入共享 State，延长各 activity 对象的生命周期，
     *          不据此宣称资源已关闭。输出与错误：Drain() 先排空 Parent。Parent 未退休时不封止仍可能被其
     *          操作使用的 Child，并返回其失败或 Blocked；Parent 退休后才逐个封止、排空 Children，保留首错
     *          并继续排空兄弟。全部 Drain 成功而聚合 IsRetired() 为 false 时返回 Blocked。
     *          取消：DrainState 先禁用协程取消并以值交付；基类契约见 CarrierActivity。本类型没有 Cancel 入口。
     *          半关闭：本类型不执行写半关闭，写方向由 WriteDriver::WriteShutdown 负责。
     *          最终关闭者：Seal() 只封止 Parent 准入；Child 在 Parent Drain 完成后逐个封止。本类型不关闭资源，
     *          实际关闭由链上取得 OwnsClose() 权限的 owner 负责。Executor() 返回 Parent 的执行域；Child Drain
     *          使用各自实现的执行域，本类型不另建 strand。
     * @note 子级只在 Parent 取得退休回执后逐个 Seal/Drain，避免未退出的父操作被过早拒绝其子 I/O。
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
        { return IsStateRetired(*State_); }
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
            if (!Owner->Parent->IsRetired())
            {
                if (Result)
                    Result = std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                co_return Result;
            }
            for (const auto& Child : Owner->Children)
            {
                Child->Seal();
                const auto ChildResult = co_await Child->Drain();
                if (!ChildResult && Result) Result = std::unexpected(ChildResult.error());
            }
            if (Result && !IsStateRetired(*Owner))
                Result = std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            co_return Result;
        }
        [[nodiscard]] static auto IsStateRetired(const State& Owner) noexcept -> bool
        {
            if (!Owner.Parent || !Owner.Parent->IsRetired()) return false;
            for (const auto& Child : Owner.Children)
                if (!Child || !Child->IsRetired()) return false;
            return true;
        }
        std::shared_ptr<State> State_;
    };
}

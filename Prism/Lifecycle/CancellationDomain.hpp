/** @file CancellationDomain.hpp @brief 绑定单一 executor 的侵入式取消树。 */
#pragma once
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <atomic>
#include <memory>
namespace Prism::Lifecycle
{
    namespace Net = boost::asio;
    /** @brief 取消树在绑定 executor 通知任务 hook；观察者只以 weak 引用接入。 */
    class CancellationObserver
    {
    public:
        virtual ~CancellationObserver() = default;
        virtual auto OnCancellation() -> void = 0;
    };
    /** @brief 取消状态跨线程只读；树链接和信号由原 executor 串行访问。
     * @details 子域拥有独立节点，父只保留节点直到 Detach；无兄弟数组复制。
     * 无半关闭及资源最终关闭；取消只唤醒操作，owner 必须继续等待 drain。
     */
    class CancellationDomain final
    {
        struct State final : std::enable_shared_from_this<State>
        {
            explicit State(std::shared_ptr<Prism::Executor::ExecutorReclaimer> Value)
                : Reclaimer(std::move(Value)) {}
            std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
            std::weak_ptr<State> Parent;
            std::shared_ptr<State> First;
            std::shared_ptr<State> Next;
            Net::cancellation_signal Signal;
            std::atomic<std::weak_ptr<CancellationObserver>> Observer;
            std::atomic<bool> Requested{false};
            std::atomic<bool> Cancelled{false};
            std::atomic<bool> Blocked{false};
            std::atomic<bool> Detached{false};
            auto Attach(const std::shared_ptr<State>& Child) -> void
            {
                Prune();
                if (Child->Detached.load()) return;
                Child->Next = std::move(First);
                First = Child;
                if (Requested.load()) Child->Requested.store(true);
                if (Cancelled.load()) Child->Emit();
            }
            auto Prune() -> void
            {
                auto* Link = &First;
                while (*Link)
                {
                    if ((*Link)->Detached.load()) { *Link = std::move((*Link)->Next); continue; }
                    Link = &(*Link)->Next;
                }
            }
            auto Emit() -> void
            {
                Prune();
                if (Cancelled.exchange(true)) return;
                Requested.store(true);
                if (auto Value = Observer.load().lock())
                {
                    try { Value->OnCancellation(); }
                    catch (...) { Blocked.store(true, std::memory_order_release); }
                }
                Signal.emit(Net::cancellation_type::all);
                for (auto Child = First; Child; Child = Child->Next) Child->Emit();
            }
        };
        explicit CancellationDomain(std::shared_ptr<State> Value) : State_(std::move(Value)) {}
    public:
        explicit CancellationDomain(Net::any_io_executor Executor,
            std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer = {})
        {
            if (!Reclaimer) Reclaimer = std::make_shared<Prism::Executor::ExecutorReclaimer>(std::move(Executor));
            State_ = std::make_shared<State>(std::move(Reclaimer));
        }
        ~CancellationDomain() { Detach(); }
        CancellationDomain(const CancellationDomain&) = delete;
        auto operator=(const CancellationDomain&) -> CancellationDomain& = delete;
        /** @brief 接管独立子节点；链接在绑定 executor 执行，取消可先于链接发布。 */
        [[nodiscard]] auto CreateChild() -> std::shared_ptr<CancellationDomain>
        {
            auto ChildState = std::make_shared<State>(State_->Reclaimer);
            ChildState->Parent = State_;
            auto Child = std::shared_ptr<CancellationDomain>(new CancellationDomain(ChildState));
            if (!State_->Reclaimer->Post([Parent = State_, ChildState] { Parent->Attach(ChildState); }))
                ChildState->Blocked.store(true);
            return Child;
        }
        /** @brief 释放唯一取消节点；可重复，既有投递仍保活节点至原 executor 处理。 */
        auto Detach() noexcept -> void { State_->Detached.store(true); }
        /** @brief 跨线程发布取消；信号只在绑定 executor 发出，失败标记 Blocked。 */
        [[nodiscard]] auto Cancel() -> bool
        {
            if (State_->Requested.exchange(true) && State_->Cancelled.load()) return false;
            if (!State_->Reclaimer->Post([Value = State_] { Value->Emit(); })) State_->Blocked.store(true);
            return true;
        }
        /** @brief 在提交时发布任务观察者；观察者必须由任务预约保活至信号解绑。 */
        auto Observe(std::weak_ptr<CancellationObserver> Observer) noexcept -> void { State_->Observer.store(std::move(Observer)); }
        auto RequestCancellation() noexcept -> void { State_->Requested.store(true); }
        /** @brief 读取取消状态；无半关闭、最终关闭或 executor 调度副作用。 */
        [[nodiscard]] auto IsCancelled() const noexcept -> bool { return State_->Cancelled.load(); }
        /** @brief 读取当前域及父域的取消请求，不访问兄弟链表。 */
        [[nodiscard]] auto IsCancellationRequested() const noexcept -> bool
        {
            for (auto Value = State_; Value; Value = Value->Parent.lock())
                if (Value->Requested.load()) return true;
            return false;
        }
        /** @brief 读取本域信号交付阻断事实，不能当成成功取消或完成。 */
        [[nodiscard]] auto IsDispatchBlocked() const noexcept -> bool
        { return State_->Blocked.load() || !State_->Reclaimer->CanDispatch(); }
        /** @brief 只允许在绑定 executor 借用 slot，借用不跨越该域最终退休。 */
        [[nodiscard]] auto Slot() noexcept -> Net::cancellation_slot { return State_->Signal.slot(); }
        /** @brief 按值返回绑定 executor，调用方保持其 context 至全部 I/O 退栈。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor { return State_->Reclaimer->Executor(); }
        /** @brief 借用原 executor 的交付 owner；不转移 context 的最终释放责任。 */
        [[nodiscard]] auto Reclaimer() const -> const std::shared_ptr<Prism::Executor::ExecutorReclaimer>&
        { return State_->Reclaimer; }
    private:
        std::shared_ptr<State> State_;
    };
}

/**
 * @file CancellationDomain.hpp
 * @brief 可分层传播的取消域
 * @details 取消状态立即通过原子值可见，取消信号在各自绑定的 executor 上
 *          发出。子域以 weak snapshot 注册到父域，生命周期结束时会移除自身，
 *          不保留 owner 裸指针，也不维护自有无界事件队列。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/cancellation_signal.hpp>

#include <atomic>
#include <memory>
#include <utility>
#include <vector>

#include <Preview/Resource/ExecutorReclaimer.hpp>

namespace Preview::Lifecycle
{

    namespace Net = boost::asio;

    class CancellationDomain final
    {
    private:
        struct State;

        struct ChildSnapshot final
        {
            std::vector<std::weak_ptr<State>> Items;
        };

        struct State final : std::enable_shared_from_this<State>
        {
            State(Net::any_io_executor ExecutorValue,
                  std::shared_ptr<Preview::Resource::ExecutorReclaimer> ReclaimerValue,
                  std::weak_ptr<State> ParentValue)
                : Executor(std::move(ExecutorValue)),
                  Reclaimer(std::move(ReclaimerValue)),
                  Parent(std::move(ParentValue)),
                  Children(std::make_shared<const ChildSnapshot>())
            {
            }

            ~State() noexcept
            {
                if (const auto ParentValue = Parent.lock())
                {
                    ParentValue->RemoveChild(this);
                }
            }

            auto AddChild(const std::shared_ptr<State> &Child) -> void
            {
                for (;;)
                {
                    auto Current = Children.load(std::memory_order_acquire);
                    auto Next = std::make_shared<ChildSnapshot>(*Current);
                    Next->Items.push_back(Child);
                    if (Children.compare_exchange_weak(
                            Current,
                            std::shared_ptr<const ChildSnapshot>(std::move(Next)),
                            std::memory_order_release,
                            std::memory_order_acquire))
                    {
                        return;
                    }
                }
            }

            auto RequestCancellation() noexcept -> void
            {
                CancellationRequested.store(true, std::memory_order_release);
                const auto Current = Children.load(std::memory_order_acquire);
                for (const auto &Entry : Current->Items)
                {
                    if (const auto Child = Entry.lock())
                    {
                        Child->RequestCancellation();
                    }
                }
            }

            auto RemoveChild(const State *Target) noexcept -> void
            {
                try
                {
                    for (;;)
                    {
                        auto Current = Children.load(std::memory_order_acquire);
                        auto Next = std::make_shared<ChildSnapshot>();
                        Next->Items.reserve(Current->Items.size());
                        bool Removed = false;
                        for (const auto &Entry : Current->Items)
                        {
                            const auto Child = Entry.lock();
                            if (!Child || Child.get() == Target)
                            {
                                Removed = true;
                                continue;
                            }
                            Next->Items.push_back(Child);
                        }
                        if (!Removed)
                        {
                            return;
                        }
                        if (Children.compare_exchange_weak(
                                Current,
                                std::shared_ptr<const ChildSnapshot>(std::move(Next)),
                                std::memory_order_release,
                                std::memory_order_acquire))
                        {
                            return;
                        }
                    }
                }
                catch (...)
                {
                }
            }

            [[nodiscard]] auto Cancel() noexcept -> bool
            {
                if (Cancelled.exchange(true, std::memory_order_acq_rel))
                {
                    return false;
                }
                CancellationRequested.store(true, std::memory_order_release);

                const auto Current = Children.load(std::memory_order_acquire);
                for (const auto &Entry : Current->Items)
                {
                    if (const auto Child = Entry.lock())
                    {
                        (void)Child->Cancel();
                    }
                }

                const auto Self = shared_from_this();
                if (!Reclaimer->Post(
                        [Self]
                        {
                            Self->Signal.emit(Net::cancellation_type::all);
                        }))
                {
                    DispatchBlocked.store(true, std::memory_order_release);
                }
                return true;
            }

            Net::any_io_executor Executor;
            std::shared_ptr<Preview::Resource::ExecutorReclaimer> Reclaimer;
            std::weak_ptr<State> Parent;
            std::atomic<std::shared_ptr<const ChildSnapshot>> Children;
            Net::cancellation_signal Signal;
            std::atomic<bool> CancellationRequested{false};
            std::atomic<bool> Cancelled{false};
            std::atomic<bool> DispatchBlocked{false};
        };

        explicit CancellationDomain(std::shared_ptr<State> StateValue) : State_(std::move(StateValue)) {}

    public:
        explicit CancellationDomain(
            Net::any_io_executor Executor,
            std::shared_ptr<Preview::Resource::ExecutorReclaimer> Reclaimer = {})
            : State_(std::make_shared<State>(
                  Executor,
                  Reclaimer ? std::move(Reclaimer)
                            : std::make_shared<Preview::Resource::ExecutorReclaimer>(Executor),
                  std::weak_ptr<State>{}))
        {
        }

        CancellationDomain(const CancellationDomain &) = delete;
        auto operator=(const CancellationDomain &) -> CancellationDomain & = delete;
        CancellationDomain(CancellationDomain &&) = delete;
        auto operator=(CancellationDomain &&) -> CancellationDomain & = delete;

        /**
         * @brief 创建当前域的子域
         * @return 新建的子域；父域已取消时子域立即进入取消状态
         */
        [[nodiscard]] auto CreateChild() -> std::shared_ptr<CancellationDomain>
        {
            auto ChildState = std::make_shared<State>(State_->Executor, State_->Reclaimer, State_);
            State_->AddChild(ChildState);
            auto Child = std::shared_ptr<CancellationDomain>(new CancellationDomain(std::move(ChildState)));
            if (State_->Cancelled.load(std::memory_order_acquire))
            {
                (void)Child->Cancel();
            }
            else if (IsCancellationRequested())
            {
                Child->RequestCancellation();
            }
            return Child;
        }

        /**
         * @brief 发出一次取消请求
         * @return 首次发出返回 true，重复调用返回 false
         */
        [[nodiscard]] auto Cancel() noexcept -> bool
        {
            return State_->Cancel();
        }

        /**
         * @brief 递归发布取消请求标记，但不派发取消信号
         */
        auto RequestCancellation() noexcept -> void
        {
            State_->RequestCancellation();
        }

        [[nodiscard]] auto IsCancelled() const noexcept -> bool
        {
            return State_->Cancelled.load(std::memory_order_acquire);
        }

        /**
         * @brief 查询当前域及所有父域是否已请求或开始取消
         */
        [[nodiscard]] auto IsCancellationRequested() const noexcept -> bool
        {
            auto Current = State_;
            while (Current)
            {
                if (Current->Cancelled.load(std::memory_order_acquire) ||
                    Current->CancellationRequested.load(std::memory_order_acquire))
                {
                    return true;
                }
                Current = Current->Parent.lock();
            }
            return false;
        }

        [[nodiscard]] auto IsDispatchBlocked() const noexcept -> bool
        {
            return State_->DispatchBlocked.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Slot() noexcept -> Net::cancellation_slot
        {
            return State_->Signal.slot();
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return State_->Executor;
        }

        [[nodiscard]] auto Reclaimer() const
            -> const std::shared_ptr<Preview::Resource::ExecutorReclaimer> &
        {
            return State_->Reclaimer;
        }

    private:
        std::shared_ptr<State> State_;
    };

} // namespace Preview::Lifecycle

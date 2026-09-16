/**
 * @file ExecutorReclaimer.hpp
 * @brief 将生命周期回调收口到指定执行器，并隔离 owner 销毁后的迟到工作
 * @details 本类型不建立自有任务队列，只使用 Asio executor 的投递语义。
 *          每个投递项都有一个 pending 计数；隔离后已排队的工作会被丢弃，
 *          但仍会准确减少计数。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/post.hpp>

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <utility>

namespace Preview::Resource
{

    namespace Net = boost::asio;

    class ExecutorReclaimer final
    {
    public:
        using Action = std::function<void()>;

        explicit ExecutorReclaimer(Net::any_io_executor Executor)
            : State_(std::make_shared<State>(std::move(Executor)))
        {
        }

        ExecutorReclaimer(const ExecutorReclaimer &) = delete;
        auto operator=(const ExecutorReclaimer &) -> ExecutorReclaimer & = delete;
        ExecutorReclaimer(ExecutorReclaimer &&) = delete;
        auto operator=(ExecutorReclaimer &&) -> ExecutorReclaimer & = delete;

        /**
         * @brief 将工作投递到绑定执行器
         * @param Work 执行器上的一次性工作
         * @return 接受投递返回 true；已隔离或投递失败返回 false
         * @note Work 的异常会在此边界被吞掉，不能穿过 executor handler。
         */
        [[nodiscard]] auto Post(Action Work) noexcept -> bool
        {
            if (!Work)
            {
                return false;
            }

            const auto StateValue = State_;
            if (StateValue->Quarantined.load(std::memory_order_acquire))
            {
                StateValue->QuarantinedCount.fetch_add(1, std::memory_order_relaxed);
                return false;
            }

            StateValue->Pending.fetch_add(1, std::memory_order_acq_rel);
            if (StateValue->Quarantined.load(std::memory_order_acquire))
            {
                StateValue->Pending.fetch_sub(1, std::memory_order_acq_rel);
                StateValue->QuarantinedCount.fetch_add(1, std::memory_order_relaxed);
                return false;
            }

            try
            {
                Net::post(
                    StateValue->Executor,
                    [StateValue, Work = std::move(Work)]() mutable noexcept
                    {
                        if (StateValue->Quarantined.load(std::memory_order_acquire))
                        {
                            StateValue->QuarantinedCount.fetch_add(1, std::memory_order_relaxed);
                        }
                        else
                        {
                            try
                            {
                                Work();
                            }
                            catch (...)
                            {
                                StateValue->ActionFailures.fetch_add(1, std::memory_order_relaxed);
                            }
                        }
                        StateValue->Pending.fetch_sub(1, std::memory_order_acq_rel);
                    });
            }
            catch (...)
            {
                StateValue->Pending.fetch_sub(1, std::memory_order_acq_rel);
                return false;
            }
            return true;
        }

        /**
         * @brief 隔离 owner 销毁后的回调
         * @details 隔离只禁止后续工作触碰 owner；已排队回调仍由 executor
         *          消费并减少 pending 计数。
         */
        auto Quarantine() noexcept -> void
        {
            State_->Quarantined.store(true, std::memory_order_release);
        }

        [[nodiscard]] auto IsQuarantined() const noexcept -> bool
        {
            return State_->Quarantined.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Pending() const noexcept -> std::size_t
        {
            return State_->Pending.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto QuarantinedCount() const noexcept -> std::size_t
        {
            return State_->QuarantinedCount.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto ActionFailures() const noexcept -> std::size_t
        {
            return State_->ActionFailures.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return State_->Executor;
        }

    private:
        struct State final
        {
            explicit State(Net::any_io_executor ExecutorValue) : Executor(std::move(ExecutorValue)) {}

            Net::any_io_executor Executor;
            std::atomic<std::size_t> Pending{0};
            std::atomic<std::size_t> QuarantinedCount{0};
            std::atomic<std::size_t> ActionFailures{0};
            std::atomic<bool> Quarantined{false};
        };

        std::shared_ptr<State> State_;
    };

} // namespace Preview::Resource

/**
 * @file TrackedSessionTasks.hpp
 * @brief 拥有 HTTP/3 会话后台任务的准入、完成与 drain 记账。
 * @details 每次 co_spawn 先登记，完成回调再归还；启动失败沿会话关闭路径收敛。
 */

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>

#include <exception>
#include <expected>
#include <memory>
#include <utility>

#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>

namespace Prism::Http3::Detail
{
    namespace Net = boost::asio;

    template <class Owner>
    class TrackedSessionTasks final
    {
    public:
        explicit TrackedSessionTasks(Net::any_io_executor Executor)
            : Barrier_(std::make_shared<Prism::Lifecycle::DrainBarrier>(
                  std::make_shared<Prism::Executor::ExecutorReclaimer>(
                      std::move(Executor))))
        {
        }

        [[nodiscard]] auto Enter() noexcept -> bool { return Barrier_->Enter(); }
        auto Leave() noexcept -> void { Barrier_->Leave(); }
        auto Seal() noexcept -> void { Barrier_->Seal(); }
        [[nodiscard]] auto IsSealed() const noexcept -> bool { return Barrier_->IsSealed(); }
        [[nodiscard]] auto Active() const noexcept -> std::size_t { return Barrier_->Active(); }
        [[nodiscard]] auto IsBlocked() const noexcept -> bool { return Barrier_->IsBlocked(); }

        [[nodiscard]] auto Drain()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_return co_await Barrier_->Drain();
        }

        template <class Work>
        [[nodiscard]] auto Spawn(
            Net::any_io_executor Executor, const std::shared_ptr<Owner> &Session, Work Task) -> bool
        {
            if (!Barrier_->Enter())
            {
                return false;
            }
            auto CompletionOwner = Session;
            try
            {
                Net::co_spawn(std::move(Executor), std::move(Task),
                    [Self = std::move(CompletionOwner), Barrier = Barrier_](std::exception_ptr Error)
                    {
                        Self->OnTrackedTaskComplete(std::move(Error));
                        Barrier->Leave();
                    });
            }
            catch (...)
            {
                Session->OnTrackedTaskStartFailure(std::current_exception());
                Barrier_->Leave();
                return false;
            }
            return true;
        }

    private:
        std::shared_ptr<Prism::Lifecycle::DrainBarrier> Barrier_;
    };
}

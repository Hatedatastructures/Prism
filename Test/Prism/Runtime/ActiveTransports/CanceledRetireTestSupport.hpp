/**
 * @file CanceledRetireTestSupport.hpp
 * @brief ActiveTransports 取消退休测试共享的虚拟 Activity 与 datagram owner。
 */
#pragma once

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/this_coro.hpp>

#include <atomic>
#include <cstddef>
#include <exception>
#include <expected>
#include <memory>
#include <system_error>
#include <utility>

#include <Prism/Contract/Ingress/DatagramSession.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Runtime/ActiveTransports.hpp>

namespace
{
    namespace Net = boost::asio;
    using CloseSignal = Net::experimental::channel<void(boost::system::error_code)>;
    using Failure = Prism::Fault::Failure;

    /** @brief 控制测试 Activity 是否已经确认实物退休。 */
    struct CanceledRetirementState final
    {
        std::atomic<bool> PhysicallyRetired{false};
        std::atomic<bool> RetireOnClose{true};
        std::atomic<Prism::Fault::Code> DrainResultCode{Prism::Fault::Code::Canceled};
        std::atomic<std::size_t> CancelCalls{0};
        std::atomic<std::size_t> CloseCalls{0};
        std::atomic<std::size_t> DrainCalls{0};
        std::shared_ptr<CloseSignal> CloseEvents;
    };

    /** @brief 始终报告取消；IsRetired 独立表达实物是否已退栈。 */
    class CanceledDrainActivity final : public Prism::Contract::CarrierActivity
    {
    public:
        CanceledDrainActivity(Net::any_io_executor Executor,
                              std::shared_ptr<CanceledRetirementState> State)
            : Executor_(std::move(Executor)), State_(std::move(State))
        {
        }

        auto Seal() noexcept -> void override { Sealed_.store(true); }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Sealed_.load(std::memory_order_acquire) &&
                State_->PhysicallyRetired.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Executor_;
        }

        [[nodiscard]] auto Drain() -> Net::awaitable<std::expected<void, Failure>> override
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            State_->DrainCalls.fetch_add(1, std::memory_order_relaxed);
            if (!Sealed_.load(std::memory_order_acquire))
            {
                co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            }
            co_return std::unexpected(Failure{
                State_->DrainResultCode.load(std::memory_order_acquire)});
        }

    private:
        Net::any_io_executor Executor_;
        std::shared_ptr<CanceledRetirementState> State_;
        std::atomic<bool> Sealed_{false};
    };

    /** @brief 提供可重试 close 的 DatagramSession 测试 owner。 */
    class CanceledDrainDatagram final : public Prism::Contract::DatagramSession
    {
    public:
        CanceledDrainDatagram(Net::any_io_executor Executor,
                              std::shared_ptr<CanceledRetirementState> State)
            : State_(std::move(State)),
              Activity_(std::make_shared<CanceledDrainActivity>(
                  std::move(Executor), State_))
        {
        }

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Prism::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Failure>> override
        {
            co_return std::expected<void, Failure>{};
        }

        auto Cancel() noexcept -> void override
        {
            State_->CancelCalls.fetch_add(1, std::memory_order_relaxed);
        }

        auto Close() noexcept -> void override
        {
            State_->CloseCalls.fetch_add(1, std::memory_order_relaxed);
            if (State_->CloseEvents)
                (void)State_->CloseEvents->try_send(boost::system::error_code{});
            if (State_->RetireOnClose.load(std::memory_order_acquire))
            {
                State_->PhysicallyRetired.store(true, std::memory_order_release);
            }
        }

    private:
        std::shared_ptr<CanceledRetirementState> State_;
        std::shared_ptr<CanceledDrainActivity> Activity_;
    };

    [[nodiscard]] auto Finalize(
        Net::io_context &Context,
        Prism::Runtime::ActiveTransports &Active)
        -> std::expected<void, Failure>
    {
        std::expected<void, Failure> Result;
        std::exception_ptr Fatal;
        Net::co_spawn(Context, Active.Finalize(),
            [&Result, &Fatal](std::exception_ptr Error, std::expected<void, Failure> Value)
            {
                Fatal = std::move(Error);
                Result = std::move(Value);
            });
        Context.run();
        if (Fatal) std::rethrow_exception(Fatal);
        return Result;
    }

    /** @brief Finalize 结果交付后停止调度，保留待显式重试的控制失败 owner。 */
    [[nodiscard]] auto FinalizeAndStopAtResult(
        Net::io_context &Context,
        Prism::Runtime::ActiveTransports &Active)
        -> std::expected<void, Failure>
    {
        std::expected<void, Failure> Result;
        std::exception_ptr Fatal;
        Net::co_spawn(Context, Active.Finalize(),
            [&Result, &Fatal, &Context](std::exception_ptr Error,
                std::expected<void, Failure> Value)
            {
                Fatal = std::move(Error);
                Result = std::move(Value);
                Context.stop();
            });
        Context.run();
        if (Fatal) std::rethrow_exception(Fatal);
        return Result;
    }
}

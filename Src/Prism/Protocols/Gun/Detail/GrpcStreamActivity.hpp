/**
 * @file GrpcStreamActivity.hpp
 * @brief Gun gRPC stream 的 driver、H2 child 与外层 close 回执。
 */
#pragma once

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Contract/Io/CarrierCloseReceipt.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>

#include <atomic>
#include <exception>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Gun::Grpc::Detail
{
    /** @brief gRPC stream 三层活动和关闭回执的拥有型构造输入。 */
    struct GrpcStreamActivityLayers final
    {
        std::shared_ptr<Prism::Contract::CarrierActivity> Front;
        std::shared_ptr<Prism::Contract::CarrierActivity> Child;
        std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt;
    };

    /**
     * @brief 持有 gRPC 两个 driver 的真实完成预约并串接 H2 child 关闭回执。
     * @details Activity 不持有 StreamTransport，因而不形成 wrapper 引用环。Drain 分别
     *          等待本地 I/O、两个协程和 H2 child；先保留首个完整 Failure，再按物理状态决定
     *          是否 ConfirmExternalClose。END_STREAM 仍由 gRPC 写半关闭负责；最终 child close
     *          由 H2 session 执行，执行域固定于构造时的 stream executor。
     */
    class GrpcStreamActivity final : public Prism::Contract::CarrierActivity,
                                     public Prism::Executor::ClosingResource,
                                     public std::enable_shared_from_this<GrpcStreamActivity>
    {
        struct State final
        {
            State(
                boost::asio::any_io_executor Executor,
                GrpcStreamActivityLayers Layers);

            std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
            std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer;
            Prism::Lifecycle::DrainBarrier Drivers;
            boost::asio::any_io_executor Executor;
            std::shared_ptr<Prism::Contract::CarrierActivity> Front;
            std::shared_ptr<Prism::Contract::CarrierActivity> Child;
            std::shared_ptr<Prism::Contract::CarrierCloseReceipt> Receipt;
            Prism::Fault::FailureState Failure;
            std::atomic<bool> Sealed{false};
            std::atomic<bool> RetryScheduled{false};
        };

    public:
        GrpcStreamActivity(
            boost::asio::any_io_executor Executor,
            GrpcStreamActivityLayers Layers);

        [[nodiscard]] auto StartDriver() noexcept -> bool;

        auto RecordFailure(Prism::Fault::Failure Failure) noexcept -> void;

        [[nodiscard]] auto Failure() const noexcept -> Prism::Fault::Failure
        {
            return State_->Failure.Load();
        }

        auto CompleteDriver(Prism::Fault::Failure Failure) noexcept -> void;

        auto Seal() noexcept -> void override;

        [[nodiscard]] auto Executor() const -> boost::asio::any_io_executor override
        {
            return State_->Executor;
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return State_->Sealed.load(std::memory_order_acquire) &&
                !State_->Drivers.IsBlocked() && State_->Drivers.Active() == 0 &&
                State_->Front->IsRetired() && State_->Child->IsRetired();
        }

        [[nodiscard]] auto Drain()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override;

        auto RequestRetirement() -> void override;

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            return !State_->Reclaimer || !State_->Reclaimer->CanDispatch();
        }

    private:
        struct RetryCommand final
        {
            std::shared_ptr<GrpcStreamActivity> Owner;
            auto operator()() noexcept -> void;
        };

        struct RetryCompletion final
        {
            std::shared_ptr<GrpcStreamActivity> Owner;

            auto operator()(
                std::exception_ptr Exception,
                std::expected<void, Prism::Fault::Failure> Result) const noexcept -> void;
        };

        [[nodiscard]] auto RetryOnExecutor()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        auto StartRetry() noexcept -> void;

        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Value)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>;

        std::shared_ptr<State> State_;
    };
}

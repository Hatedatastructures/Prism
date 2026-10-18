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
                GrpcStreamActivityLayers Layers)
                : Storage(Prism::Executor::ContextOwner::Storage(Executor)),
                  Reclaimer(std::make_shared<Prism::Executor::ExecutorReclaimer>(
                      boost::asio::make_strand(std::move(Executor)))),
                  Drivers(Reclaimer), Executor(Reclaimer->Executor()),
                  Front(std::move(Layers.Front)), Child(std::move(Layers.Child)),
                  Receipt(std::move(Layers.Receipt))
            {
            }

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
            GrpcStreamActivityLayers Layers)
            : State_(std::make_shared<State>(
                  std::move(Executor), std::move(Layers)))
        {
        }

        [[nodiscard]] auto StartDriver() noexcept -> bool
        {
            return State_->Drivers.Enter();
        }

        auto RecordFailure(Prism::Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Failed()) (void)State_->Failure.TrySet(Failure);
        }

        [[nodiscard]] auto Failure() const noexcept -> Prism::Fault::Failure
        {
            return State_->Failure.Load();
        }

        auto CompleteDriver(Prism::Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Failed()) (void)State_->Failure.TrySet(Failure);
            State_->Drivers.Leave();
        }

        auto Seal() noexcept -> void override
        {
            if (State_->Sealed.exchange(true, std::memory_order_acq_rel)) return;
            State_->Drivers.Seal();
            State_->Front->Seal();
            State_->Child->Seal();
        }

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
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>> override
        {
            const auto Result = co_await DrainState(State_);
            if (IsRetired())
            {
                State_->Storage->Collect();
            }
            else
            {
                RequestRetirement();
            }
            co_return Result;
        }

        auto RequestRetirement() -> void override
        {
            if (IsRetired() || State_->RetryScheduled.exchange(true, std::memory_order_acq_rel))
                return;
            const auto Self = shared_from_this();
            State_->Storage->Retain(Self);
            const auto Posted = State_->Reclaimer->Post(RetryCommand{Self});
            if (!Posted)
            {
                State_->RetryScheduled.store(false, std::memory_order_release);
                RecordFailure(Posted.error());
                State_->Storage->Retain(Self);
            }
        }

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            return !State_->Reclaimer || !State_->Reclaimer->CanDispatch();
        }

    private:
        struct RetryCommand final
        {
            std::shared_ptr<GrpcStreamActivity> Owner;
            auto operator()() noexcept -> void { Owner->StartRetry(); }
        };

        struct RetryCompletion final
        {
            std::shared_ptr<GrpcStreamActivity> Owner;

            auto operator()(
                std::exception_ptr Exception,
                std::expected<void, Prism::Fault::Failure> Result) const noexcept -> void
            {
                Owner->State_->RetryScheduled.store(false, std::memory_order_release);
                if (Exception)
                {
                    Owner->RecordFailure(
                        Prism::Contract::InboundAdmission::ExceptionFailure(
                            std::move(Exception)));
                    Owner->State_->Storage->Retain(Owner);
                }
                else if (!Result)
                {
                    Owner->State_->Storage->Retain(Owner);
                }
                else
                {
                    Owner->State_->Storage->Collect();
                }
            }
        };

        [[nodiscard]] auto RetryOnExecutor()
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            const auto Result = co_await Drain();
            if (IsRetired()) co_return std::expected<void, Prism::Fault::Failure>{};
            if (!Result) co_return std::unexpected(Result.error());
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }

        auto StartRetry() noexcept -> void
        {
            if (IsRetired())
            {
                State_->RetryScheduled.store(false, std::memory_order_release);
                return;
            }
            const auto Self = shared_from_this();
            try
            {
                boost::asio::co_spawn(
                    State_->Reclaimer->Executor(), RetryOnExecutor(), RetryCompletion{Self});
            }
            catch (...)
            {
                State_->RetryScheduled.store(false, std::memory_order_release);
                RecordFailure(
                    Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception()));
                State_->Storage->Retain(Self);
            }
        }

        [[nodiscard]] static auto DrainState(std::shared_ptr<State> Value)
            -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await boost::asio::this_coro::throw_if_cancelled(false);
            co_await boost::asio::this_coro::reset_cancellation_state(
                boost::asio::disable_cancellation());
            const auto CloseDispatch = co_await Value->Receipt->AwaitCloseDispatch();
            if (!CloseDispatch) (void)Value->Failure.TrySet(CloseDispatch.error());
            Value->Drivers.Seal();
            Value->Front->Seal();
            Value->Child->Seal();

            const auto Driver = co_await Value->Drivers.Drain();
            if (!Driver) (void)Value->Failure.TrySet(Driver.error());
            const auto Child = co_await Value->Child->Drain();
            if (!Child) (void)Value->Failure.TrySet(Child.error());

            if (!Value->Child->IsRetired() || Value->Drivers.Active() != 0 ||
                Value->Drivers.IsBlocked())
            {
                auto Failure = Value->Failure.Load();
                if (Failure.Succeeded()) Failure = {Prism::Fault::Code::Blocked};
                co_return std::unexpected(Failure);
            }

            Value->Receipt->ConfirmExternalClose();
            const auto Front = co_await Value->Front->Drain();
            if (!Front) (void)Value->Failure.TrySet(Front.error());
            if (!Value->Front->IsRetired())
            {
                auto Failure = Value->Failure.Load();
                if (Failure.Succeeded()) Failure = {Prism::Fault::Code::Blocked};
                co_return std::unexpected(Failure);
            }

            const auto Failure = Value->Failure.Load();
            if (Failure.Failed()) co_return std::unexpected(Failure);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        std::shared_ptr<State> State_;
    };
}

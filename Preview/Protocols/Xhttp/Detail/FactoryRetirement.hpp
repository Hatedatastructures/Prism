/**
 * @file FactoryRetirement.hpp
 * @brief XHTTP 接受工厂的 typed 状态退休 owner。
 * @details 每个 ticket 以编译期 State 持有一份真实 XHTTP 域状态；失败后在原 executor
 *          重试 CloseAndDrain，成功发布时由工厂 Release 移交唯一数据面 owner。
 */
#pragma once

#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <exception>
#include <memory>
#include <utility>

namespace Preview::Xhttp::Detail
{
    namespace Net = boost::asio;

    /** @brief 物理退休完成状态及沿同一回执保留的首个 typed cause。 */
    struct FactoryRetirementReceipt final
    {
        bool Completed{false};
        Preview::Fault::Failure Failure;
    };

    namespace Detail
    {
        inline auto RecordRetirementFailure(
            Preview::Fault::Failure &Primary,
            const Preview::Fault::Failure &Next) noexcept -> void
        {
            if (!Primary.Failed() && Next.Failed())
            {
                Primary = Next;
            }
        }

        template<class Channel>
        [[nodiscard]] auto DrainFactoryDriver(
            const std::shared_ptr<Channel> &DriverDone,
            bool Started,
            bool &Completed) -> Net::awaitable<Preview::Fault::Failure>;

        template<class Transport>
        [[nodiscard]] auto DrainTransportActivity(
            const std::shared_ptr<Transport> &Value,
            Preview::Fault::Failure &FirstFailure)
            -> Net::awaitable<bool>
        {
            if (!Value) co_return true;
            const auto Activity = Value->Activity();
            if (!Activity)
            {
                RecordRetirementFailure(
                    FirstFailure, {Preview::Fault::Code::Blocked});
                co_return false;
            }
            const auto Drained = co_await Activity->Drain();
            if (!Drained) RecordRetirementFailure(FirstFailure, Drained.error());
            bool Complete = Activity->IsRetired();
            if constexpr (requires { Value->DrainWriter(); Value->WriterIsRetired(); })
            {
                const auto Writer = co_await Value->DrainWriter();
                if (!Writer) RecordRetirementFailure(FirstFailure, Writer.error());
                Complete = Value->WriterIsRetired() && Complete;
            }
            if (!Complete)
                RecordRetirementFailure(
                    FirstFailure, {Preview::Fault::Code::Blocked});
            co_return Complete;
        }

        template<class State>
        [[nodiscard]] auto CloseAndDrainState(State &Value)
            -> Net::awaitable<FactoryRetirementReceipt>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            bool Complete = true;
            Preview::Fault::Failure FirstFailure;
            if (Value.Transport)
            {
                const auto Closed = Value.Transport->Close();
                if (!Closed)
                    RecordRetirementFailure(FirstFailure, Closed.error());
                if constexpr (requires { Value.Transport->CloseFailure(); })
                    RecordRetirementFailure(
                        FirstFailure, Value.Transport->CloseFailure());
            }
            if constexpr (requires { Value.CloseFailure; })
                RecordRetirementFailure(FirstFailure, Value.CloseFailure);
            if (Value.Wire) Value.Wire->Close();
            if (Value.Encrypted)
            {
                const auto Canceled = Value.Encrypted->Cancel();
                if (!Canceled)
                    RecordRetirementFailure(FirstFailure, Canceled.error());
                const auto Closed = Value.Encrypted->Close();
                if (!Closed)
                    RecordRetirementFailure(FirstFailure, Closed.error());
            }

            Complete = co_await DrainTransportActivity(
                Value.Transport, FirstFailure) && Complete;
            if (Value.Wire)
            {
                const auto Drained = co_await Value.Wire->Drain();
                if (!Drained)
                    RecordRetirementFailure(FirstFailure, Drained.error());
                Complete = Value.Wire->IsRetired() && Complete;
            }
            if (Value.Encrypted)
            {
                const auto Activity = Value.Encrypted->Activity();
                if (!Activity)
                {
                    RecordRetirementFailure(
                        FirstFailure, {Preview::Fault::Code::Blocked});
                    Complete = false;
                }
                else
                {
                    const auto Drained = co_await Activity->Drain();
                    if (!Drained)
                        RecordRetirementFailure(FirstFailure, Drained.error());
                    Complete = Activity->IsRetired() &&
                        !Value.Encrypted->IsOpen() && Complete;
                }
            }
            const auto Driver = co_await DrainFactoryDriver(
                Value.DriverDone, Value.DriverStarted, Value.DriverCompleted);
            if (Driver.Failed())
                RecordRetirementFailure(FirstFailure, Driver);
            if (Value.DriverStarted && !Value.DriverCompleted) Complete = false;
            if (!Complete && FirstFailure.Succeeded())
                FirstFailure = {Preview::Fault::Code::Blocked};
            co_return FactoryRetirementReceipt{Complete, FirstFailure};
        }

        template<class Channel>
        [[nodiscard]] auto DrainFactoryDriver(
            const std::shared_ptr<Channel> &DriverDone,
            bool Started,
            bool &Completed) -> Net::awaitable<Preview::Fault::Failure>
        {
            if (!Started || Completed)
            {
                co_return Preview::Fault::Failure{};
            }
            if (!DriverDone)
            {
                co_return Preview::Fault::Failure{Preview::Fault::Code::Blocked};
            }
            boost::system::error_code Error;
            const auto Failure = co_await DriverDone->async_receive(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error)
            {
                co_return Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error));
            }
            Completed = true;
            co_return Failure;
        }
    }

    template<class State>
    class FactoryRetirement final
        : public Preview::Executor::ClosingResource,
          public std::enable_shared_from_this<FactoryRetirement<State>>
    {
        struct RetryCommand final
        {
            std::shared_ptr<FactoryRetirement> Owner;
            auto operator()() noexcept -> void { Owner->StartRetry(); }
        };

        struct RetryCompletion final
        {
            std::shared_ptr<FactoryRetirement> Owner;
            auto operator()(
                std::exception_ptr Exception,
                std::expected<void, Preview::Fault::Failure> Result) noexcept -> void
            {
                Owner->Scheduled_.store(false, std::memory_order_release);
                if (Exception)
                {
                    Owner->RecordFailure(
                        Preview::Contract::InboundAdmission::ExceptionFailure(
                            std::move(Exception)));
                    Owner->Storage_->Retain(Owner);
                }
                else if (!Result)
                {
                    Owner->Storage_->Retain(Owner);
                }
            }
        };

    public:
        [[nodiscard]] static auto Prepare(const Net::any_io_executor &Executor)
            -> std::shared_ptr<FactoryRetirement>
        {
            auto Context = Preview::Executor::ContextOwner::Find(Executor);
            auto Storage = Preview::Executor::ContextOwner::Storage(Executor);
            auto Reclaimer = std::make_shared<Preview::Executor::ExecutorReclaimer>(
                Net::make_strand(Executor));
            return std::shared_ptr<FactoryRetirement>(new FactoryRetirement(
                std::move(Context), std::move(Storage), std::move(Reclaimer)));
        }

        auto Attach(std::shared_ptr<State> Value) noexcept -> void
        {
            if (!State_)
            {
                State_ = std::move(Value);
            }
        }

        [[nodiscard]] auto Retire(Preview::Fault::Failure Cause)
            -> Net::awaitable<Preview::Fault::Failure>
        {
            RecordFailure(Cause);
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(
                Net::disable_cancellation());
            bool Idle = false;
            if (!Running_.compare_exchange_strong(
                    Idle, true, std::memory_order_acq_rel))
            {
                Storage_->Retain(this->shared_from_this());
                const auto Failure = Failure_.Load();
                if (Failure.Failed()) co_return Failure;
                co_return Preview::Fault::Failure{Preview::Fault::Code::Blocked};
            }

            const auto Receipt = co_await RetireState(this->shared_from_this());
            RecordFailure(Receipt.Failure);
            Running_.store(false, std::memory_order_release);
            if (Receipt.Completed)
            {
                CompleteRetirement();
            }
            else
            {
                Storage_->Retain(this->shared_from_this());
                RequestRetirement();
            }
            const auto Failure = Failure_.Load();
            if (Failure.Failed()) co_return Failure;
            if (!Receipt.Completed)
                co_return Preview::Fault::Failure{Preview::Fault::Code::Blocked};
            co_return Preview::Fault::Failure{};
        }


        auto RequestRetirement() -> void override
        {
            if (Retired_.load(std::memory_order_acquire) ||
                Scheduled_.exchange(true, std::memory_order_acq_rel))
            {
                return;
            }
            const auto Self = this->shared_from_this();
            const auto Posted = Reclaimer_->Post(RetryCommand{Self});
            if (!Posted)
            {
                Scheduled_.store(false, std::memory_order_release);
                RecordFailure(Posted.error());
                Storage_->Retain(Self);
            }
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            return !Reclaimer_ || !Reclaimer_->CanDispatch();
        }

    private:
        auto RecordFailure(const Preview::Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Failed())
            {
                // TrySet 的返回值只报告首因发布胜负；Receipt 仍独立报告物理完成。
                (void)Failure_.TrySet(Failure);
            }
        }

        FactoryRetirement(
            std::shared_ptr<Preview::Executor::ContextOwner> Context,
            std::shared_ptr<Preview::Executor::ClosingStorage> Storage,
            std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer)
            : Context_(std::move(Context)), Storage_(std::move(Storage)),
              Reclaimer_(std::move(Reclaimer))
        {
        }

        [[nodiscard]] static auto RetireState(
            std::shared_ptr<FactoryRetirement> Owner)
            -> Net::awaitable<FactoryRetirementReceipt>
        {
            try
            {
                co_await Net::dispatch(
                    Owner->Reclaimer_->Executor(), Net::use_awaitable);
                co_await Net::this_coro::throw_if_cancelled(false);
                co_await Net::this_coro::reset_cancellation_state(
                    Net::disable_cancellation());
                const auto RetiringState = Owner->State_;
                if (!RetiringState)
                    co_return FactoryRetirementReceipt{true, {}};
                const auto Receipt = co_await RetiringState->CloseAndDrain();
                Owner->RecordFailure(Receipt.Failure);
                co_return Receipt;
            }
            catch (...)
            {
                const auto Failure =
                    Preview::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception());
                Owner->RecordFailure(Failure);
                co_return FactoryRetirementReceipt{false, Failure};
            }
        }

        [[nodiscard]] static auto RetryOnExecutor(
            std::shared_ptr<FactoryRetirement> Owner)
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            bool Idle = false;
            if (!Owner->Running_.compare_exchange_strong(
                    Idle, true, std::memory_order_acq_rel))
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            const auto Receipt = co_await RetireState(Owner);
            Owner->RecordFailure(Receipt.Failure);
            Owner->Running_.store(false, std::memory_order_release);
            if (Receipt.Completed)
            {
                Owner->CompleteRetirement();
                co_return std::expected<void, Preview::Fault::Failure>{};
            }
            Owner->Storage_->Retain(Owner);
            const auto Failure = Owner->Failure_.Load();
            if (Failure.Failed())
            {
                co_return std::unexpected(Failure);
            }
            co_return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }

        auto StartRetry() noexcept -> void
        {
            if (Retired_.load(std::memory_order_acquire))
            {
                Scheduled_.store(false, std::memory_order_release);
                return;
            }
            const auto Self = this->shared_from_this();
            try
            {
                Net::co_spawn(Reclaimer_->Executor(), RetryOnExecutor(Self),
                    RetryCompletion{Self});
            }
            catch (...)
            {
                Scheduled_.store(false, std::memory_order_release);
                RecordFailure(
                    Preview::Contract::InboundAdmission::ExceptionFailure(
                        std::current_exception()));
                Storage_->Retain(Self);
            }
        }

        auto CompleteRetirement() noexcept -> void
        {
            State_.reset();
            Context_.reset();
            Retired_.store(true, std::memory_order_release);
            Storage_->Collect();
        }

        std::shared_ptr<Preview::Executor::ContextOwner> Context_;
        std::shared_ptr<Preview::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer_;
        std::shared_ptr<State> State_;
        std::atomic<bool> Running_{false};
        std::atomic<bool> Scheduled_{false};
        std::atomic<bool> Retired_{false};
        Preview::Fault::FailureState Failure_;
    };
} // namespace Preview::Xhttp::Detail

/**
 * @file Retirement.hpp
 * @brief Trojan/Vmess 数据报 Run 预约与承载链最终退休 owner。
 * @details 全部 Pump、Run、Cancel、Close 与退休状态只在固定 strand 上访问；失败时保留
 *          Pump、Run Reservation 与原生原因，只有完整控制和 Drain 成功后才完成退休。
 */
#pragma once

#include <Prism/Protocols/Common/Datagram/Failure.hpp>
#include <Prism/Protocols/Common/Datagram/Retirement/Actions.hpp>

#include <Prism/Contract/Io/CarrierActivity.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Protocols/Common/Datagram/Relay/Pump.hpp>
#include <Prism/Protocols/Common/ProtocolActivity.hpp>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>

namespace Prism::Protocols
{
    namespace Net = boost::asio;
    using DatagramNotifications =
        Net::experimental::concurrent_channel<void(boost::system::error_code)>;

    /**
     * @brief DatagramRelayPump 的完整关闭、Drain 与失败保留 owner。
     * @details 外部门面只投递托管动作；所有非原子状态与 Pump 操作在 Strand_ 上串行执行。
     *          Run Reservation 仅在任务真实返回且所有 carrier 层 Drain 成功后完成。
     */
    template<class Wire>
    class DatagramRetirement final : public Prism::Contract::CarrierActivity,
                                    public Prism::Executor::ClosingResource,
                                    public std::enable_shared_from_this<DatagramRetirement<Wire>>
    {
        using Failure = Prism::Fault::Failure;
        using CompletionResult = std::expected<void, Failure>;
        using Pump = DatagramRelayPump<Wire>;
        using Strand = Net::strand<Net::any_io_executor>;
        using DeliveryKind = DatagramRetirementDetail::DeliveryKind;
        using Delivery = DatagramRetirementDetail::Delivery<Wire>;
        using Completion = DatagramRetirementDetail::Completion<Wire>;

        friend struct DatagramRetirementDetail::Delivery<Wire>;
        friend struct DatagramRetirementDetail::Completion<Wire>;

    public:
        /** @brief 接管完整 Pump 并固定其底层执行域、strand、回收域与通知通道。 */
        DatagramRetirement(Wire Value, DatagramRelayOptions Options)
            : Pump_(std::in_place, std::move(Value), std::move(Options)),
              Executor_(Pump_->Executor()), Strand_(Net::make_strand(Executor_)),
              Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(Strand_)),
              Storage_(Prism::Executor::ContextOwner::Storage(Executor_)),
              RunActivity_(std::make_shared<Prism::Protocols::ProtocolActivity>(Strand_)),
              Changed_(Strand_, 1)
        {
        }

        DatagramRetirement(const DatagramRetirement&) = delete;
        auto operator=(const DatagramRetirement&) -> DatagramRetirement& = delete;

        /** @brief 运行唯一 pump；状态切换到固定 strand 后才读取生命周期字段。 */
        [[nodiscard]] auto Run() -> Net::awaitable<CompletionResult>
        {
            return RunOwned(this->shared_from_this());
        }

        /** @brief 只提交托管取消动作；取消信号与 typed controls 在固定 strand 上发出。 */
        auto Cancel() noexcept -> void
        {
            Dispatch(DeliveryKind::Cancel, false);
        }

        /** @brief 请求最终关闭；实际资源释放只由串行退休状态确认。 */
        auto Close() noexcept -> void
        {
            Dispatch(DeliveryKind::Shutdown, false);
        }

        /** @brief 同步封止新的 Run admission，随后在固定 strand 通知状态 owner。 */
        auto Seal() noexcept -> void override
        {
            RunActivity_->Seal();
            Dispatch(DeliveryKind::Seal, false);
        }

        /** @brief 返回 Run、controls 与载体 Drain 共用的固定 strand。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor override
        {
            return Strand_;
        }

        /** @brief 首因先返回；失败不会完成 Run Reservation 或释放 Pump。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<CompletionResult> override
        {
            return DrainOwned(this->shared_from_this());
        }

        /** @brief ClosingStorage 显式重试；同一 strand 合并并发退休请求。 */
        auto RequestRetirement() -> void override
        {
            Dispatch(DeliveryKind::Retry, true);
        }

        /** @brief 仅所有 controls 和每层真实 Drain 成功后为 true。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_.load(std::memory_order_acquire);
        }

        /** @brief 反映原执行域当前是否还能接收回收请求。 */
        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            return !Reclaimer_->CanDispatch();
        }

    private:
        [[nodiscard]] static auto RunOwned(std::shared_ptr<DatagramRetirement> Owner)
            -> Net::awaitable<CompletionResult>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            const auto Executor = Owner->Strand_;
            if (!Owner->Reclaimer_->CanDispatch())
            {
                const Failure Cause{Prism::Fault::Code::Blocked};
                Owner->Record(Cause);
                co_return std::unexpected(Cause);
            }
            auto Task = RunState(Owner);
            co_return co_await Net::co_spawn(Executor, std::move(Task), Net::use_awaitable);
        }

        [[nodiscard]] static auto RunState(std::shared_ptr<DatagramRetirement> Owner)
            -> Net::awaitable<CompletionResult>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            if (Owner->Started_)
                co_return std::unexpected(Failure{Prism::Fault::Code::InvalidArgument});
            Owner->Started_ = true;
            if (Owner->Retired_.load(std::memory_order_acquire))
            {
                const auto Cause = Owner->Failure_.Load();
                if (Cause.Failed()) co_return std::unexpected(Cause);
                if (Owner->Cancelled_)
                    co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
                co_return CompletionResult{};
            }
            if (Owner->Closed_)
            {
                Owner->RunDone_ = true;
                Owner->RunTaskReturned_ = true;
                Owner->Pump_->Report();
                Owner->RequestRetirementOnStrand(false);
                const auto Cause = Owner->Failure_.Load();
                if (Cause.Failed()) co_return std::unexpected(Cause);
                if (Owner->Cancelled_)
                    co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
                co_return CompletionResult{};
            }

            auto Admission = Owner->RunActivity_->TryBegin();
            if (!Admission)
            {
                Owner->RunDone_ = true;
                Owner->RunTaskReturned_ = true;
                Owner->Pump_->Report();
                Owner->BeginShutdown(false);
                Owner->RequestRetirementOnStrand(false);
                const auto Cause = Owner->Failure_.Load();
                if (Cause.Failed()) co_return std::unexpected(Cause);
                co_return std::unexpected(Admission.error());
            }
            Owner->RunReservation_.emplace(std::move(*Admission));

            const auto Validation = Owner->Pump_->Validate();
            if (Prism::Fault::Failed(Validation))
            {
                const Failure Cause{Validation};
                Owner->RunDone_ = true;
                Owner->RunTaskReturned_ = true;
                Owner->Pump_->Report();
                Owner->BeginShutdown(false);
                Owner->RequestRetirementOnStrand(false);
                co_return std::unexpected(Cause);
            }

            CompletionResult Result;
            try
            {
                Result = co_await Net::co_spawn(
                    Owner->Strand_, Owner->RunPump(),
                    Net::bind_cancellation_slot(
                        Owner->Pump_->CancellationSlot(), Net::use_awaitable));
                Owner->RunTaskReturned_ = true;
            }
            catch (...)
            {
                const auto Cause = DatagramFailure::FromException(std::current_exception());
                Owner->Record(Cause);
                Result = std::unexpected(Cause);
            }
            Owner->RunDone_ = true;
            Owner->Pump_->Report();
            Owner->BeginShutdown(false);
            Owner->RequestRetirementOnStrand(false);
            const auto First = Owner->Failure_.Load();
            if (First.Failed()) co_return std::unexpected(First);
            if (Owner->Cancelled_)
                co_return std::unexpected(Failure{Prism::Fault::Code::Canceled});
            if (!Result) co_return std::unexpected(Result.error());
            co_return CompletionResult{};
        }

        /** @brief 把 pump 异常转换为值；协程真实退栈后才向 owner 报告完成。 */
        auto RunPump() -> Net::awaitable<CompletionResult>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            try
            {
                const auto Result = co_await Pump_->Run();
                if (!Result)
                {
                    co_return std::unexpected(Result.error());
                }
                co_return CompletionResult{};
            }
            catch (...)
            {
                const auto Error = DatagramFailure::FromException(std::current_exception());
                co_return std::unexpected(Error);
            }
        }

        [[nodiscard]] static auto DrainOwned(std::shared_ptr<DatagramRetirement> Owner)
            -> Net::awaitable<CompletionResult>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            const auto Executor = Owner->Strand_;
            if (Owner->Retired_.load(std::memory_order_acquire)) co_return CompletionResult{};
            if (!Owner->Reclaimer_->CanDispatch())
            {
                const auto FailureValue = Owner->FirstFailure();
                Owner->Record(FailureValue);
                co_return std::unexpected(FailureValue);
            }
            auto Task = DrainState(Owner);
            co_return co_await Net::co_spawn(Executor, std::move(Task), Net::use_awaitable);
        }

        [[nodiscard]] static auto DrainState(std::shared_ptr<DatagramRetirement> Owner)
            -> Net::awaitable<CompletionResult>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            Owner->RunActivity_->Seal();
            for (;;)
            {
                if (Owner->Retired_.load(std::memory_order_acquire))
                {
                    Owner->Notify();
                    co_return CompletionResult{};
                }
                const auto FailureValue = Owner->Failure_.Load();
                if (FailureValue.Failed())
                {
                    Owner->Notify();
                    co_return std::unexpected(FailureValue);
                }
                if (!Owner->Reclaimer_->CanDispatch())
                {
                    const Failure Error{Prism::Fault::Code::Blocked};
                    Owner->Record(Error);
                    co_return std::unexpected(Error);
                }
                boost::system::error_code Error;
                co_await Owner->Changed_.async_receive(
                    Net::redirect_error(Net::use_awaitable, Error));
                if (Error)
                {
                    const auto Recorded = Owner->Failure_.Load();
                    if (Recorded.Failed()) co_return std::unexpected(Recorded);
                    co_return std::unexpected(
                        Prism::Fault::FromNative(static_cast<std::error_code>(Error)));
                }
            }
        }

        /** @brief 按值交付外部生命周期动作；失败后保留整个 owner。 */
        auto Dispatch(DeliveryKind Kind, bool RetryControls) noexcept -> void
        {
            if (Retired_.load(std::memory_order_acquire)) return;
            try
            {
                auto Self = this->shared_from_this();
                Storage_->Retain(Self);
                const auto Result = Reclaimer_->Post(
                    Delivery(std::move(Self), Kind, RetryControls));
                if (!Result) Record(Result.error());
            }
            catch (...)
            {
                Record(DatagramFailure::FromException(std::current_exception()));
            }
        }

        /** @brief 只在固定 strand 封止准入；不提前关闭或完成在途 Run。 */
        auto SealOnStrand() noexcept -> void
        {
            RunActivity_->Seal();
            Notify();
        }

        /** @brief 在固定 strand 开始一次退休；Run 未真实返回时只记下待办请求。 */
        auto RequestRetirementOnStrand(bool RetryControls) -> void
        {
            if (Retired_.load(std::memory_order_acquire)) return;
            if (RetirementRunning_)
            {
                if (RetryControls)
                {
                    RetirementRequested_ = true;
                    RetryControlsRequested_ = true;
                }
                return;
            }
            RetirementRequested_ = true;
            RetryControlsRequested_ = RetryControlsRequested_ || RetryControls;
            StartRetirement();
        }

        /** @brief 同一 strand 合并正在进行与排队中的关闭/Drain 尝试。 */
        auto StartRetirement() -> void
        {
            if (Retired_.load(std::memory_order_acquire) || RetirementRunning_ ||
                !RetirementRequested_ || !RunDone_ || !RunTaskReturned_)
                return;
            const bool RetryControls = RetryControlsRequested_;
            RetirementRequested_ = false;
            RetryControlsRequested_ = false;
            RetirementRunning_ = true;
            try
            {
                auto Self = this->shared_from_this();
                Net::co_spawn(Strand_, RetireOnStrand(RetryControls),
                    Net::bind_executor(Strand_, Completion(std::move(Self))));
            }
            catch (...)
            {
                RetirementRunning_ = false;
                Record(DatagramFailure::FromException(std::current_exception()));
                Notify();
            }
        }

        /** @brief controls 被接受且所有真实层排空后才释放 Pump 与 Run Reservation。 */
        [[nodiscard]] auto RetireOnStrand(bool RetryControls)
            -> Net::awaitable<CompletionResult>
        {
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            if (!RunDone_ || !RunTaskReturned_)
                co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
            if (!ControlsRequested_ || RetryControls)
            {
                ControlsRequested_ = true;
                ControlsAccepted_ = RequestControls(Cancelled_);
            }
            if (!ControlsAccepted_)
            {
                co_return std::unexpected(FirstFailure());
            }

            std::optional<Failure> First;
            if (Pump_->CarrierActivities().empty())
                DatagramFailure::Preserve(First, Failure{Prism::Fault::Code::InvalidArgument});
            for (const auto& CarrierActivity : Pump_->CarrierActivities())
            {
                if (!CarrierActivity)
                {
                    DatagramFailure::Preserve(First, Failure{Prism::Fault::Code::InvalidArgument});
                    continue;
                }
                try
                {
                    const auto Result = co_await CarrierActivity->Drain();
                    // 只有独立物理回执已成立时才接受取消；其余失败必须保留首因与 owner。
                    if (!Result &&
                        (Result.error().Code != Prism::Fault::Code::Canceled ||
                         !CarrierActivity->IsRetired()))
                    {
                        DatagramFailure::Preserve(First, Result.error());
                        Record(Result.error());
                    }
                }
                catch (...)
                {
                    const auto Error = DatagramFailure::FromException(std::current_exception());
                    DatagramFailure::Preserve(First, Error);
                    Record(Error);
                }
            }
            if (First)
            {
                co_return std::unexpected(*First);
            }
            co_return CompletionResult{};
        }

        /** @brief 仅在退休协程的完成 handler 返回成功后释放 Pump 和 Run Reservation。 */
        auto FinalizeRetirement() noexcept -> void
        {
            Pump_.reset();
            if (RunReservation_)
            {
                RunReservation_->Complete();
                RunReservation_.reset();
            }
            Retired_.store(true, std::memory_order_release);
        }

        /** @brief 固定 strand 上记录停机并接管失败实物；不伪造 Run 任务已退栈。 */
        auto BeginShutdown(bool CancelRun) noexcept -> void
        {
            if (Retired_.load(std::memory_order_acquire) || !Pump_) return;
            RunActivity_->Seal();
            if (CancelRun && !Cancelled_)
            {
                Cancelled_ = true;
                Pump_->Stop(true);
            }
            else
            {
                Pump_->Stop(false);
            }
            Closed_ = true;
            Storage_->Retain(this->shared_from_this());
            if (!ControlsRequested_)
            {
                ControlsRequested_ = true;
                ControlsAccepted_ = RequestControls(Cancelled_);
            }
            if (!Started_)
            {
                RunDone_ = true;
                RunTaskReturned_ = true;
                Pump_->Report();
                RequestRetirementOnStrand(false);
            }
            Notify();
        }

        /** @brief 同步控制结果失败时立即发布首因，显式 Retry 可重新提交 controls。 */
        [[nodiscard]] auto RequestControls(const bool CancelRun) noexcept -> bool
        {
            const auto Result = Pump_->RequestControls(CancelRun);
            if (Result) return true;
            Record(Result.error());
            return false;
        }

        /** @brief 记录首个完整 cause；不参与后续重试的成功判定。 */
        auto Record(Failure Error) noexcept -> void
        {
            if (Error.Succeeded()) return;
            (void)Failure_.TrySet(Error);
            Storage_->Retain(this->shared_from_this());
            Notify();
        }

        [[nodiscard]] auto FirstFailure() const noexcept -> Failure
        {
            const auto Value = Failure_.Load();
            return Value.Failed() ? Value : Failure{Prism::Fault::Code::Blocked};
        }

        /** @brief 合并状态变更通知；容量为一时已有通知足以唤醒 waiter。 */
        auto Notify() noexcept -> void
        {
            (void)Changed_.try_send(boost::system::error_code{});
        }

        std::optional<Pump> Pump_;
        Net::any_io_executor Executor_;
        Strand Strand_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Prism::Protocols::ProtocolActivity> RunActivity_;
        DatagramNotifications Changed_;
        std::optional<Prism::Protocols::ProtocolActivity::Reservation> RunReservation_;
        Prism::Fault::FailureState Failure_;
        std::atomic<bool> Retired_{false};
        bool Started_{false}, RunDone_{false}, RunTaskReturned_{false};
        bool Closed_{false}, Cancelled_{false}, ControlsRequested_{false}, ControlsAccepted_{false};
        bool RetirementRunning_{false}, RetirementRequested_{false}, RetryControlsRequested_{false};
    };
}

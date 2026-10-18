/**
 * @file ProviderSessionRetirement.hpp
 * @brief Trojan、VLESS 与 VMess provider binding 的真实 session owner。
 */
#pragma once

#include <Prism/Contract/Ingress/DataPlane.hpp>
#include <Prism/Contract/Ingress/InboundAdmission.hpp>
#include <Prism/Contract/Ingress/SessionRetirementOwner.hpp>
#include <Prism/Foundation/Executor/ClosingStorage.hpp>
#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/FailureState.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Protocols/Common/ProviderMuxRootState.hpp>
#include <Prism/Protocols/Common/ProviderSessionDrainAttempt.hpp>
#include <Prism/Protocols/Common/ProviderSessionResources.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <cstdint>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <utility>

namespace Prism::Protocols
{
    namespace Net = boost::asio;
    using ProviderRetirementResult = std::expected<void, Prism::Fault::Failure>;

    /**
     * @brief 一个已开始的协议接入及已发布根 owner 的同一失败退休票据。
     * @details 成功发布后保留真实传输、协议根、材料与 generation lease；失败时在原
     *          executor 重试。业务 SessionFailure、DrainFailure 与物理 IsRetired 分开保存，
     *          坏凭据不会污染后续准入或把已完成的物理退休变成失败。
     */
    template<class Material>
    class ProviderSessionRetirement final
        : public Prism::Executor::ClosingResource,
          public ProviderMuxRootState,
          public Prism::Contract::Ingress::SessionRetirementOwner,
          public std::enable_shared_from_this<ProviderSessionRetirement<Material>>
    {
    public:
        using Pointer = std::shared_ptr<ProviderSessionRetirement>;

        ProviderSessionRetirement(Prism::SharedTransmission Inbound,
            std::shared_ptr<const Material> MaterialValue,
            Prism::Foundation::GenerationUseLease UseLease)
            : Resources_(Inbound), Material_(std::move(MaterialValue)), UseLease_(std::move(UseLease)),
              Executor_(Inbound->Executor()), Context_(Prism::Executor::ContextOwner::Find(Executor_)),
              Storage_(Prism::Executor::ContextOwner::Storage(Executor_)),
              Reclaimer_(std::make_shared<Prism::Executor::ExecutorReclaimer>(
                  Net::make_strand(Executor_)))
        {
        }

        ProviderSessionRetirement(const ProviderSessionRetirement&) = delete;
        auto operator=(const ProviderSessionRetirement&) -> ProviderSessionRetirement& = delete;

        /** @brief 在握手后登记 Connection 或 replay；固定槽在任何协议 I/O 前已建好。 */
        [[nodiscard]] auto Track(const Prism::SharedTransmission& Transport)
            -> std::expected<void, Prism::Fault::Failure>
        {
            if (!Transport)
            {
                return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
            }
            const auto Tracked = Resources_.Track(Transport);
            if (!Tracked) return std::unexpected(Tracked.error());
            if (CloseRequested_.load(std::memory_order_acquire))
            {
                RecordDrainAttemptFailure(Resources_.CloseTransport(Transport, true));
            }
            return {};
        }

        /** @brief 在 Admission::Admit 前保存与运行时共享的 transport/root 实物。 */
        [[nodiscard]] auto Publish(const Prism::Contract::ProtocolDataPlane& Plane)
            -> std::expected<void, Prism::Fault::Failure>
        {
            const auto Transport = Plane.Transport();
            const auto Tracked = Track(Transport);
            if (!Tracked)
            {
                return std::unexpected(Tracked.error());
            }
            RootSlot_->Transport = Transport;
            if (const auto* Datagram = Plane.Datagram())
            {
                RootSlot_->Datagram = Datagram->Session;
            }
            if (const auto* Mux = Plane.Mux())
            {
                RootSlot_->Mux = Mux->Session;
            }
            Root_.store(RootSlot_, std::memory_order_release);
            if (CloseRequested_.load(std::memory_order_acquire))
            {
                Resources_.CloseRootOnly(Root_.load(std::memory_order_acquire));
            }
            return {};
        }

        /** @brief 记录完整首因；Native 不与任何 cleanup failure 拼接。 */
        auto RecordFailure(Prism::Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Failed())
            {
                (void)Failure_.TrySet(std::move(Failure));
            }
        }

        /** @brief 返回本次接入/协议运行首因；不表示绑定关闭或物理退休失败。 */
        [[nodiscard]] auto SessionFailure() const noexcept -> Prism::Fault::Failure
        {
            return Failure_.Load();
        }

        /** @brief 只记录关闭、排空或 executor 退休本身的失败。 */
        auto RecordDrainFailure(Prism::Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Failed()) (void)DrainFailure_.TrySet(std::move(Failure));
        }

        /** @brief 取消 attempt 可重试；最终退休回执决定是否可作为正常 close。 */
        auto RecordDrainAttemptFailure(Prism::Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Code != Prism::Fault::Code::Canceled)
            {
                RecordDrainFailure(std::move(Failure));
            }
        }

        /** @brief 绑定唯一 generation-use lease；只在协议 I/O 前调用一次。 */
        auto SetUseLease(Prism::Foundation::GenerationUseLease Lease) noexcept -> void
        {
            UseLease_ = std::move(Lease);
        }

        /** @brief Accept 返回前标记握手与发布代码已退栈。 */
        auto FinishAccept() noexcept -> void
        { AcceptFinished_.store(true, std::memory_order_release); }

        /** @brief binding owner 请求关闭；只有 AcceptAttempt 终态后才安排退休。 */
        auto RequestOwnerRetirement() noexcept -> void
        {
            const auto Ready = DrainCoordinator_.SignalOwnerClose();
            if (Ready) RequestRetirement();
        }

        /** @brief 协议完成发布或显式 drain 后标记 AcceptAttempt 终态。 */
        auto CompleteAcceptAttempt() noexcept -> void
        {
            const auto Ready = DrainCoordinator_.SignalAcceptAttemptComplete();
            if (Ready) RequestRetirement();
        }

        /** @brief 任意线程请求协议根和 tracked carriers 关闭；不等待或清除实物。 */
        auto RequestClose() noexcept -> void
        {
            CloseRequested_.store(true, std::memory_order_release);
            const auto Root = Root_.load(std::memory_order_acquire);
            RecordDrainAttemptFailure(Resources_.Close(Root));
        }

        /** @brief 将未完成实物保留到同一个 ClosingStorage，供拥有者继续排空。 */
        auto RetainForOwnerRetry() noexcept -> void
        {
            if (!Retired_.load(std::memory_order_acquire))
            {
                Storage_->Retain(this->shared_from_this());
            }
        }

        /** @brief 未完成时把同一票据交给原 executor 的 ClosingStorage 重试。 */
        auto RetainAndRetry() noexcept -> void
        {
            Storage_->Retain(this->shared_from_this());
            RequestRetirement();
        }

        /** @brief 原 executor 重试入口；一次失败不会在协程内无界循环。 */
        auto RequestRetirement() noexcept -> void override
        {
            if (Retired_.load(std::memory_order_acquire)) return;
            auto State = RetrySchedule_.load(std::memory_order_acquire);
            for (;;)
            {
                if (Retired_.load(std::memory_order_acquire)) return;
                const bool AlreadyScheduled = (State & RetryScheduledFlag) != 0U;
                const auto Desired = AlreadyScheduled
                    ? static_cast<std::uint8_t>(State | RetryRequestedFlag)
                    : RetryScheduledFlag;
                if (Desired == State) return;
                if (RetrySchedule_.compare_exchange_weak(State, Desired,
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    if (!AlreadyScheduled) PostRetryCommand();
                    return;
                }
            }
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_.load(std::memory_order_acquire);
        }

        /** @brief 返回关闭和真实排空过程的首个完整错误，不包含握手业务拒绝。 */
        [[nodiscard]] auto DrainFailure() const noexcept -> Prism::Fault::Failure
        {
            return DrainFailure_.Load();
        }

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            return !Reclaimer_ || !Reclaimer_->CanDispatch();
        }

        /** @brief close root，再逐层 drain root activity、Connection/replay 与原 inbound。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<ProviderRetirementResult> override
        {
            const auto Self = this->shared_from_this();
            if (Retired_.load(std::memory_order_acquire))
            {
                const auto Failure = DrainFailure_.Load();
                if (Failure.Failed()) co_return std::unexpected(Failure);
                co_return ProviderRetirementResult{};
            }
            std::optional<Detail::ProviderSessionDrainCoordinator::DrainTurn> DrainOwner;
            while (!DrainOwner)
            {
                auto Acquired = co_await DrainCoordinator_.Acquire();
                if (!Acquired) co_return std::unexpected(Acquired.error());
                if (Acquired->IsOwner()) DrainOwner.emplace(std::move(*Acquired));
                else
                {
                    const auto Joined = Acquired->Outcome();
                    if (!Joined) co_return std::unexpected(Joined.error());
                    if (Retired_.load(std::memory_order_acquire))
                        co_return ProviderRetirementResult{};
                }
            }

            ProviderRetirementResult Outcome;
            try
            {
                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                RequestClose();
                const auto Root = Root_.load(std::memory_order_acquire);
                const auto Result = co_await Resources_.Drain(Root, Executor_);
                RecordDrainAttemptFailure(Result.Error);
                const bool PhysicallyReady = Result.Complete && PhysicalRetirementReady();
                if (PhysicallyReady) ReleaseResources();
                else if (Result.Error.Code != Prism::Fault::Code::Canceled)
                    RecordDrainFailure({Prism::Fault::Code::Blocked});
                if (Retired_.load(std::memory_order_acquire)) Storage_->Collect();
                else
                {
                    Storage_->Retain(Self);
                    if (!IsRetryScheduled())
                    {
                        RequestRetirement();
                    }
                }
                const auto Failure = DrainFailure_.Load();
                if (Failure.Failed()) Outcome = std::unexpected(Failure);
                else if (Result.Error.Failed() &&
                    !(Result.Error.Code == Prism::Fault::Code::Canceled && PhysicallyReady))
                {
                    Outcome = std::unexpected(Result.Error);
                }
            }
            catch (...)
            {
                const auto Failure = Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
                RecordDrainFailure(Failure);
                Outcome = std::unexpected(DrainFailure_.Load());
            }
            DrainOwner->SetResult(Outcome);
            co_return Outcome;
        }

        /** @brief 清理之前同时核验 root 与每个真实 transmission 的物理 receipt。 */
        [[nodiscard]] auto PhysicalRetirementReady() const noexcept -> bool
        {
            if (!AcceptFinished_.load(std::memory_order_acquire))
            {
                return false;
            }
            return Resources_.IsRetired(Root_.load(std::memory_order_acquire));
        }

    private:
        auto OnMuxRootSessionAttached() noexcept -> void override
        {
            if (CloseRequested_.load(std::memory_order_acquire))
            {
                Resources_.CloseRootOnly(Root_.load(std::memory_order_acquire));
            }
        }

        auto RetainMuxRootTicket() noexcept -> void override
        {
            RequestClose();
            Storage_->Retain(this->shared_from_this());
            if (DrainCoordinator_.SignalMuxRootRetirement()) RequestRetirement();
        }



        struct RetryCommand final
        {
            Pointer Owner;
            auto operator()() noexcept -> void { Owner->StartRetry(); }
        };

        struct RetryCompletion final
        {
            Pointer Owner;
            auto operator()(std::exception_ptr Exception,
                ProviderRetirementResult Result) noexcept -> void
            {
                if (Exception)
                {
                    Owner->RecordDrainFailure(Prism::Contract::InboundAdmission::ExceptionFailure(
                        std::move(Exception)));
                }
                else if (!Result)
                {
                    Owner->RecordDrainAttemptFailure(Result.error());
                }
                if (Owner->Retired_.load(std::memory_order_acquire))
                {
                    Owner->Storage_->Collect();
                }
                else
                {
                    Owner->Storage_->Retain(Owner);
                }
                Owner->FinishScheduledRetry();
            }
        };

        static constexpr std::uint8_t RetryScheduledFlag{0x01U};
        static constexpr std::uint8_t RetryRequestedFlag{0x02U};

        [[nodiscard]] auto IsRetryScheduled() const noexcept -> bool
        {
            return (RetrySchedule_.load(std::memory_order_acquire) & RetryScheduledFlag) != 0U;
        }

        /** @brief 只由成功认领 schedule 位的调用者投递；失败保留 owner 与 typed cause。 */
        auto PostRetryCommand() noexcept -> void
        {
            const auto Self = this->shared_from_this();
            const auto Posted = Reclaimer_->Post(RetryCommand{Self});
            if (!Posted)
            {
                ClearRetrySchedule();
                Storage_->Retain(Self);
                RecordDrainFailure(Posted.error());
            }
        }

        auto ClearRetrySchedule() noexcept -> void
        {
            auto State = RetrySchedule_.load(std::memory_order_acquire);
            while ((State & RetryScheduledFlag) != 0U)
            {
                const auto Desired = static_cast<std::uint8_t>(State & ~RetryScheduledFlag);
                if (RetrySchedule_.compare_exchange_weak(State, Desired,
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    return;
                }
            }
        }

        /** @brief 用同一原子状态交接完成中的 retry 请求，避免清零和采样之间丢唤醒。 */
        auto FinishScheduledRetry() noexcept -> void
        {
            auto State = RetrySchedule_.load(std::memory_order_acquire);
            for (;;)
            {
                const bool Retry = !Retired_.load(std::memory_order_acquire) &&
                    (State & RetryRequestedFlag) != 0U;
                const auto Desired = Retry ? RetryScheduledFlag : std::uint8_t{0U};
                if (RetrySchedule_.compare_exchange_weak(State, Desired,
                        std::memory_order_acq_rel, std::memory_order_acquire))
                {
                    if (Retry) PostRetryCommand();
                    return;
                }
            }
        }

        auto ReleaseResources() noexcept -> void
        {
            bool Expected = false;
            if (!Releasing_.compare_exchange_strong(Expected, true, std::memory_order_acq_rel))
            {
                return;
            }
            Root_.store({}, std::memory_order_release);
            RootGenerationUseLease_ = {};
            UseLease_ = {};
            Resources_.Release();
            RootSlot_.reset();
            Material_.store({}, std::memory_order_release);
            Retired_.store(true, std::memory_order_release);
        }

        auto StartRetry() noexcept -> void
        {
            if (Retired_.load(std::memory_order_acquire))
            {
                FinishScheduledRetry();
                return;
            }
            const auto Self = this->shared_from_this();
            try
            {
                Net::co_spawn(Executor_, Self->Drain(), RetryCompletion{Self});
            }
            catch (...)
            {
                ClearRetrySchedule();
                RecordDrainFailure(Prism::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
                Storage_->Retain(Self);
            }
        }

        ProviderSessionResources Resources_;
        std::atomic<std::shared_ptr<const Material>> Material_;
        Prism::Foundation::GenerationUseLease UseLease_;
        Net::any_io_executor Executor_;
        std::shared_ptr<Prism::Executor::ContextOwner> Context_;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Prism::Executor::ExecutorReclaimer> Reclaimer_;
        Prism::Fault::FailureState Failure_;
        Prism::Fault::FailureState DrainFailure_;
        std::atomic<bool> AcceptFinished_{false}, CloseRequested_{false};
        Detail::ProviderSessionDrainCoordinator DrainCoordinator_;
        std::atomic<std::uint8_t> RetrySchedule_{0U};
        std::atomic<bool> Releasing_{false};
        std::atomic<bool> Retired_{false};
    };
}

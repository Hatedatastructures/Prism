/**
 * @file ProviderSessionRetirement.hpp
 * @brief Trojan、VLESS 与 VMess provider binding 的真实 session owner。
 */
#pragma once

#include <Preview/Contract/Ingress/DataPlane.hpp>
#include <Preview/Contract/Ingress/InboundAdmission.hpp>
#include <Preview/Foundation/Executor/ClosingStorage.hpp>
#include <Preview/Foundation/Executor/ContextOwner.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Protocols/Common/ProviderMuxRootState.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <exception>
#include <expected>
#include <memory>
#include <optional>
#include <utility>

namespace Preview::Protocols
{
    namespace Net = boost::asio;
    using ProviderRetirementResult = std::expected<void, Preview::Fault::Failure>;

    /**
     * @brief 一个已开始的协议接入及已发布根 owner 的同一失败退休票据。
     * @details 成功发布后保留真实传输、协议根、材料与 generation lease；失败时在原
     *          executor 重试。业务 SessionFailure、DrainFailure 与物理 IsRetired 分开保存，
     *          坏凭据不会污染后续准入或把已完成的物理退休变成失败。
     */
    template<class Material>
    class ProviderSessionRetirement final
        : public Preview::Executor::ClosingResource,
          public ProviderMuxRootState,
          public std::enable_shared_from_this<ProviderSessionRetirement<Material>>
    {
    public:
        using Pointer = std::shared_ptr<ProviderSessionRetirement>;

        ProviderSessionRetirement(Preview::SharedTransmission Inbound,
            std::shared_ptr<const Material> MaterialValue,
            Preview::Foundation::GenerationUseLease UseLease)
            : Material_(std::move(MaterialValue)), UseLease_(std::move(UseLease)),
              Executor_(Inbound->Executor()), Context_(Preview::Executor::ContextOwner::Find(Executor_)),
              Storage_(Preview::Executor::ContextOwner::Storage(Executor_)),
              Reclaimer_(std::make_shared<Preview::Executor::ExecutorReclaimer>(
                  Net::make_strand(Executor_)))
        {
            Tracked_[0].store(std::move(Inbound), std::memory_order_release);
            TrackedCount_.store(1U, std::memory_order_release);
        }

        ProviderSessionRetirement(const ProviderSessionRetirement&) = delete;
        auto operator=(const ProviderSessionRetirement&) -> ProviderSessionRetirement& = delete;

        /** @brief 在握手后登记 Connection 或 replay；固定槽在任何协议 I/O 前已建好。 */
        [[nodiscard]] auto Track(const Preview::SharedTransmission& Transport)
            -> std::expected<void, Preview::Fault::Failure>
        {
            if (!Transport)
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            const auto Count = TrackedCount_.load(std::memory_order_acquire);
            for (std::size_t Index = 0; Index < Count; ++Index)
            {
                if (Tracked_[Index].load(std::memory_order_acquire) == Transport)
                {
                    return {};
                }
            }
            if (Count >= Tracked_.size())
            {
                return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::ResourceUnavailable});
            }
            Tracked_[Count].store(Transport, std::memory_order_release);
            TrackedCount_.store(Count + 1U, std::memory_order_release);
            if (CloseRequested_.load(std::memory_order_acquire))
            {
                CloseTransmission(Transport);
            }
            return {};
        }

        /** @brief 在 Admission::Admit 前保存与运行时共享的 transport/root 实物。 */
        [[nodiscard]] auto Publish(const Preview::Contract::ProtocolDataPlane& Plane)
            -> std::expected<void, Preview::Fault::Failure>
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
                CloseRoot(Root_.load(std::memory_order_acquire));
            }
            return {};
        }

        /** @brief 记录完整首因；Native 不与任何 cleanup failure 拼接。 */
        auto RecordFailure(Preview::Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Failed())
            {
                Failure_.TrySet(std::move(Failure));
            }
        }

        /** @brief 返回本次接入/协议运行首因；不表示绑定关闭或物理退休失败。 */
        [[nodiscard]] auto SessionFailure() const noexcept -> Preview::Fault::Failure
        {
            return Failure_.Load();
        }

        /** @brief 只记录关闭、排空或 executor 退休本身的失败。 */
        auto RecordDrainFailure(Preview::Fault::Failure Failure) noexcept -> void
        {
            if (Failure.Failed()) DrainFailure_.TrySet(std::move(Failure));
        }

        /** @brief 绑定唯一 generation-use lease；只在协议 I/O 前调用一次。 */
        auto SetUseLease(Preview::Foundation::GenerationUseLease Lease) noexcept -> void
        {
            UseLease_ = std::move(Lease);
        }

        /** @brief Accept 返回前标记握手与发布代码已退栈。 */
        auto FinishAccept() noexcept -> void
        {
            AcceptFinished_.store(true, std::memory_order_release);
        }

        /** @brief 任意线程请求协议根和 tracked carriers 关闭；不等待或清除实物。 */
        auto RequestClose() noexcept -> void
        {
            CloseRequested_.store(true, std::memory_order_release);
            CloseRoot(Root_.load(std::memory_order_acquire));
            const auto Count = TrackedCount_.load(std::memory_order_acquire);
            for (std::size_t Index = Count; Index > 0U; --Index)
            {
                CloseTransmission(Tracked_[Index - 1U].load(std::memory_order_acquire));
            }
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
                Storage_->Retain(Self);
                RecordDrainFailure(Posted.error());
            }
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Retired_.load(std::memory_order_acquire);
        }

        /** @brief 返回关闭和真实排空过程的首个完整错误，不包含握手业务拒绝。 */
        [[nodiscard]] auto DrainFailure() const noexcept -> Preview::Fault::Failure
        {
            return DrainFailure_.Load();
        }

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        {
            return !Reclaimer_ || !Reclaimer_->CanDispatch();
        }

        /** @brief close root，再逐层 drain root activity、Connection/replay 与原 inbound。 */
        [[nodiscard]] auto Drain() -> Net::awaitable<ProviderRetirementResult>
        {
            if (Retired_.load(std::memory_order_acquire))
            {
                const auto Failure = DrainFailure_.Load();
                if (Failure.Failed())
                {
                    co_return std::unexpected(Failure);
                }
                co_return ProviderRetirementResult{};
            }
            bool Idle = false;
            if (!Running_.compare_exchange_strong(Idle, true, std::memory_order_acq_rel))
            {
                RecordDrainFailure({Preview::Fault::Code::Blocked});
                Storage_->Retain(this->shared_from_this());
                co_return std::unexpected(DrainFailure_.Load());
            }

            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            RequestClose();
            const auto Result = co_await DrainResources(this->shared_from_this());
            RecordDrainFailure(Result.Error);
            if (Result.Complete && PhysicalRetirementReady())
            {
                ReleaseResources();
            }
            else
            {
                RecordDrainFailure({Preview::Fault::Code::Blocked});
            }
            Running_.store(false, std::memory_order_release);
            if (Retired_.load(std::memory_order_acquire))
            {
                Storage_->Collect();
            }
            else
            {
                Storage_->Retain(this->shared_from_this());
                RequestRetirement();
            }
            const auto Failure = DrainFailure_.Load();
            if (Failure.Failed())
            {
                co_return std::unexpected(Failure);
            }
            co_return ProviderRetirementResult{};
        }

        /** @brief 清理之前同时核验 root 与每个真实 transmission 的物理 receipt。 */
        [[nodiscard]] auto PhysicalRetirementReady() const noexcept -> bool
        {
            if (!AcceptFinished_.load(std::memory_order_acquire))
            {
                return false;
            }
            const auto Root = Root_.load(std::memory_order_acquire);
            if (Root && !RootRetired(Root))
            {
                return false;
            }
            const auto Count = TrackedCount_.load(std::memory_order_acquire);
            for (std::size_t Index = 0; Index < Count; ++Index)
            {
                const auto Transport = Tracked_[Index].load(std::memory_order_acquire);
                if (!Transport || !Transport->Activity() || !Transport->Activity()->IsRetired())
                {
                    return false;
                }
            }
            return true;
        }

    private:
        auto OnMuxRootSessionAttached() noexcept -> void override
        {
            if (CloseRequested_.load(std::memory_order_acquire))
            {
                CloseRoot(Root_.load(std::memory_order_acquire));
            }
        }

        auto RetainMuxRootTicket() noexcept -> void override
        {
            RequestClose();
            Storage_->Retain(this->shared_from_this());
            RequestRetirement();
        }

        struct DrainResult final
        {
            bool Complete{true};
            Preview::Fault::Failure Error{};
        };

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
                Owner->Scheduled_.store(false, std::memory_order_release);
                if (Exception)
                {
                    Owner->RecordDrainFailure(Preview::Contract::InboundAdmission::ExceptionFailure(
                        std::move(Exception)));
                }
                else if (!Result)
                {
                    Owner->RecordDrainFailure(Result.error());
                }
                if (Owner->Retired_.load(std::memory_order_acquire))
                {
                    Owner->Storage_->Collect();
                }
                else
                {
                    Owner->Storage_->Retain(Owner);
                }
            }
        };

        static auto PreserveFailure(Preview::Fault::Failure& Primary,
            const Preview::Fault::Failure& Secondary) noexcept -> void
        {
            if (Primary.Succeeded() && Secondary.Failed())
            {
                Primary = Secondary;
            }
        }

        [[nodiscard]] static auto RootRetired(const std::shared_ptr<RootOwner>& Root) noexcept -> bool
        {
            if (Root->Datagram)
            {
                const auto Activity = Root->Datagram->Activity();
                return Activity && Activity->IsRetired();
            }
            if (Root->Mux)
            {
                const auto Activity = Root->Mux->Activity();
                return Root->Mux->IsRetired() && Activity && Activity->IsRetired();
            }
            return true;
        }

        static auto CloseRoot(const std::shared_ptr<RootOwner>& Root) noexcept -> void
        {
            if (!Root)
            {
                return;
            }
            if (Root->Datagram)
            {
                Root->Datagram->Cancel();
                Root->Datagram->Close();
            }
            if (Root->Mux)
            {
                Root->Mux->Cancel();
                Root->Mux->Close();
            }
        }

        auto CloseTransmission(const Preview::SharedTransmission& Transport) noexcept -> void
        {
            if (!Transport)
            {
                return;
            }
            const auto Cancelled = Transport->Cancel();
            if (!Cancelled)
            {
                RecordDrainFailure(Cancelled.error());
            }
            const auto Closed = Transport->Close();
            if (!Closed)
            {
                RecordDrainFailure(Closed.error());
            }
        }

        [[nodiscard]] static auto DrainActivity(
            const std::shared_ptr<Preview::Contract::CarrierActivity>& Activity)
            -> Net::awaitable<DrainResult>
        {
            DrainResult Result;
            if (!Activity)
            {
                Result.Complete = false;
                Result.Error = {Preview::Fault::Code::Blocked};
                co_return Result;
            }
            Activity->Seal();
            try
            {
                const auto Drained = co_await Activity->Drain();
                if (!Drained)
                {
                    Result.Error = Drained.error();
                }
            }
            catch (...)
            {
                Result.Error = Preview::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
            }
            Result.Complete = Activity->IsRetired();
            co_return Result;
        }

        [[nodiscard]] static auto DrainRoot(const std::shared_ptr<RootOwner>& Root)
            -> Net::awaitable<DrainResult>
        {
            DrainResult Result;
            if (!Root)
            {
                co_return Result;
            }
            if (Root->Datagram)
            {
                const auto Activity = Root->Datagram->Activity();
                const auto Drained = co_await DrainActivity(Activity);
                Result.Complete = Drained.Complete;
                Result.Error = Drained.Error;
            }
            if (Root->Mux)
            {
                const auto Activity = Root->Mux->Activity();
                const auto Drained = co_await DrainActivity(Activity);
                Result.Complete = Result.Complete && Drained.Complete && Root->Mux->IsRetired();
                PreserveFailure(Result.Error, Drained.Error);
                if (!Root->Mux->IsRetired())
                {
                    PreserveFailure(Result.Error,
                        Preview::Fault::Failure{Preview::Fault::Code::Blocked});
                }
            }
            co_return Result;
        }

        [[nodiscard]] static auto DrainTransmission(
            const Preview::SharedTransmission& Transport) -> Net::awaitable<DrainResult>
        {
            DrainResult Result;
            if (!Transport)
            {
                Result.Complete = false;
                Result.Error = {Preview::Fault::Code::Blocked};
                co_return Result;
            }
            const auto Activity = Transport->Activity();
            if (!Activity)
            {
                Result.Complete = false;
                Result.Error = {Preview::Fault::Code::Blocked};
                co_return Result;
            }
            Activity->Seal();
            try
            {
                const auto Drained = co_await Activity->Drain();
                if (!Drained)
                {
                    Result.Error = Drained.error();
                }
            }
            catch (...)
            {
                Result.Error = Preview::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception());
            }
            Result.Complete = Activity->IsRetired();
            co_return Result;
        }

        [[nodiscard]] static auto DrainResources(const Pointer& Owner)
            -> Net::awaitable<DrainResult>
        {
            co_await Net::dispatch(Owner->Executor_, Net::use_awaitable);
            co_await Net::this_coro::throw_if_cancelled(false);
            DrainResult Result;
            const auto Root = Owner->Root_.load(std::memory_order_acquire);
            const auto RootResult = co_await DrainRoot(Root);
            Result.Complete = RootResult.Complete;
            Result.Error = RootResult.Error;
            const auto Count = Owner->TrackedCount_.load(std::memory_order_acquire);
            for (std::size_t Index = Count; Index > 0U; --Index)
            {
                const auto Transport = Owner->Tracked_[Index - 1U].load(std::memory_order_acquire);
                if (Root && Transport == Root->Transport)
                {
                    continue;
                }
                const auto TransportResult = co_await DrainTransmission(Transport);
                Result.Complete = Result.Complete && TransportResult.Complete;
                PreserveFailure(Result.Error, TransportResult.Error);
            }
            co_return Result;
        }

        auto ReleaseResources() noexcept -> void
        {
            bool Expected = false;
            if (!Releasing_.compare_exchange_strong(Expected, true, std::memory_order_acq_rel))
            {
                return;
            }
            Root_.store({}, std::memory_order_release);
            for (auto& Transport : Tracked_)
            {
                Transport.store({}, std::memory_order_release);
            }
            TrackedCount_.store(0U, std::memory_order_release);
            RootSlot_.reset();
            RootGenerationUseLease_ = {};
            Material_.store({}, std::memory_order_release);
            UseLease_ = {};
            Retired_.store(true, std::memory_order_release);
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
                Net::co_spawn(Executor_, Self->Drain(), RetryCompletion{Self});
            }
            catch (...)
            {
                Scheduled_.store(false, std::memory_order_release);
                RecordDrainFailure(Preview::Contract::InboundAdmission::ExceptionFailure(
                    std::current_exception()));
                Storage_->Retain(Self);
            }
        }

        std::atomic<std::shared_ptr<const Material>> Material_;
        Preview::Foundation::GenerationUseLease UseLease_;
        Net::any_io_executor Executor_;
        std::shared_ptr<Preview::Executor::ContextOwner> Context_;
        std::shared_ptr<Preview::Executor::ClosingStorage> Storage_;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer_;
        std::array<std::atomic<Preview::SharedTransmission>, 4> Tracked_{};
        std::atomic<std::size_t> TrackedCount_{0U};
        Preview::Fault::FailureState Failure_;
        Preview::Fault::FailureState DrainFailure_;
        std::atomic<bool> AcceptFinished_{false};
        std::atomic<bool> CloseRequested_{false};
        std::atomic<bool> Running_{false};
        std::atomic<bool> Scheduled_{false};
        std::atomic<bool> Releasing_{false};
        std::atomic<bool> Retired_{false};
    };
}

/** @file RootSession.hpp @brief XUDP 根会话的 typed Run、关联与 writer 退休边界。 */
#pragma once

#include <Preview/Protocols/Vless/Xudp/Association.hpp>
#include <Preview/Lifecycle/DrainReservation.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

#include <expected>
#include <chrono>
#include <memory>
#include <utility>

namespace Preview::Vless::Xudp
{
    using RunResult = std::expected<void, Preview::Fault::Failure>;

    /** @brief 登记 reader、执行域及子任务的首个完整失败。 */
    inline auto PreserveRunFailure(State& Root, Preview::Fault::Failure Failure) -> void
    {
        Root.RecordFailure(std::move(Failure));
    }

    [[nodiscard]] inline auto CurrentRunResult(const State& Root) -> RunResult
    {
        if (Root.Failure->First.Failed())
        {
            return std::unexpected(Root.Failure->First);
        }
        return {};
    }

    class FrameCompletion final
    {
    public:
        explicit FrameCompletion(std::shared_ptr<State> Root) : Root_(std::move(Root)) {}
        ~FrameCompletion() { (void)Root_->FrameFinished.try_send(boost::system::error_code{}); }

    private:
        std::shared_ptr<State> Root_;
    };

    /** @brief reader 异常交给 TaskRegistry 的 typed failure owner，不在热循环捕获普通异常。 */
    inline auto RunFrames(std::shared_ptr<State> Root) -> Net::awaitable<void>
    {
        FrameCompletion Completion(Root);
        while (!Root->Stopping.load())
        {
            auto Packet = co_await ReadFrame(Root->Inbound);
            if (!Packet)
            {
                const auto Failure = Packet.error();
                if (Failure.Code != Preview::Fault::Code::Eof || Failure.Native)
                    PreserveRunFailure(*Root, Failure);
                break;
            }
            const auto Found = Root->Associations.find(Packet->SessionId);
            if (Packet->StatusValue == Status::End)
            {
                if (Found != Root->Associations.end())
                {
                    const auto Retiring = Found->second;
                    Retiring->Cancel();
                    Retiring->RetiringNext = std::move(Root->RetiringAssociations);
                    Root->RetiringAssociations = Retiring;
                    Root->Associations.erase(Found);
                }
                continue;
            }
            if (Packet->StatusValue == Status::KeepAlive) continue;
            if (Found == Root->Associations.end())
            {
                if (Packet->StatusValue != Status::New || !Packet->HasTarget)
                {
                    Preview::Lifecycle::TaskRequest Request{
                        .Context = Preview::Lifecycle::FromParent(Root->Metadata.TaskIdentity),
                        .StartOnSubmit = true};
                    Request.Context.StreamId = Preview::StreamId{Packet->SessionId};
                    (void)Root->Children->SpawnTracked(
                        std::move(Request), RejectAssociation(Root, Packet->SessionId));
                    continue;
                }
                if (!StartAssociation(Root, std::move(*Packet))) break;
            }
            else if (!Found->second->Incoming.try_send(
                         boost::system::error_code{}, std::move(*Packet)))
            {
                Found->second->Cancel();
            }
        }
        Root->Stop();
    }

    /** @brief 先退 reader、关联和 writer 的真实任务，再保存底层载体物理回执。 */
    inline auto DrainOwnedResources(const std::shared_ptr<State>& Root) -> Net::awaitable<void>
    {
        Root->CancelAssociationsOnExecutor();
        const auto Children = co_await Root->Children->Drain();
        if (!Children) PreserveRunFailure(*Root, Children.error());
        const auto Loops = co_await Root->Loops->Drain();
        if (!Loops) PreserveRunFailure(*Root, Loops.error());
        const auto Writes = co_await Root->Writes->Drain();
        if (!Writes) PreserveRunFailure(*Root, Writes.error());
        if (TaskScopePhysicallyRetired(Root->Children) &&
            TaskScopePhysicallyRetired(Root->Loops))
        {
            const bool Associations = co_await RetireAssociationOwners(Root);
            if (!Associations) PreserveRunFailure(*Root, {Preview::Fault::Code::Blocked});
        }
        else PreserveRunFailure(*Root, {Preview::Fault::Code::Blocked});

        const auto InboundActivity = Root->Inbound ? Root->Inbound->Activity() : nullptr;
        if (!InboundActivity)
        {
            PreserveRunFailure(*Root, {Preview::Fault::Code::Blocked});
            co_return;
        }
        const auto Carrier = co_await InboundActivity->Drain();
        if (!Carrier) PreserveRunFailure(*Root, Carrier.error());
        const bool CarrierRetired = InboundActivity->IsRetired();
        Root->CarrierRetired.store(CarrierRetired, std::memory_order_release);
        if (!CarrierRetired)
        {
            PreserveRunFailure(*Root, {Preview::Fault::Code::Blocked});
        }
    }

    inline auto WaitForDrainCompletion(const std::shared_ptr<State>& Root) -> Net::awaitable<void>
    {
        boost::system::error_code Error;
        co_await Root->DrainChanged.async_wait(
            Net::redirect_error(Net::use_awaitable, Error));
        if (Error && Error != Net::error::operation_aborted)
        {
            PreserveRunFailure(*Root,
                Preview::Fault::FromNative(static_cast<std::error_code>(Error)));
        }
    }

    inline auto SignalDrainCompletion(State& Root) noexcept -> void
    {
        Root.DrainInProgress = false;
        try
        {
            (void)Root.DrainChanged.cancel();
        }
        catch (const boost::system::system_error& Error)
        {
            PreserveRunFailure(Root, Preview::Fault::FromNative(
                static_cast<std::error_code>(Error.code())));
        }
    }

    [[nodiscard]] inline auto FinishPhysicalRetirement(const std::shared_ptr<State>& Root)
        -> Net::awaitable<RunResult>;

    inline auto DrainActivityResources(const std::shared_ptr<State>& Root)
        -> Net::awaitable<RunResult>
    {
        const auto Lifetime = co_await Root->Lifetime.Drain();
        if (!Lifetime) PreserveRunFailure(*Root, Lifetime.error());
        if (Root->Lifetime.Active() != 0U)
        {
            PreserveRunFailure(*Root, {Preview::Fault::Code::Blocked});
            co_return CurrentRunResult(*Root);
        }
        if (!Root->ResourcesReleased.load(std::memory_order_acquire))
        {
            if (!Root->PhysicalRetirementReady()) co_await DrainOwnedResources(Root);
            co_return co_await FinishPhysicalRetirement(Root);
        }
        co_return CurrentRunResult(*Root);
    }

    /** @brief 只凭任务计数、关联关闭、Run reservation 与 carrier receipt 释放资源。 */
    [[nodiscard]] inline auto FinishPhysicalRetirement(const std::shared_ptr<State>& Root)
        -> Net::awaitable<RunResult>
    {
        if (Root->Cancelled.load(std::memory_order_acquire) && Root->Failure->First.Succeeded())
        {
            PreserveRunFailure(*Root, {Preview::Fault::Code::Canceled});
        }
        if (!Root->PhysicalRetirementReady())
        {
            PreserveRunFailure(*Root, {Preview::Fault::Code::Blocked});
        }
        else
        {
            const bool Released = co_await Root->ReleaseResources();
            if (!Released) PreserveRunFailure(*Root, {Preview::Fault::Code::Blocked});
        }
        co_return CurrentRunResult(*Root);
    }

    /** @brief Run 自己排空资源后归还 reservation，再确认 generation lease 可释放。 */
    inline auto DrainRunResources(
        const std::shared_ptr<State>& Root,
        Preview::Lifecycle::DrainReservation Reservation) -> Net::awaitable<RunResult>
    {
        co_await DrainOwnedResources(Root);
        if (Root->DrainInProgress)
        {
            Reservation.Transfer();
            Root->Lifetime.Leave();
            const auto Lifetime = co_await Root->Lifetime.Drain();
            if (!Lifetime) PreserveRunFailure(*Root, Lifetime.error());
            co_await WaitForDrainCompletion(Root);
            co_return CurrentRunResult(*Root);
        }
        Root->DrainInProgress = true;
        Root->DrainChanged.expires_at(std::chrono::steady_clock::time_point::max());
        Reservation.Transfer();
        Root->Lifetime.Leave();
        const auto Lifetime = co_await Root->Lifetime.Drain();
        if (!Lifetime) PreserveRunFailure(*Root, Lifetime.error());
        const auto Result = co_await FinishPhysicalRetirement(Root);
        SignalDrainCompletion(*Root);
        co_return Result;
    }

    class RootSession final : public Preview::Contract::MuxSession
    {
        class SessionActivity final : public Preview::Contract::CarrierActivity
        {
        public:
            explicit SessionActivity(std::shared_ptr<State> Value) : State_(std::move(Value)) {}

            /** @brief 封止 XUDP 的 frame、association、writer 与 Run reservation。 */
            auto Seal() noexcept -> void override
            {
                State_->Lifetime.Seal();
                State_->Loops->Seal();
                State_->Children->Seal();
                State_->Writes->Seal();
            }

            [[nodiscard]] auto Executor() const -> Net::any_io_executor override
            {
                return State_->Executor;
            }

            [[nodiscard]] auto IsRetired() const noexcept -> bool override
            {
                return State_->ResourcesReleased.load(std::memory_order_acquire) &&
                    State_->CarrierRetired.load(std::memory_order_acquire) &&
                    State_->Lifetime.Active() == 0U && !State_->Lifetime.IsBlocked() &&
                    TaskScopePhysicallyRetired(State_->Children) &&
                    TaskScopePhysicallyRetired(State_->Loops) &&
                    TaskScopePhysicallyRetired(State_->Writes);
            }

            /** @brief 活动 Run 退栈后再统一 drain；失败保留同一 owner 供重试。 */
            [[nodiscard]] auto Drain() -> Net::awaitable<RunResult> override
            {
                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                Seal();
                State_->Stop();
                co_await Net::dispatch(State_->Executor, Net::use_awaitable);
                if (State_->DrainInProgress)
                {
                    co_await WaitForDrainCompletion(State_);
                    co_return CurrentRunResult(*State_);
                }
                State_->DrainInProgress = true;
                State_->DrainChanged.expires_at(std::chrono::steady_clock::time_point::max());
                const auto Result = co_await DrainActivityResources(State_);
                SignalDrainCompletion(*State_);
                co_return Result;
            }

        private:
            std::shared_ptr<State> State_;
        };

    public:
        RootSession(Preview::SharedTransmission Inbound,
                    Preview::Protocols::DatagramBinding Binding,
                    std::shared_ptr<Preview::Foundation::GenerationUseState> UseState)
            : State_(std::make_shared<State>(std::move(Inbound), std::move(Binding),
                  std::move(UseState))),
              Activity_(std::make_shared<SessionActivity>(State_))
        {
        }

        ~RootSession() override { Close(); }

        /**
         * @brief 接管账户与代次租约，保留首个完整失败并等待 XUDP 实体资源退栈。
         * @details GenerationUseState 必须由请求携带；本根只获取一次，直到
         *          读帧循环、关联子任务、回包 writer 和底层载体都成功排空后才释放。
         */
        [[nodiscard]] auto Run(Preview::Contract::MuxRootRequest Request)
            -> Net::awaitable<RunResult> override
        {
            const auto Root = State_;
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            co_await Net::dispatch(Root->Executor, Net::use_awaitable);
            if (Root->Started.exchange(true))
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
            }
            if (Root->ResourcesReleased.load(std::memory_order_acquire))
            {
                co_return std::unexpected(
                    Preview::Fault::Failure{Preview::Fault::Code::Canceled});
            }
            if (!Request.GenerationUseState ||
                Request.GenerationUseState != Root->RequiredGenerationUseState)
            {
                co_return co_await FailAndDrain(
                    {Preview::Fault::Code::InvalidArgument});
            }
            auto Generation = Root->RequiredGenerationUseState->Acquire();
            if (!Generation) co_return co_await FailAndDrain(Generation.error());
            Root->GenerationLease = std::move(*Generation);
            if (!Root->Lifetime.Enter())
            {
                co_return co_await FailAndDrain({Preview::Fault::Code::Canceled});
            }
            Preview::Lifecycle::DrainReservation Lifetime(Root->Lifetime);
            Root->Lease = std::move(Request.Lease);
            Root->Admission = Root->Lease.Streams();
            Root->Metadata = std::move(Request.Metadata);
            Root->Output->BindIdentity(Root->Metadata.TaskIdentity);

            Preview::Lifecycle::TaskRequest Loop{
                .Context = Preview::Lifecycle::FromParent(Root->Metadata.TaskIdentity),
                .StartOnSubmit = true};
            const auto Weak = std::weak_ptr<State>(Root);
            Loop.Cancel = [Weak]
            {
                if (const auto Owner = Weak.lock()) Owner->Stop();
            };
            bool FrameStarted = false;
            if (!Root->Stopping.load())
            {
                const auto Frame = Root->Loops->SpawnTracked(
                    std::move(Loop), RunFrames(Root));
                if (!Frame)
                {
                    PreserveRunFailure(*Root, Frame.error());
                    Root->Stop();
                }
                else
                {
                    FrameStarted = true;
                }
            }

            if (FrameStarted)
            {
                boost::system::error_code CompletionError;
                co_await Root->FrameFinished.async_receive(
                    Net::redirect_error(Net::use_awaitable, CompletionError));
                if (CompletionError)
                {
                    PreserveRunFailure(*Root, Preview::Fault::FromNative(
                        static_cast<std::error_code>(CompletionError)));
                }
            }
            Root->Stop();
            co_return co_await DrainRunResources(Root, std::move(Lifetime));
        }

        [[nodiscard]] auto Activity() const
            -> std::shared_ptr<Preview::Contract::CarrierActivity> override
        {
            return Activity_;
        }

        /** @brief 独立回报 XUDP 全部实体活动与底层载体均已退栈。 */
        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        {
            return Activity_->IsRetired();
        }

        auto Cancel() noexcept -> void override
        {
            Activity_->Seal();
            State_->Cancel();
        }

        auto Close() noexcept -> void override
        {
            Activity_->Seal();
            State_->Stop();
        }

    private:
        [[nodiscard]] auto FailAndDrain(Preview::Fault::Failure Failure)
            -> Net::awaitable<RunResult>
        {
            PreserveRunFailure(*State_, std::move(Failure));
            State_->Stop();
            const auto Drain = co_await Activity_->Drain();
            if (!Drain) PreserveRunFailure(*State_, Drain.error());
            co_return CurrentRunResult(*State_);
        }

        std::shared_ptr<State> State_;
        std::shared_ptr<SessionActivity> Activity_;
    };
}

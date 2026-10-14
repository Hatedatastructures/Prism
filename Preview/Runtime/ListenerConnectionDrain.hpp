/**
 * @file ListenerConnectionDrain.hpp
 * @brief listener admission 的关闭交付、Activity 排空和 quota owner。
 * @details Reservation 中的 worker admission receipt 跟随该 owner；未启动 task 需排空入站
 *          Activity，已进入 Session 的 task 还必须确认 Session 完整 Control/Active 终态。
 */

#pragma once

#include <Preview/Foundation/Executor/PreparedAction.hpp>
#include <Preview/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Preview/Foundation/Fault/FailureState.hpp>
#include <Preview/Runtime/ListenerConnectionGate.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>

#include <atomic>
#include <cstdint>
#include <exception>
#include <memory>
#include <system_error>
#include <utility>

namespace Preview::Runtime
{
    class Session;
}

namespace Preview::Runtime::Detail
{

    namespace Net = boost::asio;

    /** @brief admission task 的真实执行/排空状态，不由 TaskOutcome 猜测。 */
    struct SessionAdmissionState final
    {
        std::atomic<bool> Started{false};
        std::atomic<bool> Drained{false};
        std::atomic<bool> Terminal{false};
        std::atomic<std::shared_ptr<Preview::Runtime::Session>> SessionOwner{};
        Preview::Fault::FailureState TerminalFailure;

        auto RetainSession(std::shared_ptr<Preview::Runtime::Session> Owner) noexcept -> void
        { SessionOwner.store(std::move(Owner), std::memory_order_release); }

        auto ReleaseSession() noexcept -> void
        { SessionOwner.store({}, std::memory_order_release); }
    };

    /**
     * @brief 关闭交付后的 admission cleanup owner。
     * @details CloseAction 自身 Await 成功后才开始 Activity::Drain；已启动 Session
     *          还需观察完整 SessionAdmissionState，否则失败实物继续保留于 storage。
     */
    class ListenerConnectionDrain final : public Preview::Executor::ClosingResource,
                                          public std::enable_shared_from_this<ListenerConnectionDrain>
    {
    public:
        struct Options final
        {
            Preview::SharedTransmission Transport;
            std::shared_ptr<ListenerConnectionGate::Reservation> Reservation;
            std::shared_ptr<Preview::Executor::PreparedAction> CloseAction;
            std::shared_ptr<SessionAdmissionState> SessionState;
        };

        explicit ListenerConnectionDrain(Options Input)
            : Transport_(std::move(Input.Transport)), Reservation_(std::move(Input.Reservation)),
              CloseAction_(std::move(Input.CloseAction)), SessionState_(std::move(Input.SessionState)),
              Storage_(Transport_ ? Preview::Executor::ContextOwner::Storage(Transport_->Executor())
                                  : Preview::Executor::ClosingStorage::ProcessStorage())
        {
            if (Transport_)
                if (const auto Activity = Transport_->Activity())
                    Reclaimer_ = std::make_shared<Preview::Executor::ExecutorReclaimer>(Activity->Executor());
        }

        /** @brief 在真实 transport executor 启动排空；失败 owner 交给 ClosingStorage。 */
        auto Start() noexcept -> void
        {
            if (Retired_.load(std::memory_order_acquire) || HasTerminalSessionFailure()) return;
            StartOwner();
        }

        auto RequestRetirement() noexcept -> void override
        {
            if (Retired_.load(std::memory_order_acquire) || HasTerminalSessionFailure()) return;
            if (Blocked_.exchange(false, std::memory_order_acq_rel))
                Started_.store(false, std::memory_order_release);
            Start();
        }

        [[nodiscard]] auto IsRetired() const noexcept -> bool override
        { return Retired_.load(std::memory_order_acquire); }

        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        { return DispatchUnavailable_.load(std::memory_order_acquire); }

        /** @brief 首次进入 Session::Run；未启动任务的 cleanup 不等待伪造 Session 终态。 */
        auto MarkSessionStarted() noexcept -> void
        { if (SessionState_) SessionState_->Started.store(true, std::memory_order_release); }

        /** @brief 由实际 Run 协程保留 Session/Registration/Control/Active owner。 */
        auto RetainSession(std::shared_ptr<Preview::Runtime::Session> SessionOwner) noexcept -> void
        { if (SessionState_) SessionState_->RetainSession(std::move(SessionOwner)); }

        /** @brief Session Control delivery 与 Active Finalize 全成功后的正式确认。 */
        auto MarkSessionDrained() noexcept -> void
        {
            if (!SessionState_) return;
            SessionState_->Drained.store(true, std::memory_order_release);
            RequestRetirement();
        }

        /** @brief Session 协程已终态但未真实排空时发布失败并保留完整关闭 owner。 */
        auto MarkSessionTerminalFailure(Preview::Fault::Failure Error) noexcept -> void
        {
            if (SessionState_ && SessionState_->Drained.load(std::memory_order_acquire)) return;
            if (SessionState_)
            {
                SessionState_->TerminalFailure.TrySet(Error);
                SessionState_->Terminal.store(true, std::memory_order_release);
                Error = SessionState_->TerminalFailure.Load();
            }
            Storage_->Retain(shared_from_this());
            StartOwner();
            Block(Error);
        }

        /** @brief 在预构造 owner 上安装 Session 关闭交付与完整状态。 */
        auto ConfigureSession(std::shared_ptr<Preview::Executor::PreparedAction> CloseAction,
                              std::shared_ptr<SessionAdmissionState> SessionState) noexcept -> void
        {
            CloseAction_ = std::move(CloseAction);
            SessionState_ = std::move(SessionState);
        }

        [[nodiscard]] static auto Make(Options Input)
            -> std::shared_ptr<ListenerConnectionDrain>
        {
            return std::make_shared<ListenerConnectionDrain>(std::move(Input));
        }

    private:
        struct DispatchCompletion final
        {
            std::shared_ptr<ListenerConnectionDrain> Owner;
            std::uint64_t Generation{0};
            std::exception_ptr Error;
            bool Invoked{false};

            DispatchCompletion(std::shared_ptr<ListenerConnectionDrain> Value,
                               const std::uint64_t ValueGeneration) noexcept
                : Owner(std::move(Value)), Generation(ValueGeneration) {}
            DispatchCompletion(DispatchCompletion &&Other) noexcept
                : Owner(std::move(Other.Owner)), Generation(Other.Generation), Error(std::move(Other.Error)),
                  Invoked(Other.Invoked)
            {
            }
            ~DispatchCompletion() noexcept
            {
                if (!Owner) return;
                if (!Invoked) Owner->OnDispatchDropped(Generation);
                else Owner->OnDispatchCompleted(Generation, Error);
            }
            auto operator()(std::exception_ptr Value) noexcept -> void
            {
                Invoked = true;
                Error = std::move(Value);
            }
        };

        [[nodiscard]] auto HasTerminalSessionFailure() const noexcept -> bool
        {
            if (!SessionState_) return false;
            return SessionState_->Terminal.load(std::memory_order_acquire);
        }

        auto StartOwner() noexcept -> void
        {
            if (Retired_.load(std::memory_order_acquire) || Started_.exchange(true)) return;
            try
            {
                const auto Owner = shared_from_this();
                Storage_->Retain(Owner);
                if (!Transport_ || !Transport_->Activity())
                {
                    Block({Preview::Fault::Code::InvalidArgument});
                    return;
                }
                const auto Generation = DispatchGeneration_.fetch_add(1, std::memory_order_acq_rel) + 1U;
                Net::co_spawn(Transport_->Activity()->Executor(), Run(Owner),
                              DispatchCompletion(Owner, Generation));
            }
            catch (const std::system_error &Error)
            {
                const auto Failure = Preview::Fault::FromNative(Error.code());
                if (CanDispatch()) Block(Failure);
                else BlockDispatch(Failure);
            }
            catch (...)
            {
                const Preview::Fault::Failure Failure{Preview::Fault::Code::Blocked};
                if (CanDispatch()) Block(Failure);
                else BlockDispatch(Failure);
            }
        }

        static auto Run(std::shared_ptr<ListenerConnectionDrain> Owner) -> Net::awaitable<void>
        {
            try
            {
                co_await Net::this_coro::throw_if_cancelled(false);
                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                if (Owner->CloseAction_)
                {
                    const auto Submitted = Owner->CloseAction_->Submit();
                    if (!Submitted)
                    {
                        if (Owner->CloseAction_->IsDispatchUnavailable())
                            Owner->BlockDispatch(Submitted.error());
                        else Owner->Block(Submitted.error());
                        co_return;
                    }
                    const auto Delivered = co_await Owner->CloseAction_->Await();
                    if (!Delivered)
                    {
                        if (Owner->CloseAction_->IsDispatchUnavailable())
                            Owner->BlockDispatch(Delivered.error());
                        else Owner->Block(Delivered.error());
                        co_return;
                    }
                }
                else
                {
                    const auto Canceled = Owner->Transport_->Cancel();
                    const auto Closed = Owner->Transport_->Close();
                    if (!Canceled)
                    {
                        if (!Owner->CanDispatch()) Owner->BlockDispatch(Canceled.error());
                        else Owner->Block(Canceled.error());
                        co_return;
                    }
                    if (!Closed)
                    {
                        if (!Owner->CanDispatch()) Owner->BlockDispatch(Closed.error());
                        else Owner->Block(Closed.error());
                        co_return;
                    }
                }
                const auto Activity = Owner->Transport_->Activity();
                if (!Activity) { Owner->Block({Preview::Fault::Code::InvalidArgument}); co_return; }
                const auto Drained = co_await Activity->Drain();
                if (!Drained)
                {
                    if (!Owner->CanDispatch()) Owner->BlockDispatch(Drained.error());
                    else Owner->Block(Drained.error());
                    co_return;
                }
                if (Owner->HasTerminalSessionFailure())
                {
                    Owner->BlockTerminal(Owner->SessionState_->TerminalFailure.Load());
                    co_return;
                }
                if (Owner->SessionState_ && Owner->SessionState_->Started.load(std::memory_order_acquire) &&
                    !Owner->SessionState_->Drained.load(std::memory_order_acquire))
                {
                    Owner->WaitForSessionDrain();
                    if (Owner->SessionState_->Drained.load(std::memory_order_acquire))
                        Owner->RetryRequested_.store(true, std::memory_order_release);
                    co_return;
                }
                Owner->Completed_.store(true, std::memory_order_release);
            }
            catch (const std::system_error &Error)
            {
                const auto Failure = Preview::Fault::FromNative(Error.code());
                if (Owner->CanDispatch()) Owner->Block(Failure);
                else Owner->BlockDispatch(Failure);
            }
            catch (...)
            {
                const Preview::Fault::Failure Failure{Preview::Fault::Code::IoError};
                if (Owner->CanDispatch()) Owner->Block(Failure);
                else Owner->BlockDispatch(Failure);
            }
        }

        auto Block(Preview::Fault::Failure Error) noexcept -> void
        {
            if (Reservation_) Reservation_->BlockDrain();
            Failure_.TrySet(Error);
            Completed_.store(false, std::memory_order_release);
            Blocked_.store(true, std::memory_order_release);
            Started_.store(false, std::memory_order_release);
        }

        auto BlockDispatch(Preview::Fault::Failure Error) noexcept -> void
        {
            DispatchUnavailable_.store(true, std::memory_order_release);
            Storage_->Retain(shared_from_this());
            Block(Error);
        }

        auto BlockTerminal(Preview::Fault::Failure Error) noexcept -> void
        {
            Block(Error);
        }

        [[nodiscard]] auto CanDispatch() const noexcept -> bool
        {
            return Reclaimer_ && Reclaimer_->CanDispatch();
        }

        /** @brief Session 完整终态尚未发布时保留预约；这不是关闭失败。 */
        auto WaitForSessionDrain() noexcept -> void
        {
            Completed_.store(false, std::memory_order_release);
            Started_.store(false, std::memory_order_release);
        }

        auto OnDispatchDropped(const std::uint64_t Generation) noexcept -> void
        {
            if (Generation == DispatchGeneration_.load(std::memory_order_acquire) &&
                !Retired_.load(std::memory_order_acquire))
                BlockDispatch({Preview::Fault::Code::Blocked});
        }

        auto OnDispatchCompleted(const std::uint64_t Generation,
                                 const std::exception_ptr &Error) noexcept -> void
        {
            if (Generation != DispatchGeneration_.load(std::memory_order_acquire) ||
                Retired_.load(std::memory_order_acquire))
                return;
            if (Error)
            {
                try { std::rethrow_exception(Error); }
                catch (const std::system_error &Native)
                { Block(Preview::Fault::FromNative(Native.code())); }
                catch (...)
                { Block({Preview::Fault::Code::IoError}); }
                return;
            }
            if (!Completed_.load(std::memory_order_acquire))
            {
                if (RetryRequested_.exchange(false, std::memory_order_acq_rel)) RequestRetirement();
                return;
            }
            if (SessionState_) SessionState_->ReleaseSession();
            Retired_.store(true, std::memory_order_release);
            if (Reservation_) Reservation_->Release();
            Storage_->Collect();
        }

        Preview::SharedTransmission Transport_;
        std::shared_ptr<ListenerConnectionGate::Reservation> Reservation_;
        std::shared_ptr<Preview::Executor::PreparedAction> CloseAction_;
        std::shared_ptr<SessionAdmissionState> SessionState_;
        std::shared_ptr<Preview::Executor::ClosingStorage> Storage_;
        /** @brief 冷创建的原 Activity 执行域凭据，支持正式 io_context 与 strand 类型。 */
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer_;
        std::atomic<bool> Started_{false};
        std::atomic<bool> Completed_{false};
        std::atomic<bool> Blocked_{false};
        std::atomic<bool> DispatchUnavailable_{false};
        std::atomic<bool> Retired_{false};
        std::atomic<bool> RetryRequested_{false};
        std::atomic<std::uint64_t> DispatchGeneration_{0};
        Preview::Fault::FailureState Failure_;
    };

} // namespace Preview::Runtime::Detail

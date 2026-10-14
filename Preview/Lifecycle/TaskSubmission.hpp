/** @file TaskSubmission.hpp @brief 覆盖提交、启动与真实 completion 的唯一任务输入 owner。 */
#pragma once
#include <Preview/Lifecycle/TaskRegistryCommands.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/system/system_error.hpp>
#include <Preview/Foundation/Utility/TrafficSink.hpp>
#include <boost/asio/awaitable.hpp>
#include <exception>
#include <optional>
#include <system_error>
#include <type_traits>
namespace Preview::Lifecycle::Detail
{
    namespace Net = boost::asio;
    /** @brief Operation/reservation/Task 在身份发布、取消 hook 和 co_spawn 分配期间不移出本 owner。
     * @details co_spawn 只接管持有本 owner 的 runner；用户 Operation 仅在 runner 实际执行后被 await。
     * 启动失败不析构输入、不发布退休；显式 Retry 才在原 executor 进行真实取消与清理。
     */
    template<class Coro>
    class TaskSubmission final : public Preview::Executor::ClosingResource,
        public std::enable_shared_from_this<TaskSubmission<Coro>>
    {
        struct StartAttempt final
        {
            TaskSubmission& Owner;
            bool Accepted{false};
            ~StartAttempt() { if (!Accepted) Owner.Abandon({Preview::Fault::Code::IoError}); }
        };
        struct CleanupAttempt final
        {
            TaskSubmission& Owner;
            bool Released{false};
            ~CleanupAttempt()
            {
                if (Released) Owner.FinishCleanup();
                else Owner.BlockWithoutCompletion();
            }
        };
        struct CleanupDelivery final
        {
            std::shared_ptr<TaskSubmission> Owner;
            bool Invoked{false};
            explicit CleanupDelivery(std::shared_ptr<TaskSubmission> Value) : Owner(std::move(Value)) {}
            CleanupDelivery(CleanupDelivery&& Other) noexcept : Owner(std::move(Other.Owner)), Invoked(Other.Invoked) {}
            ~CleanupDelivery()
            {
                if (!Owner) return;
                Owner->CleanupQueued_.store(false);
                if (!Invoked) Owner->BlockWithoutCompletion();
            }
            auto operator()() -> void { Invoked = true; Owner->Cleanup(); }
        };
        /** @brief 真实 co_spawn 完成回调及其退出是正常退休边界；未调用的 drop 仍保留本 owner。 */
        struct Completion final
        {
            std::shared_ptr<TaskSubmission> Owner;
            bool Invoked{false};
            explicit Completion(std::shared_ptr<TaskSubmission> Value) : Owner(std::move(Value)) {}
            Completion(Completion&& Other) noexcept : Owner(std::move(Other.Owner)), Invoked(Other.Invoked) {}
            ~Completion()
            {
                if (!Owner) return;
                Owner->CompletionReleased_.store(true);
                if (Invoked && Owner->ReadyToRetire_.load()) Owner->FinishCleanup();
                else Owner->BlockWithoutCompletion();
            }
            auto operator()(std::exception_ptr Fatal) -> void { Invoked = true; Owner->Complete(std::move(Fatal)); }
        };
        struct RunExit final
        {
            TaskSubmission& Owner;
            ~RunExit() { Owner.BodyExited_.store(true); }
        };
    public:
        /** @brief 创建后先 Retain，再建立 TaskState；真实 owning 输入和 context 均归本 owner。 */
        TaskSubmission(TaskReservation Reservation, Coro Operation)
            : Scope_(Reservation.Owner()), Reservation_(std::move(Reservation)), Operation_(std::move(Operation)),
              Context_(Preview::Executor::ContextOwner::Find(Scope_->CommandExecutor)),
              Reclaimer_(std::make_shared<Preview::Executor::ExecutorReclaimer>(Scope_->CommandExecutor)) {}
        auto Retain() noexcept -> void { Scope_->ClosingStorage->Retain(this->shared_from_this()); }
        /** @brief TaskState 建立后立即接管清理责任；随后 Install 不分配且不能先发布执行。 */
        auto Attach(std::shared_ptr<TaskState> Task) noexcept -> void
        {
            Retirement_ = Task->Retirement();
            Task_ = std::move(Task);
        }
        /** @brief 让 registry teardown 在原 executor 处理 queued owner，不保存反向强引用。 */
        auto InstallQuarantine() -> void
        {
            const auto Weak = this->weak_from_this();
            Reservation_->SetQuarantine([Weak]
                {
                    if (const auto Self = Weak.lock()) Self->OnQuarantine();
                });
        }
        /** @brief 原 executor 上的启动事务；第一项即建立失败 owner，之后才触碰 observer/hook。 */
        auto Start() -> void
        {
            try
            {
                StartAttempt Attempt{*this};
                if (Retired_.load()) { Attempt.Accepted = true; return; }
                if (Abandoned_.load()) { Cleanup(); Attempt.Accepted = true; return; }
                if (Scope_->Blocked.load(std::memory_order_acquire) || !Reclaimer_->CanDispatch())
                {
                    BlockWithoutCompletion();
                    Attempt.Accepted = true;
                    return;
                }
                if (Scope_->TearingDown.load(std::memory_order_acquire))
                {
                    Cleanup();
                    Attempt.Accepted = true;
                    return;
                }
                Reservation_->Publish(Task_);
                Task_->PublishAcceptedIdentity();
                if (Scope_->CancelRequested.load() || Scope_->Blocked.load()) RequestTaskCancel(Scope_, Task_);
                if (!Task_->TryStart())
                {
                    if (Task_->IsCancelDispatchFailed())
                    {
                        BlockWithoutCompletion();
                        Attempt.Accepted = true;
                        return;
                    }
                    if (Scope_->TearingDown.load(std::memory_order_acquire)) Cleanup();
                    else
                    {
                        if (Task_->IsCancelRequested() ||
                            (Task_->Domain() && Task_->Domain()->IsCancellationRequested()))
                        {
                            if (!Task_->CancelBeforeRetirement())
                            {
                                BlockWithoutCompletion();
                                Attempt.Accepted = true;
                                return;
                            }
                        }
                        (void)Task_->Complete();
                        Cleanup();
                    }
                    Attempt.Accepted = true;
                    return;
                }
                RecordStarted(Scope_);
                CompletionArmed_.store(true);
                Completion CompletionOwner(this->shared_from_this());
                auto Runner = Run(this->shared_from_this());
                Net::co_spawn(Scope_->CommandExecutor, std::move(Runner),
                    Net::bind_cancellation_slot(Task_->CancellationSlot(), std::move(CompletionOwner)));
                Attempt.Accepted = true;
            }
            catch (...) { Abandon({Preview::Fault::Code::IoError}); }
        }
        /** @brief 任意线程只发布交付失败；不清空 coroutine、Cancel、Domain 或 reservation。 */
        auto Dropped() noexcept -> void { BlockWithoutCompletion(); }
        /** @brief 显式恢复原 executor 清理；未完成取消或仍执行的用户帧不能被提前退休。 */
        auto RequestRetirement() -> void override
        {
            if (Retired_.load() || CleanupQueued_.exchange(true)) return;
            if (!Reclaimer_->Post(CleanupDelivery(this->shared_from_this())))
            {
                CleanupQueued_.store(false, std::memory_order_release);
                BlockWithoutCompletion();
            }
        }
        [[nodiscard]] auto IsRetired() const noexcept -> bool override { return Retired_.load(); }
        [[nodiscard]] auto IsDispatchUnavailable() const noexcept -> bool override
        { return Unavailable_.load() || !Reclaimer_->CanDispatch(); }
        /** @brief 回收器已隔离 queued action 时，在原 executor 进行唯一 cleanup。 */
        auto OnQuarantine() noexcept -> void { Quarantine(); }
    private:
        [[nodiscard]] static auto FailureFromException(
            const std::exception_ptr Error) noexcept -> Preview::Fault::Failure
        {
            try
            {
                if (Error) std::rethrow_exception(Error);
            }
            catch (const boost::system::system_error &Native)
            {
                return Preview::Fault::FromNative(
                    static_cast<std::error_code>(Native.code()));
            }
            catch (const std::system_error &Native)
            {
                return Preview::Fault::FromNative(Native.code());
            }
            catch (...)
            {
                return {Preview::Fault::Code::IoError};
            }
            return {Preview::Fault::Code::IoError};
        }

        auto BlockWithoutCompletion(
            Preview::Fault::Failure Failure =
                Preview::Fault::Failure{Preview::Fault::Code::Blocked}) noexcept -> void
        {
            Unavailable_.store(true, std::memory_order_release);
            if (Task_) Task_->MarkDrainBlocked(Failure);
            MarkTaskRegistryBlocked(Scope_);
            Retain();
        }

        auto Abandon(Preview::Fault::Failure Error) noexcept -> void
        {
            if (Retired_.load()) return;
            Abandoned_.store(true);
            Unavailable_.store(true);
            if (Task_)
            {
                Task_->MarkDrainBlocked(Error);
                (void)Task_->Complete(Error);
            }
            MarkTaskRegistryBlocked(Scope_);
            Retain();
        }

        auto Quarantine() noexcept -> void
        {
            if (Retired_.load()) return;
            if ((BodyEntered_.load() && !BodyExited_.load()) ||
                (CompletionArmed_.load() && !CompletionReleased_.load()) || OperationStarted_.load())
            {
                if (Task_) (void)Task_->RequestCancel();
                BlockWithoutCompletion();
                return;
            }
            try
            {
                if (Task_)
                {
                    if (Task_->IsCancelDispatchFailed())
                    {
                        BlockWithoutCompletion();
                        return;
                    }
                    const auto Cancelled = Task_->CancelBeforeRetirement();
                    if (!Cancelled) { BlockWithoutCompletion(); return; }
                    (void)Task_->Quarantine();
                }
                Operation_.reset();
                ReadyToRetire_.store(true, std::memory_order_release);
                PublishCompletion(false);
                FinishCleanup();
            }
            catch (...) { BlockWithoutCompletion(); }
        }
        /** @brief runner 进入才允许移动用户 awaitable；此前所有分配/observer 失败都留完整输入。 */
        static auto Run(std::shared_ptr<TaskSubmission> Self) -> Net::awaitable<void>
        {
            RunExit Exit{*Self};
            Self->BodyEntered_.store(true);
            co_await Net::this_coro::throw_if_cancelled(false);
            co_await Net::this_coro::reset_cancellation_state(Net::enable_total_cancellation());
            if (Self->Retired_.load() || Self->Abandoned_.load()) co_return;
            if (Self->Task_->Domain()->IsCancellationRequested())
            {
                (void)Self->Task_->RequestCancel();
                if (Self->Task_->IsCancelDispatchFailed())
                {
                    Self->BlockWithoutCompletion();
                    co_return;
                }
                (void)Self->Task_->Complete({Preview::Fault::Code::Canceled});
                co_return;
            }
            Self->OperationStarted_.store(true);
            using ResultType = typename Coro::value_type;
            if constexpr (std::is_void_v<ResultType>)
            { co_await std::move(*Self->Operation_); (void)Self->Task_->Complete(); }
            else if constexpr (std::is_same_v<ResultType, Preview::Fault::Failure>)
            { (void)Self->Task_->Complete(co_await std::move(*Self->Operation_)); }
            else
            {
                static_assert(std::is_same_v<ResultType, std::expected<void, Preview::Fault::Failure>>);
                auto Result = co_await std::move(*Self->Operation_);
                if (!Result) (void)Self->Task_->Complete(Result.error());
                else (void)Self->Task_->Complete();
            }
        }
        auto PublishCompletion(const bool NotifyFailure = true) noexcept -> void
        {
            if (!Task_ || Recorded_.exchange(true)) return;
            const auto Result = Task_->Result();
            RecordCompleted(Scope_, Result.Outcome);
            if (NotifyFailure && Result.Outcome == TaskOutcome::Failed && Scope_->OnFailure)
            {
                try { Scope_->OnFailure(Task_->Identity(), Result.Failure); }
                catch (...) { MarkTaskRegistryBlocked(Scope_); }
            }
        }
        /** @brief 真实 runner 已退出；取消交接失败继续保留，只有实体释放成立才能允许 callback 退休。 */
        auto Complete(std::exception_ptr Fatal) -> void
        {
            if (Retired_.load()) return;
            if (Task_->IsCancelDispatchFailed())
            {
                BlockWithoutCompletion();
                return;
            }
            Preview::Fault::Failure Result;
            if (Fatal) Result = FailureFromException(Fatal);
            (void)Task_->Complete(Result);
            if (Fatal || !OperationStarted_.load())
            {
                auto Cancelled = Task_->CancelBeforeRetirement();
                if (!Cancelled)
                { BlockWithoutCompletion(); return; }
            }
            Operation_.reset();
            ReadyToRetire_.store(true);
            PublishCompletion();
        }
        auto Cleanup() -> void
        {
            if (Retired_.load()) return;
            CleanupAttempt Attempt{*this};
            if (Task_ && !Task_->IsCompleted())
            {
                if (Task_->IsCancelDispatchFailed())
                {
                    BlockWithoutCompletion();
                    return;
                }
                auto Cancelled = Task_->CancelBeforeRetirement();
                if (!Cancelled) { BlockWithoutCompletion(); return; }
            }
            if (Task_ && !Task_->IsCompleted() && !Task_->IsStarted())
            {
                (void)Task_->Quarantine();
                Operation_.reset();
                ReadyToRetire_.store(true, std::memory_order_release);
                PublishCompletion(false);
                Attempt.Released = true;
                return;
            }
            if (CompletionArmed_.load() && !CompletionReleased_.load())
            { BlockWithoutCompletion(); return; }
            if (BodyEntered_.load() && !BodyExited_.load())
            { BlockWithoutCompletion(); return; }
            Operation_.reset();
            Attempt.Released = true;
            PublishCompletion();
        }
        /** @brief 等待统计观察退休回执后释放任务状态与 reservation；观察失败不改写 TaskOutcome。 */
        static auto FinishCleanupAsync(std::shared_ptr<TaskSubmission> Owner) -> Net::awaitable<void>
        {
            try
            {
                co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
                if (Owner->Task_ && Owner->Scope_->Traffic)
                {
                    const auto Identity = Owner->Task_->Identity();
                    const auto Retired = co_await Preview::Foundation::RetireTraffic(
                        Owner->Scope_->Traffic,
                        Preview::Foundation::TrafficRetirement{
                            Preview::Foundation::TaskTrafficOwner{Identity.WorkerId, Identity.TaskId}});
                    if (!Retired)
                    {
                        Owner->BlockWithoutCompletion(Retired.error());
                        co_return;
                    }
                }
                if (Owner->Task_) Owner->Task_->Retire();
                Owner->Reservation_.reset();
                Owner->Task_.reset();
                Owner->Retired_.store(true, std::memory_order_release);
                Owner->FinalizationQueued_.store(false, std::memory_order_release);
                Owner->Scope_->ClosingStorage->Collect();
            }
            catch (...)
            {
                Owner->FinalizationQueued_.store(false, std::memory_order_release);
                Owner->BlockWithoutCompletion(
                    FailureFromException(std::current_exception()));
            }
        }

        auto FinishCleanupCompleted(const std::exception_ptr Failure) noexcept -> void
        {
            if (Failure || !Retired_.load(std::memory_order_acquire))
            {
                FinalizationQueued_.store(false, std::memory_order_release);
                BlockWithoutCompletion();
                return;
            }
            Retirement_->Publish();
        }

        /** @brief completion frame 退栈后在原 worker executor 等待统计退休回执。 */
        auto FinishCleanup() noexcept -> void
        {
            if (Retired_.load(std::memory_order_acquire) || FinalizationQueued_.exchange(true)) return;
            try
            {
                auto Owner = this->shared_from_this();
                Net::co_spawn(Scope_->CommandExecutor, FinishCleanupAsync(Owner),
                    [Owner](std::exception_ptr Failure) noexcept
                    { Owner->FinishCleanupCompleted(std::move(Failure)); });
            }
            catch (...)
            {
                FinalizationQueued_.store(false, std::memory_order_release);
                BlockWithoutCompletion();
            }
        }
        std::shared_ptr<TaskRegistryState> Scope_;
        std::optional<TaskReservation> Reservation_;
        std::shared_ptr<TaskState> Task_;
        std::shared_ptr<TaskRetirementReceipt> Retirement_;
        std::optional<Coro> Operation_;
        std::shared_ptr<Preview::Executor::ContextOwner> Context_;
        std::shared_ptr<Preview::Executor::ExecutorReclaimer> Reclaimer_;
        std::atomic<bool> Abandoned_{false}, Retired_{false}, CleanupQueued_{false},
            FinalizationQueued_{false}, Unavailable_{false};
        std::atomic<bool> BodyEntered_{false}, BodyExited_{false}, OperationStarted_{false};
        std::atomic<bool> ReadyToRetire_{false}, Recorded_{false};
        std::atomic<bool> CompletionArmed_{false}, CompletionReleased_{false};
    };
    /** @brief 创建任务状态的致命 unwind 仍保留已经接管的协程输入与原 context。 */
    template<class Coro>
    struct TaskSetup final
    {
        std::shared_ptr<TaskSubmission<Coro>> Owner;
        bool Ready{false};
        ~TaskSetup() { if (!Ready) Owner->Dropped(); }
    };
    /** @brief Asio 队列只持保留 owner；drop 析构不直接拥有或销毁输入。 */
    template<class Coro>
    struct TaskDelivery final
    {
        std::shared_ptr<TaskSubmission<Coro>> Owner;
        bool Invoked{false};
        explicit TaskDelivery(std::shared_ptr<TaskSubmission<Coro>> Value) : Owner(std::move(Value)) {}
        TaskDelivery(TaskDelivery&& Other) noexcept : Owner(std::move(Other.Owner)), Invoked(Other.Invoked) {}
        ~TaskDelivery() { if (Owner && !Invoked) Owner->Dropped(); }
        auto operator()() -> void { Invoked = true; Owner->Start(); }
        auto OnQuarantine() noexcept -> void { Invoked = true; if (Owner) Owner->OnQuarantine(); }
    };
}

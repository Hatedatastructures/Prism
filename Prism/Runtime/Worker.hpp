/**
 * @file Worker.hpp
 * @brief Prism worker executor、mailbox 和本地资源边界
 * @details 外部线程只能通过 Dispatch 发布命令；命令消费、任务启动和
 *          worker-local 可变状态均在 Scheduler 上执行。Worker 不复制也不
 *          共享其 WorkerResources owner。
 */

#pragma once

#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Executor/ExecutorReclaimer.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Lifecycle/DrainBarrier.hpp>
#include <Prism/Resource/WorkerResources.hpp>
#include <Prism/Runtime/Detail/Mailbox.hpp>
#include <Prism/Runtime/GenerationPublication.hpp>
#include <Prism/Runtime/WorkerAdmissionReceipt.hpp>
#include <Prism/Runtime/WorkerDispatchResult.hpp>
#include <Prism/Runtime/SessionTraceRing.hpp>
#include <Prism/Runtime/WorkerTaskSnapshotGate.hpp>
#include <Prism/Runtime/WorkerExecution.hpp>

#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <utility>

namespace Prism::Runtime
{

    namespace Net = boost::asio;

    struct WorkerSnapshot final
    {
        Prism::ProcessId Process{};
        Prism::WorkerId Id{};
        Prism::GenerationId Generation{};
        bool Running{false};
        bool Accepting{false};
        std::size_t MailboxSize{0};
        std::size_t MailboxCapacity{0};
        std::size_t ActiveTasks{0};
        std::size_t StartedTasks{0};
        std::size_t CompletedTasks{0};
        std::size_t CancelledTasks{0};
        std::uint64_t DispatchAccepted{0};
        std::uint64_t DispatchFull{0};
        std::uint64_t DispatchClosed{0};
        std::uint64_t DispatchWorkerUnavailable{0};
        std::uint64_t DispatchGenerationRejected{0};
        std::uint64_t CommandsExecuted{0};
        std::uint64_t CommandsFailed{0};
    };

    enum class GenerationPrepareStatus : std::uint8_t
    {
        Prepared,
        WorkerUnavailable,
        BaseMismatch,
        CandidateMismatch,
    };

    struct GenerationPrepareAck final
    {
        Prism::WorkerId Worker{};
        Prism::GenerationId Base{};
        Prism::GenerationId Candidate{};
        GenerationPrepareStatus Status{GenerationPrepareStatus::WorkerUnavailable};
    };

    class Worker final : public WorkerSessionTraceOwner
    {
    public:
        using AdmissionReceipt = WorkerAdmissionReceipt;

        struct Options final
        {
            Prism::ProcessId Process{};
            Prism::WorkerId Id{};
            Prism::GenerationId Generation{};
            std::size_t MailboxCapacity{64};
            Prism::Network::Dns::Config Dns{};
            std::shared_ptr<GenerationPublication> Publication;
        };

        Worker() : Worker(Options{}) {}
        explicit Worker(Options Value)
            : WorkerSessionTraceOwner(Value.Process, Value.Id),
              Resources_(Prism::Resource::WorkerResources::Options{
                  Value.Process, Value.Id, Value.Generation, Value.Dns}),
              Publication_(std::move(Value.Publication)),
              Mailbox_(Detail::Mailbox::Options{Value.MailboxCapacity, Value.Generation, Publication_}),
              TaskSnapshots_(Resources_.Executor()),
              AdmissionFence_(std::make_shared<Prism::Lifecycle::DrainBarrier>(
                  Resources_.Tasks->Reclaimer()))
        {
        }

        ~Worker() noexcept
        {
            DispatchTarget_->Owner.store(nullptr, std::memory_order_release);
            Stop();
        }
        Worker(const Worker &) = delete;
        auto operator=(const Worker &) -> Worker & = delete;
        Worker(Worker &&) = delete;
        auto operator=(Worker &&) -> Worker & = delete;

        [[nodiscard]] auto Id() const noexcept -> Prism::WorkerId
        {
            return Resources_.Id;
        }

        [[nodiscard]] auto Process() const noexcept -> Prism::ProcessId
        {
            return Resources_.Process;
        }

        [[nodiscard]] auto Generation() const noexcept -> Prism::GenerationId
        {
            if (Publication_)
            {
                const auto Current = Publication_->Current();
                if (Current)
                {
                    return Current->Id();
                }
            }
            return Resources_.Generation;
        }

        /** @brief 借用 root TaskRegistry；仅 Worker 存活且 Shutdown 未开始时有效。Cancel 仅登记请求，Drain/Shutdown 确认退栈；I/O 关闭归实际 Session/Carrier owner。 */
        [[nodiscard]] auto TaskRegistry() noexcept -> Prism::Lifecycle::TaskRegistry &
        {
            return *Resources_.Tasks;
        }
        /** @brief 按值返回 scheduler executor；句柄不保活 Worker/ContextOwner，最终停止 io_context 归 Process::Stop。 */
        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return Resources_.Executor();
        }

        [[nodiscard]] auto IsOnExecutor() const noexcept -> bool
        {
            return Resources_.Scheduler.running_in_this_thread();
        }

        [[nodiscard]] auto IsRunning() const noexcept -> bool
        {
            return Running_.load(std::memory_order_acquire);
        }

        [[nodiscard]] auto IsAccepting() const noexcept -> bool
        {
            return Accepting_.load(std::memory_order_acquire);
        }

        /** @brief 按 generation 预约 listener carrier；不匹配或 admission 已封止返回空。
         * @param Generation 当前 worker group generation。
         * @return 固定 WorkerId/Generation 的票据，由 Reservation 接管至真实 carrier 退役。 */
        [[nodiscard]] auto TryReserveAdmission(const Prism::GenerationId Generation)
            -> std::shared_ptr<AdmissionReceipt>
        {
            auto Retained = false;
            if (Publication_)
            {
                Retained = Publication_->Contains(Generation);
            }
            else
            {
                Retained = Generation == this->Generation();
            }
            if (!Retained || !IsAccepting() ||
                !AdmissionFence_->Enter())
            {
                return {};
            }
            AdmissionReceipt Guard(AdmissionFence_, Id(), Generation);
            auto *RawReceipt = new AdmissionReceipt(AdmissionFence_, Id(), Generation);
            Guard.Disarm();
            auto Receipt = std::shared_ptr<AdmissionReceipt>(RawReceipt);
            if (!IsAccepting() || !Retained)
            {
                Receipt->Release();
                return {};
            }
            return Receipt;
        }

        /** @brief 在 worker executor 确认候选代次可被共享发布，不修改任何活动状态。 */
        [[nodiscard]] auto PrepareGeneration(
            const Prism::GenerationId Base,
            Prism::Foundation::GenerationPin Candidate)
            -> Net::awaitable<GenerationPrepareAck>
        {
            co_await Net::post(Resources_.Scheduler, Net::use_awaitable);
            const auto Current = Publication_ ? Publication_->Current()
                                              : Prism::Foundation::GenerationPin{};
            if (!IsRunning() || !IsAccepting())
            {
                co_return GenerationPrepareAck{Id(), Base, {},
                    GenerationPrepareStatus::WorkerUnavailable};
            }
            if (!Candidate || !Candidate->Id() || Candidate->Id() <= Base)
            {
                co_return GenerationPrepareAck{Id(), Base, Candidate ? Candidate->Id() : Prism::GenerationId{},
                    GenerationPrepareStatus::CandidateMismatch};
            }
            if (!Current || Current->Id() != Base)
            {
                co_return GenerationPrepareAck{Id(), Base, Candidate->Id(),
                    GenerationPrepareStatus::BaseMismatch};
            }
            co_return GenerationPrepareAck{Id(), Base, Candidate->Id(),
                GenerationPrepareStatus::Prepared};
        }

        /** @brief 将命令交给本 worker 的固定容量 executor 队列。
         * @details 按值接管闭包；Accepted 仅表示入队，worker executor 执行仍在队列中的命令，Stop 可释放未执行闭包。
         * 返回队列、worker 或 generation 的拒绝原因。提交不取消 I/O、不做半关闭；最终关闭归闭包捕获的真实 owner。
         * @param Generation 此次 dispatch 所属的已发布代次。
         * @param CommandValue 由 worker 接管的命令及其 owning captures。
         * @return 入队结果；命令执行期异常由 worker 隔离并计入失败统计。
         */
        [[nodiscard]] auto Dispatch(Prism::GenerationId Generation,
                                    WorkerDispatchCommand CommandValue) -> WorkerDispatchResult
        {
            if (!IsAccepting())
            {
                Resources_.Stats.RecordWorkerUnavailable();
                return WorkerDispatchResult::WorkerUnavailable;
            }

            const auto Result = Mailbox_.Post(Generation, std::move(CommandValue));
            Record(Result);
            if (Result == WorkerDispatchResult::Accepted)
            {
                Notify();
            }
            return Result;
        }

        auto Run() -> void
        {
            if (!IsRunning())
            {
                return;
            }
            Detail::RunWorkerContext(Resources_);
        }

        [[nodiscard]] auto Pump() -> std::size_t
        {
            if (!IsRunning())
            {
                return 0;
            }
            return Detail::PumpWorkerContext(Resources_);
        }

        /** @brief 同步封闭准入/mailbox、封止并请求取消；仅尝试退休确认为空的 root scope，不能代替完整 Drain。 */
        auto Stop() noexcept -> void
        {
            CloseAdmission();
            Running_.store(false, std::memory_order_release);
            auto AllowTaskRetirement = true;
            if (Resources_.Tasks)
            {
                Resources_.Tasks->Seal();
                (void)Resources_.Tasks->Cancel();
                try
                {
                    TaskSnapshots_.StoreRetiredStats(Resources_.Tasks->Stats());
                }
                catch (...)
                {
                    AllowTaskRetirement = false;
                }
            }
            if (TaskSnapshots_.Close())
            {
                AllowTaskRetirement = false;
            }
            Resources_.Stop(AllowTaskRetirement);
        }

        /** @brief 封闭 admission、receipt fence 与 mailbox；不取消任务、不 Drain，也不停止 executor。 */
        auto CloseAdmission() noexcept -> void
        {
            Accepting_.store(false, std::memory_order_release);
            AdmissionFence_->Seal();
            Mailbox_.Close();
        }

        /** @brief 异步退休 root tasks、admission receipts 与 DNS owner。
         * @details 屏蔽调用方取消并在 worker scheduler 排空；首次失败后 gate 不复位，
         *          后续调用返回 WouldBlock，调用方须保留 Worker/ContextOwner；最终停止 io_context
         *          仍归 Process::Stop。
         * @return tasks、receipts、DNS owner、executor 与快照 fence 全部 drain 成功才成功，否则返回 Failure。 */
        [[nodiscard]] auto Shutdown()
            -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
        {
            co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
            if (ShutdownDrained_.load(std::memory_order_acquire))
                co_return std::expected<void, Prism::Fault::Failure>{};
            if (ShutdownRunning_.exchange(true, std::memory_order_acq_rel))
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
            }
            CloseAdmission();
            if (!Resources_.Tasks || Resources_.Execution->Fatal->HasFailure() ||
                Resources_.IoContext.stopped())
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }

            const auto Reclaimer = Resources_.Tasks->Reclaimer();
            const auto TaskExecutor = Resources_.Tasks->Executor();
            const auto Storage = Prism::Executor::ContextOwner::Storage(Resources_.Executor());
            (void)Resources_.Tasks->Cancel();

            co_await Net::post(Resources_.Scheduler, Net::use_awaitable);
            if (Mailbox_.Size() != 0 || DrainPosted_.load(std::memory_order_acquire))
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }

            const auto Drained = co_await Resources_.Tasks->Drain();
            if (!Drained) co_return std::unexpected(Drained.error());
            const auto AdmissionsDrained = co_await AdmissionFence_->Drain();
            if (!AdmissionsDrained)
            {
                co_return std::unexpected(AdmissionsDrained.error());
            }
            if (!Resources_.DialService)
            {
                co_return std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            const auto DialServiceStopped = co_await Resources_.DialService->Shutdown();
            if (!DialServiceStopped)
            {
                co_return std::unexpected(DialServiceStopped.error());
            }
            co_await Net::post(TaskExecutor, Net::use_awaitable);
            if (!IsShutdownFenceClear(Reclaimer, Storage))
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }

            const auto FinalTaskStats = Resources_.Tasks->Stats();
            TaskSnapshots_.StoreRetiredStats(FinalTaskStats);
            if (TaskSnapshots_.Close())
            {
                if (!(co_await TaskSnapshots_.WaitForReaders()))
                {
                    co_return std::unexpected(
                        Prism::Fault::Failure{Prism::Fault::Code::Blocked});
                }
            }
            Resources_.Tasks.reset();
            co_await Net::post(TaskExecutor, Net::use_awaitable);
            if (!IsRetirementFenceClear(Reclaimer, Storage))
            {
                co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            ShutdownDrained_.store(true, std::memory_order_release);
            co_return std::expected<void, Prism::Fault::Failure>{};
        }

        /** @brief 读取 worker 快照；TaskStats 通过关闭读闸门与退休快照安全切换。 */
        [[nodiscard]] auto Snapshot() const noexcept -> WorkerSnapshot
        {
            const auto Tasks = TaskSnapshots_.Snapshot(Resources_.Tasks);
            const auto Stats = Resources_.Stats.Snapshot();
            return WorkerSnapshot{
                Resources_.Process,
                Resources_.Id,
                Generation(),
                IsRunning(),
                IsAccepting(),
                Mailbox_.Size(),
                Mailbox_.Capacity(),
                Tasks.Active,
                Tasks.Started,
                Tasks.Completed,
                Tasks.Cancelled,
                Stats.DispatchAccepted,
                Stats.DispatchFull,
                Stats.DispatchClosed,
                Stats.DispatchWorkerUnavailable,
                Stats.DispatchGenerationRejected,
                Stats.CommandsExecuted,
                Stats.CommandsFailed};
        }
        /** @brief 借用 WorkerResources；引用不拥有 Worker/ContextOwner，Stop/Shutdown 会改变成员状态。 */
        [[nodiscard]] auto Resources() noexcept -> Prism::Resource::WorkerResources &
        {
            return Resources_;
        }
        /** @brief 只读借用同一 WorkerResources；资源生命周期仍由 Worker 与 Process 所有。 */
        [[nodiscard]] auto Resources() const noexcept
            -> const Prism::Resource::WorkerResources &
        {
            return Resources_;
        }

    private:
        friend class WorkerTestAccess;

        using Mailbox = Detail::Mailbox;

        [[nodiscard]] auto IsShutdownFenceClear(
            const std::shared_ptr<Prism::Executor::ExecutorReclaimer>& Reclaimer,
            const std::shared_ptr<Prism::Executor::ClosingStorage>& Storage) const noexcept -> bool
        {
            const auto Tasks = Resources_.Tasks->Stats();
            return !Resources_.Execution->Fatal->HasFailure() && !Resources_.IoContext.stopped() &&
                   Tasks.Active == 0 && !Tasks.DrainBlocked &&
                   Mailbox_.Size() == 0 && !DrainPosted_.load(std::memory_order_acquire) &&
                   Reclaimer->Pending() == 0 && Reclaimer->QuarantinedCount() == 0 &&
                   Reclaimer->ActionFailures() == 0 && !Storage->IsSealed();
        }

        [[nodiscard]] auto IsRetirementFenceClear(
            const std::shared_ptr<Prism::Executor::ExecutorReclaimer>& Reclaimer,
            const std::shared_ptr<Prism::Executor::ClosingStorage>& Storage) const noexcept -> bool
        {
            return !Resources_.Execution->Fatal->HasFailure() && !Resources_.IoContext.stopped() &&
                   Mailbox_.Size() == 0 && !DrainPosted_.load(std::memory_order_acquire) &&
                   Reclaimer->Pending() == 0 && Reclaimer->QuarantinedCount() == 0 &&
                   Reclaimer->ActionFailures() == 0 && !Storage->IsSealed();
        }

        auto Record(WorkerDispatchResult Result) noexcept -> void
        {
            switch (Result)
            {
            case WorkerDispatchResult::Accepted:
                Resources_.Stats.RecordAccepted();
                break;
            case WorkerDispatchResult::Full:
                Resources_.Stats.RecordFull();
                break;
            case WorkerDispatchResult::Closed:
                Resources_.Stats.RecordClosed();
                break;
            case WorkerDispatchResult::WorkerUnavailable:
                Resources_.Stats.RecordWorkerUnavailable();
                break;
            case WorkerDispatchResult::GenerationRejected:
                Resources_.Stats.RecordGenerationRejected();
                break;
            }
        }

        auto Notify() noexcept -> void
        {
            bool Expected = false;
            if (!DrainPosted_.compare_exchange_strong(Expected, true,
                                                      std::memory_order_acq_rel,
                                                      std::memory_order_acquire))
            {
                return;
            }
            try
            {
                const auto Weak = std::weak_ptr<DispatchTarget>(DispatchTarget_);
                Net::post(Resources_.Scheduler, [Weak]
                {
                    if (auto Target = Weak.lock())
                        if (auto* Owner = Target->Owner.load(std::memory_order_acquire)) Owner->DrainMailbox();
                });
            }
            catch (...)
            {
                DrainPosted_.store(false, std::memory_order_release);
                Stop();
            }
        }

        auto DrainMailbox() noexcept -> void
        {
            Mailbox::Command CommandValue;
            while (Mailbox_.TryReceive(CommandValue))
            {
                if (!IsAccepting())
                {
                    CommandValue = {};
                    continue;
                }
                try
                {
                    if (CommandValue)
                    {
                        CommandValue();
                    }
                    Resources_.Stats.RecordExecuted();
                }
                catch (...)
                {
                    Resources_.Stats.RecordFailed();
                }
                CommandValue = {};
            }

            DrainPosted_.store(false, std::memory_order_release);
            if (Mailbox_.Size() != 0 && IsAccepting())
            {
                Notify();
            }
        }

        Prism::Resource::WorkerResources Resources_;
        std::shared_ptr<GenerationPublication> Publication_;
        Mailbox Mailbox_;
        Detail::WorkerTaskSnapshotGate TaskSnapshots_;
        std::shared_ptr<Prism::Lifecycle::DrainBarrier> AdmissionFence_;
        /** @brief 已停止并 join driver 后使迟到通知失效；不保留 Worker/服务，独立 context 可安全退休。 */
        struct DispatchTarget final
        {
            explicit DispatchTarget(Worker* Value):Owner(Value) {}
            std::atomic<Worker*> Owner;
        };
        std::shared_ptr<DispatchTarget> DispatchTarget_{std::make_shared<DispatchTarget>(this)};
        std::atomic<bool> Accepting_{true};
        std::atomic<bool> Running_{true};
        std::atomic<bool> DrainPosted_{false};
        std::atomic<bool> ShutdownDrained_{false};
        std::atomic<bool> ShutdownRunning_{false};
    };

} // namespace Prism::Runtime

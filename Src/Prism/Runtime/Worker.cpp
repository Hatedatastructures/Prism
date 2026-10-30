/** @file Worker.cpp @brief worker mailbox dispatch、统计与串行消费。 */
#include <Prism/Runtime/Worker.hpp>

#include <Prism/Runtime/Detail/Mailbox.hpp>

#include <Prism/Foundation/Executor/ContextOwner.hpp>
#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Net/Services/WorkerDialService.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <exception>
#include <memory>
#include <utility>

namespace Prism::Runtime
{
    auto Detail::WorkerStatistics::Snapshot() const noexcept -> Detail::WorkerStatisticsSnapshot
    {
        return {DispatchAccepted_.load(std::memory_order_relaxed),
            DispatchFull_.load(std::memory_order_relaxed),
            DispatchClosed_.load(std::memory_order_relaxed),
            DispatchWorkerUnavailable_.load(std::memory_order_relaxed),
            DispatchGenerationRejected_.load(std::memory_order_relaxed),
            CommandsExecuted_.load(std::memory_order_relaxed),
            CommandsFailed_.load(std::memory_order_relaxed)};
    }

    WorkerAdmissionReceipt::WorkerAdmissionReceipt(
        std::shared_ptr<Prism::Lifecycle::DrainBarrier> Fence,
        const Prism::WorkerId Id,
        const Prism::GenerationId Generation) noexcept
        : Fence_(std::move(Fence)), Id_(Id), Generation_(Generation)
    {
    }

    WorkerAdmissionReceipt::~WorkerAdmissionReceipt() noexcept
    {
        Release();
    }

    auto WorkerAdmissionReceipt::Release() noexcept -> void
    {
        if (!Released_.exchange(true, std::memory_order_acq_rel))
        {
            Fence_->Leave();
        }
    }

    auto WorkerAdmissionReceipt::Block() noexcept -> void
    {
        Fence_->Block();
    }

    auto WorkerAdmissionReceipt::Disarm() noexcept -> void
    {
        Released_.store(true, std::memory_order_release);
    }

    struct Worker::DispatchTarget final
    {
        explicit DispatchTarget(Worker* Value) : Owner(Value) {}
        std::atomic<Worker*> Owner;
    };

    Detail::WorkerTaskSnapshotGate::WorkerTaskSnapshotGate(
        boost::asio::any_io_executor Executor)
        : Released_(std::move(Executor), 1U)
    {
    }

    auto Detail::WorkerTaskSnapshotGate::StoreRetiredStats(
        Prism::Lifecycle::TaskStats Stats) -> void
    {
        RetiredStats_.store(
            std::make_shared<const Prism::Lifecycle::TaskStats>(std::move(Stats)),
            std::memory_order_release);
    }

    auto Detail::WorkerTaskSnapshotGate::Close() noexcept -> bool
    {
        const auto State = Gate_.fetch_or(ClosedBit, std::memory_order_acq_rel);
        return (State & ReaderMask) != 0;
    }

    auto Detail::WorkerTaskSnapshotGate::Snapshot(
        const std::unique_ptr<Prism::Lifecycle::TaskRegistry>& Tasks) const noexcept
        -> Prism::Lifecycle::TaskStats
    {
        auto State = Gate_.load(std::memory_order_acquire);
        while ((State & ClosedBit) == 0)
        {
            if ((State & ReaderMask) == ReaderMask)
            {
                Prism::Lifecycle::TaskStats Failed;
                Failed.DrainBlocked = true;
                return Failed;
            }
            if (Gate_.compare_exchange_weak(
                    State, State + 1, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                if (Tasks)
                {
                    const auto Result = Tasks->Stats();
                    ReleaseReader();
                    return Result;
                }
                ReleaseReader();
                break;
            }
        }
        const auto Retired = RetiredStats_.load(std::memory_order_acquire);
        if (Retired) return *Retired;
        Prism::Lifecycle::TaskStats Failed;
        Failed.DrainBlocked = true;
        return Failed;
    }

    auto Detail::WorkerTaskSnapshotGate::WaitForReaders() -> boost::asio::awaitable<bool>
    {
        co_await boost::asio::this_coro::reset_cancellation_state(
            boost::asio::disable_cancellation());
        boost::system::error_code Error;
        co_await Released_.async_receive(
            boost::asio::redirect_error(boost::asio::use_awaitable, Error));
        co_return !Error;
    }

    auto Detail::WorkerTaskSnapshotGate::ReleaseReader() const noexcept -> void
    {
        const auto Previous = Gate_.fetch_sub(1, std::memory_order_acq_rel);
        if ((Previous & ClosedBit) != 0 && (Previous & ReaderMask) == 1)
        {
            (void)Released_.try_send(boost::system::error_code{});
        }
    }

    Worker::Worker() : Worker(Options{})
    {
    }

    Worker::Worker(Options Value)
        : WorkerSessionTraceOwner(Value.Process, Value.Id),
          Resources_(Prism::Resource::WorkerResources::Options{
              Value.Process, Value.Id, Value.Generation, Value.Bytes}),
          Scheduler_(Net::make_strand(Net::any_io_executor(Resources_.Execution->Io.get_executor()))),
          Work_(Net::any_io_executor(Scheduler_)),
          Publication_(std::move(Value.Publication)),
          Mailbox_(std::make_unique<Detail::Mailbox>(Detail::Mailbox::Options{
              Value.MailboxCapacity, Value.Generation, Publication_})),
          TaskSnapshots_(Net::any_io_executor(Scheduler_)),
          DispatchTarget_(std::make_shared<DispatchTarget>(this))
    {
        ContextOwner_ = Resources_.Execution;
        DialService_ = std::make_shared<Prism::Network::Services::WorkerDialService>(
            Prism::Network::Services::WorkerDialOptions{
                Net::any_io_executor(Scheduler_), Value.Dns});
        Resources_.Tasks = std::make_unique<Prism::Lifecycle::TaskRegistry>(
            Net::any_io_executor(Scheduler_));
        AdmissionFence_ = std::make_shared<Prism::Lifecycle::DrainBarrier>(
            Resources_.Tasks->Reclaimer());
    }

    auto Worker::Id() const noexcept -> Prism::WorkerId
    {
        return Resources_.Id;
    }

    auto Worker::Process() const noexcept -> Prism::ProcessId
    {
        return Resources_.Process;
    }

    auto Worker::Generation() const noexcept -> Prism::GenerationId
    {
        if (Publication_)
        {
            const auto Current = Publication_->Current();
            if (Current) return Current->Id();
        }
        return Resources_.Generation;
    }

    auto Worker::TaskRegistry() noexcept -> Prism::Lifecycle::TaskRegistry&
    {
        return *Resources_.Tasks;
    }

    auto Worker::Executor() const -> Net::any_io_executor
    {
        return Net::any_io_executor(Scheduler_);
    }

    auto Worker::IsOnExecutor() const noexcept -> bool
    {
        return Scheduler_.running_in_this_thread();
    }

    auto Worker::IsRunning() const noexcept -> bool
    {
        return Running_.load(std::memory_order_acquire);
    }

    auto Worker::IsAccepting() const noexcept -> bool
    {
        return Accepting_.load(std::memory_order_acquire);
    }

    auto Worker::Resources() noexcept -> Prism::Resource::WorkerResources&
    {
        return Resources_;
    }

    auto Worker::Resources() const noexcept -> const Prism::Resource::WorkerResources&
    {
        return Resources_;
    }

    auto Worker::DialService() const noexcept
        -> std::shared_ptr<Prism::Network::Services::WorkerDialService>
    {
        return DialService_;
    }

    Worker::~Worker() noexcept
    {
        DispatchTarget_->Owner.store(nullptr, std::memory_order_release);
        Stop();
    }

    auto Worker::Dispatch(const Prism::GenerationId Generation,
        WorkerDispatchCommand CommandValue) -> WorkerDispatchResult
    {
        if (!IsAccepting())
        {
            Stats_.RecordWorkerUnavailable();
            return WorkerDispatchResult::WorkerUnavailable;
        }
        const auto Result = Mailbox_->Post(Generation, std::move(CommandValue));
        Record(Result);
        if (Result == WorkerDispatchResult::Accepted) Notify();
        return Result;
    }

    auto Worker::TryReserveAdmission(const Prism::GenerationId Generation)
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
        if (!Retained || !IsAccepting() || !AdmissionFence_->Enter()) return {};
        AdmissionReceipt Guard(AdmissionFence_, Id(), Generation);
        auto* RawReceipt = new AdmissionReceipt(AdmissionFence_, Id(), Generation);
        Guard.Disarm();
        auto Receipt = std::shared_ptr<AdmissionReceipt>(RawReceipt);
        if (!IsAccepting() || !Retained)
        {
            Receipt->Release();
            return {};
        }
        return Receipt;
    }

    auto Worker::PrepareGeneration(const Prism::GenerationId Base,
        Prism::Foundation::GenerationPin Candidate) -> Net::awaitable<GenerationPrepareAck>
    {
        co_await Net::post(Scheduler_, Net::use_awaitable);
        const auto Current = Publication_ ? Publication_->Current()
                                          : Prism::Foundation::GenerationPin{};
        if (!IsRunning() || !IsAccepting())
            co_return GenerationPrepareAck{Id(), Base, {},
                GenerationPrepareStatus::WorkerUnavailable};
        if (!Candidate || !Candidate->Id() || Candidate->Id() <= Base)
            co_return GenerationPrepareAck{Id(), Base, Candidate ? Candidate->Id() : Prism::GenerationId{},
                GenerationPrepareStatus::CandidateMismatch};
        if (!Current || Current->Id() != Base)
            co_return GenerationPrepareAck{Id(), Base, Candidate->Id(),
                GenerationPrepareStatus::BaseMismatch};
        co_return GenerationPrepareAck{Id(), Base, Candidate->Id(),
            GenerationPrepareStatus::Prepared};
    }

    auto Worker::Run() -> void
    {
        struct DriverScope final
        {
            explicit DriverScope(std::atomic<std::size_t>& Count) noexcept : Value(Count)
            {
                Value.fetch_add(1, std::memory_order_release);
            }
            ~DriverScope()
            {
                Value.fetch_sub(1, std::memory_order_release);
            }
            std::atomic<std::size_t>& Value;
        } Driver(DriverCount_);
        if (!IsRunning()) return;
        Prism::Memory::ResourceScope Scope(Resources_.MemoryResource);
        ContextOwner_->Io.run();
    }

    auto Worker::Pump() -> std::size_t
    {
        struct DriverScope final
        {
            explicit DriverScope(std::atomic<std::size_t>& Count) noexcept : Value(Count)
            {
                Value.fetch_add(1, std::memory_order_release);
            }
            ~DriverScope()
            {
                Value.fetch_sub(1, std::memory_order_release);
            }
            std::atomic<std::size_t>& Value;
        } Driver(DriverCount_);
        if (!IsRunning()) return 0;
        Prism::Memory::ResourceScope Scope(Resources_.MemoryResource);
        return ContextOwner_->Io.poll();
    }

    auto Worker::Stop() noexcept -> void
    {
        if (Stopping_.exchange(true, std::memory_order_acq_rel)) return;
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
        if (TaskSnapshots_.Close()) AllowTaskRetirement = false;
        if (AllowTaskRetirement && DriverCount_.load(std::memory_order_acquire) == 0 &&
            CanRetireEmptyTasks() && DrainAndRetireEmptyTasks())
        {
            Work_.reset();
            ContextOwner_->Io.stop();
            return;
        }
        if (Resources_.Tasks) (void)Resources_.Tasks->Cancel();
        Work_.reset();
        ContextOwner_->Io.stop();
    }

    auto Worker::CloseAdmission() noexcept -> void
    {
        Accepting_.store(false, std::memory_order_release);
        AdmissionFence_->Seal();
        Mailbox_->Close();
    }

    auto Worker::Shutdown() -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_await Net::this_coro::reset_cancellation_state(Net::disable_cancellation());
        if (ShutdownDrained_.load(std::memory_order_acquire))
            co_return std::expected<void, Prism::Fault::Failure>{};
        if (ShutdownRunning_.exchange(true, std::memory_order_acq_rel))
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::WouldBlock});
        CloseAdmission();
        if (!Resources_.Tasks || ContextOwner_->Fatal->HasFailure() ||
            ContextOwner_->Io.stopped())
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});

        const auto Reclaimer = Resources_.Tasks->Reclaimer();
        const auto TaskExecutor = Resources_.Tasks->Executor();
        const auto Storage = Prism::Executor::ContextOwner::Storage(Executor());
        (void)Resources_.Tasks->Cancel();
        co_await Net::post(Scheduler_, Net::use_awaitable);
        if (Mailbox_->Size() != 0 || DrainPosted_.load(std::memory_order_acquire))
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        const auto Drained = co_await Resources_.Tasks->Drain();
        if (!Drained) co_return std::unexpected(Drained.error());
        const auto AdmissionsDrained = co_await AdmissionFence_->Drain();
        if (!AdmissionsDrained) co_return std::unexpected(AdmissionsDrained.error());
        if (!DialService_)
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        const auto DialServiceStopped = co_await DialService_->Shutdown();
        if (!DialServiceStopped) co_return std::unexpected(DialServiceStopped.error());
        co_await Net::post(TaskExecutor, Net::use_awaitable);
        if (!IsShutdownFenceClear(Reclaimer, Storage))
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});

        const auto FinalTaskStats = Resources_.Tasks->Stats();
        TaskSnapshots_.StoreRetiredStats(FinalTaskStats);
        if (TaskSnapshots_.Close() && !(co_await TaskSnapshots_.WaitForReaders()))
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        Resources_.Tasks.reset();
        co_await Net::post(TaskExecutor, Net::use_awaitable);
        if (!IsRetirementFenceClear(Reclaimer, Storage))
            co_return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        ShutdownDrained_.store(true, std::memory_order_release);
        co_return std::expected<void, Prism::Fault::Failure>{};
    }

    auto Worker::Snapshot() const noexcept -> WorkerSnapshot
    {
        const auto Tasks = TaskSnapshots_.Snapshot(Resources_.Tasks);
        const auto Stats = Stats_.Snapshot();
        return WorkerSnapshot{Resources_.Process, Resources_.Id, Generation(), IsRunning(), IsAccepting(),
            Mailbox_->Size(), Mailbox_->Capacity(), Tasks.Active, Tasks.Started, Tasks.Completed,
            Tasks.Cancelled, Stats.DispatchAccepted, Stats.DispatchFull, Stats.DispatchClosed,
            Stats.DispatchWorkerUnavailable, Stats.DispatchGenerationRejected,
            Stats.CommandsExecuted, Stats.CommandsFailed};
    }

    auto Worker::IsShutdownFenceClear(
        const std::shared_ptr<Prism::Executor::ExecutorReclaimer>& Reclaimer,
        const std::shared_ptr<Prism::Executor::ClosingStorage>& Storage) const noexcept -> bool
    {
        const auto Tasks = Resources_.Tasks->Stats();
        return !ContextOwner_->Fatal->HasFailure() && !ContextOwner_->Io.stopped() &&
            Tasks.Active == 0 && !Tasks.DrainBlocked && Mailbox_->Size() == 0 &&
            !DrainPosted_.load(std::memory_order_acquire) && Reclaimer->Pending() == 0 &&
            Reclaimer->QuarantinedCount() == 0 && Reclaimer->ActionFailures() == 0 &&
            !Storage->IsSealed();
    }

    auto Worker::IsRetirementFenceClear(
        const std::shared_ptr<Prism::Executor::ExecutorReclaimer>& Reclaimer,
        const std::shared_ptr<Prism::Executor::ClosingStorage>& Storage) const noexcept -> bool
    {
        return !ContextOwner_->Fatal->HasFailure() && !ContextOwner_->Io.stopped() &&
            Mailbox_->Size() == 0 && !DrainPosted_.load(std::memory_order_acquire) &&
            Reclaimer->Pending() == 0 && Reclaimer->QuarantinedCount() == 0 &&
            Reclaimer->ActionFailures() == 0 && !Storage->IsSealed();
    }

    auto Worker::CanRetireEmptyTasks() const noexcept -> bool
    {
        if (!Resources_.Tasks || !ContextOwner_ || ContextOwner_->Fatal->HasFailure() ||
            ContextOwner_->Io.stopped() || Scheduler_.running_in_this_thread()) return false;
        const auto Snapshot = Resources_.Tasks->Stats();
        const auto Reclaimer = Resources_.Tasks->Reclaimer();
        if (Snapshot.Active != 0 || Snapshot.DrainBlocked || Snapshot.Quarantined != 0 ||
            !Reclaimer->CanDispatch() || Reclaimer->IsQuarantined() ||
            Reclaimer->QuarantinedCount() != 0 || Reclaimer->ActionFailures() != 0) return false;
        try
        {
            return !Prism::Executor::ContextOwner::Storage(Executor())->IsSealed();
        }
        catch (...)
        {
            return false;
        }
    }

    auto Worker::RetireEmptyTasks(
        std::unique_ptr<Prism::Lifecycle::TaskRegistry> Registry,
        std::shared_ptr<Prism::Network::Services::WorkerDialService> DialService)
        -> Net::awaitable<bool>
    {
        if (!Registry || !DialService) co_return false;
        const auto Drained = co_await Registry->Drain();
        if (!Drained) co_return false;
        const auto DialServiceStopped = co_await DialService->Shutdown();
        if (!DialServiceStopped) co_return false;
        const auto Snapshot = Registry->Stats();
        if (Snapshot.Active != 0 || Snapshot.DrainBlocked || Snapshot.Quarantined != 0)
            co_return false;
        Registry.reset();
        co_return true;
    }

    auto Worker::DrainAndRetireEmptyTasks() noexcept -> bool
    {
        const auto Reclaimer = Resources_.Tasks->Reclaimer();
        const auto Fatal = ContextOwner_->Fatal;
        std::shared_ptr<Prism::Executor::ClosingStorage> Storage;
        std::shared_ptr<EmptyTaskRetirement> Outcome;
        std::size_t StoragePendingBefore = 0;
        try
        {
            Storage = Prism::Executor::ContextOwner::Storage(Executor());
            StoragePendingBefore = Storage->Pending();
            Outcome = std::make_shared<EmptyTaskRetirement>();
            auto Registry = std::move(Resources_.Tasks);
            (void)Registry->Cancel();
            Net::co_spawn(Scheduler_, RetireEmptyTasks(std::move(Registry), DialService_),
                [Outcome, Fatal](std::exception_ptr Error, const bool Completed)
                {
                    if (Error)
                    {
                        Fatal->Publish(std::move(Error));
                        Outcome->Failed.store(true, std::memory_order_release);
                        return;
                    }
                    Outcome->Retired.store(Completed, std::memory_order_release);
                });
            Work_.reset();
            ContextOwner_->Io.run();
        }
        catch (...)
        {
            Fatal->Publish(std::current_exception());
            Work_.reset();
            ContextOwner_->Io.stop();
            return false;
        }
        Storage->Collect();
        return Outcome->Retired.load(std::memory_order_acquire) &&
            !Outcome->Failed.load(std::memory_order_acquire) && !Fatal->HasFailure() &&
            !Storage->IsSealed() && Storage->Pending() <= StoragePendingBefore &&
            Reclaimer->Pending() == 0 && Reclaimer->QuarantinedCount() == 0 &&
            Reclaimer->ActionFailures() == 0;
    }

    auto Worker::Record(const WorkerDispatchResult Result) noexcept -> void
    {
        switch (Result)
        {
        case WorkerDispatchResult::Accepted: Stats_.RecordAccepted(); break;
        case WorkerDispatchResult::Full: Stats_.RecordFull(); break;
        case WorkerDispatchResult::Closed: Stats_.RecordClosed(); break;
        case WorkerDispatchResult::WorkerUnavailable: Stats_.RecordWorkerUnavailable(); break;
        case WorkerDispatchResult::GenerationRejected: Stats_.RecordGenerationRejected(); break;
        }
    }

    auto Worker::Notify() noexcept -> void
    {
        bool Expected = false;
        if (!DrainPosted_.compare_exchange_strong(Expected, true,
            std::memory_order_acq_rel, std::memory_order_acquire)) return;
        try
        {
            const auto Weak = std::weak_ptr<DispatchTarget>(DispatchTarget_);
            Net::post(Scheduler_, [Weak]
            {
                if (const auto Target = Weak.lock())
                    if (auto* Owner = Target->Owner.load(std::memory_order_acquire)) Owner->DrainMailbox();
            });
        }
        catch (...)
        {
            DrainPosted_.store(false, std::memory_order_release);
            Stop();
        }
    }

    auto Worker::DrainMailbox() noexcept -> void
    {
        Detail::Mailbox::Command CommandValue;
        while (Mailbox_->TryReceive(CommandValue))
        {
            if (!IsAccepting())
            {
                CommandValue = {};
                continue;
            }
            try
            {
                if (CommandValue) CommandValue();
                Stats_.RecordExecuted();
            }
            catch (...)
            {
                Stats_.RecordFailed();
            }
            CommandValue = {};
        }
        DrainPosted_.store(false, std::memory_order_release);
        if (Mailbox_->Size() != 0 && IsAccepting()) Notify();
    }
}

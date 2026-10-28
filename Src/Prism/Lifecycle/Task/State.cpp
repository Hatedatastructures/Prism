/** @file State.cpp @brief 任务状态机、取消与终态发布实现。 */
#include <Prism/Lifecycle/Task/State.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <utility>

namespace Prism::Lifecycle
{
    auto TaskState::CurrentTimestamp() noexcept -> std::uint64_t
    {
        const auto Value = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return Value > 0 ? static_cast<std::uint64_t>(Value) : 0U;
    }

    auto TaskState::BeginCompletion() noexcept -> bool
    {
        auto Expected = TaskPhase::Pending;
        if (Phase_.compare_exchange_strong(Expected, TaskPhase::Completing)) return true;
        Expected = TaskPhase::Started;
        return Phase_.compare_exchange_strong(Expected, TaskPhase::Completing);
    }

    auto TaskState::CancellationPreventsStart() const noexcept -> bool
    {
        const auto DomainValue = Domain_.load();
        return !StartOnSubmit_ && DomainValue && DomainValue->IsCancellationRequested();
    }

    TaskState::TaskState(Options Value)
        : Identity_(Value.Identity), Domain_(std::move(Value.Domain)),
          Cancel_(std::move(Value.Cancel)), StartOnSubmit_(Value.StartOnSubmit),
          IdentityObserver_(std::move(Value.IdentityObserver)),
          Retirement_(std::move(Value.Retirement)) {}

    auto TaskState::PublishAcceptedIdentity() -> void
    {
        if (IdentityObserver_) IdentityObserver_->PublishIdentity(Identity_);
        IdentityObserver_.reset();
    }

    auto TaskState::TryStart() -> bool
    {
        if (IsCompleted()) return false;
        if (CancellationPreventsStart())
        {
            (void)RequestCancel();
            return false;
        }
        auto Expected = TaskPhase::Pending;
        if (!Phase_.compare_exchange_strong(Expected, TaskPhase::Started)) return false;
        StartedAt_.store(CurrentTimestamp(), std::memory_order_release);
        Started_.store(true, std::memory_order_release);
        if (CancellationPreventsStart())
        {
            (void)RequestCancel();
            if (IsCancelDispatchFailed()) return false;
            (void)Complete({Prism::Fault::Code::Canceled});
            return false;
        }
        return true;
    }

    auto TaskState::RequestCancel() -> bool
    {
        if (IsCompleted() || CancelRequested_.exchange(true)) return false;
        auto DomainValue = Domain_.load();
        if (!DomainValue) return false;
        (void)DomainValue->Cancel();
        const auto Weak = weak_from_this();
        if (!DomainValue->Reclaimer()->Post([Weak]
            {
                if (const auto Self = Weak.lock()) Self->InvokeCancel();
            })) CancelDispatchFailed_.store(true, std::memory_order_release);
        return true;
    }

    auto TaskState::OnCancellation() -> void
    {
        if (IsCompleted()) return;
        CancelRequested_.store(true, std::memory_order_release);
        (void)InvokeCancel();
    }

    auto TaskState::Complete(Prism::Fault::Failure Failure) noexcept -> bool
    {
        if (!BeginCompletion()) return false;
        TaskOutcome ResultValue = TaskOutcome::Succeeded;
        if (Failure.Failed()) ResultValue = TaskOutcome::Failed;
        if (Failure.Code == Prism::Fault::Code::Canceled) ResultValue = TaskOutcome::Cancelled;
        const auto DomainValue = Domain_.load();
        if (Failure.Succeeded() &&
            (CancelRequested_.load() || (DomainValue && DomainValue->IsCancellationRequested())))
        {
            ResultValue = TaskOutcome::Cancelled;
            Failure.Code = Prism::Fault::Code::Canceled;
        }
        CompletedAt_.store(CurrentTimestamp(), std::memory_order_release);
        Failure_ = Failure;
        Outcome_.store(ResultValue, std::memory_order_release);
        CompletionCount_.fetch_add(1, std::memory_order_relaxed);
        Phase_.store(TaskPhase::Completed, std::memory_order_release);
        Completed_.store(true, std::memory_order_release);
        return true;
    }

    auto TaskState::Quarantine() noexcept -> bool
    {
        if (!BeginCompletion()) return false;
        CompletedAt_.store(CurrentTimestamp(), std::memory_order_release);
        Failure_ = {};
        Outcome_.store(TaskOutcome::Quarantined, std::memory_order_release);
        CompletionCount_.fetch_add(1, std::memory_order_relaxed);
        Phase_.store(TaskPhase::Quarantined, std::memory_order_release);
        Completed_.store(true, std::memory_order_release);
        return true;
    }

    auto TaskState::Observation() const noexcept -> TaskObservation
    {
        const bool Cancellable = Cancellable_.load(std::memory_order_acquire) &&
            !IsCancelRequested() && !IsCompleted();
        const auto Failure = DrainFailure_.load(std::memory_order_acquire);
        const bool IsDrainBlocked = DrainBlocked_.load(std::memory_order_acquire) ||
            static_cast<bool>(Failure) || IsCancelDispatchFailed();
        auto DrainFailure = Prism::Fault::Failure{Prism::Fault::Code::Success};
        if (Failure) DrainFailure = *Failure;
        else if (IsDrainBlocked) DrainFailure.Code = Prism::Fault::Code::Blocked;
        return {Identity_, Result(), StartedAt_.load(std::memory_order_acquire),
            CompletedAt_.load(std::memory_order_acquire), IsStarted(),
            IsCancelRequested(), IsDrainBlocked, DrainFailure, Cancellable};
    }

    auto TaskState::MarkDrainBlocked(Prism::Fault::Failure Failure) noexcept -> void
    {
        if (Failure.Succeeded()) Failure.Code = Prism::Fault::Code::Blocked;
        try
        {
            auto Cause = std::make_shared<const Prism::Fault::Failure>(std::move(Failure));
            std::shared_ptr<const Prism::Fault::Failure> Empty;
            (void)DrainFailure_.compare_exchange_strong(
                Empty, std::move(Cause), std::memory_order_acq_rel, std::memory_order_acquire);
        }
        catch (...) {}
        DrainBlocked_.store(true, std::memory_order_release);
    }

    auto TaskState::CancelBeforeRetirement() -> std::expected<void, Prism::Fault::Failure>
    {
        CancelRequested_.store(true, std::memory_order_release);
        if (!InvokeCancel()) return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
        if (IsCancelDispatchFailed())
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        if (!CancelFinished_.load(std::memory_order_acquire))
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        return {};
    }

    auto TaskState::Retire() noexcept -> void
    {
        Cancel_ = {};
        Cancellable_.store(false, std::memory_order_release);
        Domain_.store({});
        IdentityObserver_.reset();
    }

    auto TaskState::Install(TaskRequest Request) noexcept -> void
    {
        Cancel_ = std::move(Request.Cancel);
        Cancellable_.store(static_cast<bool>(Cancel_), std::memory_order_release);
        IdentityObserver_ = std::move(Request.IdentityObserver);
    }

    auto TaskState::InvokeCancel() noexcept -> bool
    {
        if (CancelInvoked_.exchange(true)) return !CancelHookFailed_.load();
        try
        {
            if (Cancel_) Cancel_();
        }
        catch (...)
        {
            CancelHookFailed_.store(true, std::memory_order_release);
            CancelDispatchFailed_.store(true, std::memory_order_release);
        }
        CancelFinished_.store(true, std::memory_order_release);
        return !CancelHookFailed_.load(std::memory_order_acquire);
    }

    auto TaskHandle::WaitForRetirementAsync() const
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        const auto Retirement = State_->Retirement();
        if (!Retirement)
        {
            return FailedRetirementWait(Prism::Fault::Failure{
                Prism::Fault::Code::Blocked});
        }
        return Retirement->WaitAsync();
    }

    auto TaskHandle::FailedRetirementWait(Prism::Fault::Failure Failure)
        -> Net::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        co_return std::unexpected(std::move(Failure));
    }
}

/**
 * @file GenerationRetirement.hpp
 * @brief 应用停机时按真实物理回执退休活动与历史 generation owner。
 * @details 保留 Drain 首因；只有 Drain 协程完成且独立物理回执为真时释放 owner，
 *          失败但物理完成的兄弟继续排空，未知或在途 owner 留在原所有者集合中。
 */
#pragma once

#include <Preview/Application/RuntimeGenerationSnapshot.hpp>
#include <Preview/Application/RuntimeState.hpp>
#include <Preview/Application/Shutdown/BoundedOperation.hpp>
#include <Preview/Application/Shutdown/Types.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <cstddef>
#include <algorithm>
#include <chrono>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>

namespace Preview::Application::Shutdown::GenerationRetirement
{
    namespace Net = boost::asio;
    using Failure = Preview::Fault::Failure;

    struct GenerationRetirementRun final
    {
        std::shared_ptr<Application::RuntimeState> Runtime;
        ShutdownDeadline Deadline;
        std::optional<Failure> FirstFailure;
    };

    inline auto PreserveFirstFailure(
        std::optional<Failure> &FirstFailure,
        const Failure Cause) -> void
    {
        if (!FirstFailure)
        {
            FirstFailure = Cause;
        }
    }

    [[nodiscard]] inline auto PreserveOwnerFailure(
        std::optional<Failure> &FirstFailure,
        const std::shared_ptr<Application::RuntimeState> &State,
        const SharedRuntimeGenerationSnapshot &Owner) -> bool
    {
        const auto Cause = Owner->FirstDrainFailure();
        if (!Cause)
        {
            return false;
        }
        State->RecordGenerationRetirementFailure(Owner->Id(), *Cause);
        PreserveFirstFailure(FirstFailure, *Cause);
        return true;
    }

    [[nodiscard]] inline auto BoundedFailure(
        const ShutdownOperation::WaitResult &Result) noexcept -> Failure
    {
        if (!Result.Outcome)
        {
            return Result.Outcome.error();
        }
        return {Preview::Fault::Code::Blocked};
    }

    [[nodiscard]] inline auto DrainSnapshot(
        SharedRuntimeGenerationSnapshot Owner) -> Net::awaitable<ShutdownOutcome>
    {
        if (!Owner)
        {
            co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
        }
        co_return co_await Owner->DrainOwnedServices();
    }

    struct SnapshotDrainAttempt final
    {
        bool Completed{false};
        bool PhysicallyRetired{false};
        ShutdownOutcome Outcome{};
        std::optional<Failure> DurableFailure;
    };

    /** @brief 在同一绝对期限内重试可恢复的 drain attempt，直至任务与物理回执都完成。 */
    [[nodiscard]] inline auto DrainSnapshotUntilRetired(
        const std::shared_ptr<Application::RuntimeState> &State,
        const ShutdownDeadline Deadline,
        const SharedRuntimeGenerationSnapshot &Owner) -> Net::awaitable<SnapshotDrainAttempt>
    {
        SnapshotDrainAttempt Attempt;
        if (!State || !Owner)
        {
            Attempt.Completed = true;
            Attempt.Outcome = std::unexpected(Failure{Preview::Fault::Code::Blocked});
            co_return Attempt;
        }

        auto Executor = co_await Net::this_coro::executor;
        auto RetryTimer = Net::steady_timer(Executor);
        auto FirstAttemptFailure = std::optional<Failure>{};
        for (;;)
        {
            if (Attempt.Completed)
            {
                Attempt.PhysicallyRetired = Owner->PhysicalRetirementComplete();
                Attempt.DurableFailure = Owner->FirstDrainFailure();
            }
            if (Attempt.Completed && Attempt.PhysicallyRetired)
            {
                if (Attempt.DurableFailure)
                {
                    Attempt.Outcome = std::unexpected(*Attempt.DurableFailure);
                }
                else if (FirstAttemptFailure)
                {
                    Attempt.Outcome = std::unexpected(*FirstAttemptFailure);
                }
                else
                {
                    Attempt.Outcome = ShutdownOutcome{};
                }
                co_return Attempt;
            }
            if (std::chrono::steady_clock::now() >= Deadline)
            {
                if (Attempt.DurableFailure)
                {
                    Attempt.Outcome = std::unexpected(*Attempt.DurableFailure);
                }
                else if (FirstAttemptFailure)
                {
                    Attempt.Outcome = std::unexpected(*FirstAttemptFailure);
                }
                else if (Attempt.Completed && !Attempt.Outcome)
                {
                    // 保留最后一轮 retryable failure，供本次 shutdown 返回，不写入 owner 历史。
                }
                else
                {
                    Attempt.Outcome = std::unexpected(Failure{
                        Preview::Fault::Code::Timeout, std::make_error_code(std::errc::timed_out)});
                }
                co_return Attempt;
            }

            auto Operation = DrainSnapshot(Owner);
            const auto Wait = co_await ShutdownOperation::Await(
                ShutdownOperation::Request{State, Deadline, std::move(Operation)});
            Attempt.Completed = Wait.Completed;
            Attempt.Outcome = Wait.Outcome;
            if (!Wait.Completed)
            {
                Attempt.PhysicallyRetired = false;
                Attempt.DurableFailure.reset();
                Attempt.Outcome = std::unexpected(BoundedFailure(Wait));
                co_return Attempt;
            }
            Attempt.PhysicallyRetired = Owner->PhysicalRetirementComplete();
            Attempt.DurableFailure = Owner->FirstDrainFailure();
            if (!Wait.Outcome && !Attempt.DurableFailure)
            {
                const auto Cause = Wait.Outcome.error();
                if (Cause.Code != Preview::Fault::Code::Canceled &&
                    Cause.Code != Preview::Fault::Code::Blocked && !FirstAttemptFailure)
                {
                    FirstAttemptFailure = Cause;
                }
            }
            if (Attempt.DurableFailure)
            {
                Attempt.Outcome = std::unexpected(*Attempt.DurableFailure);
            }
            if (Attempt.PhysicallyRetired)
            {
                if (Attempt.DurableFailure)
                {
                    Attempt.Outcome = std::unexpected(*Attempt.DurableFailure);
                }
                else if (FirstAttemptFailure)
                {
                    Attempt.Outcome = std::unexpected(*FirstAttemptFailure);
                }
                else if (!Wait.Outcome)
                {
                    const auto Code = Wait.Outcome.error().Code;
                    if (Code == Preview::Fault::Code::Canceled ||
                        Code == Preview::Fault::Code::Blocked)
                    {
                        Attempt.Outcome = ShutdownOutcome{};
                    }
                }
                co_return Attempt;
            }

            const auto RetryAt = std::min(Deadline,
                std::chrono::steady_clock::now() + std::chrono::milliseconds(1));
            RetryTimer.expires_at(RetryAt);
            boost::system::error_code Error;
            co_await RetryTimer.async_wait(Net::redirect_error(Net::use_awaitable, Error));
            if (Error && Error != Net::error::operation_aborted)
            {
                Attempt.Outcome = std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
                co_return Attempt;
            }
        }
    }

    /** @brief 在同一停机 deadline 内等待已经开始的周期 reaper 退出。 */
    [[nodiscard]] inline auto WaitForReaper(
        const std::shared_ptr<Application::RuntimeState> &State,
        const ShutdownDeadline Deadline) -> Net::awaitable<ShutdownOutcome>
    {
        while (State->GenerationReaperRunning.load(std::memory_order_acquire))
        {
            State->GenerationReaperSignal.expires_at(Deadline);
            if (!State->GenerationReaperRunning.load(std::memory_order_acquire))
            {
                break;
            }
            boost::system::error_code Error;
            co_await State->GenerationReaperSignal.async_wait(
                Net::redirect_error(Net::use_awaitable, Error));
            if (Error == Net::error::operation_aborted)
            {
                continue;
            }
            if (Error)
            {
                co_return std::unexpected(Preview::Fault::FromNative(
                    static_cast<std::error_code>(Error)));
            }
            co_return std::unexpected(Failure{
                Preview::Fault::Code::Timeout, std::make_error_code(std::errc::timed_out)});
        }
        co_return ShutdownOutcome{};
    }

    /** @brief 尝试所有可退休快照；已完成 owner 释放后继续处理其兄弟。 */
    [[nodiscard]] inline auto ReapRetiredGenerationSnapshots(
        const std::shared_ptr<Application::RuntimeState> &State)
        -> Net::awaitable<ShutdownOutcome>
    {
        if (!State || State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
        {
            co_return ShutdownOutcome{};
        }
        std::optional<Failure> FirstFailure;
        for (std::size_t Index = 0; Index < State->RetiredGenerationSnapshots.size();)
        {
            if (State->Phase.load(std::memory_order_acquire) != RuntimePhase::Ready)
            {
                break;
            }
            const auto Owner = State->RetiredGenerationSnapshots[Index];
            if (!Owner->CanRetire())
            {
                ++Index;
                continue;
            }
            const auto Result = co_await DrainSnapshot(Owner);
            if (!Owner->PhysicalRetirementComplete())
            {
                if (!PreserveOwnerFailure(FirstFailure, State, Owner))
                {
                    if (!Result)
                    {
                        PreserveFirstFailure(FirstFailure, Result.error());
                    }
                    else
                    {
                        PreserveFirstFailure(FirstFailure, Failure{Preview::Fault::Code::Blocked});
                    }
                }
                ++Index;
                continue;
            }
            if (!PreserveOwnerFailure(FirstFailure, State, Owner) && !Result)
            {
                PreserveFirstFailure(FirstFailure, Result.error());
            }
            const auto Retired = std::find_if(
                State->RetiredGenerationSnapshots.begin(), State->RetiredGenerationSnapshots.end(),
                [&Owner](const auto &Value) { return Value == Owner; });
            if (Retired == State->RetiredGenerationSnapshots.end())
            {
                PreserveFirstFailure(FirstFailure, Failure{Preview::Fault::Code::Blocked});
                ++Index;
                continue;
            }
            State->RetiredGenerationSnapshots.erase(Retired);
        }
        if (FirstFailure)
        {
            co_return std::unexpected(*FirstFailure);
        }
        co_return ShutdownOutcome{};
    }

    /** @brief 活动 owner 完成且物理回执为真后清 publication 与精确共享别名。 */
    [[nodiscard]] inline auto DrainActiveGeneration(
        GenerationRetirementRun &Run,
        const SharedRuntimeGenerationSnapshot &Owner) -> Net::awaitable<void>
    {
        const auto Attempt = co_await DrainSnapshotUntilRetired(
            Run.Runtime, Run.Deadline, Owner);
        if (!Attempt.Completed)
        {
            PreserveFirstFailure(Run.FirstFailure, Attempt.Outcome ?
                Failure{Preview::Fault::Code::Blocked} : Attempt.Outcome.error());
            co_return;
        }
        if (!Attempt.PhysicallyRetired)
        {
            if (!PreserveOwnerFailure(Run.FirstFailure, Run.Runtime, Owner))
            {
                PreserveFirstFailure(Run.FirstFailure, Attempt.Outcome ?
                    Failure{Preview::Fault::Code::Blocked} : Attempt.Outcome.error());
            }
            co_return;
        }
        if (!PreserveOwnerFailure(Run.FirstFailure, Run.Runtime, Owner) && !Attempt.Outcome)
        {
            PreserveFirstFailure(Run.FirstFailure, Attempt.Outcome.error());
        }
        if (!Run.Runtime->GenerationPublisher || !Run.Runtime->GenerationPublisher->Clear())
        {
            PreserveFirstFailure(Run.FirstFailure, Failure{Preview::Fault::Code::Blocked});
            co_return;
        }
        if (Run.Runtime->ProviderBindings == Owner->Services.Providers)
        {
            Run.Runtime->ProviderBindings.reset();
        }
        if (Run.Runtime->Services == Owner->Services.Session)
        {
            Run.Runtime->Services.reset();
        }
    }

    /** @brief 同期限尝试每个 retired sibling；只移除已完成且已物理退休的 owner。 */
    [[nodiscard]] inline auto DrainRetiredGenerations(
        GenerationRetirementRun &Run) -> Net::awaitable<void>
    {
        auto &Owners = Run.Runtime->RetiredGenerationSnapshots;
        for (std::size_t Index = 0; Index < Owners.size();)
        {
            const auto Owner = Owners[Index];
            const auto Attempt = co_await DrainSnapshotUntilRetired(
                Run.Runtime, Run.Deadline, Owner);
            if (!Attempt.Completed)
            {
                PreserveFirstFailure(Run.FirstFailure, Attempt.Outcome ?
                    Failure{Preview::Fault::Code::Blocked} : Attempt.Outcome.error());
                ++Index;
                continue;
            }
            if (!Attempt.PhysicallyRetired)
            {
                if (!PreserveOwnerFailure(Run.FirstFailure, Run.Runtime, Owner))
                {
                    PreserveFirstFailure(Run.FirstFailure, Attempt.Outcome ?
                        Failure{Preview::Fault::Code::Blocked} : Attempt.Outcome.error());
                }
                ++Index;
                continue;
            }
            if (!PreserveOwnerFailure(Run.FirstFailure, Run.Runtime, Owner) && !Attempt.Outcome)
            {
                PreserveFirstFailure(Run.FirstFailure, Attempt.Outcome.error());
            }
            const auto Retired = std::find_if(
                Owners.begin(), Owners.end(), [&Owner](const auto &Value) { return Value == Owner; });
            if (Retired == Owners.end())
            {
                PreserveFirstFailure(Run.FirstFailure, Failure{Preview::Fault::Code::Blocked});
                ++Index;
                continue;
            }
            Owners.erase(Retired);
        }
    }

    /**
     * @brief 关闭账户准入后按同一绝对期限排空活动及所有 retired generation。
     * @param State 持有 publisher、活动别名与 retired snapshot owner 的应用状态。
     * @param Deadline 本次 shutdown 共用期限；此函数不重置或延长期限。
     * @return 所有 owner 物理退休且无 drain 错误时成功；失败完整保留首因与 Native。
     * @details drain 协程完成且独立物理回执为真时才释放对应 owner；未知、超时或仍在途 owner
     *          保留在原 publication/vector 中。由 Application control executor 调用。
     */
    [[nodiscard]] inline auto DrainGenerationSnapshots(
        const std::shared_ptr<Application::RuntimeState> &State,
        const ShutdownDeadline Deadline) -> Net::awaitable<ShutdownOutcome>
    {
        if (!State)
        {
            co_return std::unexpected(Failure{Preview::Fault::Code::Blocked});
        }
        const auto Reaper = co_await WaitForReaper(State, Deadline);
        if (!Reaper)
        {
            co_return std::unexpected(Reaper.error());
        }
        GenerationRetirementRun Run{State, Deadline, {}};
        if (!State->GenerationPublisher)
        {
            PreserveFirstFailure(Run.FirstFailure, Failure{Preview::Fault::Code::Blocked});
        }
        else
        {
            const auto ClosedAccounts = State->GenerationPublisher->CloseAllAccounts();
            if (!ClosedAccounts)
            {
                PreserveFirstFailure(Run.FirstFailure, ClosedAccounts.error());
            }
        }
        const auto Active = State->ActiveGenerationSnapshot();
        if (Active)
        {
            co_await DrainActiveGeneration(Run, Active);
        }
        co_await DrainRetiredGenerations(Run);
        if (Run.FirstFailure)
        {
            co_return std::unexpected(*Run.FirstFailure);
        }
        co_return ShutdownOutcome{};
    }
}

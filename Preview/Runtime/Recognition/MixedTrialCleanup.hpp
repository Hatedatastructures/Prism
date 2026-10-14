/**
 * @file MixedTrialCleanup.hpp
 * @brief MixedTrial 的 deadline、cancel 和 transport cleanup owner。
 */

#pragma once

#include <Preview/Runtime/Recognition/MixedTrialDecision.hpp>
#include <Preview/Runtime/Recognition/MixedTrialModel.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <utility>

namespace Preview::Recognition
{

    /**
     * @class MixedTrialCleanup
     * @brief 统一处理控制终态、replay 结果和 commit 后 transport 所有权。
     * @details 控制终态会取消底层等待；返回 transport 与入站 transport 始终按别名关系只清理一次。
     */
    class MixedTrialCleanup
    {
    public:
        explicit MixedTrialCleanup(SharedProfile Profile,
            Preview::Diagnose::ContextState Trace = Preview::Diagnose::CaptureCurrentContext())
            : Profile_(std::move(Profile)), Trace_(std::move(Trace))
        {
        }

        [[nodiscard]] auto EffectiveDeadline(const RecognitionControl& Control) const
            -> RecognitionControl::Clock::time_point
        {
            const auto Limit = RecognitionControl::Clock::time_point::max();
            if (Profile_->Budget().Timeout.count() <= 0)
            {
                return Control.Deadline;
            }
            const auto BudgetDeadline = RecognitionControl::Clock::now() + Profile_->Budget().Timeout;
            return Control.Deadline == Limit ? BudgetDeadline : (std::min)(Control.Deadline, BudgetDeadline);
        }

        [[nodiscard]] auto SetControlTerminal(MixedTrialTerminalRequest Request) const -> bool
        {
            auto& Result = *Request.Result;
            const auto& Control = *Request.Control;
            if (Control.IsCancelled())
            {
                if (Request.InvokeCancel)
                {
                    detail::InvokeCancel(Control);
                }
                detail::SetControlStatus(Result, RecognitionControlEvent::Cancelled);
                Result = CompleteBufferResult(std::move(Result), *Request.Buffer, *Request.Inbound);
                return true;
            }
            if (Request.Deadline != RecognitionControl::Clock::time_point::max() &&
                RecognitionControl::Clock::now() >= Request.Deadline)
            {
                if (Request.InvokeCancel)
                {
                    detail::InvokeCancel(Control);
                }
                detail::SetControlStatus(Result, RecognitionControlEvent::TimedOut);
                Result = CompleteBufferResult(std::move(Result), *Request.Buffer, *Request.Inbound);
                return true;
            }
            return false;
        }

        auto CommitPrepared(MixedTrialCommitRequest Request) const -> Net::awaitable<RecognizeResult>
        {
            auto Result = std::move(Request.Result);
            auto Prepared = std::move(Request.Prepared);
            const auto Handle = Request.Handle;
            auto Inbound = std::move(Request.Inbound);
            auto Control = std::move(Request.Control);
            auto* Buffer = Request.Buffer;
            const auto Deadline = Request.Deadline;
            if (SetControlTerminal(MixedTrialTerminalRequest{&Result, &Control, Deadline, Buffer, &Inbound}))
            {
                co_return Result;
            }

            Result.preread.assign(Buffer->Data().begin(), Buffer->Data().end());
            CommitContext Context;
            Context.Candidate = Handle.Id();
            Context.Inbound = Buffer->Replay(Inbound);
            Context.Bytes = Buffer->Bytes();
            Context.Trace = Trace_;
            auto CommittedRace = co_await detail::AwaitWithControl(Prepared.Commit(std::move(Context)),
                ControlRaceRequest{Control, Deadline});
            auto Committed = std::move(CommittedRace.Value);
            if (CommittedRace.Controlled)
            {
                const auto CleanupFailure = detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                detail::SetControlStatus(Result, CommittedRace.Event);
                detail::RethrowCleanupFailure(CleanupFailure);
                co_return CompleteNoTransportResult(std::move(Result), *Buffer);
            }
            if (SetControlTerminal(
                    MixedTrialTerminalRequest{&Result, &Control, Deadline, Buffer, &Inbound, false}))
            {
                const auto CleanupFailure = detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                Result.transport.reset();
                detail::RethrowCleanupFailure(CleanupFailure);
                co_return Result;
            }

            MixedTrialDecision::NormalizeCommit(Result, Committed, Handle);
            if (Committed.Status == RecognitionStatus::Accepted && !Committed.Polluted)
            {
                if (!Committed.Transport)
                {
                    const auto CleanupFailure = detail::CleanupTransports({{}, Inbound});
                    detail::SetResultStatus(ResultStatusRequest{&Result, RecognitionStatus::IoError,
                        std::make_error_code(std::errc::operation_not_supported)});
                    detail::RethrowCleanupFailure(CleanupFailure);
                }
                else
                {
                    Result.transport = std::move(Committed.Transport);
                }
            }
            else
            {
                const auto CleanupFailure = detail::CleanupTransports({std::move(Committed.Transport), Inbound});
                Result.transport.reset();
                detail::RethrowCleanupFailure(CleanupFailure);
            }
            co_return Result;
        }

        static auto CompleteBufferResult(RecognizeResult Result, ProbeBuffer& Buffer,
            const SharedTransmission& Inbound) -> RecognizeResult
        {
            Result.ProbeBytes = Buffer.Size();
            Result.preread.assign(Buffer.Data().begin(), Buffer.Data().end());
            Result.transport = Buffer.Replay(Inbound);
            return Result;
        }

        static auto CompleteNoTransportResult(RecognizeResult Result, ProbeBuffer& Buffer) -> RecognizeResult
        {
            Result.ProbeBytes = Buffer.Size();
            Result.preread.assign(Buffer.Data().begin(), Buffer.Data().end());
            Result.transport.reset();
            return Result;
        }

    private:
        SharedProfile Profile_;
        Preview::Diagnose::ContextState Trace_;
    };

} // namespace Preview::Recognition

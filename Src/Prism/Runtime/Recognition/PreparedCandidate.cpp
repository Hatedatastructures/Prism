/** @file PreparedCandidate.cpp @brief 一次性已准备候选提交实现。 */
#include <Prism/Runtime/Recognition/PreparedCandidate.hpp>
#include <Prism/Runtime/Recognition/Detail/RecognitionConfig.hpp>
#include <Prism/Runtime/Recognition/CandidateHandle.hpp>

#include <system_error>
#include <utility>

namespace Prism::Recognition
{
    auto CandidateHandle::PrepareOwned(SharedCandidateStore Owner, CandidateId Id,
        PrepareContext Context) -> Net::awaitable<PrepareResult>
    {
        const CandidateSpec *Candidate = Owner ? Owner->Find(Id) : nullptr;
        if (!Candidate || !Candidate->Prepare)
        {
            PrepareResult Result;
            Result.Candidate = Id;
            co_return Result;
        }
        Context.Candidate = Id;
        co_return co_await Candidate->Prepare(std::move(Context));
    }

    auto CandidateHandle::CommitOwned(SharedCandidateStore Owner, CandidateId Id,
        CommitContext Context) -> Net::awaitable<CommitResult>
    {
        const CandidateSpec *Candidate = Owner ? Owner->Find(Id) : nullptr;
        if (!Candidate || !Candidate->Commit)
        {
            CommitResult Result;
            Result.Candidate = Id;
            co_return Result;
        }
        Context.Candidate = Id;
        co_return co_await Candidate->Commit(std::move(Context));
    }

    PreparedCandidate::PreparedCandidate(CandidateHandle Handle, PrepareResult Result)
        : Handle_(std::move(Handle)), Result_(std::move(Result))
    {
    }

    auto PreparedCandidate::IsValid() const noexcept -> bool
    {
        return Handle_.IsValid() && Result_.Status == RecognitionStatus::Accepted &&
            !Result_.Polluted && !detail::IsCancellationError(Result_.Error);
    }

    auto PreparedCandidate::Id() const noexcept -> CandidateId
    {
        return Handle_.Id();
    }

    auto PreparedCandidate::Handle() const -> CandidateHandle
    {
        return Handle_;
    }

    auto PreparedCandidate::Result() const noexcept -> const PrepareResult&
    {
        return Result_;
    }

    auto PreparedCandidate::Commit(CommitContext Context) -> Net::awaitable<CommitResult>
    {
        const bool AlreadyAttempted = Committed_;
        Committed_ = true;
        if (AlreadyAttempted || !IsValid() || Context.Polluted)
        {
            CommitResult Result;
            Result.Candidate = Handle_.Id();
            Result.Status = RecognitionStatus::Polluted;
            Result.Error = std::make_error_code(std::errc::operation_not_permitted);
            Result.Polluted = true;
            co_return Result;
        }
        Context.Candidate = Handle_.Id();
        Context.PreparedState = Result_.PreparedState;
        Context.Polluted = Context.Polluted || Result_.Polluted;
        co_return co_await Handle_.Commit(std::move(Context));
    }

    auto PreparedCandidate::Commit(SharedTransmission Inbound) -> Net::awaitable<CommitResult>
    {
        CommitContext Context;
        Context.Inbound = std::move(Inbound);
        co_return co_await Commit(std::move(Context));
    }
}

/**
 * @file ConfiguredAcceptor.hpp
 * @brief 一次性提交的已准备候选接受状态。
 */

#pragma once

#include <Prism/Runtime/Recognition/RecognitionConfig.hpp>

#include <boost/asio/awaitable.hpp>

#include <system_error>
#include <utility>

namespace Prism::Recognition
{
    /**
     * @class PreparedCandidate
     * @brief 可移动的已准备候选，带一次性提交屏障。
     */
    class PreparedCandidate
    {
    public:
        PreparedCandidate() = default;

        PreparedCandidate(CandidateHandle Handle, PrepareResult Result)
            : Handle_(std::move(Handle)), Result_(std::move(Result))
        {
        }

        PreparedCandidate(const PreparedCandidate&) = delete;
        auto operator=(const PreparedCandidate&) -> PreparedCandidate& = delete;
        PreparedCandidate(PreparedCandidate&&) noexcept = default;
        auto operator=(PreparedCandidate&&) noexcept -> PreparedCandidate& = default;

        [[nodiscard]] auto IsValid() const noexcept -> bool
        {
            return Handle_.IsValid() && Result_.Status == RecognitionStatus::Accepted && !Result_.Polluted &&
                !detail::IsCancellationError(Result_.Error);
        }

        [[nodiscard]] auto Id() const noexcept -> CandidateId
        {
            return Handle_.Id();
        }

        [[nodiscard]] auto Handle() const -> CandidateHandle
        {
            return Handle_;
        }

        [[nodiscard]] auto Result() const noexcept -> const PrepareResult&
        {
            return Result_;
        }

        /**
         * @brief 只提交一次。
         * @param Context 提交输入，包含回放用的 transport。
         * @return 提交结果。
         */
        [[nodiscard]] auto Commit(CommitContext Context) -> Net::awaitable<CommitResult>
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

        /**
         * @brief 面向回放 transport 的便捷提交重载。
         * @param Inbound 回放 transport。
         * @return 提交结果。
         */
        [[nodiscard]] auto Commit(SharedTransmission Inbound) -> Net::awaitable<CommitResult>
        {
            CommitContext Context;
            Context.Inbound = std::move(Inbound);
            co_return co_await Commit(std::move(Context));
        }

    private:
        CandidateHandle Handle_;
        PrepareResult Result_;
        bool Committed_{false};
    };
} // namespace Prism::Recognition

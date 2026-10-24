/**
 * @file PreparedCandidate.hpp
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

        PreparedCandidate(CandidateHandle Handle, PrepareResult Result);

        PreparedCandidate(const PreparedCandidate&) = delete;
        auto operator=(const PreparedCandidate&) -> PreparedCandidate& = delete;
        PreparedCandidate(PreparedCandidate&&) noexcept = default;
        auto operator=(PreparedCandidate&&) noexcept -> PreparedCandidate& = default;

        [[nodiscard]] auto IsValid() const noexcept -> bool;

        [[nodiscard]] auto Id() const noexcept -> CandidateId;

        [[nodiscard]] auto Handle() const -> CandidateHandle;

        [[nodiscard]] auto Result() const noexcept -> const PrepareResult&;

        /**
         * @brief 只提交一次。
         * @param Context 提交输入，包含回放用的 transport。
         * @return 提交结果。
         */
        [[nodiscard]] auto Commit(CommitContext Context) -> Net::awaitable<CommitResult>;

        /**
         * @brief 面向回放 transport 的便捷提交重载。
         * @param Inbound 回放 transport。
         * @return 提交结果。
         */
        [[nodiscard]] auto Commit(SharedTransmission Inbound) -> Net::awaitable<CommitResult>;

    private:
        CandidateHandle Handle_;
        PrepareResult Result_;
        bool Committed_{false};
    };
} // namespace Prism::Recognition

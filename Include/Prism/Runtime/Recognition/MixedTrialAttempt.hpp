/**
 * @file MixedTrialAttempt.hpp
 * @brief MixedTrial 候选认证试探和控制 race owner。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <vector>

#include <Prism/Runtime/Recognition/MixedTrialModel.hpp>

namespace Prism::Recognition
{

    /**
     * @class MixedTrialAttempt
     * @brief 按候选顺序执行 prepare，并把每次等待与取消/超时做 race。
     * @details 候选 ID 和 CryptoTrials 由调用方结果 owner 保持，PreparedCandidate 只在本轮返回。
     */
    class MixedTrialAttempt
    {
    public:
        explicit MixedTrialAttempt(MixedTrialAttemptContext Context);

        auto Prepare(std::vector<CandidateId> Candidates, ProbeSnapshot Snapshot)
            -> Net::awaitable<detail::ControlRaceResult<MixedTrialAttemptResult>>;

    private:
        [[nodiscard]] auto RemainingBudget() const -> RecognitionBudget;

        auto SetControlTerminal(MixedTrialAttemptResult &Outcome) const -> bool;

        SharedProfile Profile_;
        RecognizeResult *Result_{nullptr};
        const RecognitionControl *Control_{nullptr};
        RecognitionControl::Clock::time_point Deadline_{};
    };

} // namespace Prism::Recognition

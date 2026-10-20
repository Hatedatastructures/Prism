/**
 * @file MixedTrialModel.hpp
 * @brief MixedTrial 试探阶段共享的纯请求、结果和状态模型。
 */

#pragma once

#include <Prism/Runtime/Recognition/PreparedCandidate.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <system_error>
#include <vector>

namespace Prism::Recognition
{

    /** @struct MixedTrialInspection @brief 一次结构检查产生的候选计划。 */
    struct MixedTrialInspection
    {
        std::vector<CandidateId> Active;
        std::vector<CandidateId> Structural;
        std::size_t Required{0};
        bool NeedMore{false};
    };

    /** @struct MixedTrialAttemptResult @brief 一轮候选试探结果。 */
    struct MixedTrialAttemptResult
    {
        std::vector<PreparedCandidate> Prepared;
        std::vector<CandidateId> Rejected;
        CandidateId Candidate{InvalidCandidate};
        RecognitionStatus Status{RecognitionStatus::Accepted};
        std::error_code Error{};
        bool Polluted{false};
        bool Terminal{false};
        bool NeedMore{false};
        std::size_t Required{0};
    };

    /** @struct MixedTrialAttemptContext @brief 试探 owner 的稳定输入。 */
    struct MixedTrialAttemptContext
    {
        SharedProfile Profile;
        RecognizeResult *Result{nullptr};
        const RecognitionControl *Control{nullptr};
        RecognitionControl::Clock::time_point Deadline{};
    };

    /** @struct MixedTrialTerminalRequest @brief 终态检查和回放清理所需的借用输入。 */
    struct MixedTrialTerminalRequest
    {
        RecognizeResult *Result{nullptr};
        const RecognitionControl *Control{nullptr};
        RecognitionControl::Clock::time_point Deadline{};
        ProbeBuffer *Buffer{nullptr};
        const SharedTransmission *Inbound{nullptr};
        bool InvokeCancel{true};
    };

    /** @struct MixedTrialCommitRequest @brief 已准备候选提交所需的所有权输入。 */
    struct MixedTrialCommitRequest
    {
        RecognizeResult Result;
        PreparedCandidate Prepared;
        CandidateHandle Handle;
        SharedTransmission Inbound;
        ProbeBuffer *Buffer{nullptr};
        RecognitionControl Control;
        RecognitionControl::Clock::time_point Deadline{};
    };

    /** @struct MixedTrialWinner @brief 已认证候选的唯一性决策。 */
    struct MixedTrialWinner
    {
        CandidateId Candidate{InvalidCandidate};
        bool Ambiguous{false};
    };

} // namespace Prism::Recognition

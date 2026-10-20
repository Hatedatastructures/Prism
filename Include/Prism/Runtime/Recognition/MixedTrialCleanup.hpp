/**
 * @file MixedTrialCleanup.hpp
 * @brief MixedTrial 的 deadline、cancel 和 transport cleanup owner。
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <Prism/Runtime/Recognition/MixedTrialDecision.hpp>
#include <Prism/Runtime/Recognition/MixedTrialModel.hpp>

#include <utility>

namespace Prism::Recognition
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
            Prism::Diagnose::ContextState Trace = Prism::Diagnose::CaptureCurrentContext())
            : Profile_(std::move(Profile)), Trace_(std::move(Trace))
        {
        }

        [[nodiscard]] auto EffectiveDeadline(const RecognitionControl& Control) const
            -> RecognitionControl::Clock::time_point;

        [[nodiscard]] auto SetControlTerminal(MixedTrialTerminalRequest Request) const -> bool;

        auto CommitPrepared(MixedTrialCommitRequest Request) const -> Net::awaitable<RecognizeResult>;

        static auto CompleteBufferResult(RecognizeResult Result, ProbeBuffer& Buffer,
            const SharedTransmission& Inbound) -> RecognizeResult;

        static auto CompleteNoTransportResult(RecognizeResult Result, ProbeBuffer& Buffer) -> RecognizeResult;

    private:
        SharedProfile Profile_;
        Prism::Diagnose::ContextState Trace_;
    };

} // namespace Prism::Recognition

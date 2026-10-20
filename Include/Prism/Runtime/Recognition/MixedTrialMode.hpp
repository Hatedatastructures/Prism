/**
 * @file MixedTrialMode.hpp
 * @brief MixedTrial recognition coordinator.
 */

#pragma once

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

#include <Prism/Runtime/Recognition/MixedTrialAttempt.hpp>
#include <Prism/Runtime/Recognition/MixedTrialCleanup.hpp>
#include <Prism/Runtime/Recognition/MixedTrialDecision.hpp>
#include <Prism/Runtime/Recognition/MixedTrialModel.hpp>
#include <Prism/Runtime/Recognition/MixedTrialPlan.hpp>

namespace Prism::Recognition
{

    namespace Net = boost::asio;

    /**
     * @class MixedTrialMode
     * @brief 串行协调结构检查、认证试探、候选决策和提交清理。
     */
    class MixedTrialMode
    {
    private:
        enum class ProbeProgress
        {
            Ready,
            NeedMore,
            Complete,
        };

        struct TrialInput final
        {
            SharedProfile Profile;
            RecognizeResult Result;
            SharedTransmission Inbound;
            ProbeBuffer *Buffer{nullptr};
            RecognitionControl Control;
            Prism::Diagnose::ContextState Trace;
        };

        struct TrialState final
        {
            RecognizeResult Result;
            SharedTransmission Inbound;
            ProbeBuffer *Buffer{nullptr};
            RecognitionControl Control;
            RecognitionControl::Clock::time_point Deadline{};
            std::vector<CandidateId> Active;
            std::vector<CandidateId> Structural;
            ProbeSnapshot Snapshot{};
            std::size_t Required{0};
            std::size_t CandidateRequired{0};
            bool Indexed{false};
            MixedTrialPlan Plan;
            MixedTrialDecision Decision;
            MixedTrialCleanup Cleanup;

            explicit TrialState(TrialInput Input);
        };

    public:
        explicit MixedTrialMode(SharedProfile Profile,
            Prism::Diagnose::ContextState Trace = Prism::Diagnose::CaptureCurrentContext())
            : Profile_(std::move(Profile)), Trace_(std::move(Trace))
        {
        }

        /**
         * @brief Recognize using the caller-owned probe buffer.
         * @param Inbound Inbound transport.
         * @param Buffer Connection-level pre-read owner.
         * @param Control Optional total deadline and cancellation state.
         * @return Recognition result.
         */
        [[nodiscard]] auto Recognize(SharedTransmission Inbound, ProbeBuffer &Buffer,
                                     RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>;

    private:
        /** @brief 按当前控制状态完成一次受控增量预读。 */
        auto EnsureProbe(TrialState &State) -> Net::awaitable<bool>;

        /** @brief 完成首字节索引、结构检查和 TLS route 收敛。 */
        auto InspectProbe(TrialState &State) -> ProbeProgress;

        /** @brief 运行候选认证试探并收口受控终态。 */
        auto PrepareTrial(TrialState &State)
            -> Net::awaitable<std::optional<MixedTrialAttemptResult>>;

        auto RunTrial(TrialState State) -> Net::awaitable<RecognizeResult>;

    private:
        SharedProfile Profile_;
        Prism::Diagnose::ContextState Trace_;
    };

} // namespace Prism::Recognition

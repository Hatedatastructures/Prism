/**
 * @file ConfiguredMode.hpp
 * @brief Configured recognition coordinator and decision state owner.
 */

#pragma once

#include <Prism/Runtime/Recognition/CandidateSelection.hpp>
#include <Prism/Runtime/Recognition/PreparedCandidate.hpp>
#include <Prism/Runtime/Recognition/ProbeBuffer.hpp>
#include <Prism/Runtime/Recognition/RecognitionConfig.hpp>

#include <boost/asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <optional>
#include <utility>

namespace Prism::Recognition
{
    /**
     * @class ConfiguredMode
     * @brief Coordinator for a profile with one configured candidate.
     */
    class ConfiguredMode
    {
    private:
        enum class ProbeProgress
        {
            Ready,
            NeedMore,
            Complete,
        };

        struct TerminalRequest
        {
            RecognizeResult* Result{nullptr};
            const RecognitionControl* Control{nullptr};
            RecognitionControl::Clock::time_point Deadline{};
            ProbeBuffer* Buffer{nullptr};
            const SharedTransmission* Inbound{nullptr};
            bool InvokeCancel{true};
        };

        struct PrepareRequest
        {
            CandidateHandle Handle;
            ProbeSnapshot Snapshot;
            const RecognitionControl* Control{nullptr};
            RecognitionControl::Clock::time_point Deadline{};
            RecognizeResult* Result{nullptr};
        };

        struct CommitRequest
        {
            RecognizeResult Result;
            PreparedCandidate Prepared;
            CandidateHandle Handle;
            SharedTransmission Inbound;
            ProbeBuffer* Buffer{nullptr};
            RecognitionControl Control;
            RecognitionControl::Clock::time_point Deadline{};
        };

        struct ConfiguredProbeState
        {
            RecognizeResult Result;
            CandidateHandle Handle;
            SharedTransmission Inbound;
            ProbeBuffer *Buffer{nullptr};
            RecognitionControl Control;
            RecognitionControl::Clock::time_point Deadline{};
            std::size_t Required{0};
        };

        struct PreparedProbeResult final
        {
            std::optional<PreparedCandidate> Candidate;
            bool NeedMore{false};
        };

    public:
        explicit ConfiguredMode(SharedProfile Profile,
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
        [[nodiscard]] auto Recognize(SharedTransmission Inbound, ProbeBuffer& Buffer,
            RecognitionControl Control = {}) -> Net::awaitable<RecognizeResult>;

    private:
        /** @brief 执行单候选的增量预读、路由、认证准备和一次性提交。 */
        auto RunProbe(ConfiguredProbeState State) -> Net::awaitable<RecognizeResult>;

        auto InspectProbe(ConfiguredProbeState &State, const ProbeSnapshot &Snapshot) -> ProbeProgress;

        auto PrepareCandidate(ConfiguredProbeState &State, const ProbeSnapshot &Snapshot)
            -> Net::awaitable<PreparedProbeResult>;

    private:
        [[nodiscard]] auto EffectiveDeadline(const RecognitionControl& Control) const
            -> RecognitionControl::Clock::time_point;

        static auto InitializeResult(RecognizeResult& Result, const CandidateHandle& Handle) -> void;

        static auto SetStatus(ResultStatusRequest Request) -> void;

        static auto CompleteBufferResult(RecognizeResult Result, ProbeBuffer& Buffer,
            const SharedTransmission& Inbound) -> RecognizeResult;

        static auto CompleteNoTransportResult(RecognizeResult Result, ProbeBuffer& Buffer) -> RecognizeResult;

        static auto SetControlTerminal(TerminalRequest Request) -> bool;

        static auto RemainingBudget(const RecognitionBudget& Budget,
            RecognitionControl::Clock::time_point Deadline) -> RecognitionBudget;

        auto CommitPrepared(CommitRequest Request) -> Net::awaitable<RecognizeResult>;

        auto Prepare(PrepareRequest Request) -> Net::awaitable<detail::ControlRaceResult<PrepareResult>>;

        static auto NormalizeCommit(RecognizeResult& Result, CommitResult& Committed,
            const CandidateHandle& Handle) -> void;

        SharedProfile Profile_;
        Prism::Diagnose::ContextState Trace_;
    };
} // namespace Prism::Recognition

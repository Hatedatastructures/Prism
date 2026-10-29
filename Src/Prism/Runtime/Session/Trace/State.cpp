/** @file State.cpp @brief 会话阶段记录和 exactly-once close audit 实现。 */
#include <Prism/Runtime/Session/LogState.hpp>

#include <chrono>
#include <cstdint>
#include <string_view>

namespace Prism::Runtime::SessionSupport
{
    auto SessionLogState::AppendPhase(
        Prism::Text::FixedText<128U>& Result,
        const std::uint32_t CurrentMask,
        const PhaseEntry Entry) -> void
    {
        if ((CurrentMask & Entry.Flag) == 0U)
        {
            return;
        }
        if (!Result.Empty())
        {
            Result.PushBack('>');
        }
        Result.Append(Entry.Name);
    }

    auto SessionLogState::MarkStage(const std::string_view Stage) noexcept -> void
    {
        if (Stage == "Recognition" || Stage == "recognition")
        {
            PhaseMask.fetch_or(RecognitionPhase, std::memory_order_relaxed);
        }
        else if (Stage == "Accept" || Stage == "accept")
        {
            PhaseMask.fetch_or(AcceptPhase, std::memory_order_relaxed);
        }
        else if (Stage == "Authentication" || Stage == "Auth" || Stage == "auth")
        {
            PhaseMask.fetch_or(AuthPhase, std::memory_order_relaxed);
        }
        else if (Stage == "Dial" || Stage == "dial")
        {
            PhaseMask.fetch_or(DialPhase, std::memory_order_relaxed);
        }
        else if (Stage == "Relay" || Stage == "relay")
        {
            PhaseMask.fetch_or(RelayPhase, std::memory_order_relaxed);
        }
        else if (Stage == "CarrierProbe" || Stage == "carrier_probe")
        {
            PhaseMask.fetch_or(CarrierProbePhase, std::memory_order_relaxed);
        }
        else if (Stage == "CarrierCommit" || Stage == "carrier_commit")
        {
            PhaseMask.fetch_or(CarrierCommitPhase, std::memory_order_relaxed);
        }
    }

    auto SessionLogState::PhaseSequence() const noexcept -> Prism::Text::FixedText<128U>
    {
        const auto Mask = PhaseMask.load(std::memory_order_relaxed);
        Prism::Text::FixedText<128U> Result;
        AppendPhase(Result, Mask, PhaseEntry{CarrierProbePhase, "CarrierProbe"});
        AppendPhase(Result, Mask, PhaseEntry{CarrierCommitPhase, "CarrierCommit"});
        AppendPhase(Result, Mask, PhaseEntry{RecognitionPhase, "Recognition"});
        AppendPhase(Result, Mask, PhaseEntry{AcceptPhase, "Accept"});
        AppendPhase(Result, Mask, PhaseEntry{AuthPhase, "Authentication"});
        AppendPhase(Result, Mask, PhaseEntry{DialPhase, "Dial"});
        AppendPhase(Result, Mask, PhaseEntry{RelayPhase, "Relay"});
        if (Result.Empty())
        {
            Result.Append("None");
        }
        Result.Append(">Close");
        return Result;
    }

    auto SessionLogState::LogClose() noexcept -> void
    {
        if (CloseLogged.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        const auto Elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - StartedAt).count();
        const auto Status = Prism::Text::PascalCaseValue(
            Prism::Fault::Describe(FinalCode.load(std::memory_order_acquire)));
        const auto Context = Trace.With(Prism::Diagnose::Fields::Stage, std::string_view{"Close"})
            .With(Prism::Diagnose::Fields::Status, Status.View())
            .With(Prism::Diagnose::Fields::FaultCode, Status.View())
            .With(Prism::Diagnose::Fields::ElapsedMs, static_cast<std::uint64_t>(Elapsed));
        const auto Sequence = PhaseSequence();
        const auto Receipt = Prism::Diagnose::Audit(Context,
            "SessionClosed Status={} ElapsedMs={} PhaseSequence={}", Status, Elapsed, Sequence);
        if (!Receipt.Accepted())
        {
            AuditFailures.fetch_add(1U, std::memory_order_relaxed);
        }
    }
}

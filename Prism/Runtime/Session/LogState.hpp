/**
 * @file LogState.hpp
 * @brief Session 阶段状态与 close audit owner
 * @details 记录阶段位图、最终 fault code 和一次性关闭审计；不依赖 Session 编排。
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <memory>
#include <string>
#include <string_view>
#include <Prism/Foundation/Utility/Text/FixedText.hpp>

#include <Prism/Foundation/Utility/Diagnose/ContextState.hpp>
#include <Prism/Foundation/Utility/Diagnose/Facade.hpp>
#include <Prism/Foundation/Utility/Diagnose/FieldKey.hpp>
#include <Prism/Foundation/Fault/Code.hpp>

namespace Prism::Runtime::SessionSupport
{

    /**
     * @struct SessionLogState
     * @brief 会话诊断状态
     * @details 阶段位图和最终 fault code 由会话协程写入；close 审计通过
     *          原子标志保证 exactly-once。
     */
    struct SessionLogState final
    {
        static constexpr std::uint32_t RecognitionPhase = 1U << 0U;
        static constexpr std::uint32_t AcceptPhase = 1U << 1U;
        static constexpr std::uint32_t AuthPhase = 1U << 2U;
        static constexpr std::uint32_t DialPhase = 1U << 3U;
        static constexpr std::uint32_t RelayPhase = 1U << 4U;
        static constexpr std::uint32_t CarrierProbePhase = 1U << 5U;
        static constexpr std::uint32_t CarrierCommitPhase = 1U << 6U;

        Prism::Diagnose::ContextState Trace{Prism::Diagnose::ContextState::Empty()};
        std::atomic<bool> CloseLogged{false};
        std::atomic<std::uint64_t> AuditFailures{0U};
        std::atomic<std::uint32_t> PhaseMask{0};
        std::chrono::steady_clock::time_point StartedAt{std::chrono::steady_clock::now()};
        std::atomic<Prism::Fault::Code> FinalCode{Prism::Fault::Code::Success};

        struct PhaseEntry final
        {
            std::uint32_t Flag;
            std::string_view Name;
        };

        static auto AppendPhase(Prism::Text::FixedText<128U> &Result,
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

        /**
         * @brief 记录阶段
         * @param Stage 阶段名称
         */
        auto MarkStage(const std::string_view Stage) noexcept -> void
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

        /**
         * @brief 生成阶段序列
         * @return 以 Close 结尾的阶段序列
         */
        [[nodiscard]] auto PhaseSequence() const noexcept -> Prism::Text::FixedText<128U>
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

        /**
         * @brief 写入 exactly-once close 审计
         */
        auto LogClose() noexcept -> void
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
            if (!Receipt.Accepted()) { AuditFailures.fetch_add(1U, std::memory_order_relaxed); }
        }
    };

} // namespace Prism::Runtime::SessionSupport
